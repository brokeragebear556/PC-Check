<#
.SYNOPSIS
  Read-only gaming PC audit. Checks hardware, BIOS-level settings (XMP, ReBAR, UEFI),
  Windows gaming settings, displays, storage, background load, and writes an HTML report
  plus a JSON snapshot. If a previous snapshot exists, the report shows a before/after diff.

.USAGE
  powershell -ExecutionPolicy Bypass -File .\PC-Audit.ps1
  powershell -ExecutionPolicy Bypass -File .\PC-Audit.ps1 -OutDir D:\Reports -NoOpen

  Run from an elevated (Administrator) PowerShell to also check TPM, Secure Boot,
  CPU/ACPI temperature and SSD wear. Nothing on the system is changed.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PC-Audit'),
    [switch]$NoOpen
)

$ErrorActionPreference = 'Continue'
$started = Get-Date
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- helpers
$Results = New-Object System.Collections.Generic.List[object]
$Info    = [ordered]@{}

function Add-Check {
    param([string]$Id, [string]$Category, [string]$Name, [string]$Value,
          [ValidateSet('PASS','WARN','FAIL','INFO')][string]$Status = 'INFO',
          [int]$Impact = 5, [string]$Fix = '')
    $Results.Add([pscustomobject]@{
        Id = $Id; Category = $Category; Name = $Name; Value = $Value
        Status = $Status; Impact = $Impact; Fix = $Fix })
}

function Invoke-Check {
    param([string]$Label, [scriptblock]$Block)
    Write-Host ("  - {0}" -f $Label)
    try { & $Block } catch {
        Add-Check -Id ("error-" + $Label) -Category 'Script' -Name $Label -Value ("Check failed: " + $_.Exception.Message) -Status 'INFO'
    }
}

function Get-RegValue($Path, $Name) {
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

if (-not ([System.Management.Automation.PSTypeName]'PcAuditNative').Type) {
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class PcAuditNative {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct DISPLAY_DEVICE {
    public int cb;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]  public string DeviceName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceString;
    public int StateFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceID;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=128)] public string DeviceKey;
  }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct DEVMODE {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmDeviceName;
    public short dmSpecVersion; public short dmDriverVersion; public short dmSize; public short dmDriverExtra;
    public int dmFields; public int dmPositionX; public int dmPositionY; public int dmDisplayOrientation; public int dmDisplayFixedOutput;
    public short dmColor; public short dmDuplex; public short dmYResolution; public short dmTTOption; public short dmCollate;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)] public string dmFormName;
    public short dmLogPixels; public int dmBitsPerPel; public int dmPelsWidth; public int dmPelsHeight;
    public int dmDisplayFlags; public int dmDisplayFrequency;
    public int dmICMMethod; public int dmICMIntent; public int dmMediaType; public int dmDitherType;
    public int dmReserved1; public int dmReserved2; public int dmPanningWidth; public int dmPanningHeight;
  }
  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);
  [DllImport("kernel32.dll")]
  static extern bool GetFirmwareType(ref int firmwareType);

  public static int FirmwareType() { int t = 0; try { GetFirmwareType(ref t); } catch {} return t; }

  public static string[] Displays() {
    List<string> list = new List<string>();
    DISPLAY_DEVICE d = new DISPLAY_DEVICE(); d.cb = Marshal.SizeOf(d);
    for (uint i = 0; EnumDisplayDevices(null, i, ref d, 0); i++) {
      if ((d.StateFlags & 1) != 0) {
        DEVMODE cur = new DEVMODE(); cur.dmSize = (short)Marshal.SizeOf(cur);
        if (EnumDisplaySettings(d.DeviceName, -1, ref cur)) {
          int max = cur.dmDisplayFrequency; int maxAny = cur.dmDisplayFrequency;
          DEVMODE m = new DEVMODE(); m.dmSize = (short)Marshal.SizeOf(m);
          for (int k = 0; EnumDisplaySettings(d.DeviceName, k, ref m); k++) {
            if (m.dmDisplayFrequency > maxAny) maxAny = m.dmDisplayFrequency;
            if (m.dmPelsWidth == cur.dmPelsWidth && m.dmPelsHeight == cur.dmPelsHeight && m.dmDisplayFrequency > max) max = m.dmDisplayFrequency;
          }
          string mon = "";
          DISPLAY_DEVICE md = new DISPLAY_DEVICE(); md.cb = Marshal.SizeOf(md);
          if (EnumDisplayDevices(d.DeviceName, 0, ref md, 0)) mon = md.DeviceString;
          list.Add(d.DeviceName + "|" + mon + "|" + d.DeviceString + "|" + cur.dmPelsWidth + "|" + cur.dmPelsHeight + "|" + cur.dmDisplayFrequency + "|" + max + "|" + maxAny + "|" + (((d.StateFlags & 4) != 0) ? "1" : "0"));
        }
      }
      d = new DISPLAY_DEVICE(); d.cb = Marshal.SizeOf(d);
    }
    return list.ToArray();
  }
}
"@
}

Write-Host "PC Audit - read-only diagnostics" -ForegroundColor Cyan
if (-not $IsAdmin) { Write-Host "  (Not elevated: TPM, Secure Boot, temps and SSD wear will be skipped. Run as Administrator for the full set.)" -ForegroundColor Yellow }

# Shared data
$cs   = Get-CimInstance Win32_ComputerSystem
$os   = Get-CimInstance Win32_OperatingSystem
$cpu  = @(Get-CimInstance Win32_Processor)[0]
$bb   = Get-CimInstance Win32_BaseBoard
$bios = Get-CimInstance Win32_BIOS
$gpus = @(Get-CimInstance Win32_VideoController)
$nvsmi = (Get-Command nvidia-smi -ErrorAction SilentlyContinue)
$nv = $null
if ($nvsmi) {
    try {
        $line = (& nvidia-smi --query-gpu=name,driver_version,temperature.gpu,power.limit,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max,memory.total,clocks.max.graphics --format=csv,noheader,nounits | Select-Object -First 1)
        $p = $line -split '\s*,\s*'
        $nv = [pscustomobject]@{ Name=$p[0]; Driver=$p[1]; Temp=$p[2]; PowerLimit=$p[3]; GenMax=$p[4]; WidthCur=$p[5]; WidthMax=$p[6]; MemMiB=$p[7]; MaxClock=$p[8] }
    } catch { $nv = $null }
}

# ---------------------------------------------------------------- SYSTEM
Write-Host "System" -ForegroundColor Cyan
Invoke-Check 'System summary' {
    $vram = $null
    Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0*" -ErrorAction SilentlyContinue |
        Where-Object { $_.'HardwareInformation.qwMemorySize' } | ForEach-Object { $vram = [math]::Round($_.'HardwareInformation.qwMemorySize'/1GB,1) }
    $mons = @(Get-CimInstance -Namespace root\wmi WmiMonitorID -ErrorAction SilentlyContinue | ForEach-Object { (($_.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '') })
    $Info['Computer']    = $env:COMPUTERNAME
    $Info['Motherboard'] = "$($bb.Manufacturer) $($bb.Product)"
    $Info['BIOS']        = "$($bios.SMBIOSBIOSVersion) ($(([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd')))"
    $Info['CPU']         = "$($cpu.Name.Trim()) - $($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T"
    $Info['GPU']         = (($gpus | ForEach-Object { $_.Name }) -join ', ') + $(if ($vram) { " ($vram GB VRAM)" } else { '' })
    $Info['RAM']         = "$([math]::Round($cs.TotalPhysicalMemory/1GB)) GB"
    $Info['OS']          = "$($os.Caption) $((Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')) (build $($os.BuildNumber))"
    $Info['Monitors']    = ($mons -join ', ')
    $Info['Elevated']    = [string]$IsAdmin
}

# ---------------------------------------------------------------- MEMORY
Write-Host "Memory" -ForegroundColor Cyan
Invoke-Check 'RAM speed / XMP' {
    $dimms = @(Get-CimInstance Win32_PhysicalMemory)
    $cfg = ($dimms | Measure-Object ConfiguredClockSpeed -Minimum).Minimum
    $type = $dimms[0].SMBIOSMemoryType   # 26 = DDR4, 34 = DDR5
    $typeName = switch ($type) { 26 {'DDR4'} 34 {'DDR5'} 24 {'DDR3'} default {"type $type"} }
    $rated = $null
    foreach ($d in $dimms) {
        $pn = ($d.PartNumber + '').Trim()
        if     ($pn -match '(\d{4})C\d{2}')            { $rated = [int]$Matches[1] }   # Corsair / G.Skill  e.g. ...3200C16
        elseif ($pn -match 'KF\d(\d{2})C')            { $rated = [int]$Matches[1] * 100 } # Kingston Fury e.g. KF432C16
        elseif ($pn -match 'BL\d+G(\d{2})C')          { $rated = [int]$Matches[1] * 100 } # Crucial Ballistix
        elseif ($pn -match '-(\d{4})-')               { $rated = [int]$Matches[1] }
        if ($rated) { break }
    }
    $parts = (($dimms | ForEach-Object { ($_.PartNumber + '').Trim() } | Select-Object -Unique) -join ', ')
    $val = "$typeName running at $cfg MT/s; modules: $parts" + $(if ($rated) { "; kit rated $rated MT/s" } else { '' })
    if ($rated -and $cfg -lt ($rated - 50)) {
        Add-Check 'ram-xmp' 'Memory' 'RAM speed vs rated (XMP/EXPO)' $val 'FAIL' 1 "XMP/EXPO is off. BIOS -> enable XMP Profile 1 (Gigabyte: Tweaker -> Extreme Memory Profile). Expect +5-15% avg FPS and better 1% lows in CPU-bound games."
    } elseif (-not $rated -and (($type -eq 26 -and $cfg -le 2666) -or ($type -eq 34 -and $cfg -le 4800))) {
        Add-Check 'ram-xmp' 'Memory' 'RAM speed vs rated (XMP/EXPO)' $val 'WARN' 1 "Running at JEDEC default speed - XMP/EXPO is probably off. Check the kit's rated speed and enable XMP/EXPO in BIOS."
    } else {
        Add-Check 'ram-xmp' 'Memory' 'RAM speed vs rated (XMP/EXPO)' $val 'PASS' 1
    }
}
Invoke-Check 'RAM layout' {
    $dimms = @(Get-CimInstance Win32_PhysicalMemory)
    $chans = @($dimms | ForEach-Object { if ($_.DeviceLocator -match 'Channel\s*([A-Z])') { $Matches[1] } elseif ($_.BankLabel) { $_.BankLabel } } | Select-Object -Unique)
    $val = "$($dimms.Count) module(s): " + (($dimms | ForEach-Object { "$([math]::Round($_.Capacity/1GB))GB" }) -join ' + ') + "; channels: $($chans -join ',')"
    if ($dimms.Count -eq 1) { Add-Check 'ram-layout' 'Memory' 'Dual-channel' $val 'FAIL' 1 'Single stick = single channel. Add a matching second stick (big gain in games).' }
    else { Add-Check 'ram-layout' 'Memory' 'Dual-channel' $val 'PASS' 5 }
}
Invoke-Check 'RAM in use' {
    $used = ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100
    $val = "{0:N1} / {1:N1} GB ({2:N0}%) in use right now" -f (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)/1MB), ($os.TotalVisibleMemorySize/1MB), $used
    if ($used -gt 60) { Add-Check 'ram-used' 'Memory' 'RAM usage at audit time' $val 'WARN' 3 'Close background apps before gaming/benchmarking.' }
    else { Add-Check 'ram-used' 'Memory' 'RAM usage at audit time' $val 'PASS' 5 }
}
Invoke-Check 'Page file' {
    $pf = @(Get-CimInstance Win32_PageFileUsage)
    $val = if ($pf.Count) { ($pf | ForEach-Object { "$($_.Name) $($_.AllocatedBaseSize) MB" }) -join '; ' } else { 'none' }
    $val += "; system managed: $($cs.AutomaticManagedPagefile)"
    if (-not $pf.Count) { Add-Check 'pagefile' 'Memory' 'Page file' $val 'FAIL' 2 'No page file: some games crash. Re-enable "Automatically manage paging file size".' }
    else { Add-Check 'pagefile' 'Memory' 'Page file' $val 'PASS' 5 }
}

# ---------------------------------------------------------------- CPU
Write-Host "CPU" -ForegroundColor Cyan
Invoke-Check 'CPU turbo' {
    $s = (Get-Counter '\Processor Information(_Total)\% Processor Performance' -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop).CounterSamples | ForEach-Object { $_.CookedValue }
    $pct = [math]::Round(($s | Measure-Object -Maximum).Maximum)
    $eff = [math]::Round($cpu.MaxClockSpeed * $pct / 100)
    $val = "Peak $pct% of base clock (~$eff MHz effective, base $($cpu.MaxClockSpeed) MHz)"
    if ($pct -gt 102) { Add-Check 'cpu-turbo' 'CPU' 'Turbo boost active' $val 'PASS' 2 }
    else { Add-Check 'cpu-turbo' 'CPU' 'Turbo boost active' $val 'WARN' 2 'CPU did not exceed base clock during sampling. Check power plan max state = 100% and that Turbo/Enhanced Multi-Core is enabled in BIOS (re-check under load).' }
}
Invoke-Check 'CPU load' {
    $l = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop).CounterSamples | ForEach-Object { $_.CookedValue }
    $avg = [math]::Round(($l | Measure-Object -Average).Average, 1)
    $top = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object { $_.ProcessName }
    $val = "Idle CPU load $avg%; most CPU time so far: $($top -join ', ')"
    if ($avg -gt 15) { Add-Check 'cpu-load' 'CPU' 'Background CPU load' $val 'WARN' 3 'Something is using CPU at idle. Close it before benchmarking (see Task Manager).' }
    else { Add-Check 'cpu-load' 'CPU' 'Background CPU load' $val 'PASS' 5 }
}
Invoke-Check 'CPU temperature' {
    if (-not $IsAdmin) { Add-Check 'cpu-temp' 'CPU' 'CPU / ACPI temperature' 'Needs Administrator (or use HWiNFO for accurate core temps)' 'INFO' 5; return }
    $t = @(Get-CimInstance -Namespace root/wmi MSAcpi_ThermalZoneTemperature -ErrorAction Stop | ForEach-Object { [math]::Round($_.CurrentTemperature/10 - 273.15, 1) })
    if (-not $t.Count) { Add-Check 'cpu-temp' 'CPU' 'CPU / ACPI temperature' 'Not exposed by this board - use HWiNFO' 'INFO' 5; return }
    $mx = ($t | Measure-Object -Maximum).Maximum
    $val = "ACPI zones: $($t -join ', ') C (idle reading)"
    if ($mx -gt 80) { Add-Check 'cpu-temp' 'CPU' 'CPU / ACPI temperature' $val 'WARN' 2 'Hot at idle - check cooler mounting, fan curve and dust.' }
    else { Add-Check 'cpu-temp' 'CPU' 'CPU / ACPI temperature' $val 'PASS' 5 }
}

# ---------------------------------------------------------------- GPU
Write-Host "GPU" -ForegroundColor Cyan
Invoke-Check 'GPU driver' {
    $g = $gpus | Where-Object { $_.Name -match 'NVIDIA|AMD|Radeon|Arc' } | Select-Object -First 1
    if (-not $g) { $g = $gpus[0] }
    $age = [int]((Get-Date) - [datetime]$g.DriverDate).TotalDays
    $ver = if ($nv) { $nv.Driver } else { $g.DriverVersion }
    $val = "$($g.Name) driver $ver, dated $(([datetime]$g.DriverDate).ToString('yyyy-MM-dd')) ($age days old)"
    if ($age -gt 120) { Add-Check 'gpu-driver' 'GPU' 'GPU driver age' $val 'WARN' 3 'Update the GPU driver (NVIDIA App / AMD Adrenalin) - new games get fixes and performance profiles.' }
    else { Add-Check 'gpu-driver' 'GPU' 'GPU driver age' $val 'PASS' 3 }
}
Invoke-Check 'Resizable BAR' {
    if (-not $nv) { Add-Check 'gpu-rebar' 'GPU' 'Resizable BAR' 'Not an NVIDIA GPU or nvidia-smi missing - check AMD Adrenalin (Smart Access Memory) or GPU-Z' 'INFO' 2; return }
    $q = & nvidia-smi -q
    $i = [array]::FindIndex([string[]]$q, [Predicate[string]]{ param($x) $x -match 'BAR1 Memory Usage' })
    $total = $null
    if ($i -ge 0) { for ($k = $i + 1; $k -lt [math]::Min($i + 5, $q.Count); $k++) { if ($q[$k] -match 'Total\s*:\s*(\d+)\s*MiB') { $total = [int]$Matches[1]; break } } }
    if ($null -eq $total) { Add-Check 'gpu-rebar' 'GPU' 'Resizable BAR' 'Could not read BAR1 size' 'INFO' 2; return }
    $val = "BAR1 aperture $total MiB"
    if ($total -le 256) { Add-Check 'gpu-rebar' 'GPU' 'Resizable BAR' "$val (OFF)" 'FAIL' 2 'BIOS: enable "Above 4G Decoding" + "Re-Size BAR Support" (requires UEFI boot with CSM disabled). 0-10% gain depending on game.' }
    else { Add-Check 'gpu-rebar' 'GPU' 'Resizable BAR' "$val (ON)" 'PASS' 2 }
}
Invoke-Check 'HAGS' {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode'
    $state = switch ($v) { 2 {'On'} 1 {'Off'} default {'Not set (Off by default on Windows 10)'} }
    $isRtx40 = ($Info['GPU'] -match 'RTX\s*(40|50)')
    if ($v -eq 2) { Add-Check 'gpu-hags' 'GPU' 'Hardware-accelerated GPU scheduling' $state 'PASS' 2 }
    else {
        $fix = 'Settings -> System -> Display -> Graphics settings -> Hardware-accelerated GPU scheduling: On, then reboot.'
        if ($isRtx40) { $fix += ' Required for DLSS Frame Generation on RTX 40/50 cards.' }
        Add-Check 'gpu-hags' 'GPU' 'Hardware-accelerated GPU scheduling' $state $(if ($isRtx40) { 'FAIL' } else { 'WARN' }) 2 $fix
    }
}
Invoke-Check 'PCIe link' {
    if (-not $nv) { return }
    $val = "PCIe Gen$($nv.GenMax) max, width x$($nv.WidthCur) (card supports x$($nv.WidthMax)). Link drops to Gen1 at idle to save power - normal."
    if ([int]$nv.WidthCur -lt [int]$nv.WidthMax) { Add-Check 'gpu-pcie' 'GPU' 'PCIe link width' $val 'WARN' 2 'GPU is running at reduced lane width. Re-seat it in the top x16 slot; check that M.2 slots are not stealing lanes.' }
    elseif ([int]$nv.GenMax -le 3 -and [int]$nv.WidthMax -le 8) { Add-Check 'gpu-pcie' 'GPU' 'PCIe link width' $val 'INFO' 4 'x8 card on PCIe 3.0: small loss (2-5%), larger when VRAM overflows. Prefer x16 cards for future upgrades on this board.' }
    else { Add-Check 'gpu-pcie' 'GPU' 'PCIe link width' $val 'PASS' 4 }
}
Invoke-Check 'GPU temp / power' {
    if (-not $nv) { return }
    $val = "$($nv.Name): $($nv.Temp) C now, power limit $($nv.PowerLimit) W, boost up to $($nv.MaxClock) MHz, $($nv.MemMiB) MiB VRAM"
    if ([int]$nv.Temp -gt 70) { Add-Check 'gpu-temp' 'GPU' 'GPU temperature (idle)' $val 'WARN' 3 'Hot at idle - check fan curve, airflow and background GPU load.' }
    else { Add-Check 'gpu-temp' 'GPU' 'GPU temperature (idle)' $val 'PASS' 5 }
}

# ---------------------------------------------------------------- DISPLAY
Write-Host "Displays" -ForegroundColor Cyan
Invoke-Check 'Refresh rates' {
    $n = 0
    foreach ($row in [PcAuditNative]::Displays()) {
        $n++
        $f = $row -split '\|'
        $cur = [int]$f[5]; $max = [int]$f[6]; $maxAny = [int]$f[7]; $primary = ($f[8] -eq '1')
        $label = "Display $n" + $(if ($primary) { ' (primary)' } else { '' })
        $val = "$($f[3])x$($f[4]) @ $cur Hz; max at this resolution $max Hz" + $(if ($maxAny -gt $max) { "; $maxAny Hz available at another resolution" } else { '' })
        if ($cur -lt $max) {
            Add-Check "display-$n" 'Display' "$label refresh rate" $val 'WARN' $(if ($primary) { 2 } else { 4 }) "Settings -> System -> Display -> Advanced display -> pick this monitor -> set refresh rate to $max Hz. Also enable G-SYNC/FreeSync if supported."
        } else {
            Add-Check "display-$n" 'Display' "$label refresh rate" $val 'PASS' 4
        }
    }
}

# ---------------------------------------------------------------- WINDOWS GAMING SETTINGS
Write-Host "Windows settings" -ForegroundColor Cyan
Invoke-Check 'Power plan' {
    $act = (powercfg /getactivescheme) -join ' '
    $name = if ($act -match '\((.+)\)') { $Matches[1] } else { $act }
    $min = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN | Select-String 'Current AC') -replace '.*:\s*0x', ''
    $max = (powercfg /q SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX | Select-String 'Current AC') -replace '.*:\s*0x', ''
    $minP = if ($min) { [Convert]::ToInt32($min.Trim(), 16) } else { '?' }
    $maxP = if ($max) { [Convert]::ToInt32($max.Trim(), 16) } else { '?' }
    $val = "$name (CPU min $minP% / max $maxP%)"
    $hasBattery = @(Get-CimInstance Win32_Battery).Count -gt 0
    if ($maxP -ne '?' -and $maxP -lt 100) { Add-Check 'power-plan' 'Windows' 'Power plan' $val 'FAIL' 2 'Max processor state is below 100% - CPU is capped. Set it to 100% in Power Options -> Advanced.' }
    elseif ($name -match 'High performance|Ultimate|Bitsum|Ultra') { Add-Check 'power-plan' 'Windows' 'Power plan' $val 'PASS' 3 }
    elseif ($name -match 'saver') { Add-Check 'power-plan' 'Windows' 'Power plan' $val 'FAIL' 2 'Switch to High performance: Control Panel -> Power Options.' }
    elseif (-not $hasBattery) { Add-Check 'power-plan' 'Windows' 'Power plan' $val 'WARN' 4 'Desktop: High performance gives slightly snappier clocks. Control Panel -> Power Options.' }
    else { Add-Check 'power-plan' 'Windows' 'Power plan' $val 'PASS' 4 }
}
Invoke-Check 'Game Mode' {
    $v = Get-RegValue 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled'
    if ($v -eq 0) { Add-Check 'game-mode' 'Windows' 'Game Mode' 'Off' 'WARN' 4 'Settings -> Gaming -> Game Mode: On.' }
    else { Add-Check 'game-mode' 'Windows' 'Game Mode' $(if ($null -eq $v) { 'On (default)' } else { 'On' }) 'PASS' 4 }
}
Invoke-Check 'Game DVR' {
    $a = Get-RegValue 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled'
    $b = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled'
    $c = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'HistoricalCaptureEnabled'
    $val = "GameDVR=$a, AppCapture=$b, Background recording=$c"
    if ($c -eq 1) { Add-Check 'game-dvr' 'Windows' 'Xbox Game Bar background recording' $val 'WARN' 3 'Settings -> Gaming -> Captures -> turn off "Record what happened".' }
    else { Add-Check 'game-dvr' 'Windows' 'Xbox Game Bar background recording' $val 'PASS' 4 }
}
Invoke-Check 'Mouse acceleration' {
    $v = Get-RegValue 'HKCU:\Control Panel\Mouse' 'MouseSpeed'
    if ("$v" -ne '0') { Add-Check 'mouse-accel' 'Windows' 'Mouse acceleration (Enhance pointer precision)' 'On' 'WARN' 5 'Control Panel -> Mouse -> Pointer Options -> untick "Enhance pointer precision" for consistent aim.' }
    else { Add-Check 'mouse-accel' 'Windows' 'Mouse acceleration (Enhance pointer precision)' 'Off' 'PASS' 5 }
}
Invoke-Check 'Hypervisor / VBS' {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard -ErrorAction SilentlyContinue
    $hvci = ($dg -and ($dg.SecurityServicesRunning -contains 2))
    $vbs = if ($dg) { switch ([int]$dg.VirtualizationBasedSecurityStatus) { 0 {'Off'} 1 {'Enabled, not running'} 2 {'Running'} default {'?'} } } else { '?' }
    $val = "Hypervisor present: $($cs.HypervisorPresent); VBS: $vbs; Memory integrity (HVCI): $(if ($hvci) {'On'} else {'Off'})"
    if ($hvci) { Add-Check 'vbs' 'Windows' 'Virtualization-based security' $val 'WARN' 3 'Memory integrity costs ~5% in some games. Windows Security -> Device security -> Core isolation -> Memory integrity: Off (security tradeoff).' }
    elseif ($cs.HypervisorPresent) { Add-Check 'vbs' 'Windows' 'Virtualization-based security' $val 'INFO' 4 'Hyper-V is running (WSL/Docker/VM apps use it). Costs 0-5%. Only disable (bcdedit /set hypervisorlaunchtype off) if you do not need those features.' }
    else { Add-Check 'vbs' 'Windows' 'Virtualization-based security' $val 'PASS' 4 }
}
Invoke-Check 'Windows version' {
    $build = [int]$os.BuildNumber
    $val = $Info['OS']
    if ($build -lt 22000) { Add-Check 'os-version' 'Windows' 'Windows version / support' "$val - Windows 10 (mainstream support ended Oct 2025)" 'WARN' 3 'Upgrade to Windows 11 (or enroll in Extended Security Updates) to keep getting security fixes.' }
    else { Add-Check 'os-version' 'Windows' 'Windows version / support' $val 'PASS' 4 }
}
Invoke-Check 'Pending reboot / uptime' {
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $up = (Get-Date) - $os.LastBootUpTime
    $val = "Uptime {0}d {1}h; reboot pending: {2}" -f $up.Days, $up.Hours, $pending
    if ($pending -or $up.TotalDays -gt 7) { Add-Check 'uptime' 'Windows' 'Uptime / pending reboot' $val 'WARN' 4 'Reboot before benchmarking so before/after results are comparable.' }
    else { Add-Check 'uptime' 'Windows' 'Uptime / pending reboot' $val 'PASS' 5 }
}
Invoke-Check 'Defender' {
    try { $m = Get-MpComputerStatus -ErrorAction Stop; Add-Check 'defender' 'Windows' 'Windows Defender' "Real-time protection: $($m.RealTimeProtectionEnabled); signatures $($m.AntivirusSignatureAge) day(s) old" $(if ($m.RealTimeProtectionEnabled) { 'PASS' } else { 'WARN' }) 5 $(if (-not $m.RealTimeProtectionEnabled) { 'Turn real-time protection back on.' } else { '' }) }
    catch { Add-Check 'defender' 'Windows' 'Windows Defender' 'Unavailable (third-party AV?)' 'INFO' 5 }
}

# ---------------------------------------------------------------- FIRMWARE
Write-Host "Firmware" -ForegroundColor Cyan
Invoke-Check 'Boot mode' {
    $ft = [PcAuditNative]::FirmwareType()
    $mode = switch ($ft) { 1 {'Legacy BIOS (CSM)'} 2 {'UEFI'} default {'Unknown'} }
    $style = try { (Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) -ErrorAction Stop | Get-Disk -ErrorAction Stop).PartitionStyle } catch { '?' }
    $val = "Firmware: $mode; system disk partition style: $style"
    if ($ft -eq 1) { Add-Check 'boot-mode' 'Firmware' 'UEFI boot (needed for ReBAR)' $val 'WARN' 2 'Booting in Legacy mode: Resizable BAR needs UEFI. Convert the disk with MBR2GPT (back up first), then disable CSM.' }
    else { Add-Check 'boot-mode' 'Firmware' 'UEFI boot (needed for ReBAR)' "$val - safe to disable CSM" 'PASS' 3 }
}
Invoke-Check 'BIOS age' {
    $d = [datetime]$bios.ReleaseDate
    Add-Check 'bios' 'Firmware' 'BIOS version' "$($bios.SMBIOSBIOSVersion) released $($d.ToString('yyyy-MM-dd'))" 'INFO' 5 'Check the board vendor support page for a newer BIOS (microcode/ReBAR fixes). Updating resets BIOS settings, so redo XMP/ReBAR afterwards.'
}
Invoke-Check 'Secure Boot / TPM' {
    if (-not $IsAdmin) { Add-Check 'secureboot' 'Firmware' 'Secure Boot / TPM (Windows 11 readiness)' 'Needs Administrator' 'INFO' 5; return }
    $sb = try { Confirm-SecureBootUEFI -ErrorAction Stop } catch { 'n/a' }
    $tpm = try { $t = Get-Tpm -ErrorAction Stop; "present=$($t.TpmPresent) ready=$($t.TpmReady)" } catch { 'n/a' }
    $val = "Secure Boot: $sb; TPM: $tpm"
    if ("$sb" -ne 'True' -or $tpm -notmatch 'present=True') { Add-Check 'secureboot' 'Firmware' 'Secure Boot / TPM (Windows 11 readiness)' $val 'WARN' 4 'Windows 11 and some anti-cheat need TPM 2.0 (Intel PTT / AMD fTPM) and Secure Boot - enable in BIOS.' }
    else { Add-Check 'secureboot' 'Firmware' 'Secure Boot / TPM (Windows 11 readiness)' $val 'PASS' 4 }
}

# ---------------------------------------------------------------- STORAGE
Write-Host "Storage" -ForegroundColor Cyan
Invoke-Check 'Disk health' {
    $n = 0
    foreach ($d in Get-PhysicalDisk) {
        $n++
        $wear = ''
        if ($IsAdmin) { try { $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop; if ($null -ne $r.Wear) { $wear = "; wear $($r.Wear)%" }; if ($r.Temperature) { $wear += "; $($r.Temperature) C" } } catch {} }
        $val = "$($d.MediaType) $($d.BusType), $([math]::Round($d.Size/1GB)) GB, health $($d.HealthStatus)$wear"
        $name = "Disk: $($d.FriendlyName.Trim())"
        if ($d.HealthStatus -ne 'Healthy') { Add-Check "disk-$n" 'Storage' $name $val 'FAIL' 1 'Back up this drive now and plan a replacement.' }
        elseif ($d.MediaType -eq 'HDD' -and $n -eq 1) { Add-Check "disk-$n" 'Storage' $name $val 'WARN' 2 'Games on a hard drive load slowly and stutter - move them to an SSD.' }
        else { Add-Check "disk-$n" 'Storage' $name $val 'PASS' 5 }
    }
}
Invoke-Check 'Free space' {
    foreach ($v in Get-Volume | Where-Object { $_.DriveLetter -and $_.Size -gt 10GB }) {
        $pct = $v.SizeRemaining / $v.Size * 100
        $val = "{0:N0} GB free of {1:N0} GB ({2:N0}% free)" -f ($v.SizeRemaining/1GB), ($v.Size/1GB), $pct
        $nm = "Free space $($v.DriveLetter):"
        if ($pct -lt 5) { Add-Check "vol-$($v.DriveLetter)" 'Storage' $nm $val 'FAIL' 2 'Nearly full - SSDs slow down and games fail to patch. Free space or move games.' }
        elseif ($pct -lt 20 -and "$($v.DriveLetter):" -eq $env:SystemDrive) { Add-Check "vol-$($v.DriveLetter)" 'Storage' $nm $val 'WARN' 4 'System drive is over 80% full. Move game libraries to a roomier drive.' }
        elseif ($pct -lt 10) { Add-Check "vol-$($v.DriveLetter)" 'Storage' $nm $val 'WARN' 4 'Over 90% full.' }
        else { Add-Check "vol-$($v.DriveLetter)" 'Storage' $nm $val 'PASS' 5 }
    }
}
Invoke-Check 'TRIM' {
    $t = (fsutil behavior query DisableDeleteNotify) -join ' '
    if ($t -match 'NTFS DisableDeleteNotify = 0') { Add-Check 'trim' 'Storage' 'SSD TRIM' 'Enabled' 'PASS' 5 }
    elseif ($t -match 'NTFS DisableDeleteNotify = 1') { Add-Check 'trim' 'Storage' 'SSD TRIM' 'Disabled' 'WARN' 3 'Admin PowerShell: fsutil behavior set DisableDeleteNotify 0' }
    else { Add-Check 'trim' 'Storage' 'SSD TRIM' $t 'INFO' 5 }
}

# ---------------------------------------------------------------- BACKGROUND LOAD
Write-Host "Background load" -ForegroundColor Cyan
Invoke-Check 'Startup apps' {
    $approved = @{}
    foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
                   'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder') {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $approved[$_.Name] = ($_.Value[0] % 2 -eq 0) } }
    }
    $items = @(Get-CimInstance Win32_StartupCommand | ForEach-Object {
        $name = $_.Name; $key = ($approved.Keys | Where-Object { $_ -eq $name -or $_ -eq ($name + '.lnk') } | Select-Object -First 1)
        [pscustomobject]@{ Name = $name; Enabled = $(if ($key) { $approved[$key] } else { $true }) } })
    $on = @($items | Where-Object Enabled | ForEach-Object Name)
    $off = @($items | Where-Object { -not $_.Enabled } | ForEach-Object Name)
    $val = "Enabled ($($on.Count)): $($on -join ', '); disabled ($($off.Count))"
    if ($on.Count -gt 5) { Add-Check 'startup' 'Background' 'Startup apps' $val 'WARN' 3 'Task Manager -> Startup: disable launchers/updaters you do not need at boot.' }
    else { Add-Check 'startup' 'Background' 'Startup apps' $val 'PASS' 4 }
}
Invoke-Check 'Bloat services' {
    $pattern = 'EasyTune|AppCenter|AdjustService|GCloud\.exe|RGBFusion|nordsec-threatprotection|LGHUBUpdater|ArmouryCrate|AsusCertService|LightingService|iCUE|CorsairService|Razer|MSI\.CentralServer|Mystic|WallpaperEngine|McAfee|Norton|Avast|AVG|Dell.*Support|HP.*Analytics'
    $svc = @(Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and (($_.Name + ' ' + $_.PathName) -match $pattern) } | ForEach-Object { $_.Name })
    $val = if ($svc.Count) { "Running: $($svc -join ', ')" } else { 'None of the common offenders found' }
    if ($svc.Count) { Add-Check 'bloat' 'Background' 'Vendor bloat services' $val 'WARN' 3 'Uninstall vendor utilities you do not use (Settings -> Apps). Motherboard tuning apps (EasyTune/AppCenter) can also override BIOS settings.' }
    else { Add-Check 'bloat' 'Background' 'Vendor bloat services' $val 'PASS' 4 }
}
Invoke-Check 'Background apps' {
    $pattern = '^(chrome|msedge|firefox|Discord|steamwebhelper|EpicGamesLauncher|EADesktop|Spotify|OneDrive|Teams|ms-teams|lghub|iCUE|NVIDIA Overlay|PhoneExperienceHost|Dropbox|nordvpn)$'
    $p = @(Get-Process | Where-Object { $_.ProcessName -match $pattern } | Group-Object ProcessName | ForEach-Object {
        [pscustomobject]@{ N = $_.Name; MB = [math]::Round(($_.Group | Measure-Object WorkingSet64 -Sum).Sum / 1MB) } } | Sort-Object MB -Descending)
    $total = (Get-Process).Count
    $val = "$total processes; heavy apps open: " + $(if ($p.Count) { ($p | ForEach-Object { "$($_.N) ($($_.MB) MB)" }) -join ', ' } else { 'none' })
    if ($p.Count -ge 3 -or $total -gt 250) { Add-Check 'bg-apps' 'Background' 'Background apps' $val 'WARN' 3 'Close browsers, chat and launchers before benchmarking or competitive play.' }
    else { Add-Check 'bg-apps' 'Background' 'Background apps' $val 'PASS' 4 }
}
Invoke-Check 'Network' {
    $a = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Hyper-V|Virtual|VPN|TAP|WireGuard|Loopback' })
    if (-not $a.Count) { Add-Check 'network' 'Background' 'Network link' 'No physical adapter up' 'INFO' 5; return }
    $val = ($a | ForEach-Object { "$($_.Name): $($_.InterfaceDescription) @ $($_.LinkSpeed)" }) -join '; '
    $wired = $a | Where-Object { $_.MediaType -eq '802.3' -or $_.Name -match 'Ethernet' }
    if (-not $wired) { Add-Check 'network' 'Background' 'Network link' $val 'INFO' 4 'Wi-Fi only - Ethernet gives lower, steadier ping for online games.' }
    elseif ($wired | Where-Object { $_.LinkSpeed -match 'Mbps' -and [int]($_.LinkSpeed -replace '\D.*','') -lt 1000 }) { Add-Check 'network' 'Background' 'Network link' $val 'WARN' 4 'Ethernet negotiated below 1 Gbps - check the cable (Cat5e or better).' }
    else { Add-Check 'network' 'Background' 'Network link' $val 'PASS' 5 }
}

# ---------------------------------------------------------------- OUTPUT
$stamp   = $started.ToString('yyyyMMdd_HHmmss')
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$jsonPath = Join-Path $OutDir "PC-Audit_$stamp.json"
$htmlPath = Join-Path $OutDir "PC-Audit_$stamp.html"

$prevFile = Get-ChildItem -Path $OutDir -Filter 'PC-Audit_*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
$prev = $null
if ($prevFile) { try { $prev = Get-Content $prevFile.FullName -Raw | ConvertFrom-Json } catch { $prev = $null } }

$snapshot = [pscustomobject]@{ Timestamp = $started.ToString('s'); Info = $Info; Checks = $Results }
[IO.File]::WriteAllText($jsonPath, ($snapshot | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

function ConvertTo-HtmlText([string]$s) { [System.Net.WebUtility]::HtmlEncode($s) }

$scored = @($Results | Where-Object { $_.Status -ne 'INFO' })
$pass = @($scored | Where-Object Status -eq 'PASS').Count
$warn = @($scored | Where-Object Status -eq 'WARN').Count
$fail = @($scored | Where-Object Status -eq 'FAIL').Count
$score = if ($scored.Count) { [math]::Round((($pass + 0.5 * $warn) / $scored.Count) * 100) } else { 0 }

$sb = New-Object System.Text.StringBuilder
$null = $sb.Append(@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Audit Report</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e6ea;--pass:#1f883d;--warn:#b26b00;--fail:#cf222e;--info:#57606a;--passbg:#e6f4ea;--warnbg:#fff4e0;--failbg:#fde8e8;--infobg:#eef1f4;--accent:#0b62d6}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--muted:#9aa3ad;--line:#2a2f38;--pass:#3fb950;--warn:#d29922;--fail:#f85149;--info:#8b949e;--passbg:#12261a;--warnbg:#2b2110;--failbg:#2d1416;--infobg:#1f242c;--accent:#4c9aff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card b{display:block;font-size:24px}.card span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.spec{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.spec dt{color:var(--muted)}.spec dd{margin:0}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--muted);text-transform:uppercase}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.PASS{color:var(--pass);background:var(--passbg)}.WARN{color:var(--warn);background:var(--warnbg)}.FAIL{color:var(--fail);background:var(--failbg)}.INFO{color:var(--info);background:var(--infobg)}
ol.fixes{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 14px 14px 36px;margin:0}ol.fixes li{margin:6px 0}
.fix{color:var(--muted);font-size:13px}.wrap{overflow-x:auto}
</style></head><body><main>
<h1>PC Audit Report</h1>
<div class="muted">$(ConvertTo-HtmlText $Info['Computer']) &middot; $(ConvertTo-HtmlText ($started.ToString('yyyy-MM-dd HH:mm'))) &middot; $(if ($IsAdmin) {'run as Administrator'} else {'not elevated - some checks skipped'})</div>
<div class="cards">
<div class="card"><span>Score</span><b>$score%</b></div>
<div class="card"><span>Pass</span><b style="color:var(--pass)">$pass</b></div>
<div class="card"><span>Warnings</span><b style="color:var(--warn)">$warn</b></div>
<div class="card"><span>Failures</span><b style="color:var(--fail)">$fail</b></div>
</div>
<h2>System</h2><dl class="spec">
"@)
foreach ($k in $Info.Keys) { $null = $sb.Append("<dt>$(ConvertTo-HtmlText $k)</dt><dd>$(ConvertTo-HtmlText ([string]$Info[$k]))</dd>") }
$null = $sb.Append('</dl>')

# Before/after
if ($prev) {
    $prevMap = @{}; foreach ($c in $prev.Checks) { $prevMap[$c.Id] = $c }
    $rows = foreach ($c in $Results) {
        $o = $prevMap[$c.Id]
        $noisy = $c.Id -match '^(cpu-turbo|cpu-load|ram-used|bg-apps|uptime|gpu-temp|cpu-temp|vol-|defender)'
        if ($o -and ($o.Status -ne $c.Status -or (-not $noisy -and $o.Value -ne $c.Value))) {
            "<tr><td>$(ConvertTo-HtmlText $c.Name)</td><td><span class='pill $($o.Status)'>$($o.Status)</span> $(ConvertTo-HtmlText $o.Value)</td><td><span class='pill $($c.Status)'>$($c.Status)</span> $(ConvertTo-HtmlText $c.Value)</td></tr>"
        }
    }
    $null = $sb.Append("<h2>Changes since previous run <span class='muted'>($(ConvertTo-HtmlText $prev.Timestamp))</span></h2>")
    if ($rows) { $null = $sb.Append("<div class='wrap'><table><tr><th>Check</th><th>Before</th><th>After</th></tr>$($rows -join '')</table></div>") }
    else { $null = $sb.Append("<p class='muted'>No setting changes detected (ignoring live values like load, temps, free space).</p>") }
}

# Prioritized fixes
$todo = @($Results | Where-Object { $_.Status -in 'FAIL','WARN' -or ($_.Status -eq 'INFO' -and $_.Fix -and $_.Impact -le 4) } |
          Sort-Object @{e={$_.Impact}}, @{e={ switch ($_.Status) { 'FAIL' {0} 'WARN' {1} default {2} } }})
$null = $sb.Append('<h2>Fix these first (ranked by impact)</h2>')
if ($todo.Count) {
    $null = $sb.Append('<ol class="fixes">')
    foreach ($t in $todo) { $null = $sb.Append("<li><span class='pill $($t.Status)'>$($t.Status)</span> <b>$(ConvertTo-HtmlText $t.Name)</b> - $(ConvertTo-HtmlText $t.Value)<div class='fix'>$(ConvertTo-HtmlText $t.Fix)</div></li>") }
    $null = $sb.Append('</ol>')
} else { $null = $sb.Append('<p>Nothing to fix - all checks passed.</p>') }

# Full table
$null = $sb.Append("<h2>All checks</h2><div class='wrap'><table><tr><th>Status</th><th>Category</th><th>Check</th><th>Finding</th><th>Impact</th></tr>")
foreach ($c in ($Results | Sort-Object Category, Impact)) {
    $null = $sb.Append("<tr><td><span class='pill $($c.Status)'>$($c.Status)</span></td><td>$(ConvertTo-HtmlText $c.Category)</td><td>$(ConvertTo-HtmlText $c.Name)</td><td>$(ConvertTo-HtmlText $c.Value)$(if ($c.Fix -and $c.Status -ne 'PASS') { "<div class='fix'>$(ConvertTo-HtmlText $c.Fix)</div>" })</td><td>$($c.Impact)</td></tr>")
}
$elapsed = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
$null = $sb.Append("</table></div><p class='muted'>Impact: 1 = biggest real-world gain, 5 = minor. Read-only audit, nothing was changed. Took $elapsed s. Snapshot: $(ConvertTo-HtmlText $jsonPath)</p></main></body></html>")

[IO.File]::WriteAllText($htmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host ("Score {0}%  |  PASS {1}  WARN {2}  FAIL {3}" -f $score, $pass, $warn, $fail) -ForegroundColor Green
foreach ($t in ($todo | Select-Object -First 8)) {
    $color = if ($t.Status -eq 'FAIL') { 'Red' } elseif ($t.Status -eq 'WARN') { 'Yellow' } else { 'Gray' }
    Write-Host ("  [{0}] {1}: {2}" -f $t.Status, $t.Name, $t.Value) -ForegroundColor $color
}
Write-Host ""
Write-Host "Report:   $htmlPath"
Write-Host "Snapshot: $jsonPath"
if ($prev) { Write-Host "Compared against: $($prevFile.Name)" }
if (-not $NoOpen) { Start-Process $htmlPath }
