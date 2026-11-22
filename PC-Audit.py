#!/usr/bin/env python3
"""
PC Audit - read-only gaming PC audit (Linux engine, Windows launcher).

Linux:   checks hardware, firmware (UEFI, ReBAR, Secure Boot), memory speed (XMP/EXPO),
         GPU driver / PCIe link, displays, power profile, gaming tweaks, storage,
         background load and network, then writes an HTML report plus a JSON snapshot.
         If a previous snapshot exists, the report shows a before/after diff.
Windows: hands off to PC-Audit.ps1 (same folder), which produces the same report format.

USAGE
  python3 PC-Audit.py
  python3 PC-Audit.py --out-dir ~/Reports --no-open
  sudo python3 PC-Audit.py        # adds SSD wear/health via smartctl and RAM details via dmidecode

Nothing on the system is changed. Only the Python standard library is used.
"""
import argparse
import datetime as dt
import glob
import html
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- Windows hand-off
def run_windows(args):
    ps1 = os.path.join(HERE, 'PC-Audit.ps1')
    if not os.path.isfile(ps1):
        sys.exit('PC-Audit.ps1 was not found next to this script.')
    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ps1]
    if args.out_dir:
        cmd += ['-OutDir', args.out_dir]
    if args.no_open:
        cmd += ['-NoOpen']
    sys.exit(subprocess.call(cmd))


# ---------------------------------------------------------------- helpers
RESULTS = []
INFO = {}
IS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0
SUDO_USER = os.environ.get('SUDO_USER') if IS_ROOT else None

C = {'cyan': '\033[36m', 'yellow': '\033[33m', 'red': '\033[31m', 'green': '\033[32m',
     'gray': '\033[90m', 'reset': '\033[0m'} if sys.stdout.isatty() else {k: '' for k in
     ('cyan', 'yellow', 'red', 'green', 'gray', 'reset')}


def say(text, color=None):
    print((C[color] if color else '') + text + (C['reset'] if color else ''), flush=True)


def add(id_, category, name, value, status='INFO', impact=5, fix=''):
    RESULTS.append({'Id': id_, 'Category': category, 'Name': name, 'Value': str(value),
                    'Status': status, 'Impact': impact, 'Fix': fix})


def check(label):
    """Decorator: run the check immediately, turn exceptions into an INFO row."""
    def wrap(fn):
        say('  - ' + label)
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - one broken check must not stop the audit
            add('error-' + label, 'Script', label, 'Check failed: %s' % e, 'INFO')
        return fn
    return wrap


def section(name):
    say(name, 'cyan')


def read(path, default=None):
    try:
        with open(path, 'r', errors='replace') as f:
            return f.read().strip()
    except OSError:
        return default


def run(cmd, timeout=15):
    """Run a command, return stdout ('' if missing or failing)."""
    if not shutil.which(cmd[0]):
        return ''
    try:
        env = dict(os.environ, LC_ALL='C')
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=timeout, env=env, universal_newlines=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ''


# XDG_DATA_DIRS matters: without it snap/flatpak apps (e.g. Ubuntu's Firefox snap) are invisible
# and .html files fall through to the text editor.
GUI_VARS = ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
            'XDG_DATA_DIRS', 'XDG_CONFIG_DIRS', 'XDG_CURRENT_DESKTOP', 'XDG_SESSION_TYPE', 'DESKTOP_SESSION', 'PATH', 'LANG')
_gui_env_cache = None


def gui_env():
    """Desktop session variables (DISPLAY, DBus...). sudo strips them, so under sudo
    borrow them from one of the real user's running desktop processes."""
    global _gui_env_cache
    if _gui_env_cache is not None:
        return _gui_env_cache
    env = {k: os.environ[k] for k in GUI_VARS if os.environ.get(k)}
    if SUDO_USER:  # sudo resets most of these, so always take them from the user's own session
        import pwd
        pw = pwd.getpwnam(SUDO_USER)
        uid = pw.pw_uid
        env = {}
        for d in os.listdir('/proc'):
            if not d.isdigit():
                continue
            try:
                if os.stat('/proc/' + d).st_uid != uid:
                    continue
                with open('/proc/%s/environ' % d, 'rb') as f:
                    pe = dict(x.split(b'=', 1) for x in f.read().split(b'\0') if b'=' in x)
            except (OSError, ValueError):
                continue
            if b'DISPLAY' in pe or b'WAYLAND_DISPLAY' in pe:
                cand = {k: pe[k.encode()].decode(errors='replace') for k in GUI_VARS if k.encode() in pe}
                if len(cand) > len(env):
                    env = cand  # keep the process with the most complete desktop environment
                if 'XDG_DATA_DIRS' in env and 'DBUS_SESSION_BUS_ADDRESS' in env:
                    break
        if env:
            env.update(HOME=pw.pw_dir, USER=SUDO_USER, LOGNAME=SUDO_USER)
    _gui_env_cache = env
    return env


def as_user(cmd):
    """Prefix a command so it runs as the real desktop user inside their session."""
    if SUDO_USER and shutil.which('sudo'):
        return ['sudo', '-u', SUDO_USER, 'env'] + ['%s=%s' % kv for kv in gui_env().items()] + cmd
    return cmd


def run_as_user(cmd):
    """When running under sudo, query the desktop user's session (gsettings, xrandr...)."""
    return run(as_user(cmd)) if SUDO_USER else run(cmd)


def user_home():
    if SUDO_USER:
        import pwd
        return pwd.getpwnam(SUDO_USER).pw_dir
    return os.path.expanduser('~')


def gb(n):
    return n / 1024 ** 3


def cpu_times():
    with open('/proc/stat') as f:
        p = [int(x) for x in f.readline().split()[1:]]
    idle = p[3] + (p[4] if len(p) > 4 else 0)
    return idle, sum(p[:8])


def processes():
    """[(pid, comm, rss_bytes, cpu_ticks)] for all readable processes."""
    out = []
    for d in os.listdir('/proc'):
        if not d.isdigit():
            continue
        try:
            with open('/proc/%s/stat' % d) as f:
                s = f.read()
            comm = s[s.index('(') + 1:s.rindex(')')]
            rest = s[s.rindex(')') + 2:].split()
            ticks = int(rest[11]) + int(rest[12])
            rss = int(rest[21]) * os.sysconf('SC_PAGE_SIZE')
            out.append((int(d), comm, rss, ticks))
        except (OSError, ValueError, IndexError):
            pass
    return out


def os_release():
    d = {}
    for line in (read('/etc/os-release', '') or read('/usr/lib/os-release', '')).splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            d[k] = v.strip().strip('"')
    return d


# ---------------------------------------------------------------- hardware discovery
def pci_gpus():
    """Display-class PCI devices from sysfs: [{slot, vendor, name, driver, path}]"""
    gpus = []
    names = {}
    for line in run(['lspci', '-mm', '-nn', '-D']).splitlines():
        f = re.findall(r'"([^"]*)"', line)
        slot = line.split()[0] if line else ''
        if len(f) >= 3:
            names[slot] = re.sub(r'\s*\[[0-9a-f]{4}\]', '', '%s %s' % (f[1], f[2])).strip()
    for dev in sorted(glob.glob('/sys/bus/pci/devices/*')):
        cls = read(dev + '/class', '')
        if not cls.startswith('0x03'):
            continue
        slot = os.path.basename(dev)
        vendor = {'0x10de': 'NVIDIA', '0x1002': 'AMD', '0x8086': 'Intel'}.get(read(dev + '/vendor', ''), 'Other')
        drv = os.path.basename(os.path.realpath(dev + '/driver')) if os.path.exists(dev + '/driver') else 'none'
        gpus.append({'slot': slot, 'vendor': vendor, 'name': names.get(slot, vendor + ' GPU ' + slot),
                     'driver': drv, 'path': dev})
    # Discrete first
    gpus.sort(key=lambda g: (g['vendor'] == 'Intel', g['slot']))
    return gpus


def dimms():
    """Memory modules. Prefer udev's copy of SMBIOS (no root needed), fall back to dmidecode."""
    mods = {}
    for line in run(['udevadm', 'info', '-q', 'property', '-p', '/sys/class/dmi/id']).splitlines():
        m = re.match(r'MEMORY_DEVICE_(\d+)_([A-Z_]+)=(.*)', line)
        if m:
            mods.setdefault(int(m.group(1)), {})[m.group(2)] = m.group(3).strip()
    out = []
    for i in sorted(mods):
        d = mods[i]
        size = int(d.get('SIZE', '0') or 0)
        if not size or d.get('PRESENT') == '0':
            continue
        out.append({'size': size, 'type': d.get('TYPE', '?'), 'speed': int(d.get('SPEED_MTS', 0) or 0),
                    'configured': int(d.get('CONFIGURED_SPEED_MTS', 0) or 0),
                    'part': d.get('PART_NUMBER', ''), 'locator': d.get('LOCATOR', ''),
                    'bank': d.get('BANK_LOCATOR', '')})
    if out or not IS_ROOT:
        return out
    # dmidecode fallback (root only)
    for block in run(['dmidecode', '-t', '17']).split('\n\n'):
        def field(name):
            m = re.search(r'^\s*%s:\s*(.+)$' % re.escape(name), block, re.M)
            return m.group(1).strip() if m else ''
        sz = field('Size')
        m = re.match(r'(\d+)\s*(GB|MB)', sz)
        if not m:
            continue
        size = int(m.group(1)) * (1024 ** 3 if m.group(2) == 'GB' else 1024 ** 2)
        num = lambda s: int(re.sub(r'\D.*', '', s) or 0)
        out.append({'size': size, 'type': field('Type'), 'speed': num(field('Speed')),
                    'configured': num(field('Configured Memory Speed') or field('Configured Clock Speed')),
                    'part': field('Part Number'), 'locator': field('Locator'), 'bank': field('Bank Locator')})
    return out


def edid_name(path):
    try:
        with open(path, 'rb') as f:
            e = f.read()
    except OSError:
        return ''
    for off in range(54, 126, 18):
        blk = e[off:off + 18]
        if len(blk) == 18 and blk[:3] == b'\x00\x00\x00' and blk[3] == 0xFC:
            return blk[5:].split(b'\x0a')[0].decode('ascii', 'replace').strip()
    return ''


def nvidia_info():
    if not shutil.which('nvidia-smi'):
        return None
    line = run(['nvidia-smi', '--query-gpu=name,driver_version,temperature.gpu,power.limit,pcie.link.gen.max,'
                'pcie.link.width.current,pcie.link.width.max,memory.total,clocks.max.graphics',
                '--format=csv,noheader,nounits']).strip().splitlines()
    if not line:
        return None
    p = [x.strip() for x in line[0].split(',')]
    if len(p) < 9:
        return None
    return dict(zip(['Name', 'Driver', 'Temp', 'PowerLimit', 'GenMax', 'WidthCur', 'WidthMax', 'MemMiB', 'MaxClock'], p))


def to_int(s, default=0):
    try:
        return int(float(s))
    except (TypeError, ValueError):
        return default


# ================================================================= LINUX AUDIT
def audit_linux():
    started = dt.datetime.now()
    say('PC Audit - read-only diagnostics (Linux)', 'cyan')
    if not IS_ROOT:
        say('  (Not root: SSD health/wear via smartctl will be skipped. Run with sudo for the full set.)', 'yellow')

    rel = os_release()
    gpus = pci_gpus()
    nv = nvidia_info()
    mods = dimms()
    session = os.environ.get('XDG_SESSION_TYPE', '') or ('wayland' if os.environ.get('WAYLAND_DISPLAY') else 'x11' if os.environ.get('DISPLAY') else 'none')
    desktop = os.environ.get('XDG_CURRENT_DESKTOP', '')
    mem = {}
    for line in read('/proc/meminfo', '').splitlines():
        k, v = line.split(':', 1)
        mem[k] = int(v.split()[0]) * 1024
    cpuinfo = read('/proc/cpuinfo', '')
    cpu_model = (re.search(r'^model name\s*:\s*(.+)$', cpuinfo, re.M) or re.search(r'^Hardware\s*:\s*(.+)$', cpuinfo, re.M))
    cpu_model = cpu_model.group(1).strip() if cpu_model else platform.processor()
    threads = os.cpu_count() or 0
    cores = len(set(zip(re.findall(r'^physical id\s*:\s*(\d+)', cpuinfo, re.M), re.findall(r'^core id\s*:\s*(\d+)', cpuinfo, re.M)))) or threads
    dmi = lambda k: read('/sys/class/dmi/id/' + k, '') or ''

    def bios_date_str():
        d = dmi('bios_date')
        try:
            return dt.datetime.strptime(d, '%m/%d/%Y').strftime('%Y-%m-%d')
        except ValueError:
            return d or '?'


    # ------------------------------------------------------------ SYSTEM
    section('System')

    @check('System summary')
    def _():
        vram = ''
        if nv and nv['MemMiB'].isdigit():
            vram = ' (%.0f GB VRAM)' % (int(nv['MemMiB']) / 1024)
        else:
            for f in glob.glob('/sys/class/drm/card*/device/mem_info_vram_total'):
                vram = ' (%.0f GB VRAM)' % gb(to_int(read(f)))
                break
        mons = []
        for st in sorted(glob.glob('/sys/class/drm/card*-*/status')):
            if read(st) == 'connected':
                d = os.path.dirname(st)
                mons.append(edid_name(d + '/edid') or os.path.basename(d).split('-', 1)[1])
        INFO['Computer'] = socket.gethostname()
        INFO['Motherboard'] = ('%s %s' % (dmi('board_vendor'), dmi('board_name'))).strip()
        INFO['BIOS'] = '%s (%s)' % (dmi('bios_version'), bios_date_str())
        INFO['CPU'] = '%s - %dC/%dT' % (cpu_model, cores, threads)
        names = [nv['Name'] if nv and g['vendor'] == 'NVIDIA' and i == 0 else g['name'] for i, g in enumerate(gpus)]
        INFO['GPU'] = ', '.join(re.sub(r'^(NVIDIA Corporation|Advanced Micro Devices, Inc\. \[AMD/ATI\]|Intel Corporation) ', '', n) for n in names) + vram
        INFO['RAM'] = '%d GB' % round(gb(mem.get('MemTotal', 0)) + 0.3)
        INFO['OS'] = '%s (kernel %s)' % (rel.get('PRETTY_NAME', 'Linux'), platform.release())
        INFO['Desktop'] = ('%s on %s' % (desktop, session)).strip()
        INFO['Monitors'] = ', '.join(mons)
        INFO['Elevated'] = str(IS_ROOT)

    # ------------------------------------------------------------ MEMORY
    section('Memory')

    @check('RAM speed / XMP')
    def _():
        if not mods:
            add('ram-xmp', 'Memory', 'RAM speed vs rated (XMP/EXPO)',
                'Module details not exposed (needs systemd 248+ or run with sudo for dmidecode)', 'INFO', 1,
                'Re-run with sudo to read DIMM speeds.')
            return
        cfg = min(m['configured'] or m['speed'] for m in mods)
        typ = mods[0]['type']
        rated = None
        for m in mods:
            pn = m['part'].strip()
            for pat, mul in ((r'(\d{4})C\d{2}', 1), (r'KF\d(\d{2})C', 100), (r'BL\d+G(\d{2})C', 100),
                             (r'-(\d{4})-', 1), (r'DDR[45]\s+(\d{4})\b', 1)):
                mm = re.search(pat, pn)
                if mm:
                    rated = int(mm.group(1)) * mul
                    break
            if rated:
                break
        spd = max(m['speed'] for m in mods)
        if not rated and spd > cfg + 50:
            rated = spd  # SMBIOS reports the module can run faster than it does
        parts = ', '.join(sorted(set(m['part'].strip() for m in mods)))
        val = '%s running at %s MT/s; modules: %s' % (typ, cfg, parts) + ('; kit rated %d MT/s' % rated if rated else '')
        if rated and cfg < rated - 50:
            add('ram-xmp', 'Memory', 'RAM speed vs rated (XMP/EXPO)', val, 'FAIL', 1,
                'XMP/EXPO is off. BIOS -> enable XMP Profile 1 / EXPO. Expect +5-15% avg FPS and better 1% lows in CPU-bound games.')
        elif not rated and ((typ == 'DDR4' and cfg <= 2666) or (typ == 'DDR5' and cfg <= 4800)):
            add('ram-xmp', 'Memory', 'RAM speed vs rated (XMP/EXPO)', val, 'WARN', 1,
                "Running at JEDEC default speed - XMP/EXPO is probably off. Check the kit's rated speed and enable XMP/EXPO in BIOS.")
        else:
            add('ram-xmp', 'Memory', 'RAM speed vs rated (XMP/EXPO)', val, 'PASS', 1)

    @check('RAM layout')
    def _():
        if not mods:
            add('ram-layout', 'Memory', 'Dual-channel', 'Module layout not exposed - re-run with sudo', 'INFO', 1)
            return
        chans = []
        for m in mods:
            mm = re.search(r'Channel\s*([A-Z])', m['locator'] + ' ' + m['bank'], re.I)
            c = mm.group(1).upper() if mm else (m['bank'] or m['locator'])
            if c not in chans:
                chans.append(c)
        val = '%d module(s): %s; channels: %s' % (len(mods), ' + '.join('%dGB' % round(gb(m['size'])) for m in mods), ','.join(chans))
        if len(mods) == 1:
            add('ram-layout', 'Memory', 'Dual-channel', val, 'FAIL', 1, 'Single stick = single channel. Add a matching second stick (big gain in games).')
        else:
            add('ram-layout', 'Memory', 'Dual-channel', val, 'PASS', 5)

    @check('RAM in use')
    def _():
        tot, avail = mem['MemTotal'], mem.get('MemAvailable', mem.get('MemFree', 0))
        used = (tot - avail) / tot * 100
        val = '%.1f / %.1f GB (%.0f%%) in use right now' % (gb(tot - avail), gb(tot), used)
        if used > 60:
            add('ram-used', 'Memory', 'RAM usage at audit time', val, 'WARN', 3, 'Close background apps before gaming/benchmarking.')
        else:
            add('ram-used', 'Memory', 'RAM usage at audit time', val, 'PASS', 5)

    @check('Swap')
    def _():
        rows = read('/proc/swaps', '').splitlines()[1:]
        sw = ['%s %d MB' % (r.split()[0], to_int(r.split()[2]) // 1024) for r in rows if r.split()]
        swappiness = read('/proc/sys/vm/swappiness', '?')
        val = ('; '.join(sw) if sw else 'none') + '; swappiness %s' % swappiness
        if not sw:
            add('pagefile', 'Memory', 'Swap (page file)', val, 'FAIL', 2,
                'No swap: games that spike memory get OOM-killed. Enable zram (e.g. install systemd-zram-generator / zram-tools) or create a swapfile.')
        else:
            add('pagefile', 'Memory', 'Swap (page file)', val, 'PASS', 5)

    # ------------------------------------------------------------ CPU
    section('CPU')
    cpufreq = '/sys/devices/system/cpu/cpu0/cpufreq/'

    @check('CPU turbo')
    def _():
        no_turbo = read('/sys/devices/system/cpu/intel_pstate/no_turbo')
        boost = read('/sys/devices/system/cpu/cpufreq/boost')
        base = to_int(read(cpufreq + 'base_frequency')) // 1000
        if not base:
            mm = re.search(r'@\s*([\d.]+)GHz', cpu_model)
            base = int(float(mm.group(1)) * 1000) if mm else 0
        hw_max = to_int(read(cpufreq + 'cpuinfo_max_freq')) // 1000
        peak = 0
        for _i in range(3):
            for f in glob.glob('/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq'):
                peak = max(peak, to_int(read(f)) // 1000)
            time.sleep(0.5)
        if not peak:
            peak = max([int(float(x)) for x in re.findall(r'^cpu MHz\s*:\s*([\d.]+)', cpuinfo, re.M)] or [0])
        disabled = no_turbo == '1' or boost == '0'
        val = 'Peak sampled %d MHz (base %s MHz, max turbo %s MHz); turbo %s' % (
            peak, base or '?', hw_max or '?', 'DISABLED in OS' if disabled else 'allowed')
        if disabled:
            add('cpu-turbo', 'CPU', 'Turbo boost active', val, 'FAIL', 2,
                'Turbo is switched off (intel_pstate/no_turbo=1 or cpufreq/boost=0). Re-enable it, and check Turbo/Core Performance Boost is enabled in BIOS.')
        elif base and peak > base * 1.02:
            add('cpu-turbo', 'CPU', 'Turbo boost active', val, 'PASS', 2)
        elif base:
            add('cpu-turbo', 'CPU', 'Turbo boost active', val, 'WARN', 2,
                'CPU did not exceed base clock during sampling (normal at idle on some CPUs). Re-check under load; ensure Turbo is enabled in BIOS.')
        else:
            add('cpu-turbo', 'CPU', 'Turbo boost active', val, 'INFO', 2)

    @check('CPU load')
    def _():
        i1, t1 = cpu_times()
        p1 = {p[0]: p for p in processes()}
        time.sleep(3)
        i2, t2 = cpu_times()
        p2 = processes()
        load = 100.0 * (1 - (i2 - i1) / max(t2 - t1, 1))
        deltas = {}
        for pid, comm, _rss, ticks in p2:
            if pid in p1:
                deltas[comm] = deltas.get(comm, 0) + ticks - p1[pid][3]
        top = [c for c, d in sorted(deltas.items(), key=lambda x: -x[1]) if d > 0][:5]
        val = 'Idle CPU load %.1f%%; busiest during sampling: %s' % (load, ', '.join(top) or 'nothing notable')
        if load > 15:
            add('cpu-load', 'CPU', 'Background CPU load', val, 'WARN', 3, 'Something is using CPU at idle. Close it before benchmarking (check with top / System Monitor).')
        else:
            add('cpu-load', 'CPU', 'Background CPU load', val, 'PASS', 5)

    @check('CPU temperature')
    def _():
        temps = []
        for hw in glob.glob('/sys/class/hwmon/hwmon*'):
            name = read(hw + '/name', '')
            if name in ('coretemp', 'k10temp', 'zenpower', 'cpu_thermal', 'acpitz'):
                vals = [to_int(read(f)) / 1000 for f in glob.glob(hw + '/temp*_input')]
                vals = [v for v in vals if 0 < v < 125]
                if vals:
                    temps.append((name, max(vals)))
        if not temps:
            add('cpu-temp', 'CPU', 'CPU temperature', 'No CPU sensor exposed - install lm-sensors and run sensors-detect', 'INFO', 5)
            return
        cpu_t = [t for n, t in temps if n != 'acpitz'] or [t for _n, t in temps]
        mx = max(cpu_t)
        val = ', '.join('%s %.0f C' % (n, t) for n, t in temps) + ' (idle reading)'
        if mx > 80:
            add('cpu-temp', 'CPU', 'CPU temperature', val, 'WARN', 2, 'Hot at idle - check cooler mounting, fan curve and dust.')
        else:
            add('cpu-temp', 'CPU', 'CPU temperature', val, 'PASS', 5)

    # ------------------------------------------------------------ GPU
    section('GPU')
    main_gpu = gpus[0] if gpus else None

    @check('GPU driver')
    def _():
        if not main_gpu:
            add('gpu-driver', 'GPU', 'GPU driver', 'No display adapter found', 'INFO', 3)
            return
        g = main_gpu
        if g['vendor'] == 'NVIDIA':
            if g['driver'] == 'nouveau':
                add('gpu-driver', 'GPU', 'GPU driver', '%s using open-source nouveau driver' % g['name'], 'FAIL', 1,
                    'nouveau cannot reclock most NVIDIA cards (very low FPS). Install the proprietary driver: Ubuntu -> "Additional Drivers" or `sudo ubuntu-drivers install`; Fedora -> RPM Fusion akmod-nvidia.')
                return
            ver = nv['Driver'] if nv else '?'
            line = read('/proc/driver/nvidia/version', '').splitlines()
            mm = re.search(r'(\w{3} \w{3}\s+\d+ [\d:]+ \w+ \d{4})', line[0]) if line else None
            if mm:
                built = dt.datetime.strptime(re.sub(r'\s+', ' ', mm.group(1)).replace(' UTC', ''), '%a %b %d %H:%M:%S %Y')
                age = (dt.datetime.now() - built).days
                val = '%s driver %s, built %s (%d days old)' % (g['name'], ver, built.strftime('%Y-%m-%d'), age)
                if age > 180:
                    add('gpu-driver', 'GPU', 'GPU driver age', val, 'WARN', 3,
                        'Update the NVIDIA driver (Ubuntu: `sudo ubuntu-drivers install` or a newer nvidia-driver-XXX package) - new games get fixes and Proton/DXVK improvements.')
                else:
                    add('gpu-driver', 'GPU', 'GPU driver age', val, 'PASS', 3)
            else:
                add('gpu-driver', 'GPU', 'GPU driver age', '%s driver %s (%s)' % (g['name'], ver, g['driver']), 'INFO', 3)
            return
        # AMD / Intel: kernel driver + Mesa
        mesa = ''
        out = run(['glxinfo', '-B']) or run(['vulkaninfo', '--summary'])
        mm = re.search(r'Mesa ([\d.]+)', out)
        if mm:
            mesa = mm.group(1)
        val = '%s using kernel driver %s; Mesa %s; kernel %s' % (g['name'], g['driver'], mesa or 'unknown (install mesa-utils to check)', platform.release())
        if g['vendor'] == 'AMD' and g['driver'] == 'radeon':
            add('gpu-driver', 'GPU', 'GPU driver', val, 'WARN', 2,
                'Card is on the legacy "radeon" driver. GCN 1.0/1.1 cards get Vulkan only on amdgpu: add radeon.si_support=0 amdgpu.si_support=1 (or cik_) to the kernel command line.')
        elif mesa and to_int(mesa.split('.')[0]) < 23:
            add('gpu-driver', 'GPU', 'GPU driver', val, 'WARN', 3, 'Mesa is old - newer Mesa (e.g. kisak-mesa PPA on Ubuntu) brings large RADV/ANV gaming improvements.')
        else:
            add('gpu-driver', 'GPU', 'GPU driver', val, 'PASS', 3)

    @check('Resizable BAR')
    def _():
        if not main_gpu:
            return
        # Largest prefetchable 64-bit memory BAR of the GPU = CPU-visible VRAM aperture
        biggest = 0
        for line in (read(main_gpu['path'] + '/resource', '') or '').splitlines():
            p = line.split()
            if len(p) == 3:
                start, end, flags = (int(x, 16) for x in p)
                if end > start and flags & 0x200 == 0x200 and flags & 0x2000:  # IORESOURCE_MEM + PREFETCH
                    biggest = max(biggest, (end - start + 1) // (1024 * 1024))
        if not biggest and nv:
            q = run(['nvidia-smi', '-q']).splitlines()
            for i, l in enumerate(q):
                if 'BAR1 Memory Usage' in l:
                    for l2 in q[i + 1:i + 5]:
                        mm = re.search(r'Total\s*:\s*(\d+)\s*MiB', l2)
                        if mm:
                            biggest = int(mm.group(1))
                            break
        if not biggest:
            add('gpu-rebar', 'GPU', 'Resizable BAR', 'Could not read BAR sizes', 'INFO', 2)
            return
        val = 'Largest VRAM aperture (BAR) %d MiB' % biggest
        if biggest <= 256:
            add('gpu-rebar', 'GPU', 'Resizable BAR', val + ' (OFF)', 'FAIL', 2,
                'BIOS: enable "Above 4G Decoding" + "Re-Size BAR Support" (requires UEFI boot with CSM disabled). 0-10% gain depending on game.')
        else:
            add('gpu-rebar', 'GPU', 'Resizable BAR', val + ' (ON)', 'PASS', 2)

    @check('NVIDIA DRM modeset')
    def _():
        if not main_gpu or main_gpu['vendor'] != 'NVIDIA' or main_gpu['driver'] != 'nvidia':
            return
        ms = read('/sys/module/nvidia_drm/parameters/modeset')
        if ms is None:
            cmd = read('/proc/cmdline', '')
            ms = 'Y' if 'nvidia-drm.modeset=1' in cmd or 'nvidia_drm.modeset=1' in cmd else None
            if ms is None:
                for f in glob.glob('/etc/modprobe.d/*.conf') + glob.glob('/usr/lib/modprobe.d/*.conf'):
                    if re.search(r'options\s+nvidia[-_]drm\s+.*modeset=1', read(f, '') or ''):
                        ms = 'Y'
                        break
        drv_major = to_int((nv or {}).get('Driver', '0').split('.')[0])
        if ms is None and drv_major >= 560:
            ms = 'Y'  # default-on since 560
        if ms == 'Y':
            add('gpu-modeset', 'GPU', 'NVIDIA DRM kernel modesetting', 'Enabled', 'PASS', 4)
        else:
            add('gpu-modeset', 'GPU', 'NVIDIA DRM kernel modesetting', 'Not enabled' if ms == 'N' else 'Unknown', 'WARN', 4,
                'Add nvidia-drm.modeset=1 to the kernel command line - needed for Wayland, PRIME sync and tear-free output.')

    @check('PCIe link')
    def _():
        if not main_gpu:
            return
        p = main_gpu['path']
        cw, mw = to_int(read(p + '/current_link_width')), to_int(read(p + '/max_link_width'))
        cs, ms = read(p + '/current_link_speed', '?'), read(p + '/max_link_speed', '?')
        gen = {'2.5': 1, '5.0': 2, '8.0': 3, '16.0': 4, '32.0': 5, '64.0': 6}
        gmax = gen.get((ms.split() or ['?'])[0], to_int((nv or {}).get('GenMax')))
        if not cw:
            return
        val = 'PCIe Gen%s max, width x%d (card supports x%d); link now %s. Link speed drops at idle to save power - normal.' % (gmax or '?', cw, mw, cs)
        if cw < mw:
            add('gpu-pcie', 'GPU', 'PCIe link width', val, 'WARN', 2,
                'GPU is running at reduced lane width. Re-seat it in the top x16 slot; check that M.2 slots/other cards are not stealing lanes (see board manual).')
        elif gmax and gmax <= 3 and mw <= 8:
            add('gpu-pcie', 'GPU', 'PCIe link width', val, 'INFO', 4,
                'x8 card on PCIe 3.0: small loss (2-5%), larger when VRAM overflows. Prefer x16 cards for future upgrades on this board.')
        else:
            add('gpu-pcie', 'GPU', 'PCIe link width', val, 'PASS', 4)

    @check('GPU temp / power')
    def _():
        if nv:
            val = '%s: %s C now, power limit %s W, boost up to %s MHz, %s MiB VRAM' % (nv['Name'], nv['Temp'], nv['PowerLimit'], nv['MaxClock'], nv['MemMiB'])
            t = to_int(nv['Temp'])
        else:
            t = None
            for hw in glob.glob('/sys/class/hwmon/hwmon*'):
                if read(hw + '/name') in ('amdgpu', 'i915', 'xe'):
                    t = to_int(read(hw + '/temp1_input')) // 1000 or None
                    cap = to_int(read(hw + '/power1_cap')) // 1000000
                    if t:
                        val = '%s C now' % t + (', power cap %d W' % cap if cap else '')
                        break
            if not t:
                return
        if t > 70:
            add('gpu-temp', 'GPU', 'GPU temperature (idle)', val, 'WARN', 3, 'Hot at idle - check fan curve, airflow and background GPU load.')
        else:
            add('gpu-temp', 'GPU', 'GPU temperature (idle)', val, 'PASS', 5)

    # ------------------------------------------------------------ DISPLAY
    section('Displays')

    @check('Refresh rates')
    def _():
        rows = []  # (name, w, h, cur, max_at_res, max_any, primary)
        out = run_as_user(['kscreen-doctor', '-o']) if 'KDE' in desktop and session == 'wayland' else ''
        if out:
            out = re.sub(r'\x1b\[[0-9;]*m', '', out)
            for blk in re.split(r'\n(?=Output:)', out):
                if 'enabled' not in blk or 'disabled' in blk.split('\n')[0]:
                    continue
                name = (re.search(r'Output:\s*\d+\s+(\S+)', blk) or [None, '?'])[1]
                modes = [(int(a), int(b), float(c), star) for a, b, c, star in re.findall(r'(\d+)x(\d+)@([\d.]+)(\*?)', blk)]
                cur = [m for m in modes if m[3]]
                if cur:
                    w, h, hz = cur[0][:3]
                    rows.append((name, w, h, hz, max(m[2] for m in modes if m[:2] == (w, h)), max(m[2] for m in modes), 'priority 1' in blk))
        else:
            out = run_as_user(['xrandr', '--query'])
            name = None
            for line in out.splitlines():
                mm = re.match(r'(\S+) connected( primary)?', line)
                if mm:
                    name = [mm.group(1), bool(mm.group(2)), []]
                    rows.append(name)
                    continue
                if re.match(r'\S', line):
                    name = None
                    continue
                if name is not None:
                    mm = re.match(r'\s+(\d+)x(\d+)i?\s+(.*)', line)
                    if mm:
                        for rate in re.findall(r'([\d.]+)([*+ ]*)', mm.group(3)):
                            name[2].append((int(mm.group(1)), int(mm.group(2)), float(rate[0]), '*' in rate[1]))
            done = []
            for nm, prim, modes in rows:
                cur = [m for m in modes if m[3]]
                if not cur:
                    continue
                w, h, hz = cur[0][:3]
                done.append((nm, w, h, hz, max(m[2] for m in modes if m[:2] == (w, h)), max(m[2] for m in modes), prim))
            rows = done
        if not rows:
            add('display-1', 'Display', 'Refresh rate', 'Could not query modes (%s session) - check Settings -> Displays manually' % (session or 'unknown'), 'INFO', 2)
            return
        if session == 'wayland' and 'KDE' not in desktop:
            INFO['Display note'] = 'Wayland session: refresh rates read through XWayland may not match the real monitor settings.'
        for n, (nm, w, h, cur, mx, many, prim) in enumerate(rows, 1):
            label = 'Display %d %s' % (n, nm) + (' (primary)' if prim else '')
            val = '%dx%d @ %.0f Hz; max at this resolution %.0f Hz' % (w, h, cur, mx) + ('; %.0f Hz available at another resolution' % many if many > mx + 0.5 else '')
            if cur < mx - 0.5:
                add('display-%d' % n, 'Display', label + ' refresh rate', val, 'WARN', 2 if prim or n == 1 else 4,
                    'Settings -> Displays -> pick this monitor -> Refresh Rate %.0f Hz (or: xrandr --output %s --mode %dx%d --rate %.2f). Enable VRR/G-SYNC/FreeSync if supported.' % (mx, nm, w, h, mx))
            else:
                add('display-%d' % n, 'Display', label + ' refresh rate', val, 'PASS', 4)

    # ------------------------------------------------------------ OS GAMING SETTINGS
    section('Linux settings')

    @check('Power profile')
    def _():
        prof = run(['powerprofilesctl', 'get']).strip()
        tuned = '' if prof else run(['tuned-adm', 'active']).strip().replace('Current active profile: ', '')
        gov = read(cpufreq + 'scaling_governor', '?')
        epp = read(cpufreq + 'energy_performance_preference')
        cap = to_int(read(cpufreq + 'scaling_max_freq'))
        hwmax = to_int(read(cpufreq + 'cpuinfo_max_freq'))
        maxpct = to_int(read('/sys/devices/system/cpu/intel_pstate/max_perf_pct'), 100)
        name = prof or tuned or 'no power-profile daemon'
        val = '%s (governor %s%s)' % (name, gov, ', EPP ' + epp if epp else '')
        battery = bool(glob.glob('/sys/class/power_supply/BAT*'))
        if (hwmax and cap and cap < hwmax * 0.98) or maxpct < 100:
            add('power-plan', 'Linux', 'Power profile', val + '; max frequency capped', 'FAIL', 2,
                'CPU maximum frequency is limited (scaling_max_freq / max_perf_pct). Remove the cap (check TLP, auto-cpufreq or cpupower settings).')
        elif re.search(r'power-saver|powersave|power$', name + ' ' + (epp or '')) and 'performance' not in (epp or ''):
            add('power-plan', 'Linux', 'Power profile', val, 'FAIL', 2, 'Switch to the Performance profile: Settings -> Power -> Power Mode, or `powerprofilesctl set performance`.')
        elif 'performance' in name or gov == 'performance' or (epp == 'performance'):
            add('power-plan', 'Linux', 'Power profile', val, 'PASS', 3)
        elif not battery:
            add('power-plan', 'Linux', 'Power profile', val, 'WARN', 4,
                'Desktop: the Performance profile gives faster clock ramp-up. Settings -> Power -> Power Mode -> Performance, or `powerprofilesctl set performance`. (GameMode does this automatically per game.)')
        else:
            add('power-plan', 'Linux', 'Power profile', val, 'PASS', 4)

    @check('GameMode')
    def _():
        if shutil.which('gamemoded') or shutil.which('gamemoderun'):
            add('game-mode', 'Linux', 'Feral GameMode', 'Installed (use `gamemoderun %command%` in Steam launch options)', 'PASS', 4)
        else:
            add('game-mode', 'Linux', 'Feral GameMode', 'Not installed', 'WARN', 4,
                'Install gamemode (apt/dnf/pacman install gamemode) and add `gamemoderun %command%` to Steam launch options - sets performance governor and priorities while playing.')

    @check('vm.max_map_count')
    def _():
        v = to_int(read('/proc/sys/vm/max_map_count'))
        if v and v < 1048576:
            add('max-map-count', 'Linux', 'vm.max_map_count', str(v), 'WARN', 3,
                'Some games (CS2, Hogwarts Legacy, Star Citizen...) crash with the old default. echo "vm.max_map_count=2147483642" | sudo tee /etc/sysctl.d/80-gaming.conf && sudo sysctl --system')
        else:
            add('max-map-count', 'Linux', 'vm.max_map_count', str(v), 'PASS', 5)

    @check('Split-lock mitigation')
    def _():
        v = read('/proc/sys/kernel/split_lock_mitigate')
        if v is None:
            return
        if v == '1':
            add('split-lock', 'Linux', 'Split-lock mitigation', 'On (kernel.split_lock_mitigate=1)', 'WARN', 4,
                'Can cause heavy stutter in some Proton games. echo "kernel.split_lock_mitigate=0" | sudo tee /etc/sysctl.d/81-splitlock.conf && sudo sysctl --system (small security/fairness tradeoff).')
        else:
            add('split-lock', 'Linux', 'Split-lock mitigation', 'Off', 'PASS', 5)

    @check('Mouse acceleration')
    def _():
        if 'GNOME' in desktop or 'Unity' in desktop or 'Cinnamon' in desktop:
            schema = 'org.cinnamon.desktop.peripherals.mouse' if 'Cinnamon' in desktop else 'org.gnome.desktop.peripherals.mouse'
            v = run_as_user(['gsettings', 'get', schema, 'accel-profile']).strip().strip("'")
        elif 'KDE' in desktop:
            cfg = read(os.path.join(user_home(), '.config/kcminputrc'), '') or ''
            mm = re.search(r'PointerAccelerationProfile=(\d)', cfg)
            v = {'1': 'flat', '2': 'adaptive'}.get(mm.group(1), 'default') if mm else 'default'
        else:
            v = ''
        if not v:
            add('mouse-accel', 'Linux', 'Mouse acceleration', 'Could not read (desktop: %s)' % (desktop or '?'), 'INFO', 5)
        elif v == 'flat':
            add('mouse-accel', 'Linux', 'Mouse acceleration', 'Off (flat profile)', 'PASS', 5)
        else:
            add('mouse-accel', 'Linux', 'Mouse acceleration', 'On (%s profile)' % v, 'WARN', 5,
                'For consistent aim set the flat profile: GNOME -> Settings -> Mouse -> turn off "Mouse Acceleration" (or `gsettings set org.gnome.desktop.peripherals.mouse accel-profile flat`); KDE -> Mouse -> Acceleration profile: Flat.')

    @check('Virtualization')
    def _():
        virt = run(['systemd-detect-virt']).strip() or ('vm' if 'hypervisor' in cpuinfo else 'none')
        if virt not in ('none', ''):
            add('vbs', 'Linux', 'Running in a VM / container', virt, 'WARN', 2, 'This audit is running inside a virtual machine - GPU and timing results do not reflect bare-metal performance.')
        else:
            add('vbs', 'Linux', 'Running in a VM / container', 'Bare metal', 'PASS', 4)

    @check('OS / kernel version')
    def _():
        kv = [to_int(x) for x in re.findall(r'\d+', platform.release())[:2]]
        val = INFO.get('OS', platform.release())
        if kv < [6, 1]:
            add('os-version', 'Linux', 'OS / kernel version', val, 'WARN', 3,
                'Kernel older than 6.1 - newer GPUs/CPUs and anti-cheat (Proton) work better on a current kernel. Ubuntu: install the HWE kernel (linux-generic-hwe-XX.04).')
        else:
            add('os-version', 'Linux', 'OS / kernel version', val, 'PASS', 4)

    @check('Pending reboot / uptime')
    def _():
        up = float(read('/proc/uptime', '0').split()[0])
        pending = os.path.exists('/var/run/reboot-required') or not os.path.isdir('/lib/modules/' + platform.release())
        if not pending and shutil.which('needs-restarting'):
            pending = subprocess.call(['needs-restarting', '-r'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 1
        val = 'Uptime %dd %dh; reboot pending: %s' % (up // 86400, up % 86400 // 3600, pending)
        if pending or up > 7 * 86400:
            add('uptime', 'Linux', 'Uptime / pending reboot', val, 'WARN', 4, 'Reboot (also loads updated kernel/driver) before benchmarking so before/after results are comparable.')
        else:
            add('uptime', 'Linux', 'Uptime / pending reboot', val, 'PASS', 5)

    # ------------------------------------------------------------ FIRMWARE
    section('Firmware')

    @check('Boot mode')
    def _():
        uefi = os.path.isdir('/sys/firmware/efi')
        src = run(['findmnt', '-no', 'SOURCE', '/']).strip()
        disk = run(['lsblk', '-no', 'PKNAME', src]).strip().splitlines() if src.startswith('/dev/') else []
        style = run(['lsblk', '-dno', 'PTTYPE', '/dev/' + disk[0]]).strip() if disk else ''
        style = {'gpt': 'GPT', 'dos': 'MBR'}.get(style, style or '?')
        val = 'Firmware: %s; system disk partition style: %s' % ('UEFI' if uefi else 'Legacy BIOS (CSM)', style)
        if not uefi:
            add('boot-mode', 'Firmware', 'UEFI boot (needed for ReBAR)', val, 'WARN', 2,
                'Booting in Legacy/CSM mode: Resizable BAR needs UEFI. Switching an installed Linux needs a GPT disk + EFI system partition and a UEFI GRUB install (back up first), then disable CSM in BIOS.')
        else:
            add('boot-mode', 'Firmware', 'UEFI boot (needed for ReBAR)', val + ' - safe to disable CSM', 'PASS', 3)

    @check('BIOS age')
    def _():
        add('bios', 'Firmware', 'BIOS version', '%s released %s' % (dmi('bios_version'), bios_date_str()), 'INFO', 5,
            'Check the board vendor support page (or `fwupdmgr get-updates`) for a newer BIOS. Updating resets BIOS settings, so redo XMP/ReBAR afterwards.')

    @check('Secure Boot / TPM')
    def _():
        sb = 'n/a (legacy boot)'
        if os.path.isdir('/sys/firmware/efi'):
            f = glob.glob('/sys/firmware/efi/efivars/SecureBoot-*')
            try:
                with open(f[0], 'rb') as fh:
                    sb = 'On' if fh.read()[-1] == 1 else 'Off'
            except (OSError, IndexError):
                sb = run(['mokutil', '--sb-state']).strip() or '?'
        tpm = 'none'
        if os.path.isdir('/sys/class/tpm/tpm0'):
            tpm = '%s present' % ('2.0' if read('/sys/class/tpm/tpm0/tpm_version_major') == '2' or os.path.exists('/dev/tpmrm0') else '1.2')
        val = 'Secure Boot: %s; TPM: %s' % (sb, tpm)
        if tpm == 'none' or sb != 'On':
            add('secureboot', 'Firmware', 'Secure Boot / TPM', val, 'INFO', 5,
                'Not needed for Linux gaming. Only matters if you dual-boot Windows 11 or play games whose Windows anti-cheat requires them (enable Intel PTT / AMD fTPM and Secure Boot in BIOS).')
        else:
            add('secureboot', 'Firmware', 'Secure Boot / TPM', val, 'PASS', 5)

    # ------------------------------------------------------------ STORAGE
    section('Storage')
    root_src = run(['findmnt', '-no', 'SOURCE', '/']).strip()
    root_disk = (run(['lsblk', '-no', 'PKNAME', root_src]).strip().splitlines() or [''])[0] if root_src.startswith('/dev/') else ''

    @check('Disk health')
    def _():
        data = json.loads(run(['lsblk', '-J', '-b', '-d', '-o', 'NAME,MODEL,SIZE,ROTA,TRAN,TYPE']) or '{"blockdevices":[]}')
        n = 0
        for d in data.get('blockdevices', []):
            if d.get('type') != 'disk' or d['name'].startswith(('zram', 'loop', 'ram')) or not int(d.get('size') or 0):
                continue
            n += 1
            rota = d.get('rota') in (True, '1', 1)
            media = 'HDD' if rota else 'SSD'
            bus = (d.get('tran') or ('nvme' if d['name'].startswith('nvme') else '?')).upper()
            health, extra = '?', ''
            if IS_ROOT and shutil.which('smartctl'):
                s = run(['smartctl', '-H', '-A', '/dev/' + d['name']])
                mm = re.search(r'(?:overall-health self-assessment test result|SMART Health Status):\s*(\S+)', s)
                health = mm.group(1) if mm else '?'
                mm = re.search(r'Percentage Used:\s*(\d+)%', s) or re.search(r'Wear_Leveling_Count.*?(\d+)\s*$', s, re.M)
                if mm:
                    extra += '; wear %s%%' % mm.group(1)
                mm = re.search(r'^Temperature:\s*(\d+)', s, re.M) or re.search(r'Temperature_Celsius.*?(\d+)(?:\s*\(.*\))?\s*$', s, re.M)
                if mm:
                    extra += '; %s C' % mm.group(1)
            elif not IS_ROOT:
                health = 'not checked (needs sudo + smartmontools)'
            sysroot = ' [system disk]' if d['name'] == root_disk else ''
            val = '%s %s, %d GB, health %s%s%s' % (media, bus, round(int(d['size']) / 1e9), health, extra, sysroot)
            name = 'Disk: %s' % ((d.get('model') or d['name']).strip())
            if health in ('FAILED!', 'FAILED', 'FAIL'):
                add('disk-%d' % n, 'Storage', name, val, 'FAIL', 1, 'Back up this drive now and plan a replacement.')
            elif rota and d['name'] == root_disk:
                add('disk-%d' % n, 'Storage', name, val, 'WARN', 2, 'The OS (and likely your games) is on a hard drive: slow loads and stutter. Move to an SSD.')
            else:
                add('disk-%d' % n, 'Storage', name, val, 'PASS', 5)

    @check('Free space')
    def _():
        real = {'ext2', 'ext3', 'ext4', 'btrfs', 'xfs', 'f2fs', 'ntfs', 'ntfs3', 'fuseblk', 'vfat', 'exfat', 'zfs', 'bcachefs', 'jfs', 'reiserfs'}
        seen = set()
        for line in read('/proc/mounts', '').splitlines():
            dev, mnt, fs = line.split()[:3]
            mnt = mnt.replace('\\040', ' ')
            if fs not in real or dev in seen or mnt.startswith(('/snap', '/boot', '/var/lib/docker')):
                continue
            seen.add(dev)
            try:
                st = os.statvfs(mnt)
            except OSError:
                continue
            size, free = st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize
            if size < 10 * 1024 ** 3:
                continue
            pct = free / size * 100
            val = '%.0f GB free of %.0f GB (%.0f%% free)' % (gb(free), gb(size), pct)
            nm = 'Free space %s' % mnt
            vid = 'vol-' + (mnt.strip('/').replace('/', '-') or 'root')
            if pct < 5:
                add(vid, 'Storage', nm, val, 'FAIL', 2, 'Nearly full - SSDs slow down and games fail to patch. Free space or move games.')
            elif pct < 20 and mnt == '/':
                add(vid, 'Storage', nm, val, 'WARN', 4, 'Root filesystem is over 80% full. Move the Steam library to a roomier drive (Steam -> Settings -> Storage).')
            elif pct < 10:
                add(vid, 'Storage', nm, val, 'WARN', 4, 'Over 90% full.')
            else:
                add(vid, 'Storage', nm, val, 'PASS', 5)

    @check('TRIM')
    def _():
        timer = run(['systemctl', 'is-enabled', 'fstrim.timer']).strip()
        opts = run(['findmnt', '-no', 'OPTIONS', '/']).strip()
        discard = 'discard' in opts
        ssd = any(read(f) == '0' for f in glob.glob('/sys/block/*/queue/rotational') if not re.search(r'/(loop|zram|ram)', f))
        if timer == 'enabled' or discard:
            add('trim', 'Storage', 'SSD TRIM', 'Enabled (%s)' % ('fstrim.timer' if timer == 'enabled' else 'discard mount option'), 'PASS', 5)
        elif ssd and timer:
            add('trim', 'Storage', 'SSD TRIM', 'fstrim.timer %s' % timer, 'WARN', 3, 'sudo systemctl enable --now fstrim.timer')
        else:
            add('trim', 'Storage', 'SSD TRIM', 'fstrim.timer status: %s' % (timer or 'unknown'), 'INFO', 5)

    # ------------------------------------------------------------ BACKGROUND
    section('Background load')
    procs = processes()

    @check('Startup apps')
    def _():
        on, off = [], []
        home = user_home()
        entries = {}
        for d in ['/etc/xdg/autostart', os.path.join(home, '.config/autostart')]:  # user dir overrides system
            for f in glob.glob(d + '/*.desktop'):
                entries[os.path.basename(f)] = (f, d.startswith('/etc'))
        cur = (desktop or '').split(':')
        for base, (f, system) in sorted(entries.items()):
            t = read(f, '') or ''
            name = (re.search(r'^Name=(.+)$', t, re.M) or [None, base[:-8]])[1]
            hidden = re.search(r'^Hidden=true', t, re.M) or re.search(r'^X-GNOME-Autostart-enabled=false', t, re.M)
            only = re.search(r'^OnlyShowIn=(.+)$', t, re.M)
            notin = re.search(r'^NotShowIn=(.+)$', t, re.M)
            if only and not set(only.group(1).strip(';').split(';')) & set(cur):
                continue
            if notin and set(notin.group(1).strip(';').split(';')) & set(cur):
                continue
            if system and not hidden:
                continue  # desktop's own components - not user-installed startup apps
            (off if hidden else on).append(name)
        val = 'Enabled (%d): %s; disabled (%d)' % (len(on), ', '.join(on), len(off))
        if len(on) > 5:
            add('startup', 'Background', 'Startup apps', val, 'WARN', 3, 'Disable launchers/updaters you do not need at login: GNOME Tweaks -> Startup Applications, or delete files in ~/.config/autostart.')
        else:
            add('startup', 'Background', 'Startup apps', val, 'PASS', 4)

    @check('Background services')
    def _():
        pat = re.compile(r'^(tracker-miner-f|localsearch|baloo_file|baloo_file_ext|packagekitd|apport|whoopsie|kerneloops|dockerd|containerd|snapd|openrgb|piper|ratbagd|teamviewerd|anydesk|nordvpnd|expressvpnd|mullvad-daemon)$')
        found = sorted(set(c for _p, c, _r, _t in procs if pat.match(c)))
        val = 'Running: ' + ', '.join(found) if found else 'None of the common offenders found'
        heavy = [x for x in found if x not in ('snapd', 'packagekitd')]
        if heavy:
            add('bloat', 'Background', 'Background services', val, 'WARN', 4,
                'File indexers (tracker/baloo), crash reporters and container daemons can cause stutter. Disable the ones you do not use (e.g. `systemctl disable --now docker`, `balooctl disable`, `tracker3 daemon -t`).')
        else:
            add('bloat', 'Background', 'Background services', val, 'PASS', 4)

    @check('Background apps')
    def _():
        pat = re.compile(r'^(chrome|chromium|brave|firefox|firefox-bin|msedge|opera|vivaldi-bin|Discord|discord|vesktop|steamwebhelper|spotify|slack|teams-for-linux|dropbox|onedrive|heroic|lutris|code|obs)$', re.I)
        agg = {}
        for _p, c, rss, _t in procs:
            if pat.match(c):
                agg[c] = agg.get(c, 0) + rss
        top = sorted(agg.items(), key=lambda x: -x[1])
        val = '%d processes; heavy apps open: %s' % (len(procs), ', '.join('%s (%d MB)' % (c, r // 1048576) for c, r in top) or 'none')
        if len(top) >= 3 or len(procs) > 450:
            add('bg-apps', 'Background', 'Background apps', val, 'WARN', 3, 'Close browsers, chat and launchers before benchmarking or competitive play.')
        else:
            add('bg-apps', 'Background', 'Background apps', val, 'PASS', 4)

    @check('Network')
    def _():
        ups = []
        for n in sorted(os.listdir('/sys/class/net')):
            p = '/sys/class/net/' + n
            if n == 'lo' or '/virtual/' in os.path.realpath(p) or read(p + '/operstate') != 'up':
                continue
            wifi = os.path.isdir(p + '/wireless') or os.path.isdir(p + '/phy80211')
            speed = to_int(read(p + '/speed'), -1)
            ups.append((n, wifi, speed))
        if not ups:
            add('network', 'Background', 'Network link', 'No physical adapter up', 'INFO', 5)
            return
        val = '; '.join('%s: %s%s' % (n, 'Wi-Fi' if w else 'Ethernet', ' @ %d Mbps' % s if s > 0 else '') for n, w, s in ups)
        wired = [u for u in ups if not u[1]]
        if not wired:
            add('network', 'Background', 'Network link', val, 'INFO', 4, 'Wi-Fi only - Ethernet gives lower, steadier ping for online games.')
        elif any(0 < s < 1000 for _n, _w, s in wired):
            add('network', 'Background', 'Network link', val, 'WARN', 4, 'Ethernet negotiated below 1 Gbps - check the cable (Cat5e or better).')
        else:
            add('network', 'Background', 'Network link', val, 'PASS', 5)

    return started


# ================================================================= REPORT (same format as PC-Audit.ps1)
def esc(s):
    return html.escape(str(s if s is not None else ''), quote=True)


def write_report(started, out_dir, no_open):
    os.makedirs(out_dir, exist_ok=True)
    stamp = started.strftime('%Y%m%d_%H%M%S')
    json_path = os.path.join(out_dir, 'PC-Audit_%s.json' % stamp)
    html_path = os.path.join(out_dir, 'PC-Audit_%s.html' % stamp)

    prev, prev_file = None, None
    olds = sorted(glob.glob(os.path.join(out_dir, 'PC-Audit_*.json')))
    if olds:
        prev_file = olds[-1]
        try:
            with open(prev_file, encoding='utf-8-sig') as f:
                prev = json.load(f)
        except (OSError, ValueError):
            prev = None

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({'Timestamp': started.strftime('%Y-%m-%dT%H:%M:%S'), 'Platform': 'Linux', 'Info': INFO, 'Checks': RESULTS}, f, indent=2)

    scored = [r for r in RESULTS if r['Status'] != 'INFO']
    npass = sum(r['Status'] == 'PASS' for r in scored)
    nwarn = sum(r['Status'] == 'WARN' for r in scored)
    nfail = sum(r['Status'] == 'FAIL' for r in scored)
    score = round((npass + 0.5 * nwarn) / len(scored) * 100) if scored else 0

    h = ["""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
<h1>PC Audit Report</h1>"""]
    h.append('<div class="muted">%s &middot; %s &middot; Linux &middot; %s</div>' % (
        esc(INFO.get('Computer', '')), esc(started.strftime('%Y-%m-%d %H:%M')), 'run as root' if IS_ROOT else 'not root - SSD health skipped'))
    h.append('<div class="cards"><div class="card"><span>Score</span><b>%d%%</b></div>'
             '<div class="card"><span>Pass</span><b style="color:var(--pass)">%d</b></div>'
             '<div class="card"><span>Warnings</span><b style="color:var(--warn)">%d</b></div>'
             '<div class="card"><span>Failures</span><b style="color:var(--fail)">%d</b></div></div>' % (score, npass, nwarn, nfail))
    h.append('<h2>System</h2><dl class="spec">')
    for k, v in INFO.items():
        h.append('<dt>%s</dt><dd>%s</dd>' % (esc(k), esc(v)))
    h.append('</dl>')

    if prev:
        pm = {c.get('Id'): c for c in prev.get('Checks', [])}
        noisy = re.compile(r'^(cpu-turbo|cpu-load|ram-used|bg-apps|uptime|gpu-temp|cpu-temp|vol-|defender)')
        rows = []
        for c in RESULTS:
            o = pm.get(c['Id'])
            if o and (o.get('Status') != c['Status'] or (not noisy.match(c['Id']) and o.get('Value') != c['Value'])):
                rows.append("<tr><td>%s</td><td><span class='pill %s'>%s</span> %s</td><td><span class='pill %s'>%s</span> %s</td></tr>" % (
                    esc(c['Name']), esc(o.get('Status')), esc(o.get('Status')), esc(o.get('Value')), c['Status'], c['Status'], esc(c['Value'])))
        h.append("<h2>Changes since previous run <span class='muted'>(%s)</span></h2>" % esc(prev.get('Timestamp')))
        if rows:
            h.append("<div class='wrap'><table><tr><th>Check</th><th>Before</th><th>After</th></tr>%s</table></div>" % ''.join(rows))
        else:
            h.append("<p class='muted'>No setting changes detected (ignoring live values like load, temps, free space).</p>")

    order = {'FAIL': 0, 'WARN': 1}
    todo = sorted([r for r in RESULTS if r['Status'] in ('FAIL', 'WARN') or (r['Status'] == 'INFO' and r['Fix'] and r['Impact'] <= 4)],
                  key=lambda r: (r['Impact'], order.get(r['Status'], 2)))
    h.append('<h2>Fix these first (ranked by impact)</h2>')
    if todo:
        h.append('<ol class="fixes">')
        for t in todo:
            h.append("<li><span class='pill %s'>%s</span> <b>%s</b> - %s<div class='fix'>%s</div></li>" % (t['Status'], t['Status'], esc(t['Name']), esc(t['Value']), esc(t['Fix'])))
        h.append('</ol>')
    else:
        h.append('<p>Nothing to fix - all checks passed.</p>')

    h.append("<h2>All checks</h2><div class='wrap'><table><tr><th>Status</th><th>Category</th><th>Check</th><th>Finding</th><th>Impact</th></tr>")
    for c in sorted(RESULTS, key=lambda r: (r['Category'], r['Impact'])):
        fix = "<div class='fix'>%s</div>" % esc(c['Fix']) if c['Fix'] and c['Status'] != 'PASS' else ''
        h.append("<tr><td><span class='pill %s'>%s</span></td><td>%s</td><td>%s</td><td>%s%s</td><td>%d</td></tr>" % (
            c['Status'], c['Status'], esc(c['Category']), esc(c['Name']), esc(c['Value']), fix, c['Impact']))
    elapsed = (dt.datetime.now() - started).total_seconds()
    h.append("</table></div><p class='muted'>Impact: 1 = biggest real-world gain, 5 = minor. Read-only audit, nothing was changed. Took %.1f s. Snapshot: %s</p></main></body></html>" % (elapsed, esc(json_path)))

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(h))

    if SUDO_USER:  # give the files back to the real user
        import pwd
        pw = pwd.getpwnam(SUDO_USER)
        for p in (out_dir, json_path, html_path):
            try:
                os.chown(p, pw.pw_uid, pw.pw_gid)
            except OSError:
                pass

    print()
    say('Score %d%%  |  PASS %d  WARN %d  FAIL %d' % (score, npass, nwarn, nfail), 'green')
    for t in todo[:8]:
        say('  [%s] %s: %s' % (t['Status'], t['Name'], t['Value']), 'red' if t['Status'] == 'FAIL' else 'yellow' if t['Status'] == 'WARN' else 'gray')
    print()
    print('Report:   ' + html_path)
    print('Snapshot: ' + json_path)
    if prev:
        print('Compared against: ' + os.path.basename(prev_file))
    if not no_open:
        open_report(html_path)


def open_report(path):
    """Open the finished report in the user's default browser."""
    env = gui_env()
    if not (env.get('DISPLAY') or env.get('WAYLAND_DISPLAY')):
        print('(No desktop session found - open the report above in a browser.)')
        return
    openers = []
    # Launch the default *web browser* directly, so a text editor that also claims
    # .html files can never win; fall back to the generic openers after that.
    browser = run(as_user(['xdg-settings', 'get', 'default-web-browser'])).strip()
    if browser.endswith('.desktop') and shutil.which('gtk-launch'):
        openers.append(['gtk-launch', browser])
    openers += [['xdg-open'], ['gio', 'open'], ['sensible-browser'], ['firefox']]
    for opener in openers:
        if shutil.which(opener[0]):
            try:
                subprocess.Popen(as_user(opener + [path]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)  # keeps the browser alive after the audit exits
                print('Opening report in your browser...')
                return
            except OSError:
                continue
    print('(No browser opener found - open the report above manually.)')


def default_out_dir():
    docs = ''
    if SUDO_USER:
        docs = run(['sudo', '-u', SUDO_USER, 'xdg-user-dir', 'DOCUMENTS']).strip()
    else:
        docs = run(['xdg-user-dir', 'DOCUMENTS']).strip()
    if not docs or docs == user_home():
        docs = os.path.join(user_home(), 'Documents')
    return os.path.join(docs, 'PC-Audit')


def main():
    ap = argparse.ArgumentParser(description='Read-only gaming PC audit (Linux; on Windows runs PC-Audit.ps1).')
    ap.add_argument('--out-dir', '-o', help='Where to write the report (default: ~/Documents/PC-Audit)')
    ap.add_argument('--no-open', action='store_true', help='Do not open the HTML report when done')
    args = ap.parse_args()

    if os.name == 'nt':
        run_windows(args)
    if not sys.platform.startswith('linux'):
        sys.exit('This audit supports Windows and Linux. Detected: %s' % sys.platform)
    started = audit_linux()
    write_report(started, os.path.expanduser(args.out_dir) if args.out_dir else default_out_dir(), args.no_open)


if __name__ == '__main__':
    main()
