# PC Audit

A read-only gaming PC checkup. It checks your hardware and settings, tells you what's slowing your games down, and opens an HTML report in your browser. It **doesn't change anything** on your PC.

## Which file?

| File | For | Run it with |
|---|---|---|
| `PC-Audit.ps1` | Windows | `powershell -ExecutionPolicy Bypass -File .\PC-Audit.ps1` |
| `PC-Audit.py` | Linux | `python3 PC-Audit.py` |

Keep both files in the same folder. If you run the wrong one, it starts the right one for you.

## What it checks

- **RAM**: XMP/EXPO on, dual-channel, usage
- **CPU**: turbo, temperature, idle load
- **GPU**: driver, Resizable BAR, PCIe link, temperature
- **Display**: refresh rate set to the max
- **OS settings**: power plan, Game Mode, mouse acceleration, and more
- **BIOS**: UEFI boot, Secure Boot / TPM, BIOS age
- **Storage**: disk health, free space, TRIM
- **Background**: startup apps, bloat, heavy apps, network

## The report

- A score, plus a list of fixes ranked by impact
- Saved to `Documents/PC-Audit/`
- Every run is compared to the last one, so you can see what changed

## Extras

- Run as **Administrator** (Windows) or with **sudo** (Linux) for extra checks
- Add `-NoOpen` (Windows) or `--no-open` (Linux) to skip opening the report
