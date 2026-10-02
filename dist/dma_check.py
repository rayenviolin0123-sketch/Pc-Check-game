#!/usr/bin/env python3
"""
dma_check.py - Defensive scanner for DMA-cheat / hardware-input-emulation indicators.

Windows only. Run from an elevated (Administrator) prompt for best results.
Usage:
    python dma_check.py                 # full report
    python dma_check.py --json out.json # also save JSON
    python dma_check.py --input-test 10 # also sample mouse motion for 10 seconds

IMPORTANT: Results are INDICATORS, not proof. Good DMA hardware spoofs a normal
device identity, so a clean report does not guarantee a clean PC, and a flagged
item may be a legitimate device (capture card, FPGA dev board, Arduino, etc.).
"""
import argparse
import ctypes
import json
import math
import platform
import statistics
import subprocess
import sys
import time

# ---------------------------------------------------------------- knowledge base
# PCI vendor IDs of FPGA makers whose chips power most DMA cards.
FPGA_VENDORS = {
    "10EE": "Xilinx / AMD (FPGA)",
    "1172": "Altera / Intel (FPGA)",
    "1204": "Lattice Semiconductor (FPGA)",
    "1556": "PLDA (PCIe IP core)",
    "1AE0": None,  # placeholder to keep list easy to extend; ignored
}
# Generic names Windows shows for unclassified / bare PCIe endpoints.
SUSPICIOUS_PCI_NAMES = (
    "pci device", "pci memory controller", "pci data acquisition",
    "data acquisition and signal processing", "base system device",
    "pci simple communications", "unknown device", "other pci bridge",
)
# USB VID:PID of chips commonly used in KMBox / HID-emulation boards.
USB_EMULATION_CHIPS = {
    "1A86": "WCH CH340/CH343 serial bridge (KMBox B-series uses these)",
    "2E8A": "Raspberry Pi RP2040/Pico (common DIY HID emulator)",
    "2341": "Arduino (Leonardo / Micro act as HID devices)",
    "1B4F": "SparkFun Pro Micro (ATmega32U4 HID emulator)",
    "239A": "Adafruit (CircuitPython HID boards)",
    "16C0": "Teensy / V-USB (HID emulator)",
    "303A": "Espressif ESP32-S2/S3 (USB HID capable)",
    "0483": "STMicroelectronics (STM32 USB devices)",
}

# ---------------------------------------------------------------- helpers
def ps(cmd: str):
    """Run PowerShell, return parsed JSON (list) or []."""
    full = ("$ErrorActionPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
            f"{cmd} | ConvertTo-Json -Compress -Depth 4")
    try:
        raw = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", full],
            capture_output=True, timeout=60,
        ).stdout or b""
        out = raw.decode("utf-8", errors="replace").strip().lstrip("\ufeff")
    except Exception:
        return []
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_ids(device_id: str):
    """Extract (VEN/VID, DEV/PID) from a PnP DeviceID."""
    up = (device_id or "").upper()
    def grab(tag):
        i = up.find(tag + "_")
        return up[i + len(tag) + 1: i + len(tag) + 5] if i >= 0 else ""
    if up.startswith("PCI\\"):
        return grab("VEN"), grab("DEV")
    return grab("VID"), grab("PID")


findings = []  # (level, category, message)
def add(level, cat, msg):
    findings.append({"level": level, "category": cat, "message": msg})

# ---------------------------------------------------------------- checks
def check_dma_protection():
    """Kernel DMA Protection / IOMMU / VBS state."""
    dg = ps("Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ClassName Win32_DeviceGuard | Select AvailableSecurityProperties,"
            "SecurityServicesRunning,VirtualizationBasedSecurityStatus")
    if not dg:
        add("INFO", "protection", "Could not query Device Guard / VBS state.")
        return
    d = dg[0]
    avail = d.get("AvailableSecurityProperties") or []
    running = d.get("SecurityServicesRunning") or []
    vbs = d.get("VirtualizationBasedSecurityStatus")
    if 3 in avail:
        add("OK", "protection", "DMA protection is available on this platform (IOMMU/VT-d/AMD-Vi capable).")
    else:
        add("WARN", "protection",
            "DMA protection NOT reported. Enable VT-d / AMD-Vi (IOMMU) and Kernel DMA Protection in UEFI.")
    if vbs == 2:
        add("OK", "protection", "Virtualization-Based Security is running.")
    else:
        add("WARN", "protection", "VBS is not running; memory integrity (HVCI) adds resistance to DMA tampering.")
    if 2 in running:
        add("OK", "protection", "HVCI / Memory Integrity is running.")
    sb = ps("Confirm-SecureBootUEFI")
    if sb and sb[0] is True:
        add("OK", "protection", "Secure Boot is enabled.")
    else:
        add("WARN", "protection", "Secure Boot is disabled or unavailable.")


def check_pci():
    devs = ps("Get-CimInstance Win32_PnPEntity | Where-Object {$_.DeviceID -like 'PCI\\*'} "
              "| Select Name,DeviceID,Manufacturer,Status,ConfigManagerErrorCode,PNPClass")
    if not devs:
        add("INFO", "pci", "No PCI devices returned (run as Administrator?).")
        return
    for d in devs:
        name = (d.get("Name") or "").strip()
        did = d.get("DeviceID") or ""
        ven, dev = parse_ids(did)
        label = f"{name or 'Unnamed'}  [{ven}:{dev}]"
        if ven in FPGA_VENDORS and FPGA_VENDORS[ven]:
            add("HIGH", "pci", f"FPGA-vendor PCIe endpoint: {label} -> {FPGA_VENDORS[ven]}")
        elif any(s in name.lower() for s in SUSPICIOUS_PCI_NAMES):
            add("MEDIUM", "pci", f"Generic/unclassified PCI endpoint: {label}")
        elif d.get("ConfigManagerErrorCode") == 28:
            add("MEDIUM", "pci", f"PCI device with no driver installed: {label}")
        elif not (d.get("Manufacturer") or "").strip() and not name:
            add("LOW", "pci", f"PCI device with no name or manufacturer: {did}")


def check_thunderbolt_external():
    """External PCIe exposure (Thunderbolt / USB4) is a DMA attack surface."""
    tb = ps("Get-CimInstance Win32_PnPEntity | Where-Object {$_.Name -match 'Thunderbolt|USB4'} "
            "| Select Name,Status")
    if tb:
        add("INFO", "pci", f"Thunderbolt/USB4 controller present ({len(tb)} entries): "
                           "external DMA surface; keep Kernel DMA Protection enabled.")


def check_usb():
    devs = ps("Get-CimInstance Win32_PnPEntity | Where-Object {$_.DeviceID -like 'USB\\*'} "
              "| Select Name,DeviceID,Manufacturer,PNPClass")
    hid_count_by_vid = {}
    for d in devs:
        vid, pid = parse_ids(d.get("DeviceID", ""))
        if vid in USB_EMULATION_CHIPS:
            add("MEDIUM", "usb",
                f"{d.get('Name')} [{vid}:{pid}] -> {USB_EMULATION_CHIPS[vid]}")
        if (d.get("PNPClass") or "") in ("HIDClass", "Mouse", "Keyboard"):
            hid_count_by_vid[vid] = hid_count_by_vid.get(vid, 0) + 1
    # Multiple *mice* or *keyboards* are normal for composite devices, but report it.
    mice = ps("Get-CimInstance Win32_PointingDevice | Select Name,Manufacturer,DeviceID")
    kbs = ps("Get-CimInstance Win32_Keyboard | Select Name,DeviceID")
    add("INFO", "usb", f"{len(mice)} pointing device(s), {len(kbs)} keyboard(s) enumerated.")
    for m in mice:
        n = (m.get("Name") or "").lower()
        if n in ("hid-compliant mouse", "usb input device") and not (m.get("Manufacturer") or "").strip("() "):
            continue
    # Serial (COM) ports next to HID devices is the classic KMBox B signature.
    ports = ps("Get-CimInstance Win32_SerialPort | Select Name,PNPDeviceID")
    for p in ports:
        vid, _ = parse_ids(p.get("PNPDeviceID", ""))
        if vid == "1A86":
            add("MEDIUM", "usb", f"CH340/CH343 COM port present ({p.get('Name')}): "
                                 "consistent with KMBox-style control link (also common in legit hobby gear).")


def check_drivers():
    """Known driver/service names used by PCILeech/FPGA tooling."""
    svcs = ps("Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -match "
              "'pcileech|winpmem|dumpit|rweverything|capcom|gdrv|asmmap|physmem|ene|iqvw64'} "
              "| Select Name,State,PathName")
    for s in svcs:
        add("HIGH", "driver", f"Memory-access driver registered: {s.get('Name')} ({s.get('State')}) {s.get('PathName')}")


def input_test(seconds: int):
    """Heuristic mouse-motion analysis. Hardware injectors bypass LLMHF_INJECTED,
    so we look at statistical shape instead. Low confidence; needs a human moving
    the mouse naturally during the test."""
    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    u32 = ctypes.windll.user32
    pt = POINT()
    u32.GetCursorPos(ctypes.byref(pt))
    last = (pt.x, pt.y)
    last_t = time.perf_counter()
    intervals, jumps = [], []
    end = last_t + seconds
    print(f"[input-test] Move the mouse naturally for {seconds}s...")
    while time.perf_counter() < end:
        u32.GetCursorPos(ctypes.byref(pt))
        cur = (pt.x, pt.y)
        if cur != last:
            now = time.perf_counter()
            intervals.append((now - last_t) * 1000)
            jumps.append(math.hypot(cur[0] - last[0], cur[1] - last[1]))
            last, last_t = cur, now
        time.sleep(0.0005)
    if len(intervals) < 50:
        add("INFO", "input", "Too little mouse movement captured for analysis.")
        return
    cv = statistics.pstdev(intervals) / (statistics.mean(intervals) or 1)
    big = sum(1 for j in jumps if j > 400)
    if cv < 0.05:
        add("MEDIUM", "input", f"Mouse update timing is unnaturally regular (CV={cv:.3f}).")
    if big:
        add("MEDIUM", "input", f"{big} instantaneous cursor jump(s) >400px between samples.")
    if cv >= 0.05 and not big:
        add("OK", "input", f"Mouse motion looks human-like (CV={cv:.2f}, no teleports).")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="DMA / KMBox indicator scanner (defensive)")
    ap.add_argument("--json", help="write findings to this JSON file")
    ap.add_argument("--input-test", type=int, metavar="SECONDS",
                    help="also run mouse-motion heuristic")
    args = ap.parse_args()

    print("dma_check v1.2 (utf-8 safe)")
    if platform.system() != "Windows":
        sys.exit("This tool supports Windows only.")
    if not is_admin():
        print("[!] Not running as Administrator: results may be incomplete.\n")

    print("== DMA protection posture ==");  check_dma_protection()
    print("== PCI enumeration ==");          check_pci(); check_thunderbolt_external()
    print("== USB / HID / serial ==");       check_usb()
    print("== Memory-access drivers ==");    check_drivers()
    if args.input_test:
        print("== Input analysis ==");       input_test(args.input_test)

    order = {"HIGH": 0, "MEDIUM": 1, "WARN": 2, "LOW": 3, "INFO": 4, "OK": 5}
    findings.sort(key=lambda f: order[f["level"]])
    print("\n" + "=" * 60 + "\nREPORT\n" + "=" * 60)
    for f in findings:
        print(f"[{f['level']:<6}] ({f['category']}) {f['message']}")

    high = sum(f["level"] == "HIGH" for f in findings)
    med = sum(f["level"] == "MEDIUM" for f in findings)
    score = "HIGH RISK" if high else "ELEVATED" if med >= 2 else "LOW-MODERATE"
    print(f"\nOverall indicator level: {score}  (HIGH={high}, MEDIUM={med})")
    print("Reminder: indicators only. Spoofed DMA hardware can evade software checks.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"Saved: {args.json}")


if __name__ == "__main__":
    main()
