#!/usr/bin/env python3
"""GameCheck - fichier unique (moteur d'analyse + interface graphique).
Lancer :          python gamecheck_app.py
Mode console :    python gamecheck_app.py --console
Build (.exe) :    python -m PyInstaller --clean --onefile --noconsole --noupx --uac-admin ^
                    --icon gamecheck.ico --add-data "gamecheck.ico;." --add-data "icon_preview.png;." ^
                    --name GameCheck gamecheck_app.py
"""
import codecs
import ctypes
import datetime as dt
import glob
import hashlib
import json
import os
import platform
import re
import string
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

IS_WIN = platform.system() == "Windows"
if IS_WIN:
    import winreg

FROZEN = getattr(sys, "frozen", False)
SELF = os.path.abspath(sys.executable if FROZEN else __file__).lower()
BASE_DIR = Path(SELF).parent

# ------------------------------------------------------------------ signatures
DEFAULT_SIGNATURES = {
    # Generique / injecteurs / trainers
    "cheatengine": (30, "trainer"), "cheat engine": (30, "trainer"),
    "extreme injector": (40, "injector"), "extremeinjector": (40, "injector"),
    "xenos": (25, "injector"), "kdmapper": (45, "driver-mapper"),
    "processhacker": (10, "outil-debug"), "x64dbg": (10, "outil-debug"),
    "autoclicker": (15, "macro"), "auto clicker": (15, "macro"), "gsautoclicker": (15, "macro"),
    # Minecraft
    "meteor-client": (40, "minecraft-client"), "wurst": (40, "minecraft-client"),
    "liquidbounce": (40, "minecraft-client"), "aristois": (40, "minecraft-client"),
    "impactclient": (40, "minecraft-client"), "killaura": (35, "minecraft-client"),
    "vape": (30, "minecraft-client"), "rise client": (35, "minecraft-client"),
    "doomsday": (35, "minecraft-client"),
    # FiveM / RageMP / autres
    "eulen": (45, "fivem-cheat"), "redengine": (45, "fivem-cheat"),
    "lynxmenu": (40, "fivem-cheat"), "hxsoftware": (40, "fivem-cheat"),
    "skript.gg": (40, "fivem-cheat"), "modmenu": (25, "mod-menu"),
    "aimbot": (35, "aimbot"), "triggerbot": (35, "aimbot"), "colorbot": (35, "aimbot"),
    "wallhack": (35, "esp"), "spoofer": (30, "hwid-spoofer"),
    "norecoil": (25, "recul"), "no recoil": (25, "recul"), "antirecoil": (25, "recul"),
}

WATCH_EXT = {".exe", ".dll", ".sys", ".jar", ".lnk", ".lua", ".ahk", ".py", ".bat", ".cmd",
             ".ps1", ".zip", ".rar", ".7z", ".cfg", ".ini"}
BIN_EXT = {".exe", ".dll", ".sys", ".jar"}
PRUNE = {"node_modules", ".git", "__pycache__", "$recycle.bin", "steamapps", "packages",
         "cache", "code cache", "gpucache", "windows", "winsxs", "system32",
         "program files", "program files (x86)", "$windows.~bt"}

# ---- Bibliotheques Python (liste ciblee : pile aimbot IA / vision / materiel)
LIB_GROUPS = {
    "capture":   {"bettercam": 8, "dxcam": 8, "d3dshot": 8, "mss": 3, "screeninfo": 2},
    "inference": {"onnxruntime": 5, "onnxruntime-gpu": 8, "ultralytics": 8, "cuda-python": 6,
                  "supervision": 6, "trackers": 5, "opencv-python": 2, "torch": 3, "tensorrt": 8},
    "input":     {"pynput": 3, "keyboard": 3, "pywin32": 2, "interception-python": 10, "pyautogui": 2},
    "hardware":  {"pyserial": 6, "hid": 8, "hidapi": 8, "pyusb": 6},
}
GENERIC_LIBS = {"numpy", "requests", "pandas", "psutil", "fastapi", "httpx", "uvicorn",
                "python-multipart", "packaging", "asyncio"}  # courants : informatif seulement
TARGET_LIBS = {"cuda-python", "bettercam", "screeninfo", "onnxruntime", "onnxruntime-gpu",
               "pyserial", "opencv-python", "ultralytics", "keyboard", "mss", "pynput",
               "supervision", "trackers", "hid", "pyusb", "pywin32"}
LIB_ALIAS = {"opencv-python-headless": "opencv-python", "opencv-contrib-python": "opencv-python",
             "pywin32-ctypes": "pywin32"}
MODULE_TO_LIB = {"cv2": "opencv-python", "win32api": "pywin32", "win32con": "pywin32",
                 "win32gui": "pywin32", "serial": "pyserial", "usb": "pyusb", "hid": "hid",
                 "bettercam": "bettercam", "dxcam": "dxcam", "d3dshot": "d3dshot", "mss": "mss",
                 "pynput": "pynput", "keyboard": "keyboard", "onnxruntime": "onnxruntime",
                 "ultralytics": "ultralytics", "supervision": "supervision",
                 "trackers": "trackers", "cuda": "cuda-python", "screeninfo": "screeninfo",
                 "torch": "torch", "pyautogui": "pyautogui", "interception": "interception-python",
                 "tensorrt": "tensorrt"}

# ---- Motifs dans le CONTENU des scripts
AHK_PATTERNS = [
    (r"pixelsearch|pixelgetcolor|imagesearch", 12, "recherche de pixel (colorbot)"),
    (r"mouse_event|sendinput", 6, "entree souris bas niveau"),
    (r"no\s*recoil|norecoil|anti.?recoil|\brecoil\b", 25, "controle de recul"),
    (r"triggerbot|trigger\s*bot|aimbot|rapid\s*fire|rapidfire|autofire|bhop|bunnyhop", 30, "mot-cle cheat"),
    (r"getkeystate\s*\(\s*[\"']lbutton|~lbutton|\*lbutton", 6, "detection clic gauche"),
]
LUA_PATTERNS = [
    (r"movemouserelative", 20, "deplacement souris relatif (macro G HUB)"),
    (r"enableprimarymousebuttonevents", 8, "evenements souris (G HUB)"),
    (r"\brecoil\b|norecoil|no_recoil", 25, "controle de recul"),
    (r"aimbot|triggerbot|silent\s*aim|silentaim", 30, "mot-cle cheat"),
    (r"godmode|noclip|esp_|drawesp|executor", 8, "fonction de menu cheat"),
]
PY_PATTERNS = [
    (r"aimbot|triggerbot|aim[_ ]?assist|no[_ ]?recoil|silent[_ ]?aim|color[_ ]?bot", 30, "mot-cle cheat"),
    (r"mouse_event|sendinput|setcursorpos|move_rel|mouse_move", 6, "entree souris bas niveau"),
    (r"serial\.serial\s*\(", 6, "communication serie (Arduino/KMBox)"),
]

USB_VIDS = {
    "2341": ("Arduino", 8), "2A03": ("Arduino", 8), "1B4F": ("SparkFun/Pro Micro", 12),
    "16C0": ("Teensy/PJRC", 12), "2E8A": ("Raspberry Pi Pico", 12), "239A": ("Adafruit", 10),
    "1A86": ("WCH CH340/CH343 (clones Arduino, KMBox/Makcu)", 8), "303A": ("Espressif ESP32", 8),
}
VULN_DRIVERS = {
    "dbk64": (45, "pilote Cheat Engine"), "dbk32": (45, "pilote Cheat Engine"),
    "iqvw64e": (30, "pilote vulnerable (kdmapper)"), "capcom": (35, "pilote vulnerable"),
    "dbutil_2_3": (30, "pilote vulnerable Dell"), "physmem": (20, "acces memoire physique"),
    "gdrv": (20, "pilote vulnerable Gigabyte"), "rtcore64": (15, "pilote vulnerable MSI"),
    "winring0": (15, "pilote acces materiel"), "mhyprot2": (25, "pilote vulnerable"),
    "kprocesshacker": (15, "pilote Process Hacker"),
}


def load_signatures():
    sigs, hashes = dict(DEFAULT_SIGNATURES), set()
    p = BASE_DIR / "signatures.json"
    if p.exists():
        try:
            for k, v in json.loads(p.read_text(encoding="utf-8")).items():
                if k == "_hashes":
                    hashes = {h.lower() for h in v}
                else:
                    sigs[k.lower()] = (int(v[0]), str(v[1]))
        except Exception as e:
            print(f"[!] signatures.json invalide : {e}")
    return sigs, hashes


def match(text, sigs):
    t = text.lower()
    return [(k, w, c) for k, (w, c) in sigs.items() if k in t]


def F(type_, item, keyword, category, weight, **extra):
    d = {"type": type_, "item": item, "keyword": keyword, "category": category, "weight": weight}
    d.update(extra)
    return d


def ft(v):
    try:
        return (dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=v // 10)).isoformat(timespec="seconds")
    except Exception:
        return None


def sha256(path, limit=100 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ------------------------------------------------------------------ registre
def _subkeys(root, path):
    try:
        with winreg.OpenKey(root, path) as k:
            return [winreg.EnumKey(k, i) for i in range(winreg.QueryInfoKey(k)[0])]
    except OSError:
        return []


def _reg_values(root, path):
    try:
        with winreg.OpenKey(root, path) as key:
            i = 0
            while True:
                try:
                    yield winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
    except OSError:
        return


def _reg_get(root, path, name):
    try:
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


# ------------------------------------------------------------------ analyse libs / scripts
def normalize_lib(name):
    n = name.strip().lower().replace("_", "-")
    return LIB_ALIAS.get(n, n)


def eval_libs(libs):
    """Score d'un ensemble de bibliotheques. Retourne (poids, [explications])."""
    present = {g: {l: w for l, w in d.items() if l in libs} for g, d in LIB_GROUPS.items()}
    base = sum(w for g in present.values() for w in g.values())
    notes, bonus = [], 0
    if present["capture"] and present["inference"]:
        bonus += 30
        notes.append("capture d'ecran + inference IA (pile aimbot visuel)")
        if present["input"] or present["hardware"]:
            bonus += 15
            notes.append("+ entrees souris/clavier ou materiel serie/HID")
    elif present["hardware"] and (present["capture"] or present["inference"]):
        bonus += 10
        notes.append("vision + pilotage materiel")
    hits = len(libs & TARGET_LIBS)
    if hits >= 8:
        bonus += 20
        notes.append(f"{hits}/16 bibliotheques de la liste ciblee")
    return min(base + bonus, 70), notes


def analyze_script(path, sigs):
    """Lit le contenu local d'un .py/.ahk/.lua. Retourne (poids, categorie, details) ou None."""
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            text = f.read(300_000).decode("utf-8", "ignore").lower()
    except Exception:
        return None
    details, weight = [], 0
    patterns = {".ahk": AHK_PATTERNS, ".lua": LUA_PATTERNS, ".py": PY_PATTERNS}.get(ext, [])
    for rx, w, label in patterns:
        if re.search(rx, text):
            weight += w
            details.append(label)
    for k, (w, c) in sigs.items():
        if len(k) >= 6 and k in text:
            weight += min(w, 20)
            details.append(f"mot-cle '{k}'")
    if ext == ".ahk" and re.search(r"pixelsearch|pixelgetcolor", text) and re.search(r"click|mouse_event|sendinput", text):
        weight += 15
        details.append("combo detection pixel + clic (triggerbot/colorbot probable)")
    if ext == ".py":
        mods = set(re.findall(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)", text, re.M))
        libs = {MODULE_TO_LIB[m] for m in mods if m in MODULE_TO_LIB}
        w, notes = eval_libs(libs)
        if w:
            weight += w
            details += [f"imports: {', '.join(sorted(libs))}"] + notes
    if weight < 8:
        return None
    cat = {".ahk": "script-ahk", ".lua": "script-lua", ".py": "script-python"}.get(ext, "script")
    return min(weight, 70), cat, details


def parse_dist_names(entries):
    libs = set()
    for e in entries:
        if e.endswith((".dist-info", ".egg-info")):
            libs.add(normalize_lib(e.rsplit(".", 1)[0].partition("-")[0]))
    return libs


def parse_requirements(path):
    libs = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.read(100_000).splitlines():
                line = line.split("#")[0].strip()
                if line and not line.startswith("-"):
                    libs.add(normalize_lib(re.split(r"[<>=!~;\[ ]", line)[0]))
    except Exception:
        pass
    return libs


# ------------------------------------------------------------------ scanners
def scan_processes(sigs):
    out = []
    if not psutil:
        return out, "psutil non installe : scan processus/DLL ignore (pip install psutil)"
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name, exe = proc.info["name"] or "", proc.info["exe"] or ""
            cmd = proc.info["cmdline"] or []
            label = f"{name} {exe}".strip()
            for k, w, c in match(label, sigs):
                out.append(F("process", label, k, c, w, pid=proc.info["pid"]))
            lname = name.lower()
            if "autohotkey" in lname:
                out.append(F("macro-actif", label, "autohotkey", "macro", 5, pid=proc.info["pid"],
                             cmdline=" ".join(cmd)[:300]))
            if any(x in lname for x in ("autohotkey", "python")):
                for arg in cmd[1:]:
                    if arg.lower().endswith((".py", ".ahk", ".lua")) and os.path.isfile(arg) \
                            and os.path.abspath(arg).lower() != SELF:
                        r = analyze_script(arg, sigs)
                        if r:
                            out.append(F("script-actif", arg, "script en cours d'execution", r[1],
                                         min(r[0] + 10, 80), pid=proc.info["pid"], details=r[2]))
            for m in proc.memory_maps():
                for k, w, c in match(m.path, sigs):
                    out.append(F("loaded-module", m.path, k, c, w, pid=proc.info["pid"]))
        except Exception:
            continue
    return out, None


def deep_walk(sigs, hashes):
    """Un seul parcours disque : fichiers suspects, scripts .lua/.ahk/.py, exe recents, libs Python."""
    findings = []
    inv = {"scripts": [], "recent_executables": [], "python_environments": []}
    notes = []
    deadline = time.time() + int(os.environ.get("GAMECHECK_TIMEOUT", "120"))
    home = Path.home()
    roots = [(str(home), 9)]
    if IS_WIN:
        for env in ("ProgramData", "TEMP"):
            if os.environ.get(env):
                roots.append((os.environ[env], 6))
        sysdrive = os.environ.get("SystemDrive", "C:")[0].upper()
        for L in string.ascii_uppercase:
            if os.path.isdir(f"{L}:\\"):
                for d in glob.glob(f"{L}:\\Python*"):
                    roots.append((d, 6))
                if L != sysdrive:
                    roots.append((f"{L}:\\", 3))
    else:
        roots.append(("/tmp", 4))

    now, seen, count, timed_out = time.time(), set(), 0, False
    user_dirs = ("\\downloads\\", "\\desktop\\", "\\documents\\", "\\temp\\", "/downloads/", "/desktop/")
    for root, maxd in roots:
        base = root.rstrip("\\/").count(os.sep)
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            if time.time() > deadline:
                timed_out = True
                break
            if os.path.basename(dp).lower() in ("site-packages", "dist-packages"):
                libs = parse_dist_names(dns)
                dns[:] = []
                if dp in seen or not libs:
                    continue
                seen.add(dp)
                w, why = eval_libs(libs)
                shown = sorted(libs & (TARGET_LIBS | GENERIC_LIBS | {l for g in LIB_GROUPS.values() for l in g}))
                inv["python_environments"].append({"path": dp, "weight": w, "libs": shown})
                if w >= 8:
                    findings.append(F("python-env", dp, "pile de bibliotheques", "python-aimbot-stack", w,
                                      details=why, libs=shown))
                continue
            depth = dp.count(os.sep) - base
            dns[:] = [] if depth >= maxd else [d for d in dns if d.lower() not in PRUNE]
            for fn in fns:
                full = os.path.join(dp, fn)
                if full in seen:
                    continue
                seen.add(full)
                count += 1
                if count % 20000 == 0:
                    print(f"    ... {count} fichiers examines")
                ext = os.path.splitext(fn)[1].lower()
                low = full.lower()
                if low == SELF:
                    continue
                if fn.lower().startswith("requirements") and ext == ".txt":
                    libs = parse_requirements(full)
                    w, why = eval_libs(libs)
                    if w >= 8:
                        findings.append(F("requirements", full, "dependances", "python-aimbot-stack", w, details=why))
                    continue
                if ext not in WATCH_EXT:
                    continue
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                for k, w, c in match(full, sigs):
                    findings.append(F("file", full, k, c, w,
                                      modified=dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")))
                if ext in (".lua", ".ahk"):
                    inv["scripts"].append({"path": full, "size": st.st_size,
                                           "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")})
                if ext in (".lua", ".ahk", ".py"):
                    r = analyze_script(full, sigs)
                    if r:
                        findings.append(F("script", full, "analyse du contenu", r[1], r[0], details=r[2]))
                if ext in BIN_EXT and hashes and now - st.st_mtime < 60 * 86400:
                    h = sha256(full)
                    if h and h in hashes:
                        findings.append(F("hash", full, h, "hash-connu", 60))
                if ext == ".exe" and now - st.st_mtime < 14 * 86400 and any(u in low for u in user_dirs) \
                        and len(inv["recent_executables"]) < 300:
                    inv["recent_executables"].append({
                        "path": full, "size": st.st_size, "sha256": sha256(full),
                        "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")})
        if timed_out:
            break
    if timed_out:
        notes.append("Parcours disque interrompu (delai atteint) - augmenter GAMECHECK_TIMEOUT")
    return findings, inv, notes


def scan_prefetch(sigs):
    out = []
    pf = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
    if not pf.exists():
        return out, "Prefetch inaccessible"
    try:
        files = list(pf.glob("*.pf"))
    except PermissionError:
        return out, "Prefetch : acces refuse (lancer en administrateur)"
    for f in files:
        for k, w, c in match(f.name, sigs):
            ts = dt.datetime.fromtimestamp(f.stat().st_mtime).isoformat(timespec="seconds")
            out.append(F("prefetch", f.name, k, c, w, last_run=ts))
    if len(files) < 20:
        out.append(F("anti-forensique", str(pf), "prefetch quasi vide", "nettoyage-traces", 12,
                     details=[f"{len(files)} fichiers .pf seulement (vide ou desactive)"]))
    return out, None


def scan_userassist(sigs):
    out = []
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    for g in _subkeys(winreg.HKEY_CURRENT_USER, base):
        for name, _, _ in _reg_values(winreg.HKEY_CURRENT_USER, f"{base}\\{g}\\Count"):
            decoded = codecs.decode(name, "rot_13")
            for kw, w, c in match(decoded, sigs):
                out.append(F("userassist", decoded, kw, c, w))
    return out, None


def scan_appcompat(sigs):
    out = []
    path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    for name, _, _ in _reg_values(winreg.HKEY_CURRENT_USER, path):
        for kw, w, c in match(name, sigs):
            out.append(F("appcompat", name, kw, c, w))
    return out, None


def scan_bam(sigs):
    out, base = [], r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    sids = _subkeys(winreg.HKEY_LOCAL_MACHINE, base)
    if not sids:
        return out, "BAM inaccessible (lancer en administrateur)"
    for sid in sids:
        for name, val, _ in _reg_values(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{sid}"):
            if not isinstance(name, str) or not name.lower().endswith((".exe", ".lnk")):
                continue
            when = ft(int.from_bytes(val[:8], "little")) if isinstance(val, bytes) and len(val) >= 8 else None
            for kw, w, c in match(name, sigs):
                out.append(F("bam", name, kw, c, w, last_run=when))
    return out, None


def scan_recycle(sigs):
    out = []
    for L in string.ascii_uppercase:
        rb = f"{L}:\\$Recycle.Bin"
        if not os.path.isdir(rb):
            continue
        try:
            sids = os.listdir(rb)
        except OSError:
            continue
        for sid in sids:
            sp = os.path.join(rb, sid)
            try:
                files = [f for f in os.listdir(sp) if f.startswith("$I")]
            except OSError:
                continue
            for f in files:
                try:
                    with open(os.path.join(sp, f), "rb") as fh:
                        data = fh.read(2048)
                    ver = int.from_bytes(data[:8], "little")
                    when = ft(int.from_bytes(data[16:24], "little"))
                    if ver == 2:
                        ln = int.from_bytes(data[24:28], "little")
                        raw = data[28:28 + ln * 2]
                    else:
                        raw = data[24:]
                    path = raw.decode("utf-16le", "ignore").strip("\x00")
                except Exception:
                    continue
                hits = match(path, sigs)
                for k, w, c in hits:
                    out.append(F("corbeille", path, k, c, w, deleted_at=when))
                if not hits and path.lower().endswith((".lua", ".ahk")):
                    out.append(F("corbeille", path, "script supprime", "script-supprime", 6, deleted_at=when))
    return out, None


def scan_recent_lnk(sigs):
    out = []
    rec = Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Recent"
    if not rec.exists():
        return out, None
    for f in rec.glob("*.lnk"):
        n = f.name.lower()
        for k, w, c in match(n, sigs):
            out.append(F("fichier-recent", f.name, k, c, w))
        if n.endswith((".ahk.lnk", ".lua.lnk")):
            out.append(F("fichier-recent", f.name, "script ouvert recemment", "script-recent", 3))
    return out, None


def scan_usb_history(sigs):
    """Appareils USB deja branches : Arduino/Teensy/Pico/CH340 = souris/aimbot materiel possible."""
    out, base = [], r"SYSTEM\CurrentControlSet\Enum\USB"
    for name in _subkeys(winreg.HKEY_LOCAL_MACHINE, base):
        m = re.match(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", name, re.I)
        if not m or m.group(1).upper() not in USB_VIDS:
            continue
        vid, pid = m.group(1).upper(), m.group(2).upper()
        label, w = USB_VIDS[vid]
        if (vid, pid) in {("2341", "8036"), ("2341", "8037"), ("2341", "8041")}:
            w += 10
        desc = ""
        for inst in _subkeys(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{name}"):
            desc = _reg_get(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{name}\\{inst}", "FriendlyName") or \
                   _reg_get(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{name}\\{inst}", "DeviceDesc") or desc
        out.append(F("usb-historique", f"{name} {desc}".strip(), label, "materiel-hid", w,
                     details=["peut simuler une souris/clavier (aimbot materiel) - usage legitime possible"]))
    return out, None


def run_cmd(args, timeout=30):
    """Execute une commande Windows et decode sa sortie SANS jamais planter.
    (les outils systeme sortent en cp850/cp1252/utf-8 selon la langue de Windows)"""
    r = subprocess.run(args, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    raw = r.stdout or b""
    encs = []
    if IS_WIN:
        try:
            encs.append(f"cp{ctypes.windll.kernel32.GetOEMCP()}")
        except Exception:
            pass
    encs += ["utf-8", "cp1252"]
    for enc in encs:
        try:
            return r.returncode, raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return r.returncode, raw.decode("utf-8", "replace")


def scan_drivers(sigs):
    out = []
    for svc in _subkeys(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"):
        low = svc.lower()
        for k, (w, label) in VULN_DRIVERS.items():
            if low == k or low.startswith(k):
                img = _reg_get(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{svc}", "ImagePath")
                out.append(F("pilote", f"{svc} ({img})", k, "pilote-suspect", w, details=[label]))
    try:
        _, dout = run_cmd(["driverquery", "/fo", "csv", "/nh"], 40)
        for line in dout.splitlines():
            for k, w, c in match(line, sigs):
                out.append(F("pilote-charge", line[:120], k, c, w))
    except Exception:
        pass
    return out, None


def scan_integrity(sigs):
    out, notes = [], None
    try:
        code, bout = run_cmd(["bcdedit", "/enum"], 25)
        if code != 0:
            notes = "bcdedit refuse (lancer en administrateur)"
        else:
            yes_rx = r"(?:yes|oui|ja|s[ií]|sim)\b"
            if re.search(r"testsigning\s+" + yes_rx, bout, re.I):
                out.append(F("integrite", "testsigning actif", "bcdedit", "mode-test-pilotes", 20,
                             details=["permet de charger des pilotes non signes"]))
            if re.search(r"nointegritychecks\s+" + yes_rx, bout, re.I):
                out.append(F("integrite", "nointegritychecks actif", "bcdedit", "mode-test-pilotes", 30))
    except Exception:
        notes = "bcdedit indisponible"
    for sub in ("Paths", "Processes"):
        for name, _, _ in _reg_values(winreg.HKEY_LOCAL_MACHINE,
                                      rf"SOFTWARE\Microsoft\Windows Defender\Exclusions\{sub}"):
            risky = any(x in name.lower() for x in ("downloads", "desktop", "temp", ".minecraft"))
            out.append(F("exclusion-defender", name, sub, "exclusion-antivirus", 10 if risky else 3))
    for log, eid, label, w in (("Security", 1102, "Journal Securite efface", 25),
                               ("System", 104, "Journal Systeme efface", 20)):
        try:
            code, wout = run_cmd(["wevtutil", "qe", log, f"/q:*[System[(EventID={eid})]]", "/c:1",
                                  "/rd:true", "/f:text"], 40)
            m = re.search(r"Date\s*:\s*(.+)", wout)
            if code == 0 and ("Event[" in wout or m):
                when = m.group(1).strip() if m else "date inconnue"
                out.append(F("anti-forensique", label, f"evenement {eid}", "nettoyage-traces", w,
                             details=[f"dernier effacement : {when}"]))
        except Exception:
            pass
    return out, notes


# ------------------------------------------------------------------ rapport
def risk_score(findings):
    seen, score = set(), 0.0
    for f in sorted(findings, key=lambda x: -x["weight"]):
        key = (f["keyword"], f["type"])
        score += f["weight"] * (0.35 if key in seen else 1.0)
        seen.add(key)
    return min(100, int(round(score)))


def verdict(score):
    if score >= 70:
        return "TRES SUSPECT"
    if score >= 35:
        return "SUSPECT - verification manuelle requise"
    if score > 0:
        return "INDICES FAIBLES"
    return "RIEN DETECTE"


def send_webhook(url, report):
    top = sorted(report["findings"], key=lambda x: -x["weight"])[:5]
    lines = "\n".join(f"- [{f['category']}] {f['item'][:80]}" for f in top)
    msg = {"content": (f"**Scan PIN `{report['pin']}`** - joueur : `{report['player']}`\n"
                       f"Score : **{report['risk_score']}/100** - {report['verdict']}\n"
                       f"Detections : {len(report['findings'])}\n{lines}")[:1900]}
    req = urllib.request.Request(url, data=json.dumps(msg).encode(),
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15).read()


def yes(s):
    return s.strip().lower() in ("oui", "o", "yes", "y")


def is_admin():
    if IS_WIN:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_scan(pin, player, log=print, progress=None):
    """Lance toutes les analyses et retourne le rapport (dict). Utilise par la console ET l'interface."""
    sigs, hashes = load_signatures()
    findings, notes = [], []
    inventory = {"scripts": [], "recent_executables": [], "python_environments": []}

    scanners = [("Processus, DLL, scripts actifs", scan_processes)]
    if IS_WIN:
        scanners += [("Prefetch", scan_prefetch), ("UserAssist", scan_userassist),
                     ("AppCompat", scan_appcompat), ("BAM", scan_bam), ("Corbeille", scan_recycle),
                     ("Fichiers recents", scan_recent_lnk), ("Historique USB", scan_usb_history),
                     ("Pilotes", scan_drivers), ("Integrite systeme", scan_integrity)]
    total = len(scanners) + 1
    for n, (label, fn) in enumerate(scanners):
        if progress:
            progress(n, total)
        log(f"[*] {label} ...")
        try:
            res, note = fn(sigs)
            findings += res
            if note:
                notes.append(f"{label}: {note}")
                log(f"    ! {note}")
        except Exception as e:
            notes.append(f"{label}: erreur {e}")

    if progress:
        progress(len(scanners), total)
    log("[*] Parcours disque (fichiers, scripts .lua/.ahk/.py, bibliotheques Python) ...")
    try:
        res, inv, nn = deep_walk(sigs, hashes)
        findings += res
        inventory = inv
        notes += nn
    except Exception as e:
        notes.append(f"Parcours disque: erreur {e}")
    if progress:
        progress(total, total)

    findings.sort(key=lambda x: -x["weight"])
    score = risk_score(findings)
    return {
        "pin": pin, "player": player,
        "date": dt.datetime.now().isoformat(timespec="seconds"),
        "machine": {"os": platform.platform(),
                    "host_hash": hashlib.sha256(platform.node().encode()).hexdigest()[:16]},
        "admin": is_admin(),
        "risk_score": score, "verdict": verdict(score),
        "findings": findings, "inventory": inventory, "notes": notes,
    }


def save_report(report):
    fname = f"rapport_{report['pin']}_{dt.datetime.now():%Y%m%d_%H%M%S}.json"
    path = BASE_DIR / fname
    data = json.dumps(report, indent=2, ensure_ascii=False)
    try:
        path.write_text(data, encoding="utf-8")
    except OSError:  # dossier non inscriptible : repli sur le Bureau
        path = Path.home() / "Desktop" / fname
        path.write_text(data, encoding="utf-8")
    return path


def main():
    print("=" * 64)
    print(" GameCheck v2 - analyse approfondie anti-triche (screenshare)")
    print("=" * 64)
    print("Ce scan analysera :")
    print(" - processus, DLL chargees, scripts en cours d'execution")
    print(" - fichiers .exe .dll .lua .ahk .py (noms) ; le CONTENU des scripts")
    print("   .lua/.ahk/.py est lu LOCALEMENT pour reperer des motifs de triche")
    print(" - bibliotheques Python installees et fichiers requirements.txt")
    print(" - traces d'execution Windows, corbeille, historique USB, pilotes,")
    print("   exclusions antivirus, journaux d'evenements")
    print("Aucune capture d'ecran. Le contenu de vos fichiers n'est jamais envoye :")
    print("seul un resume est transmis, et uniquement avec votre accord.\n")
    if not yes(input("Acceptez-vous le scan ? (oui/non) : ")):
        print("Scan annule.")
        return
    pin = input("PIN fourni par le staff : ").strip()
    player = input("Pseudo en jeu : ").strip() or "inconnu"
    if IS_WIN and not is_admin():
        print("\n[!] Pas administrateur : Prefetch, BAM, bcdedit et journaux seront limites.")

    report = run_scan(pin, player)
    path = save_report(report)
    findings, inventory, score = report["findings"], report["inventory"], report["risk_score"]

    print("\n" + "-" * 64)
    print(f" Score de risque : {score}/100  ->  {report['verdict']}")
    print(f" Detections      : {len(findings)}")
    print(f" Scripts .lua/.ahk trouves : {len(inventory['scripts'])}")
    print(f" .exe recents (14 j)       : {len(inventory['recent_executables'])}")
    print(f" Environnements Python     : {len(inventory['python_environments'])}")
    for f in findings[:15]:
        print(f"   - [{f['category']}] ({f['weight']}) {f['type']}: {f['item'][:80]}")
        for d in f.get("details", [])[:3]:
            print(f"        > {d}")
    if len(findings) > 15:
        print(f"   ... et {len(findings) - 15} autres (voir le rapport)")
    print(f" Rapport enregistre : {path.resolve()}")

    url = os.environ.get("GAMECHECK_WEBHOOK", "").strip()
    if url and yes(input("\nEnvoyer le resume au staff (Discord) ? (oui/non) : ")):
        try:
            send_webhook(url, report)
            print("Resume envoye.")
        except Exception as e:
            print(f"Echec de l'envoi : {e} - transmettez le fichier manuellement.")
    elif not url:
        print("\nTransmettez le fichier de rapport au staff.")
    input("\nAppuyez sur Entree pour fermer.")




# ======================================================================
#                          INTERFACE GRAPHIQUE
# ======================================================================
import html as htmlmod
import queue
import threading
import traceback
import webbrowser
import tkinter as tk
from tkinter import messagebox, ttk

gc = sys.modules[__name__]  # moteur et interface dans le meme fichier

# ================================================================== theme
BG = "#0b1120"
SIDE = "#0f172a"
CARD = "#111a2e"
CARD2 = "#16213a"
BORDER = "#1f2d4a"
FIELD = "#0b1324"
FG = "#e8eefc"
MUTED = "#8a9ab8"
ACCENT = "#14e0c4"
ACCENT2 = "#4ff0d9"
GOOD = "#34d399"
WARN = "#fbbf24"
BAD = "#fb7185"
UIF = "Segoe UI"
VERSION = "v2.0"

STR = {
    "fr": {
        "app": "GameCheck", "tagline": "Vérification anti-triche",
        "steps": ["Consentement", "Analyse", "Résultats"],
        "admin_ok": "Administrateur", "admin_no": "Droits limités",
        "admin_hint": "Relancez en administrateur pour une analyse complète (Prefetch, BAM, journaux).",
        "lang": "English",
        "h_form": "Nouvelle vérification",
        "s_form": "Un modérateur vous a demandé de passer cette analyse. Elle prend environ une minute.",
        "what": "Ce qui est analysé",
        "items": ["Processus et DLL chargées", "Fichiers .exe  .lua  .ahk  .py",
                  "Bibliothèques Python installées", "Traces d'exécution Windows",
                  "Corbeille et fichiers récents", "Historique USB et pilotes",
                  "Intégrité du système", "Contenu des scripts (lu en local)"],
        "privacy": "Aucune capture d'écran  •  Vos fichiers ne sont jamais envoyés  •  "
                   "Un résumé n'est transmis qu'avec votre accord",
        "pin": "PIN du scan", "pin_ph": "Donné par le staff",
        "player": "Pseudo en jeu", "player_ph": "Votre pseudo",
        "consent": "J'ai lu les informations ci-dessus et j'accepte l'analyse de mon PC.",
        "start": "Lancer l'analyse",
        "h_scan": "Analyse en cours", "s_scan": "Ne fermez pas la fenêtre. Cela peut durer jusqu'à 2 minutes.",
        "current": "Étape en cours", "done_steps": "Étapes",
        "h_res": "Résultat de l'analyse", "score": "Score de risque",
        "k_det": "Détections", "k_scr": "Scripts", "k_exe": ".exe récents", "k_env": "Env. Python",
        "tab_find": "Détections", "tab_scr": "Scripts .lua/.ahk", "tab_exe": "Exécutables récents",
        "tab_env": "Python", "tab_notes": "Remarques",
        "search": "Rechercher…", "all": "Tous", "sev_high": "Élevé", "sev_mid": "Moyen", "sev_low": "Faible",
        "c_sev": "Gravité", "c_w": "Poids", "c_cat": "Catégorie", "c_type": "Type", "c_item": "Élément",
        "c_path": "Chemin", "c_size": "Taille", "c_mod": "Modifié", "c_sha": "SHA256", "c_libs": "Bibliothèques",
        "details": "Détails", "pick": "Sélectionnez une détection pour voir les détails.",
        "none": "Aucune détection. Rien de suspect n'a été trouvé.",
        "empty": "Aucun élément.",
        "new": "Nouveau scan", "open": "Dossier du rapport", "html": "Rapport HTML",
        "copy": "Copier le résumé", "send": "Envoyer au staff",
        "copied": "Résumé copié dans le presse-papiers.",
        "saved": "Rapport enregistré", "disclaimer": "Le score est un indice, pas une preuve : "
                                                    "un humain relit toujours le rapport.",
        "send_confirm": "Envoyer un résumé (score, PIN, pseudo, 5 principales détections) au staff Discord ?\n"
                        "Le rapport complet reste sur votre PC.",
        "sent": "Résumé envoyé au staff.", "send_fail": "Échec de l'envoi :",
        "err": "Une erreur est survenue :", "t_err": "Erreur", "t_send": "Envoi", "t_info": "Information",
        "no_note": "Aucune remarque.",
        "kw": "Mot-clé", "cat": "Catégorie", "type": "Type", "path": "Élément", "w": "Poids",
    },
    "en": {
        "app": "GameCheck", "tagline": "Anti-cheat verification",
        "steps": ["Consent", "Scan", "Results"],
        "admin_ok": "Administrator", "admin_no": "Limited rights",
        "admin_hint": "Restart as administrator for a complete scan (Prefetch, BAM, logs).",
        "lang": "Français",
        "h_form": "New verification",
        "s_form": "A moderator asked you to run this scan. It takes about a minute.",
        "what": "What is scanned",
        "items": ["Processes and loaded DLLs", "Files .exe  .lua  .ahk  .py",
                  "Installed Python libraries", "Windows execution traces",
                  "Recycle bin and recent files", "USB history and drivers",
                  "System integrity", "Script contents (read locally)"],
        "privacy": "No screenshots  •  Your files are never uploaded  •  "
                   "A summary is sent only with your approval",
        "pin": "Scan PIN", "pin_ph": "Given by staff",
        "player": "In-game name", "player_ph": "Your name",
        "consent": "I have read the information above and I consent to the scan of my PC.",
        "start": "Start scan",
        "h_scan": "Scan in progress", "s_scan": "Do not close the window. This can take up to 2 minutes.",
        "current": "Current step", "done_steps": "Steps",
        "h_res": "Scan result", "score": "Risk score",
        "k_det": "Detections", "k_scr": "Scripts", "k_exe": "Recent .exe", "k_env": "Python envs",
        "tab_find": "Detections", "tab_scr": ".lua/.ahk scripts", "tab_exe": "Recent executables",
        "tab_env": "Python", "tab_notes": "Notes",
        "search": "Search…", "all": "All", "sev_high": "High", "sev_mid": "Medium", "sev_low": "Low",
        "c_sev": "Severity", "c_w": "Weight", "c_cat": "Category", "c_type": "Type", "c_item": "Item",
        "c_path": "Path", "c_size": "Size", "c_mod": "Modified", "c_sha": "SHA256", "c_libs": "Libraries",
        "details": "Details", "pick": "Select a detection to see its details.",
        "none": "No detections. Nothing suspicious was found.",
        "empty": "Nothing to show.",
        "new": "New scan", "open": "Report folder", "html": "HTML report",
        "copy": "Copy summary", "send": "Send to staff",
        "copied": "Summary copied to the clipboard.",
        "saved": "Report saved", "disclaimer": "The score is an indicator, not proof: "
                                              "a human always reviews the report.",
        "send_confirm": "Send a summary (score, PIN, name, top 5 detections) to the staff Discord?\n"
                        "The full report stays on your PC.",
        "sent": "Summary sent to staff.", "send_fail": "Sending failed:",
        "err": "An error occurred:", "t_err": "Error", "t_send": "Send", "t_info": "Information",
        "no_note": "No notes.",
        "kw": "Keyword", "cat": "Category", "type": "Type", "path": "Item", "w": "Weight",
    },
}


def rpath(rel):
    """Cherche une ressource : bundle PyInstaller, a cote du script, ou dans assets/."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for sub in ("", "assets"):
        p = os.path.join(base, sub, rel)
        if os.path.exists(p):
            return p
    return os.path.join(base, rel)


def sev(w):
    return "high" if w >= 30 else ("mid" if w >= 15 else "low")


SEV_COL = {"high": BAD, "mid": WARN, "low": MUTED}


def human_size(n):
    for u in ("o", "Ko", "Mo", "Go"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "o" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} To"


def score_color(s):
    return GOOD if s < 35 else (WARN if s < 70 else BAD)


# ================================================================== widgets
def rrect(cv, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x1 + r, y1, x2 - r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y1 + r,
           x2, y2 - r, x2, y2 - r, x2, y2, x2 - r, y2, x2 - r, y2, x1 + r, y2, x1 + r, y2,
           x1, y2, x1, y2 - r, x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


class Btn(tk.Canvas):
    """Bouton arrondi avec survol. kind : primary / secondary."""

    def __init__(self, parent, text, command, kind="primary", width=170, height=40, bg=BG):
        super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0,
                         cursor="hand2")
        self.w, self.h, self.text, self.command, self.kind = width, height, text, command, kind
        self.enabled, self.hover = True, False
        self.bind("<Enter>", lambda e: self._set_hover(True))
        self.bind("<Leave>", lambda e: self._set_hover(False))
        self.bind("<Button-1>", self._click)
        self._draw()

    def _set_hover(self, v):
        self.hover = v
        self._draw()

    def _click(self, _e):
        if self.enabled and self.command:
            self.command()

    def set_enabled(self, v):
        self.enabled = v
        self.configure(cursor="hand2" if v else "arrow")
        self._draw()

    def _draw(self):
        self.delete("all")
        if not self.enabled:
            fill, fg = "#1a2440", "#5b6a88"
        elif self.kind == "primary":
            fill, fg = (ACCENT2 if self.hover else ACCENT), "#04201c"
        else:
            fill, fg = ("#2a3a5e" if self.hover else CARD2), FG
        rrect(self, 1, 1, self.w - 1, self.h - 1, 12, fill=fill, outline="")
        self.create_text(self.w / 2, self.h / 2, text=self.text, fill=fg, font=(UIF, 10, "bold"))


class Switch(tk.Canvas):
    def __init__(self, parent, var, command=None, bg=CARD):
        super().__init__(parent, width=48, height=26, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self.var, self.command = var, command
        self.bind("<Button-1>", self._toggle)
        self._draw()

    def _toggle(self, _e):
        self.var.set(not self.var.get())
        self._draw()
        if self.command:
            self.command()

    def _draw(self):
        on = bool(self.var.get())
        self.delete("all")
        rrect(self, 1, 1, 47, 25, 12, fill=ACCENT if on else "#2a3552", outline="")
        x = 35 if on else 13
        self.create_oval(x - 9, 4, x + 9, 22, fill="#04201c" if on else "#9fb0cf", outline="")


class Field(tk.Frame):
    """Champ de saisie avec etiquette, bordure qui s'allume au focus et texte d'aide."""

    def __init__(self, parent, label, var, placeholder="", bg=CARD):
        super().__init__(parent, bg=bg)
        tk.Label(self, text=label, bg=bg, fg=MUTED, font=(UIF, 9, "bold")).pack(anchor="w")
        self.box = tk.Frame(self, bg=BORDER, padx=1, pady=1)
        self.box.pack(fill="x", pady=(6, 0))
        self.entry = tk.Entry(self.box, textvariable=var, bg=FIELD, fg=FG, insertbackground=FG,
                              relief="flat", bd=0, font=(UIF, 12), highlightthickness=0)
        self.entry.pack(fill="x", ipady=10, ipadx=8)
        self.ph = None
        if placeholder:
            self.ph = tk.Label(self.box, text=placeholder, bg=FIELD, fg="#4b5a78", font=(UIF, 11))
            self.ph.place(x=10, rely=0.5, anchor="w")
            self.ph.bind("<Button-1>", lambda e: self.entry.focus_set())
            var.trace_add("write", lambda *_: self._sync(var))
            self._sync(var)
        self.entry.bind("<FocusIn>", lambda e: self.box.configure(bg=ACCENT))
        self.entry.bind("<FocusOut>", lambda e: self.box.configure(bg=BORDER))

    def _sync(self, var):
        try:
            if var.get():
                self.ph.place_forget()
            else:
                self.ph.place(x=10, rely=0.5, anchor="w")
        except tk.TclError:
            pass


class Animated(tk.Canvas):
    """Base : canvas avec boucle d'animation arretee a la destruction."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._job = None
        self._alive = True
        self.bind("<Destroy>", self._on_destroy)

    def _on_destroy(self, _e):
        self._alive = False
        if self._job:
            try:
                self.after_cancel(self._job)
            except Exception:
                pass

    def _later(self, ms, fn):
        if self._alive:
            self._job = self.after(ms, fn)


class Gauge(Animated):
    def __init__(self, parent, size=190, bg=CARD):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self.size, self.cur, self.target, self.color = size, 0.0, 0, ACCENT

    def show(self, score):
        self.target, self.cur, self.color = score, 0.0, score_color(score)
        self._step()

    def _step(self):
        if not self._alive:
            return
        diff = self.target - self.cur
        self.cur = self.target if diff < 0.6 else self.cur + diff * 0.10
        self._draw()
        if self.cur < self.target:
            self._later(16, self._step)

    def _draw(self):
        s, pad = self.size, 14
        self.delete("all")
        self.create_arc(pad, pad, s - pad, s - pad, start=90, extent=-359.9, style="arc", width=14,
                        outline="#1c2a49")
        if self.cur > 0.5:
            self.create_arc(pad, pad, s - pad, s - pad, start=90, extent=-max(3.6 * self.cur, 6),
                            style="arc", width=14, outline=self.color)
        self.create_text(s / 2, s / 2 - 8, text=str(int(round(self.cur))), fill=self.color,
                         font=(UIF, 38, "bold"))
        self.create_text(s / 2, s / 2 + 30, text="/ 100", fill=MUTED, font=(UIF, 10))


class Ring(Animated):
    """Anneau de progression + arc tournant (le parcours disque est long)."""

    def __init__(self, parent, size=210, bg=CARD):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
        self.size, self.pct, self.disp, self.angle = size, 0.0, 0.0, 0
        self._tick()

    def set(self, pct):
        self.pct = pct

    def _tick(self):
        if not self._alive:
            return
        self.disp += (self.pct - self.disp) * 0.15
        self.angle = (self.angle + 7) % 360
        s, pad = self.size, 16
        self.delete("all")
        self.create_arc(pad, pad, s - pad, s - pad, start=90, extent=-359.9, style="arc", width=12,
                        outline="#1c2a49")
        self.create_arc(pad, pad, s - pad, s - pad, start=90, extent=-max(3.6 * self.disp, 4),
                        style="arc", width=12, outline=ACCENT)
        q = pad + 20
        self.create_arc(q, q, s - q, s - q, start=self.angle, extent=70, style="arc", width=4,
                        outline=ACCENT2)
        self.create_text(s / 2, s / 2, text=f"{int(self.disp)}%", fill=FG, font=(UIF, 30, "bold"))
        self._later(30, self._tick)


# ================================================================== rapport HTML
def build_html(report, T):
    esc = htmlmod.escape
    sc = report["risk_score"]
    col = score_color(sc)
    rows = []
    for f in report["findings"]:
        s = sev(f["weight"])
        extra = {k: v for k, v in f.items() if k not in ("type", "item", "keyword", "category", "weight")}
        det = "<br>".join(esc(f"{k}: {v}") for k, v in extra.items())
        rows.append(
            f"<tr><td><span class='b {s}'>{esc(T['sev_' + s])}</span></td><td>{f['weight']}</td>"
            f"<td>{esc(str(f['category']))}</td><td>{esc(str(f['type']))}</td>"
            f"<td class='m'>{esc(str(f['item']))}<div class='d'>{det}</div></td></tr>")
    inv = report["inventory"]

    def table(items, cols):
        if not items:
            return f"<p class='mu'>{esc(T['empty'])}</p>"
        head = "".join(f"<th>{esc(c)}</th>" for c, _ in cols)
        body = "".join("<tr>" + "".join(f"<td class='m'>{esc(str(it.get(k, '')))}</td>" for _, k in cols) + "</tr>"
                       for it in items)
        return f"<table><tr>{head}</tr>{body}</table>"

    envs = [{"path": e["path"], "weight": e["weight"], "libs": ", ".join(e["libs"])}
            for e in inv["python_environments"]]
    if rows:
        find_html = ("<table><tr><th>" + esc(T['c_sev']) + "</th><th>" + esc(T['c_w']) + "</th><th>" +
                     esc(T['c_cat']) + "</th><th>" + esc(T['c_type']) + "</th><th>" + esc(T['c_item']) +
                     "</th></tr>" + "".join(rows) + "</table>")
    else:
        find_html = "<p class='mu'>" + esc(T['none']) + "</p>"
    notes_html = "".join("<p class='mu'>" + esc(n) + "</p>" for n in report["notes"]) or \
                 "<p class='mu'>" + esc(T['no_note']) + "</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>GameCheck - {esc(report['pin'])}</title>
<style>
body{{margin:0;background:{BG};color:{FG};font-family:Segoe UI,Arial,sans-serif;padding:32px}}
h1{{margin:0 0 4px}} h2{{margin-top:34px;color:{ACCENT}}} .mu{{color:{MUTED}}}
.top{{display:flex;gap:28px;align-items:center;background:{CARD};padding:22px 26px;border-radius:14px;border:1px solid {BORDER}}}
.score{{font-size:56px;font-weight:700;color:{col}}} table{{width:100%;border-collapse:collapse;margin-top:10px;background:{CARD};border-radius:10px;overflow:hidden}}
th{{text-align:left;background:{CARD2};padding:10px;font-size:13px;color:{MUTED}}} td{{padding:9px 10px;border-top:1px solid {BORDER};font-size:13px;vertical-align:top}}
.m{{font-family:Consolas,monospace;word-break:break-all}} .d{{color:{MUTED};margin-top:4px;font-family:Segoe UI;font-size:12px}}
.b{{padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700;font-family:Segoe UI}}
.high{{background:{BAD}33;color:{BAD}}} .mid{{background:{WARN}33;color:{WARN}}} .low{{background:#8a9ab833;color:{MUTED}}}
</style></head><body>
<h1>GameCheck</h1><div class="mu">PIN {esc(report['pin'])} &bull; {esc(report['player'])} &bull; {esc(report['date'])} &bull; {esc(report['machine']['os'])}</div>
<div class="top" style="margin-top:18px"><div class="score">{sc}<span class="mu" style="font-size:20px"> / 100</span></div>
<div><div style="font-size:22px;font-weight:700;color:{col}">{esc(report['verdict'])}</div>
<div class="mu">{esc(T['disclaimer'])}</div></div></div>
<h2>{esc(T['tab_find'])} ({len(report['findings'])})</h2>{find_html}
<h2>{esc(T['tab_scr'])} ({len(inv['scripts'])})</h2>{table(inv['scripts'], [(T['c_path'], 'path'), (T['c_size'], 'size'), (T['c_mod'], 'modified')])}
<h2>{esc(T['tab_exe'])} ({len(inv['recent_executables'])})</h2>{table(inv['recent_executables'], [(T['c_path'], 'path'), (T['c_sha'], 'sha256'), (T['c_mod'], 'modified')])}
<h2>{esc(T['tab_env'])} ({len(envs)})</h2>{table(envs, [(T['c_path'], 'path'), (T['c_w'], 'weight'), (T['c_libs'], 'libs')])}
<h2>{esc(T['tab_notes'])}</h2>{notes_html}
</body></html>"""


# ================================================================== application
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = "fr"
        self.screen = "form"
        self.pin, self.player = tk.StringVar(), tk.StringVar()
        self.consent = tk.BooleanVar(value=False)
        self.search = tk.StringVar()
        self.level = "all"
        self.tab = "find"
        self.report = self.report_path = None
        self.q = queue.Queue()
        self.step_names = []
        self.progress_pct = 0
        self.logo = None
        self.ring = None

        self.title("GameCheck")
        w, h = 1120, 740
        self.geometry(f"{w}x{h}+{max((self.winfo_screenwidth() - w) // 2, 0)}+"
                      f"{max((self.winfo_screenheight() - h) // 2 - 20, 0)}")
        self.minsize(980, 660)
        self.configure(bg=BG)
        try:
            self.iconbitmap(rpath("gamecheck.ico"))
        except Exception:
            pass
        self._style()
        self.search.trace_add("write", lambda *_: self._fill_findings())
        self.pin.trace_add("write", lambda *_: self._update_start())
        self.root_frame = tk.Frame(self, bg=BG)
        self.root_frame.pack(fill="both", expand=True)
        self.render()
        self.after(100, self._poll)

    # ---------------------------------------------------------- base
    def t(self, k):
        return STR[self.lang][k]

    def _style(self):
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Pro.Treeview", background=CARD, fieldbackground=CARD, foreground=FG, rowheight=32,
                     borderwidth=0, font=(UIF, 10))
        st.configure("Pro.Treeview.Heading", background=CARD2, foreground=MUTED, borderwidth=0,
                     font=(UIF, 9, "bold"), padding=(8, 8))
        st.map("Pro.Treeview", background=[("selected", "#233a66")], foreground=[("selected", "#ffffff")])
        st.map("Pro.Treeview.Heading", background=[("active", CARD2)])
        st.configure("Vertical.TScrollbar", background=CARD2, troughcolor=CARD, bordercolor=CARD,
                     arrowcolor=MUTED, lightcolor=CARD2, darkcolor=CARD2)

    def render(self):
        for wdg in self.root_frame.winfo_children():
            wdg.destroy()
        self.ring = None
        self._sidebar()
        self.main = tk.Frame(self.root_frame, bg=BG)
        self.main.pack(side="left", fill="both", expand=True, padx=34, pady=28)
        {"form": self._screen_form, "scan": self._screen_scan, "result": self._screen_result}[self.screen]()

    def _page_head(self, title, subtitle):
        tk.Label(self.main, text=title, bg=BG, fg=FG, font=(UIF, 22, "bold")).pack(anchor="w")
        tk.Label(self.main, text=subtitle, bg=BG, fg=MUTED, font=(UIF, 10)).pack(anchor="w", pady=(2, 18))

    def _card(self, parent, **kw):
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, **kw)
        inner.pack(fill="both", expand=True)
        return outer, inner

    # ---------------------------------------------------------- sidebar
    def _sidebar(self):
        sb = tk.Frame(self.root_frame, bg=SIDE, width=250)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        head = tk.Frame(sb, bg=SIDE)
        head.pack(fill="x", padx=22, pady=(28, 30))
        try:
            if self.logo is None:
                img = tk.PhotoImage(file=rpath("icon_preview.png"))
                f = max(1, img.width() // 46)
                self.logo = img.subsample(f, f)
            tk.Label(head, image=self.logo, bg=SIDE).pack(side="left", padx=(0, 12))
        except Exception:
            pass
        box = tk.Frame(head, bg=SIDE)
        box.pack(side="left")
        tk.Label(box, text=self.t("app"), bg=SIDE, fg=FG, font=(UIF, 16, "bold")).pack(anchor="w")
        tk.Label(box, text=self.t("tagline"), bg=SIDE, fg=MUTED, font=(UIF, 9)).pack(anchor="w")

        idx = {"form": 0, "scan": 1, "result": 2}[self.screen]
        for i, name in enumerate(self.t("steps")):
            row = tk.Frame(sb, bg=SIDE)
            row.pack(fill="x", padx=22, pady=7)
            c = tk.Canvas(row, width=30, height=30, bg=SIDE, highlightthickness=0)
            c.pack(side="left")
            if i < idx:
                c.create_oval(2, 2, 28, 28, fill=GOOD, outline="")
                c.create_text(15, 15, text="✓", fill="#06281c", font=(UIF, 11, "bold"))
            elif i == idx:
                c.create_oval(2, 2, 28, 28, fill=ACCENT, outline="")
                c.create_text(15, 15, text=str(i + 1), fill="#04201c", font=(UIF, 11, "bold"))
            else:
                c.create_oval(2, 2, 28, 28, fill=SIDE, outline="#2a3a5e", width=2)
                c.create_text(15, 15, text=str(i + 1), fill=MUTED, font=(UIF, 10, "bold"))
            tk.Label(row, text=name, bg=SIDE, fg=FG if i == idx else MUTED,
                     font=(UIF, 11, "bold" if i == idx else "normal")).pack(side="left", padx=12)

        bottom = tk.Frame(sb, bg=SIDE)
        bottom.pack(side="bottom", fill="x", padx=22, pady=22)
        admin = gc.is_admin()
        tk.Label(bottom, text="●  " + self.t("admin_ok" if admin else "admin_no"), bg=SIDE,
                 fg=GOOD if admin else WARN, font=(UIF, 10, "bold")).pack(anchor="w")
        if not admin:
            tk.Label(bottom, text=self.t("admin_hint"), bg=SIDE, fg=MUTED, font=(UIF, 8), wraplength=200,
                     justify="left").pack(anchor="w", pady=(2, 0))
        Btn(bottom, self.t("lang"), self._toggle_lang, kind="secondary", width=206, height=34,
            bg=SIDE).pack(anchor="w", pady=(14, 8))
        tk.Label(bottom, text=VERSION, bg=SIDE, fg="#4b5a78", font=(UIF, 8)).pack(anchor="w")

    def _toggle_lang(self):
        self.lang = "en" if self.lang == "fr" else "fr"
        self.render()

    # ---------------------------------------------------------- ecran 1
    def _screen_form(self):
        self._page_head(self.t("h_form"), self.t("s_form"))

        outer, card = self._card(self.main)
        outer.pack(fill="x")
        body = tk.Frame(card, bg=CARD, padx=26, pady=22)
        body.pack(fill="x")
        tk.Label(body, text=self.t("what").upper(), bg=CARD, fg=ACCENT, font=(UIF, 9, "bold")).pack(anchor="w")
        grid = tk.Frame(body, bg=CARD)
        grid.pack(fill="x", pady=(12, 4))
        for i, txt in enumerate(self.t("items")):
            cell = tk.Frame(grid, bg=CARD)
            cell.grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 40), pady=4)
            tk.Label(cell, text="◆", bg=CARD, fg=ACCENT, font=(UIF, 8)).pack(side="left")
            tk.Label(cell, text=txt, bg=CARD, fg=FG, font=(UIF, 10)).pack(side="left", padx=8)
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        tk.Label(body, text=self.t("privacy"), bg=CARD, fg=GOOD, font=(UIF, 9),
                 wraplength=720, justify="left").pack(anchor="w", pady=(12, 0))

        outer2, card2 = self._card(self.main)
        outer2.pack(fill="x", pady=(16, 0))
        body2 = tk.Frame(card2, bg=CARD, padx=26, pady=22)
        body2.pack(fill="x")
        row = tk.Frame(body2, bg=CARD)
        row.pack(fill="x")
        row.columnconfigure(0, weight=1)
        row.columnconfigure(1, weight=1)
        f1 = Field(row, self.t("pin").upper(), self.pin, self.t("pin_ph"))
        f1.grid(row=0, column=0, sticky="ew", padx=(0, 14))
        f2 = Field(row, self.t("player").upper(), self.player, self.t("player_ph"))
        f2.grid(row=0, column=1, sticky="ew")
        f1.entry.focus_set()

        crow = tk.Frame(body2, bg=CARD)
        crow.pack(fill="x", pady=(22, 0))
        Switch(crow, self.consent, self._update_start).pack(side="left")
        tk.Label(crow, text=self.t("consent"), bg=CARD, fg=FG, font=(UIF, 10), wraplength=640,
                 justify="left").pack(side="left", padx=14)

        self.start_btn = Btn(body2, self.t("start"), self._start_scan, width=200, height=44, bg=CARD)
        self.start_btn.pack(anchor="e", pady=(20, 0))
        self._update_start()

    def _update_start(self):
        ok = bool(self.consent.get()) and self.pin.get().strip() != ""
        try:
            self.start_btn.set_enabled(ok)
        except (tk.TclError, AttributeError):
            pass

    # ---------------------------------------------------------- ecran 2
    def _start_scan(self):
        if not (self.consent.get() and self.pin.get().strip()):
            return
        self.screen = "scan"
        self.step_names, self.progress_pct = [], 0
        self.render()
        pin, player = self.pin.get().strip(), self.player.get().strip() or "inconnu"
        threading.Thread(target=self._worker, args=(pin, player), daemon=True).start()

    def _worker(self, pin, player):
        try:
            rep = gc.run_scan(pin, player, log=lambda m: self.q.put(("log", m)),
                              progress=lambda d, t: self.q.put(("progress", d, t)))
            path = gc.save_report(rep)
            self.q.put(("done", rep, str(path)))
        except Exception:
            self.q.put(("error", traceback.format_exc()))

    def _screen_scan(self):
        self._page_head(self.t("h_scan"), self.t("s_scan"))
        wrap = tk.Frame(self.main, bg=BG)
        wrap.pack(fill="both", expand=True)

        o1, left = self._card(wrap)
        o1.pack(side="left", fill="y", padx=(0, 16))
        inner = tk.Frame(left, bg=CARD, padx=34, pady=30)
        inner.pack(fill="both", expand=True)
        self.ring = Ring(inner, 210)
        self.ring.pack()
        self.ring.set(self.progress_pct)
        tk.Label(inner, text=self.t("current").upper(), bg=CARD, fg=MUTED, font=(UIF, 8, "bold")).pack(pady=(22, 2))
        self.cur_label = tk.Label(inner, text="…", bg=CARD, fg=ACCENT, font=(UIF, 11, "bold"), wraplength=210)
        self.cur_label.pack()

        o2, right = self._card(wrap)
        o2.pack(side="left", fill="both", expand=True)
        rin = tk.Frame(right, bg=CARD, padx=26, pady=24)
        rin.pack(fill="both", expand=True)
        tk.Label(rin, text=self.t("done_steps").upper(), bg=CARD, fg=ACCENT, font=(UIF, 9, "bold")).pack(anchor="w")
        self.steps_box = tk.Frame(rin, bg=CARD)
        self.steps_box.pack(fill="both", expand=True, anchor="n", pady=(10, 0))
        self._refresh_steps()

    def _refresh_steps(self):
        try:
            for wdg in self.steps_box.winfo_children():
                wdg.destroy()
            for i, name in enumerate(self.step_names):
                last = i == len(self.step_names) - 1
                row = tk.Frame(self.steps_box, bg=CARD)
                row.pack(fill="x", pady=4)
                tk.Label(row, text="●" if last else "✓", bg=CARD, fg=ACCENT if last else GOOD,
                         font=(UIF, 10, "bold")).pack(side="left")
                tk.Label(row, text=name, bg=CARD, fg=FG if last else MUTED,
                         font=(UIF, 10, "bold" if last else "normal")).pack(side="left", padx=10)
            if self.step_names:
                self.cur_label.configure(text=self.step_names[-1])
        except (tk.TclError, AttributeError):
            pass

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "log":
                    line = msg[1].strip()
                    if line.startswith("[*]"):
                        name = line[3:].strip().rstrip(".").strip()
                        self.step_names.append(name[:70])
                        if self.screen == "scan":
                            self._refresh_steps()
                elif kind == "progress":
                    self.progress_pct = 100 * msg[1] / max(msg[2], 1)
                    if self.ring is not None and self.screen == "scan":
                        self.ring.set(self.progress_pct)
                elif kind == "done":
                    self.report, self.report_path = msg[1], msg[2]
                    self.tab, self.level = "find", "all"
                    self.search.set("")
                    self.screen = "result"
                    self.render()
                elif kind == "error":
                    self.screen = "form"
                    self.render()
                    messagebox.showerror(self.t("t_err"), f"{self.t('err')}\n\n{msg[1][-900:]}")
        except queue.Empty:
            pass
        self.after(100, self._poll)

    # ---------------------------------------------------------- ecran 3
    def _kpi(self, parent, value, label, color=FG):
        outer, card = self._card(parent)
        inner = tk.Frame(card, bg=CARD, padx=18, pady=12)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=str(value), bg=CARD, fg=color, font=(UIF, 20, "bold")).pack(anchor="w")
        tk.Label(inner, text=label, bg=CARD, fg=MUTED, font=(UIF, 9)).pack(anchor="w")
        return outer

    def _screen_result(self):
        r = self.report
        inv = r["inventory"]
        score = r["risk_score"]
        col = score_color(score)
        self._page_head(self.t("h_res"), f"PIN {r['pin']}  •  {r['player']}  •  {r['date']}")

        outer, card = self._card(self.main)
        outer.pack(fill="x")
        top = tk.Frame(card, bg=CARD, padx=24, pady=16)
        top.pack(fill="x")
        gauge = Gauge(top, 170)
        gauge.pack(side="left")
        gauge.show(score)
        mid = tk.Frame(top, bg=CARD)
        mid.pack(side="left", fill="x", expand=True, padx=(26, 0))
        tk.Label(mid, text=self.t("score").upper(), bg=CARD, fg=MUTED, font=(UIF, 8, "bold")).pack(anchor="w")
        tk.Label(mid, text=r["verdict"], bg=CARD, fg=col, font=(UIF, 18, "bold"), wraplength=420,
                 justify="left").pack(anchor="w", pady=(2, 6))
        tk.Label(mid, text=self.t("disclaimer"), bg=CARD, fg=MUTED, font=(UIF, 9), wraplength=420,
                 justify="left").pack(anchor="w")
        tk.Label(mid, text=f"{self.t('saved')} : {self.report_path}", bg=CARD, fg="#5b6a88", font=(UIF, 8),
                 wraplength=420, justify="left").pack(anchor="w", pady=(8, 0))
        kp = tk.Frame(top, bg=CARD)
        kp.pack(side="right")
        for i, (v, lab, c) in enumerate(((len(r["findings"]), self.t("k_det"), col),
                                         (len(inv["scripts"]), self.t("k_scr"), FG),
                                         (len(inv["recent_executables"]), self.t("k_exe"), FG),
                                         (len(inv["python_environments"]), self.t("k_env"), FG))):
            self._kpi(kp, v, lab, c).grid(row=i // 2, column=i % 2, padx=4, pady=4, sticky="ew")

        # onglets
        self.tabs_bar = tk.Frame(self.main, bg=BG)
        self.tabs_bar.pack(fill="x", pady=(16, 0))
        self.tab_parts = {}
        items = [("find", self.t("tab_find"), len(r["findings"])),
                 ("scripts", self.t("tab_scr"), len(inv["scripts"])),
                 ("exes", self.t("tab_exe"), len(inv["recent_executables"])),
                 ("envs", self.t("tab_env"), len(inv["python_environments"]))]
        if r["notes"]:
            items.append(("notes", self.t("tab_notes"), len(r["notes"])))
        for key, label, n in items:
            cell = tk.Frame(self.tabs_bar, bg=BG)
            cell.pack(side="left", padx=(0, 6))
            lab = tk.Label(cell, text=f"{label}  {n}", bg=BG, fg=MUTED, font=(UIF, 10, "bold"),
                           padx=12, pady=8, cursor="hand2")
            lab.pack()
            line = tk.Frame(cell, bg=BG, height=2)
            line.pack(fill="x")
            lab.bind("<Button-1>", lambda e, k=key: self._select_tab(k))
            self.tab_parts[key] = (lab, line)
        self.body = tk.Frame(self.main, bg=BG)
        self.body.pack(fill="both", expand=True, pady=(6, 0))

        # actions
        bar = tk.Frame(self.main, bg=BG)
        bar.pack(fill="x", pady=(12, 0))
        Btn(bar, self.t("new"), self._new_scan, kind="secondary", width=130, height=38).pack(side="left")
        Btn(bar, self.t("open"), self._open_folder, kind="secondary", width=150, height=38).pack(side="left", padx=8)
        Btn(bar, self.t("html"), self._export_html, kind="secondary", width=130, height=38).pack(side="left")
        Btn(bar, self.t("copy"), self._copy_summary, kind="secondary", width=150, height=38).pack(side="left", padx=8)
        if os.environ.get("GAMECHECK_WEBHOOK", "").strip():
            Btn(bar, self.t("send"), self._send, kind="primary", width=160, height=38).pack(side="right")

        self._select_tab(self.tab if self.tab in self.tab_parts else "find")

    def _select_tab(self, key):
        self.tab = key
        for k, (lab, line) in self.tab_parts.items():
            lab.configure(fg=FG if k == key else MUTED)
            line.configure(bg=ACCENT if k == key else BG)
        for wdg in self.body.winfo_children():
            wdg.destroy()
        inv = self.report["inventory"]
        if key == "find":
            self._tab_findings()
        elif key == "scripts":
            self._table(self.body, [("path", self.t("c_path"), 640, "w"), ("size", self.t("c_size"), 90, "e"),
                                    ("mod", self.t("c_mod"), 160, "w")],
                        [(s["path"], human_size(s["size"]), s["modified"]) for s in inv["scripts"]])
        elif key == "exes":
            self._table(self.body, [("path", self.t("c_path"), 480, "w"), ("sha", self.t("c_sha"), 260, "w"),
                                    ("mod", self.t("c_mod"), 150, "w")],
                        [(e["path"], e["sha256"] or "-", e["modified"]) for e in inv["recent_executables"]])
        elif key == "envs":
            self._table(self.body, [("path", self.t("c_path"), 430, "w"), ("w", self.t("c_w"), 70, "center"),
                                    ("libs", self.t("c_libs"), 380, "w")],
                        [(e["path"], e["weight"], ", ".join(e["libs"])) for e in inv["python_environments"]])
        elif key == "notes":
            self._table(self.body, [("n", self.t("tab_notes"), 900, "w")], [(n,) for n in self.report["notes"]])

    def _table(self, parent, cols, rows):
        wrap = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(fill="both", expand=True)
        if not rows:
            tk.Label(wrap, text=self.t("empty"), bg=CARD, fg=MUTED, font=(UIF, 10)).pack(pady=40)
            return None
        tree = ttk.Treeview(wrap, style="Pro.Treeview", columns=[c[0] for c in cols], show="headings")
        for cid, title, wd, anc in cols:
            tree.heading(cid, text=title, anchor="w")
            tree.column(cid, width=wd, anchor=anc, stretch=(cid == cols[0][0]))
        sbar = ttk.Scrollbar(wrap, command=tree.yview)
        tree.configure(yscrollcommand=sbar.set)
        sbar.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for row in rows:
            tree.insert("", "end", values=row)
        return tree

    # ---- onglet Detections
    def _tab_findings(self):
        tools = tk.Frame(self.body, bg=BG)
        tools.pack(fill="x", pady=(2, 8))
        sbox = tk.Frame(tools, bg=BORDER, padx=1, pady=1)
        sbox.pack(side="left")
        ent = tk.Entry(sbox, textvariable=self.search, bg=FIELD, fg=FG, insertbackground=FG, relief="flat",
                       bd=0, width=34, font=(UIF, 10))
        ent.pack(ipady=7, ipadx=8)
        ent.bind("<FocusIn>", lambda e: sbox.configure(bg=ACCENT))
        ent.bind("<FocusOut>", lambda e: sbox.configure(bg=BORDER))
        self.chips = {}
        for key, label in (("all", self.t("all")), ("high", self.t("sev_high")),
                           ("mid", self.t("sev_mid")), ("low", self.t("sev_low"))):
            chip = tk.Label(tools, text=label, bg=CARD2, fg=MUTED, font=(UIF, 9, "bold"), padx=14, pady=7,
                            cursor="hand2")
            chip.pack(side="left", padx=(8, 0))
            chip.bind("<Button-1>", lambda e, k=key: self._set_level(k))
            self.chips[key] = chip
        self.count_lbl = tk.Label(tools, text="", bg=BG, fg=MUTED, font=(UIF, 9))
        self.count_lbl.pack(side="right")

        split = tk.Frame(self.body, bg=BG)
        split.pack(fill="both", expand=True)
        wrap = tk.Frame(split, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(side="left", fill="both", expand=True)
        cols = [("sev", self.t("c_sev"), 80, "w"), ("w", self.t("c_w"), 56, "center"),
                ("cat", self.t("c_cat"), 140, "w"), ("type", self.t("c_type"), 110, "w"),
                ("item", self.t("c_item"), 380, "w")]
        self.tree = ttk.Treeview(wrap, style="Pro.Treeview", columns=[c[0] for c in cols], show="headings",
                                 selectmode="browse")
        for cid, title, wd, anc in cols:
            self.tree.heading(cid, text=title, anchor="w")
            self.tree.column(cid, width=wd, anchor=anc, stretch=(cid == "item"))
        for s, c in SEV_COL.items():
            self.tree.tag_configure(s, foreground=c)
        sbar = ttk.Scrollbar(wrap, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sbar.set)
        sbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        side = tk.Frame(split, bg=CARD, highlightbackground=BORDER, highlightthickness=1, width=330)
        side.pack(side="left", fill="y", padx=(12, 0))
        side.pack_propagate(False)
        tk.Label(side, text=self.t("details").upper(), bg=CARD, fg=ACCENT, font=(UIF, 9, "bold")).pack(
            anchor="w", padx=16, pady=(14, 6))
        self.detail = tk.Text(side, bg=CARD, fg=FG, relief="flat", bd=0, wrap="word", font=(UIF, 10),
                              padx=16, pady=4, highlightthickness=0, state="disabled", cursor="arrow")
        self.detail.pack(fill="both", expand=True)
        self.detail.tag_configure("k", foreground=MUTED, font=(UIF, 8, "bold"), spacing1=10)
        self.detail.tag_configure("v", foreground=FG, font=("Consolas", 10))
        for s, c in SEV_COL.items():
            self.detail.tag_configure("sev_" + s, foreground=c, font=(UIF, 10, "bold"))
        self._set_level(self.level)

    def _set_level(self, level):
        self.level = level
        for k, chip in self.chips.items():
            on = k == level
            chip.configure(bg=ACCENT if on else CARD2, fg="#04201c" if on else MUTED)
        self._fill_findings()

    def _fill_findings(self):
        if self.report is None or self.tab != "find" or not hasattr(self, "tree"):
            return
        try:
            q = self.search.get().strip().lower()
            self.tree.delete(*self.tree.get_children())
            shown = 0
            for i, f in enumerate(self.report["findings"]):
                s = sev(f["weight"])
                if self.level != "all" and s != self.level:
                    continue
                hay = f"{f['item']} {f['category']} {f['type']} {f['keyword']}".lower()
                if q and q not in hay:
                    continue
                self.tree.insert("", "end", iid=str(i), tags=(s,),
                                 values=(self.t("sev_" + s).upper(), f["weight"], f["category"], f["type"], f["item"]))
                shown += 1
            self.count_lbl.configure(text=f"{shown} / {len(self.report['findings'])}")
            self._write_detail(None)
        except tk.TclError:
            pass

    def _on_select(self, _e):
        sel = self.tree.selection()
        if sel:
            self._write_detail(self.report["findings"][int(sel[0])])

    def _write_detail(self, f):
        d = self.detail
        d.configure(state="normal")
        d.delete("1.0", "end")
        if f is None:
            msg = self.t("none") if not self.report["findings"] else self.t("pick")
            d.insert("end", "\n" + msg, "k")
        else:
            s = sev(f["weight"])
            d.insert("end", f"{self.t('sev_' + s).upper()}  •  {f['weight']}\n", "sev_" + s)
            d.insert("end", f"{self.t('path').upper()}\n", "k")
            d.insert("end", f"{f['item']}\n", "v")
            d.insert("end", f"{self.t('cat').upper()}\n", "k")
            d.insert("end", f"{f['category']}\n", "v")
            d.insert("end", f"{self.t('type').upper()}\n", "k")
            d.insert("end", f"{f['type']}\n", "v")
            d.insert("end", f"{self.t('kw').upper()}\n", "k")
            d.insert("end", f"{f['keyword']}\n", "v")
            for key, val in f.items():
                if key in ("type", "item", "keyword", "category", "weight"):
                    continue
                d.insert("end", f"{key.upper()}\n", "k")
                txt = "\n".join(f"- {x}" for x in val) if isinstance(val, list) else str(val)
                d.insert("end", txt + "\n", "v")
        d.configure(state="disabled")

    # ---------------------------------------------------------- actions
    def _new_scan(self):
        self.screen = "form"
        self.consent.set(False)
        self.report = None
        self.render()

    def _open_folder(self):
        folder = os.path.dirname(self.report_path)
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # noqa
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception:
            pass

    def _export_html(self):
        try:
            path = os.path.splitext(self.report_path)[0] + ".html"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(build_html(self.report, STR[self.lang]))
            webbrowser.open("file:///" + path.replace("\\", "/"))
        except Exception as e:
            messagebox.showerror(self.t("t_err"), str(e))

    def _summary_text(self):
        r = self.report
        lines = [f"GameCheck - PIN {r['pin']} - {r['player']}",
                 f"{self.t('score')}: {r['risk_score']}/100 - {r['verdict']}",
                 f"{self.t('k_det')}: {len(r['findings'])}"]
        for f in r["findings"][:5]:
            lines.append(f"- [{f['category']}] {f['item'][:90]}")
        return "\n".join(lines)

    def _copy_summary(self):
        self.clipboard_clear()
        self.clipboard_append(self._summary_text())
        messagebox.showinfo(self.t("t_info"), self.t("copied"))

    def _send(self):
        if not messagebox.askyesno(self.t("t_send"), self.t("send_confirm")):
            return
        try:
            gc.send_webhook(os.environ.get("GAMECHECK_WEBHOOK", "").strip(), self.report)
            messagebox.showinfo(self.t("t_send"), self.t("sent"))
        except Exception as e:
            messagebox.showerror(self.t("t_err"), f"{self.t('send_fail')} {e}")


if __name__ == "__main__":
    if "--console" in sys.argv:
        main()
        sys.exit(0)
    try:
        try:  # texte net sur ecrans haute resolution
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        App().mainloop()
    except Exception:
        err = traceback.format_exc()
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "gamecheck_error.log"),
                      "w", encoding="utf-8") as fh:
                fh.write(err)
        except OSError:
            pass
        raise
