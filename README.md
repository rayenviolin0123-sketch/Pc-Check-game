Introduction

GameCheck is an on-demand forensic scanner for the staff of online game servers. When a player is suspected of cheating, a moderator gives them a PIN. The player starts GameCheck, explicitly agrees to the scan, enters the PIN, and within about a minute a report is produced: a risk score from 0 to 100, the list of findings, and an inventory of scripts, recent executables, Python environments and DMA / PCIe hardware checks. The moderator then reviews it and decides – a human always makes the final call.

It is built for communities running FiveM, Minecraft, Rust, Call of Duty, GTA:SA, RageMP, Roblox and similar games, where classic "screenshare" checks are slow and inconsistent.

About
	
What it is	A consent-based, user-run forensic scan with a modern desktop interface
What it is not	A real-time anti-cheat, a kernel driver, or proof of guilt
Hardware cheats	Looks for DMA (Direct Memory Access) cards: FPGA devices on PCIe / USB used with a second PC
Who it is for	Server admins, moderators and competitive league staff
Platform	Windows 10 / 11 (console mode also starts on other systems with reduced checks)
Language	Python 3.8+ · tkinter · single dependency (psutil, optional)
Interface	Graphical (French / English) and console
License	MIT
DMA scan

DMA cheats read the game's memory through a PCIe/FPGA card connected to a second computer, so nothing suspicious runs on the player's PC. GameCheck therefore checks the hardware layer:

FPGA vendors rarely found in gaming PCs (Xilinx/AMD, Altera/Intel, Lattice) and PCIe devices that expose a raw memory / data-acquisition controller with no driver
the FTDI FT600/FT601 USB3 bridges typical of PCILeech-style setups
leftovers of DMA tooling and firmware (PCILeech, LeechCore, MemProcFS, radar tools, Vivado…)
memory-protection status: Kernel DMA Protection / IOMMU, VBS, HVCI, Secure Boot (informational)

A DMA card with spoofed identifiers can evade software checks on the same PC. Treat this scan as one signal among others.

Principles
Consent first – nothing runs until the player accepts, and nothing leaves the PC without a second confirmation.
Privacy – no screenshots; file contents are analysed locally and never uploaded; only a short summary can be sent, and only if the player agrees.
Transparency – the interface lists exactly what is analysed; the report shows why each item was flagged.
Humility – the score is an indicator, not a verdict. False positives are expected and documented.
Features
<p align="center"> <img src="docs/images/features.png" alt="What GameCheck analyses" width="100%"> </p>
Processes & DLLs – running processes, loaded modules, and active .py / .ahk / .lua scripts.
Scripts – .lua, .ahk and .py contents are scanned locally for colorbot / triggerbot / recoil macros (PixelSearch + click, G HUB MoveMouseRelative, …).
Python "AI aimbot" stack – reads site-packages, requirements.txt and imports, and scores the combination of screen capture (bettercam, mss…), inference (onnxruntime, ultralytics, supervision…) and input / hardware libraries (pynput, pyserial, hid, pyusb…). Common libraries such as numpy or requests carry no weight.
Windows traces – Prefetch, UserAssist, AppCompat, BAM, Recycle Bin (including deleted .lua / .ahk), recent files.
DMA & PCIe hardware – FPGA / DMA card signatures (PCIe and USB), DMA tooling traces, IOMMU / VBS / HVCI / Secure Boot status.
Hardware & drivers – USB history (Arduino, Teensy, Pico, CH340…), vulnerable drivers used by cheat loaders.
System integrity – test-signing mode, Defender exclusions, cleared event logs, emptied Prefetch.
Readable reports – filters and search, severity levels, per-item details, HTML and JSON export, copy-to-clipboard summary, optional Discord webhook.
Screenshots

Design previews rendered from the real layout with demo data. Replace them with actual screenshots of your build when you publish.

1 · Consent	2 · Scan	3 · Results
<img src="docs/images/ui-form.png" width="100%">	<img src="docs/images/ui-scan.png" width="100%">	<img src="docs/images/ui-results.png" width="100%">
How it works
no
yes
yes
no
Moderator creates a PIN
Player runs GameCheck
Player consents?
Nothing is scanned
Local scan · about 1 minfiles · scripts · Windowstraces · DMA / PCIe
Risk score + findings +inventory
Report saved on the PC ·JSON / HTML
Player agrees to send?
Summary to staff Discord
Player hands the file overmanually
Human review and decision
Quick start

Download GameCheck.exe from the Releases page, run it as administrator, accept the scan, enter the PIN and your in-game name. Verify the download with the published .sha256 file.

From source (Windows, Python 3.8+):

bash
pip install -r requirements.txt
python gamecheck_gui.py      # graphical interface (FR / EN)
python gamecheck.py          # console version

Run as administrator for a complete scan (Prefetch, BAM, boot configuration and event logs need it).

Build the exe
bash
pip install -r requirements-dev.txt
python -m PyInstaller --clean --onefile --noconsole --noupx --uac-admin --icon assets/gamecheck.ico --add-data "assets;assets" --name GameCheck gamecheck_gui.py

Or push a tag – GitHub Actions builds and publishes the exe for you:

bash
git tag v1.0.0 && git push origin v1.0.0
Configuration
Setting	Purpose
signatures.json (next to the exe)	Add your own keywords and known SHA256 hashes. See signatures.example.json.
GAMECHECK_WEBHOOK	Discord webhook URL for the optional summary. Never commit it.
GAMECHECK_TIMEOUT	Maximum disk-scan time in seconds (default 120).
Limitations
Keyword-based: a renamed cheat can be missed, and a harmless file can match. Always review manually.
Developers who legitimately use libraries like onnxruntime or pynput will be flagged – context matters.
Not a real-time anti-cheat: no kernel driver, no deep memory analysis.
DMA detection is heuristic: spoofed PCIe identifiers or firmware that mimics a normal device can pass undetected.
PyInstaller executables are sometimes flagged by antivirus software; publish the SHA256 hash and consider code signing.
Responsible use

GameCheck must only be run with the informed consent of the person being checked. Do not use it to scan machines you do not own or administer, and do not publish players' reports. Check the privacy rules that apply to your community and country.

License

MIT

<a id="fr-français"></a>

<details> <summary><b>🇫🇷 Français</b></summary>
Introduction

GameCheck est un scanner forensic à la demande pour les staffs de serveurs de jeu. Quand un joueur est soupçonné de triche, un modérateur lui donne un PIN. Le joueur lance GameCheck, accepte explicitement l'analyse, saisit le PIN, et en environ une minute un rapport est généré : un score de risque de 0 à 100, la liste des détections et un inventaire des scripts, exécutables récents, environnements Python et contrôles du matériel DMA / PCIe. Le modérateur relit ensuite le rapport et décide – c'est toujours un humain qui tranche.

À propos
Consentement d'abord : rien ne s'exécute sans l'accord du joueur, et rien ne quitte le PC sans seconde confirmation.
Vie privée : aucune capture d'écran ; le contenu des fichiers est analysé en local, jamais envoyé.
Transparence : l'interface liste précisément ce qui est analysé, et le rapport explique chaque détection.
Humilité : le score est un indice, pas une preuve. Les faux positifs sont possibles.
Scan DMA

Les cheats DMA lisent la mémoire du jeu via une carte PCIe/FPGA reliée à un second PC : rien de suspect ne tourne sur le PC du joueur. GameCheck contrôle donc la couche matérielle : fabricants FPGA rares sur un PC de jeu (Xilinx/AMD, Altera/Intel, Lattice), périphériques PCIe « contrôleur mémoire » sans pilote, ponts USB3 FTDI FT600/FT601 typiques de PCILeech, traces d'outils DMA (PCILeech, LeechCore, MemProcFS…) et état des protections mémoire (IOMMU / Kernel DMA Protection, VBS, HVCI, Secure Boot). Une carte DMA aux identifiants usurpés peut passer inaperçue : c'est un signal parmi d'autres.

Ce qui est analysé

Processus et DLL · scripts .lua .ahk .py (contenu lu en local) · pile de bibliothèques Python « aimbot IA » · traces Windows (Prefetch, UserAssist, AppCompat, BAM) · corbeille · historique USB (Arduino, Teensy, Pico…) · cartes DMA / PCIe · pilotes vulnérables · intégrité du système (mode test, exclusions Defender, journaux effacés).

Utilisation

Télécharger GameCheck.exe depuis les Releases, le lancer en administrateur, accepter l'analyse, saisir le PIN et le pseudo. Depuis les sources : pip install -r requirements.txt puis python gamecheck_gui.py.

Utilisation responsable

N'utilisez GameCheck qu'avec le consentement éclairé de la personne contrôlée, et uniquement sur un PC qu'elle vous autorise à vérifier.
