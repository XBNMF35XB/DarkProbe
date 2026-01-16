#!/home/<user>/venv/bin/python3


# --------------- IMPORTS --------------- #


import os
import sys
import time
import random
import platform
import subprocess
import socket
import psutil
import pywifi
import threading
import readline
import wifi
import struct
import fcntl
import re
import json
import datetime
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
import ssl
import hashlib
import base64
import binascii
import itertools
import signal

# Optional Scapy for ARP Scan (needs sudo) #

try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    conf = None


# --------------- COLORS --------------- #

ICE     = "\033[97m"
PINK    = "\033[95m"
RED     = "\033[38m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[34m"
ORANGE  = "\033[38;5;214m"
RESET   = "\033[0m"
BOLD    = "\033[1m"



# --------------- GLOBAL SETTINGS --------------- #

SILENT_MODE = False
FATAL_ERROR = False
ERROR = False
WARNING = False
ENERGY_SAVER = False


# --------------- VISUAL UTILITIES --------------- #

def wt(text, d=0.02, color=BLUE, bp=True):
    global ENERGY_SAVER, SILENT_MODE
    # Adjust delay based on SILENT_MODE and ENERGY_SAVER
    delay = (d * 3 if SILENT_MODE else d) if not ENERGY_SAVER else 2.05
    
    for c in text:
        sys.stdout.write(color + c + RESET)
        sys.stdout.flush()
        if bp:
            sys.stdout.write("\a")
        time.sleep(delay)
    print()

def detect_energy_saver():
    global ENERGY_SAVER
    try:
        if platform.system() == "Linux":
            with open("/sys/class/power_supply/AC/online") as f:
                status = f.read().strip()
                ENERGY_SAVER = (status == "0")
        elif platform.system() == "Windows":
            import ctypes
            SYSTEM_POWER_STATUS = ctypes.Structure
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("Reserved1", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_ulong),
                    ("BatteryFullLifeTime", ctypes.c_ulong),
                ]
            status = SYSTEM_POWER_STATUS()
            ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status))
            ENERGY_SAVER = (status.ACLineStatus == 0)
        else:
            ENERGY_SAVER = False
    except Exception:
        ENERGY_SAVER = False

    # Only print the message if not in SILENT_MODE
    if ENERGY_SAVER:
        if platform.system() == "Windows" or platform.system() == "macOS":
            message = f"{YELLOW}[!] Energy Saver mode detected. Operations will be slower to conserve battery.{RESET}\n"
            if not SILENT_MODE:
                print(message)
            logging.warning(message)  # Log this to file if needed

def fatal_error(text):
    global FATAL_ERROR
    FATAL_ERROR = True
    wt(f"\n{RED}[FATAL ERROR]{RESET} {text}\n", color=RED)
    logging.error(f"[FATAL ERROR] {text}")  # Log the error to a file
    sys.exit(1)

def detect_scapy():
    try:
        from scapy.all import conf
        if conf is None:
            raise ImportError
    except ImportError:
        wt("\n[!] Scapy library not found. ARP Scan module will be disabled.\n", color=YELLOW)
        logging.warning("[!] Scapy library not found. ARP Scan module will be disabled.")

def step_loading(label, size=26, speed=0.02):
    global SILENT_MODE
    speed = speed * 3 if SILENT_MODE else speed 
    label = label.strip()
    for i in range(size + 1):
        filled = "#" * i
        empty = "-" * (size - i)
        pct = int((i / size) * 100)

        # Ensure the progress bar reaches 100% even if there are small rounding errors
        if i == size:
            pct = 100

        if pct == 100:
            sys.stdout.write(
                f"\r{ORANGE}[LOADING]{RESET} {label:<32} "
                f"{ORANGE}[{filled}{empty}] {pct:3d}% {GREEN}[OK]{RESET}"
            )
        else:
            sys.stdout.write(
                f"\r{ORANGE}[LOADING]{RESET} {label:<32} "
                f"{ORANGE}[{filled}{empty}] {pct:3d}%{RESET}"
            )

        sys.stdout.flush()
        time.sleep(speed)
    print()

# --------------- INTRO --------------- #


def intro():
    wt("BOOTING MODULE...", bp=True)
    time.sleep(0.4)

    steps = [
        "Loading core systems",
        "Syncing network interfaces",
        "Initializing hardware scanners",
        "Deploying software signatures",
        "Calibrating detection algorithms",
        "Establishing secure channels",
        "Activating firewall bypass",
        "Finalizing system checks",
    ]

    for s in steps:
        step_loading(s)

    wt(f"\n{BOLD}SYSTEM CORE ONLINE{RESET}\n")

    # Ask to activate Silent Mode
    global SILENT_MODE
    print(f"{BLUE}Activate Silent Mode? (y/n): {RESET}", end="")
    choice = input().strip().lower()
    SILENT_MODE = True if choice == "y" else False
    if SILENT_MODE:
        print(f"{BLUE}\n[!] Silent Mode activated. Operations will be slower to avoid detection.\n")
    else:
        print(f"{BLUE}\n[!] Silent Mode not activated. Running normally. \n")


# --------------- LOCAL OS DETECTION --------------- #


def detect_linux():
    try:
        data = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')

        if "PRETTY_NAME" in data:
            return data["PRETTY_NAME"]
        if "NAME" in data:
            return data["NAME"]

        did = data.get("ID", "").lower()

        known = {
            "arch": "Arch Linux",
            "manjaro": "Manjaro",
            "endeavouros": "EndeavourOS",
            "artix": "Artix Linux",
            "void": "Void Linux",
            "gentoo": "Gentoo Linux",
            "nixos": "NixOS",
            "slackware": "Slackware Linux",
            "alpine": "Alpine Linux",
            "popos": "Pop!_OS",
            "linuxmint": "Linux Mint",
            "garuda": "Garuda Linux",
            "archbang": "ArchBang",
            "chakra": "Chakra Linux",
            "blackarch": "BlackArch",
            "archlabs": "ArchLabs",
            "cachyos": "CachyOS",
            "archmerge": "ArchMerge",
            "archman": "Archman",
            "archbuntu": "ArchBuntu",
            "anarchy": "Anarchy Linux",
            "finnix": "Finnix",
            "osmc": "OSMC",
            "refracta": "Refracta",
            "arch-dev": "Arch Dev",
            "arch-gui": "Arch with GUI",
            "arch-lite": "Arch Lite",
            "arch-secure": "Arch Secure",
            "arch-gnome": "Arch GNOME",
            "arch-kde": "Arch KDE",
            "arch-xfce": "Arch XFCE",
            "debian": "Debian",
            "ubuntu": "Ubuntu",
            "linuxmint": "Linux Mint",
            "pop": "Pop!_OS",
            "kali": "Kali Linux",
            "parrot": "Parrot OS",
            "elementary": "elementary OS",
            "zorin": "Zorin OS",
            "mx": "MX Linux",
            "siduction": "Siduction",
            "antiX": "antiX",
            "deepin": "Deepin",
            "bunsenlabs": "BunsenLabs Linux",
            "peppermint": "Peppermint OS",
            "ubuntu-mate": "Ubuntu MATE",
            "ubuntu-budgie": "Ubuntu Budgie",
            "ubuntu-studio": "Ubuntu Studio",
            "lubuntu": "Lubuntu",
            "xubuntu": "Xubuntu",
            "ubuntu-server": "Ubuntu Server",
            "ubuntu-core": "Ubuntu Core",
            "ubuntu-touch": "Ubuntu Touch",
            "solus": "Solus",
            "q4os": "Q4OS",
            "devuan": "Devuan",
            "pureos": "PureOS",
            "bunsenlabs": "BunsenLabs",
            "backbox": "BackBox",
            "bodhi": "Bodhi Linux",
            "crunchbangplusplus": "CrunchBang++",
            "guix": "Guix System",
            "kubuntu": "Kubuntu",
            "lubuntu": "Lubuntu",
            "xubuntu": "Xubuntu",
            "peppermint": "Peppermint",
            "fedora": "Fedora",
            "rhel": "Red Hat Enterprise Linux",
            "centos": "CentOS",
            "rocky": "Rocky Linux",
            "almalinux": "AlmaLinux",
            "scientific": "Scientific Linux",
            "clearos": "ClearOS",
            "oracle-linux": "Oracle Linux",
            "zoran": "Zoran",
            "redhat": "Red Hat",
            "opensuse": "openSUSE",
            "sles": "SUSE Linux Enterprise",
            "sle": "SUSE Linux Enterprise Desktop",
            "opensuse-tumbleweed": "openSUSE Tumbleweed",
            "opensuse-leap": "openSUSE Leap",
            "suse": "SUSE Linux",
            "alpine": "Alpine Linux",
            "void": "Void Linux",
            "gentoo": "Gentoo",
            "nixos": "NixOS",
            "slackware": "Slackware",
            "crux": "CRUX",
            "salix": "Salix OS",
            "artix": "Artix Linux",
            "devuan": "Devuan",
            "manjaro-architect": "Manjaro Architect",
            "tinycore": "Tiny Core Linux",
            "puppy": "Puppy Linux",
            "slimjet": "SlimJet",
            "knoppix": "Knoppix",
            "kanotix": "Kanotix",
            "antix": "antiX",
            "sabayon": "Sabayon Linux",
            "parrotsec": "Parrot Security",
            "crunchbangplusplus": "CrunchBang++",
            "bedrock": "Bedrock Linux",
            "raspios": "Raspberry Pi OS",
            "raspbian": "Raspberry Pi OS",
            "postmarketos": "postmarketOS",
            "steam": "SteamOS",
            "clear-linux-os": "Clear Linux",
            "dietpi": "DietPi",
            "openwrt": "OpenWrt",
            "opnsense": "OPNsense",
            "tailos": "Tails",
            "alpine-pine": "Alpine Pine",
            "volumio": "Volumio",
            "coreos": "CoreOS",
            "openhabian": "openHABian",
            "funtoo": "Funtoo",
            "android-x86": "Android-x86",
            "webos": "webOS",
            "linux4one": "Linux4One",
            "plasma-mobile": "Plasma Mobile",
            "retroarch": "RetroArch",
            "batocera": "Batocera",
            "recalbox": "RecalBox",
            "lakka": "Lakka",
            "retropie": "RetroPie",
            "arcadeos": "ArcadeOS",
            "gamingonlinux": "Gaming on Linux",
            "xbox-live": "Xbox Live",
            "steamdeck": "Steam Deck",
            "playonlinux": "PlayOnLinux",
            "penguinplay": "Penguin Play",
            "ubuntu-gamepack": "Ubuntu GamePack",
            "gamestar": "GameStar OS",
            "nitrux-gaming": "Nitrux Gaming",
            "pop-os-gaming": "Pop!_OS Gaming",
            "steamOS": "SteamOS",
            "gamebuntu": "GameBuntu",
            "gameros": "GamerOS",
            "lax": "LaxOS",
            "linux-gaming": "Linux Gaming",
            "gamescope": "Gamescope",
            "galliumos": "GalliumOS",
            "void-gaming": "Void Gaming",
            "whonix": "Whonix",
            "tails": "Tails",
            "pureos": "PureOS",
            "alpine": "Alpine Linux",
            "ubuntu-secure": "Ubuntu Secure",
            "linux-secure": "Linux Secure",
            "secureos": "SecureOS",
            "subgraph": "Subgraph OS",
            "debian-hardening": "Debian Hardening",
            "debian-secure": "Debian Secure",
            "qubes": "Qubes OS",
            "tails": "Tails",
            "parrotsec": "Parrot Security OS",
            "ionside": "IonSide",
            "rhel": "Red Hat Enterprise Linux",
            "fedora": "Fedora",
            "ubuntu-dev": "Ubuntu Dev",
            "arch-dev": "Arch Dev",
            "gentoo-dev": "Gentoo Dev",
            "debian-dev": "Debian Dev",
            "clear-linux-dev": "Clear Linux Dev",
            "turingos": "TuringOS",
            "nixos-dev": "NixOS Dev",
            "solus-dev": "Solus Dev",
            "vscodeos": "VSCodeOS",
            "devuan": "Devuan",
            "codeos": "CodeOS",
            "ubuntu-builder": "Ubuntu Builder",
            "arch": "Arch Linux",
            "gentoo": "Gentoo",
            "debian": "Debian",
            "ubuntu": "Ubuntu",
            "centos": "CentOS",
            "slackware": "Slackware",
            "ubuntu-mini": "Ubuntu Mini",
            "tinycore": "Tiny Core Linux",
            "puppy": "Puppy Linux",
            "lubuntu": "Lubuntu",
            "ubuntu-lite": "Ubuntu Lite",
            "mx-lite": "MX Lite",
            "linux-lite": "Linux Lite",
            "antix": "antiX",
            "salix": "Salix OS",
            "lfs": "Linux From Scratch",
            "slimjet": "SlimJet",
            "knoppix": "Knoppix",
            "bodhi": "Bodhi Linux",
            "crux": "CRUX",
            "slimlinux": "SlimLinux",
            "lightos": "LightOS",
            "featherlinux": "Feather Linux",
            "sliTaz": "SliTaz",
            "daphile": "Daphile",
            "antiX": "antiX",
            "debian-gui": "Debian with GUI",
            "ubuntu-gui": "Ubuntu with GUI",
            "mint": "Linux Mint",
            "fedora-workstation": "Fedora Workstation",
            "pop-os": "Pop!_OS",
            "kali-linux": "Kali Linux",
            "zorin-os": "Zorin OS",
            "deepin": "Deepin",
            "linuxmint-cinnamon": "Linux Mint Cinnamon",
            "ubuntu-xfce": "Ubuntu XFCE",
            "redhat": "Red Hat",
            "manjaro-xfce": "Manjaro XFCE",
            "solus-gnome": "Solus GNOME",
            "pop-gnome": "Pop!_OS GNOME",
            "elementary-gnome": "elementary OS GNOME",
            "fedora-gnome": "Fedora GNOME",
            "debian-gnome": "Debian GNOME",
            "ubuntu-mate": "Ubuntu MATE",
            "ubuntu-budgie": "Ubuntu Budgie",
            "kubuntu": "Kubuntu",
            "lubuntu": "Lubuntu",
            "xubuntu": "Xubuntu",
            "centos-stream": "CentOS Stream",
            "rocky-linux": "Rocky Linux",
            "almalinux": "AlmaLinux",
            "opensuse-leap": "openSUSE Leap",
            "opensuse-tumbleweed": "openSUSE Tumbleweed",
            "manjaro": "Manjaro",
            "endeavouros": "EndeavourOS",
            "manjaro-gnome": "Manjaro GNOME"
        }

        if did in known:
            return known[did]
        return f"Linux ({did or 'Unknown'})"
    except Exception:
        return "Linux (Unknown)"

def detect_device_type():
    m = platform.machine().lower()
    if "arm" in m: return "ARM Device"
    if "x86" in m: return "PC / Laptop"
    return "Unknown"

def local_os():
    s = platform.system()
    if s == "Linux": return detect_linux()
    if s == "Windows": return "Windows"
    if s == "Darwin": return "macOS"
    return s

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def get_mac_address():
    try:
        import uuid
        mac = uuid.getnode()
        if (mac >> 40) % 2:
            return "Unknown"
        return ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except Exception:
        return "Unknown"

def get_processor_info():
    try:
        return platform.processor() or "Unknown"
    except Exception:
        return "Unknown"
    known = {
        "x86_64": "64-bit x86",
        "i386": "32-bit x86",
        "armv7l": "ARMv7",
        "aarch64": "ARM64",
        "ppc64le": "PowerPC 64-bit Little Endian",
        "s390x": "IBM Z 64-bit",
    }
    p = platform.machine().lower()
    return known.get(p, p.capitalize())


def build_details(osname):
    return {
        "OS": osname,
        "Kernel": platform.release(),
        "Machine": platform.machine(),
        "Platform": platform.platform(),
        "User": os.getenv("USER") or os.getenv("USERNAME") or "Unknown",
        "Device Type": detect_device_type(),
        "Local IP": get_local_ip(),
        "MAC Address": get_mac_address(),
        "Version": platform.version(),
        "Processor": platform.processor() or "Unknown",
    }

def reveal(osname, details):
    wt("\nLOCKING TARGET...", bp=True)
    step_loading("Analyzing system", size=40)

    wt(f"\n{BOLD}DETECTED OS: {osname}{RESET}")
    wt("\n-- DETAILS --\n")

    for k, v in details.items():
        wt(f"{k}: {v}")
        time.sleep(0.04)
    print()


# --------------- NETWORK MODULE --------------- #


def arp_scan(subnet="192.168.1.0/24", retries=3, timeout=2):
    if conf is None:
        print("Scapy not installed.")
        return []

    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    answered = []
    for _ in range(retries):
        ans, _ = srp(pkt, timeout=timeout, retry=0)
        answered.extend(ans)

    hosts = {}
    for _, r in answered:
        ip = r.psrc
        mac = r.hwsrc
        hosts[ip] = mac 
    results = []
    for ip, mac in hosts.items():
        # Hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown"

        # Vendor MAC
        oui = mac[:8].upper()
        vendors = {
            "00:1A:2B": "Cisco",
            "3C:52:82": "Intel",
            "FC:FB:FB": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "00:14:22": "Dell",
            "00:1B:63": "Apple",
            "00:0C:29": "VMware",
            "00:50:56": "VMware",
            "00:15:5D": "Microsoft",
            "00:1E:C2": "Hewlett-Packard",
            "00:25:90": "Samsung",
            "00:0F:FE": "Sony",
            "00:16:3E": "XenSource",
            "00:18:8B": "Huawei",
            "00:1D:D8": "Lenovo",
            "00:1F:3C": "Asus",
            "00:21:6A": "TP-Link",
            "00:22:43": "Netgear",
            "00:24:E8": "LG Electronics",
            "00:26:5E": "ZTE",
            "00:30:48": "Motorola",
            "00:50:DA": "Nokia",
            "00:60:2F": "Xiaomi",
            "00:80:48": "Panasonic",
            "00:90:4C": "HTC",
            "00:90:4C": "HTC"
        }
        vendor = vendors.get(oui, "Unknown")

        # Ping alive check
        alive = False
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            alive = True
        except Exception:
            pass

        results.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "alive": alive
        })

    return results

def guess_os_ttl(ip):
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
        o = p.stdout.lower()

        if "ttl=" not in o:
            return "Unknown"

        ttl = int(o.split("ttl=")[1].split()[0])
        if ttl == 64: return "Linux"
        if ttl == 128: return "Windows"
        if ttl == 255: return "Network Device"
        return f"Unknown (TTL={ttl})"
    except:
        return "Unknown"

def vpn_breacher(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unable to resolve"

def network_scan(subnet):
    print("\nENGAGING NETWORK MODULE...")
    hosts = arp_scan(subnet)

    if not hosts:
        print("No active hosts.\n")
        return

    print(f"\nFOUND {len(hosts)} HOSTS\n")

    global SILENT_MODE
    for h in hosts:
        ip = h["ip"]
        mac = h["mac"]

        print(f"\nTARGET    : {ip}")
        print(f"MAC       : {mac}")
        print(f"Vendor    : {h['vendor']}")
        print(f"Hostname  : {h['hostname']}")
        print(f"Alive     : {'Yes' if h['alive'] else 'No'}")
        print(f"OS Guess  : {guess_os_ttl(ip)}")
        time.sleep(0.1 * (3 if SILENT_MODE else 1))

    print("\nNetwork scan complete.\n")


# --------------- WI-FI SCAN MODULE --------------- #

def _get_wifi_iface():
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()
    if not ifaces:
        return None
    return ifaces[0]


def _parse_security(profile):
    if not profile.akm:
        return "Open"

    akm_map = {
        pywifi.const.AKM_TYPE_NONE: "Open",
        pywifi.const.AKM_TYPE_WPA: "WPA",
        pywifi.const.AKM_TYPE_WPAPSK: "WPA-PSK",
        pywifi.const.AKM_TYPE_WPA2: "WPA2",
        pywifi.const.AKM_TYPE_WPA2PSK: "WPA2-PSK",
        pywifi.const.AKM_TYPE_WPA3: "WPA3",
    }

    return ", ".join(akm_map.get(a, "Unknown") for a in profile.akm)


def scan_wifi_networks(scans=3, delay=1.2):
    iface = _get_wifi_iface()

    if iface is None:
        print(f"{YELLOW}No Wi-Fi interface found.{RESET}")
        return []

    print(f"\n{YELLOW}Using interface: {iface.name()}{RESET}")
    print(f"{YELLOW}Scanning available Wi-Fi networks...{RESET}")

    raw_results = []

    for _ in range(scans):
        iface.scan()
        time.sleep(delay)
        raw_results.extend(iface.scan_results())

    networks = {}
    for r in raw_results:
        key = (r.bssid, r.ssid)

        if key not in networks:
            networks[key] = {
                "ssid": r.ssid or "<hidden>",
                "bssid": r.bssid,
                "signals": [],
                "security": _parse_security(r),
                "freq": r.freq
            }

        networks[key]["signals"].append(r.signal)

    results = []
    for n in networks.values():
        results.append({
            "ssid": n["ssid"],
            "bssid": n["bssid"],
            "signal": round(sum(n["signals"]) / len(n["signals"]), 1),
            "security": n["security"],
            "freq": n["freq"]
        })

    results.sort(key=lambda x: x["signal"], reverse=True)

    if not results:
        print(f"{YELLOW}No Wi-Fi networks found.{RESET}")
        return []

    print(f"{YELLOW}Found {len(results)} networks:{RESET}\n")
    for i, n in enumerate(results, 1):
        print(
            f"{YELLOW}{i}. SSID: {n['ssid']}\n"
            f"   BSSID: {n['bssid']}\n"
            f"   Signal: {n['signal']} dBm\n"
            f"   Security: {n['security']}\n"
            f"   Frequency: {n['freq']} MHz{RESET}\n"
        )

    return results


def scan_selected_wifi_network(_network):
    ip = get_local_ip()
    if ip == "Unknown":
        print(f"{YELLOW}Unable to determine local IP.{RESET}")
        return

    subnet = ".".join(ip.split(".")[:3]) + ".0/24"
    print(f"{YELLOW}Scanning local network subnet: {subnet}{RESET}")
    network_scan(subnet)


def choose_network_to_scan():
    print("\nChoose the network to scan:")
    print("1. Scan Local Network (LAN)")
    print("2. Show Wi-Fi Networks in range")

    choice = input(f"{YELLOW}Enter choice: {RESET}")

    if choice == "1":
        ip = get_local_ip()
        if ip != "Unknown":
            subnet = ".".join(ip.split(".")[:3]) + ".0/24"
            print(f"{YELLOW}Scanning local network with subnet: {subnet}{RESET}")
            network_scan(subnet)
        else:
            print(f"{YELLOW}No local network found.{RESET}")

    elif choice == "2":
        scan_wifi_networks()

    else:
        print(f"{YELLOW}Invalid choice, please select again.{RESET}")


# --------------- IP / MAC INFO UTILITIES --------------- #


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False

def is_valid_mac(mac):
    mac = mac.lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    return all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts)

def ip_info(ip):
    print("\n[ IP INFO ]")
    print("IP:", ip)

    if ip.startswith("127."):
        print("Type: Loopback")
    elif ip.startswith(("10.", "192.168.", "172.")):
        print("Type: Private / Local")
    else:
        print("Type: Public")

    try:
        host = socket.gethostbyaddr(ip)[0]
        print("Hostname:", host)
    except Exception:
        print("Hostname: Not resolvable")

def mac_info(mac):
    mac = mac.lower().replace("-", ":")
    print("\n[ MAC INFO ]")
    print("MAC:", mac)

    oui = mac[:8].upper()
    vendors = {
        "00:1A:2B": "Cisco",
        "3C:52:82": "Intel",
        "FC:FB:FB": "Apple",
        "B8:27:EB": "Raspberry Pi",
        "00:14:22": "Dell",
        "00:1B:63": "Apple",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:15:5D": "Microsoft",
        "00:1E:C2": "Hewlett-Packard",
        "00:25:90": "Samsung",
        "00:0F:FE": "Sony",
        "00:16:3E": "XenSource",
        "00:18:8B": "Huawei",
        "00:1D:D8": "Lenovo",
        "00:1F:3C": "Asus",
        "00:21:6A": "TP-Link",
        "00:22:43": "Netgear",
        "00:24:E8": "LG Electronics",
        "00:26:5E": "ZTE",
        "00:30:48": "Motorola",
        "00:50:DA": "Nokia",
        "00:60:2F": "Xiaomi",
        "00:80:48": "Panasonic",
        "00:90:4C": "HTC",
    }

    print("Vendor:", vendors.get(oui, "Unknown Vendor"))

def ip_mac_info_module():
    wt("Run IP / MAC Info module? (y/n): ", d=0.01, color=ORANGE)
    if input().strip().lower() != "y":
        return

    print("\nAnalyze:")
    print("[1] IP Address")
    print("[2] MAC Address")

    choice = input("Select option: ").strip()

    if choice == "1":
        ip = input("Enter IP address: ").strip()
        if is_valid_ip(ip):
            ip_info(ip)
        else:
            print("Invalid IP address.")

    elif choice == "2":
        mac = input("Enter MAC address: ").strip()
        if is_valid_mac(mac):
            mac_info(mac)
        else:
            print("Invalid MAC address.")

    else:
        print("Invalid option.")


# --------------- MAIN --------------- #


def main():
    intro()
    osname = local_os()
    details = build_details(osname)
    reveal(osname, details)

    wt("Run network scan module? (y/n): ", d=0.01, color=ORANGE)
    if input().strip().lower() != "y":
        wt("\nShutting down...", color=BLUE)
        return
    network_scan("192.168.1.0/24")

    ip_mac_info_module()
    wt("\nShutting down...", color=BLUE)
    time.sleep(1.5)

if __name__ == "__main__":
    random.seed(int(time.time()))
    main()

# --------------- END OF FILE --------------- #
#
# 
# DarkProbe ShadowScan Module - 2026 © Nexus
# https://www.github.com/XBNMF35XB/DarkProbe/
# Licensed under the GNU GENERAL PUBLIC LICENSE License
# For support, visit: https://www.github.com/XBNMF35XB/DarkProbe/support.md
# Version 8.4.2
# NO AI USED IN THE CREATION OF THIS FILE
# ALL CODE WRITTEN BY NEXUS
# For more updates about DarkProbe, visit the official repository.
# All the code is written in Python3
# When downloading. use the installer to set up DarkProbe properly.
# DarkProbe is a powerful OSINT and Reconnaissance Framework.
# DarkProbe is intended for operational purposes only.
# Misuse of DarkProbe is not the responsibility of the author.
# Use DarkProbe with your own networks and systems only.
# Nexus - Out.
#
#
# ------------------------------------------- #
