#!/usr/bin/python3

import os
import sys
import platform
import subprocess
import time
import shutil

# Colors
ICE     = "\033[97m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
BLUE    = "\033[34m"
ORANGE  = "\033[38;5;214m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

# Config

REPO_URL = "https://github.com/XBNMF35XB/DarkProbe/"
RAW_BASE = "https://raw.githubusercontent.com/XBNMF35XB/DarkProbe/main"
REPO_DIR = "ShadowScan"
VENV_DIR = "venv"
OFFICIAL_FILES = ["ShadowScan.py", "readme.md", "LICENSE", "support.md"]

# Contact Info
CONTACT = "contact smapproject41@gmail.com for solving the problem"

# Supported Distros
DISTROS = {
            "arch": "Arch Linux",
            "manjaro": "Manjaro",
            "endeavouros": "EndeavourOS",
            "artix": "Artix Linux",
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

def wt(text, d=0.02, color=ICE):
    """Write text with delay"""
    for c in text:
        sys.stdout.write(f"{color}{c}{RESET}")
        sys.stdout.flush()
        time.sleep(d)
    print()

def detect_distro():
    """Detect Linux distribution"""
    try:
        with open("/etc/os-release") as f:
            data = {}
            for line in f:
                key, _, value = line.partition("=")
                data[key.strip()] = value.strip().strip('"')
            
            distro_id = data.get("ID", "").lower()
            distro_name = data.get("PRETTY_NAME", "Unknown")
            
            return distro_id, distro_name
    except Exception as e:
        wt(f"{RED}[ERROR] OS Detection Failed{RESET}")
        wt(f"{RED}{CONTACT}{RESET}")
        sys.exit(1)

def check_sudo():
    """Check if running with sudo"""
    if os.geteuid() != 0:
        wt(f"{RED}[ERROR] This installer requires sudo privileges{RESET}")
        wt(f"{RED}Run: sudo python3 CoreSync v3.0.13 BETA{RESET}")
        sys.exit(1)

def install_system_packages(distro_id):
    """Install required system packages based on distro"""
    
    # Package mappings by package manager
    apt_distros = [
        "ubuntu", "debian", "linuxmint", "pop", "kali", "parrot", "elementary", 
        "zorin", "mx", "siduction", "antiX", "deepin", "bunsenlabs", "peppermint", 
        "ubuntu-mate", "ubuntu-budgie", "ubuntu-studio", "lubuntu", "xubuntu", 
        "kubuntu", "ubuntu-server", "ubuntu-core", "ubuntu-touch", "q4os", 
        "devuan", "pureos", "backbox", "bodhi", "crunchbangplusplus", "raspbian",
        "raspios", "postmarketos", "dietpi", "tailos", "whonix", "tails",
        "parrotsec", "ionside", "ubuntu-dev", "debian-dev", "ubuntu-builder",
        "ubuntu-mini", "ubuntu-lite", "linux-lite", "ubuntu-xfce", "debian-gnome",
        "ubuntu-mate", "ubuntu-budgie", "kubuntu", "lubuntu", "xubuntu",
        "centos-stream", "linuxmint-cinnamon", "ubuntu-xfce", "manjaro-xfce",
        "pop-gnome", "elementary-gnome", "fedora-gnome", "debian-gnome",
        "ubuntu-secure", "linux-secure", "secureos", "debian-hardening",
        "debian-secure", "ubuntu-gamepack", "gamestar", "nitrux-gaming",
        "pop-os-gaming", "gamebuntu", "gameros", "lax", "linux-gaming",
        "galliumos", "void-gaming", "subgraph", "arch-gui", "arch-lite",
        "arch-secure", "arch-gnome", "arch-kde", "arch-xfce", "arch-dev",
        "gentoo-dev", "clear-linux-dev", "vscodeos", "codeos", "mint",
        "parrot", "kali-linux", "zorin-os", "deepin", "fedora-workstation"
    ]
    
    pacman_distros = [
        "arch", "manjaro", "endeavouros", "artix", "garuda", "archbang", 
        "chakra", "blackarch", "archlabs", "cachyos", "archmerge", "archman", 
        "archbuntu", "anarchy", "manjaro-architect", "manjaro-gnome",
        "manjaro-xfce", "arch-dev", "arch-gui", "arch-lite", "arch-secure",
        "arch-gnome", "arch-kde", "arch-xfce", "funtoo"
    ]
    
    dnf_distros = [
        "fedora", "rhel", "centos", "rocky", "almalinux", "scientific", 
        "clearos", "oracle-linux", "redhat", "nobara", "fedora-workstation",
        "fedora-gnome", "centos-stream", "rocky-linux", "zoran"
    ]
    
    zypper_distros = [
        "opensuse", "sles", "sle", "opensuse-tumbleweed", "opensuse-leap", 
        "suse", "opensuse-leap", "opensuse-tumbleweed"
    ]
    
    apk_distros = ["alpine", "alpine-pine"]
    
    xbps_distros = ["void", "void-gaming"]
    
    portage_distros = ["gentoo", "gentoo-dev", "sabayon"]
    
    nix_distros = ["nixos", "nixos-dev"]
    
    # Common packages for all distros
    common_packages = ["wireless-tools", "net-tools", "arp-scan", "git"]
    
    # Build tools by package manager
    build_tools = {
        "apt": ["build-essential", "python3", "python3-pip"],
        "pacman": ["base-devel", "python", "python-pip"],
        "dnf": ["gcc", "gcc-c++", "make", "python3", "python3-pip"],
        "zypper": ["gcc", "gcc-c++", "make", "python3", "python3-pip"],
        "apk": ["build-base", "python3", "py3-pip"],
        "xbps": ["base-devel", "python3", "python3-pip"],
        "portage": ["sys-devel/gcc", "dev-lang/python", "dev-python/pip"],
        "nix": ["python3", "git"]
    }
    
    wt(f"{BLUE}[*] Installing system packages...{RESET}")
    
    try:
        if distro_id in pacman_distros:
            packages = build_tools["pacman"] + common_packages
            subprocess.run(["pacman", "-Sy", "--noconfirm"] + packages, check=True)
        
        elif distro_id in apt_distros:
            packages = build_tools["apt"] + common_packages
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y"] + packages, check=True)
        
        elif distro_id in dnf_distros:
            packages = build_tools["dnf"] + common_packages
            subprocess.run(["dnf", "install", "-y"] + packages, check=True)
        
        elif distro_id in zypper_distros:
            packages = build_tools["zypper"] + common_packages
            subprocess.run(["zypper", "install", "-y"] + packages, check=True)
        
        elif distro_id in apk_distros:
            packages = build_tools["apk"] + common_packages
            subprocess.run(["apk", "add"] + packages, check=True)
        
        elif distro_id in xbps_distros:
            packages = build_tools["xbps"] + common_packages
            subprocess.run(["xbps-install", "-y"] + packages, check=True)
        
        elif distro_id in portage_distros:
            packages = build_tools["portage"] + common_packages
            subprocess.run(["emerge", "-u"] + packages, check=True)
        
        elif distro_id in nix_distros:
            wt(f"{YELLOW}[!] NixOS detected. Using nix-shell for installation...{RESET}")
            subprocess.run(["nix-shell", "-p"] + build_tools["nix"], check=True)
        
        else:
            wt(f"{YELLOW}[!] Unknown distro. Attempting apt-get as fallback...{RESET}")
            packages = build_tools["apt"] + common_packages
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y"] + packages, check=True)
        
        wt(f"{GREEN}[✓] System packages installed{RESET}")
    
    except subprocess.CalledProcessError as e:
        wt(f"{RED}[ERROR] Package installation failed{RESET}")
        wt(f"{RED}{CONTACT}{RESET}")
        sys.exit(1)

def install_pip_packages():
    """Install required Python packages"""
    pip_packages = ["scapy", "psutil", "pywifi"]
    
    wt(f"{BLUE}[*] Installing Python packages...{RESET}")
    
    try:
        for pkg in pip_packages:
            subprocess.run(["pip3", "install", pkg], check=True, capture_output=True)
        
        wt(f"{GREEN}[✓] Python packages installed{RESET}")
    except subprocess.CalledProcessError as e:
        wt(f"{RED}[ERROR] pip installation failed{RESET}")
        wt(f"{RED}{CONTACT}{RESET}")
        sys.exit(1)

def copy_smap():
    """Copy SMap.py to /usr/local/bin"""
    wt(f"{BLUE}[*] Copying SMap.py to system...{RESET}")
    
    try:
        source = os.path.join(os.path.dirname(__file__), "SMap.py")
        dest = "/usr/local/bin/smap"
        
        if not os.path.exists(source):
            wt(f"{RED}[ERROR] SMap.py not found in current directory{RESET}")
            wt(f"{RED}{CONTACT}{RESET}")
            sys.exit(1)
        
        shutil.copy2(source, dest)
        os.chmod(dest, 0o755)
        
        wt(f"{GREEN}[✓] SMap installed to /usr/local/bin/smap{RESET}")
    except Exception as e:
        wt(f"{RED}[ERROR] Failed to copy SMap.py{RESET}")
        wt(f"{RED}{CONTACT}{RESET}")
        sys.exit(1)

def cleanup():
    """Remove installer script after installation"""
    wt(f"{BLUE}[*] Cleaning up installer...{RESET}")
    
    try:
        installer_path = os.path.abspath(__file__)
        os.remove(installer_path)
        wt(f"{GREEN}[✓] Installer removed{RESET}")
    except Exception as e:
        wt(f"{YELLOW}[!] Could not auto-delete installer. Manual removal recommended.{RESET}")

def main():
    """Main installation routine"""
    wt(f"{BOLD}{ORANGE}=== SMap Installer V3 ==={RESET}\n")
    
    check_sudo()
    
    distro_id, distro_name = detect_distro()
    
    wt(f"{GREEN}[✓] Detected: {distro_name}{RESET}\n")
    
    install_system_packages(distro_id)
    time.sleep(0.5)
    
    install_pip_packages()
    time.sleep(0.5)
    
    copy_smap()
    time.sleep(0.5)
    
    cleanup()
    
    wt(f"\n{BOLD}{GREEN}[✓] Installation Complete!{RESET}")
    wt(f"{GREEN}Run 'smap' from terminal to start{RESET}\n")

if __name__ == "__main__":
    main()
