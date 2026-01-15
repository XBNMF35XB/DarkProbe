ShadowScan (SProbe)
ShadowScan, also known as SProbe, is a lightweight, cross-platform Python-based tool designed for system and network analysis. It helps you gather detailed information about your local system and network environment, ideal for troubleshooting and reconnaissance.

 **Features**
-Local System Information
-Displays OS and kernel details
-Identifies device type and architecture
-Local IP address and MAC address retrieval
-User and platform information
-Network Scanning
-Identifies other devices on the local network (subnet)
-Provides IP, MAC, hostname, vendor (via a limited database), and an OS guess
-Detects kernel-based or embedded systems like routers, cameras, and IoT devices
-Cross-Platform Support
-Works on Linux, Windows, and macOS
-Silent Mode
-Option for stealthier operation with reduced speed
-ARP-based Network Scanning
-Requires elevated privileges (sudo or Administrator)
-IP/MAC Analysis
-Performs detailed analysis of IP and MAC addresses
-Lightweight & Simple
-Single-file design, easy to use and modify

**Requirements**
-Python 3.8+
-Git (for cloning the repository)
-Optional: Scapy (required for ARP network scanning)

 **Installation**
 *Arch Linux*
 sudo pacman -S git
 git clone https://github.com/XBNMF35XB/DarkProbe.git
 cd ShadowScan
 sudo python3 ShadowScan.py

 *Debian-based*
 sudo apt update
 sudo apt install git python3
 git clone https://github.com/XBNMF35XB/DarkProbe.git
 cd ShadowScan
 sudo python3 ShadowScan.py

  *MacOS*
Requires Homebrew:

 brew install git python
 git clone https://github.com/XBNMF35XB/DarkProbe.git
 cd ShadowScan
 python3 ShadowScan.py

  *Windows*

 Install Git from git-scm.com 

 Install Python (ensure to check "Add Python to PATH") from python.org

 Then open PowerShell as Administrator:

 git clone https://github.com/XBNMF35XB/DarkProbe.git
 cd ShadowScan
 python ShadowScan.py

 Usage

 Once installed, simply run python3 ShadowScan.py (or python ShadowScan.py on Windows).

 Network Scanning works best on local networks (e.g., 192.168.x.0/24).
 Vendor identification is based on a limited OUI database.
 Some features, such as ARP scanning, require elevated privileges (sudo or Administrator).

 Disclaimer
This tool is for educational and informational purposes only.
 You should only use ShadowScan on systems and networks you own or have explicit permission to analyze.

 The author is not responsible for any misuse or illegal activities. 

 Author

 XBNMF35XB (Alias: Nexus)
