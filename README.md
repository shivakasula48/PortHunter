# 🚀 PortHunter – Advanced Port Scanner & Service Enumerator

PortHunter3.0 is an advanced Python-based port scanning and service enumeration tool built for penetration testers, red teamers, and cybersecurity professionals. Unlike traditional scanners, PortHunter3.0:

- Actively probes open ports  
- Extracts service banners & versions  
- Performs vulnerability assessments (Anonymous FTP, SMB Null Sessions, Weak SSL Ciphers)  
- Analyzes SSL certificates  
- Enumerates HTTP methods  
- Exports reports in JSON, CSV, and TXT formats  

It’s designed for speed, modularity, and extensibility, making it ideal for internal assessments, bug bounty recon, and CTF competitions.

---

## 🛡️ Key Features

### 🔍 Advanced Port Scanning
- Multi-threaded scanning (up to 200 concurrent threads)  
- Custom port ranges, Top 1000 ports, or profile-based scans  
- Stealth mode with decoy traffic *(prototype phase)*  

### 🖥 Service & Version Detection
- Banner grabbing (HTTP, HTTPS, FTP, SSH, SMTP, SMB)  
- Regex-based service fingerprinting (Apache, Nginx, OpenSSH, MySQL, etc.)

### ⚠️ Vulnerability Checks
- Detects Anonymous FTP access  
- Open HTTP directory listings  
- SMB Null Session checks  
- Weak SSL Cipher & Certificate info extraction  
- HTTP Method enumeration

### 📊 Comprehensive Reporting
- Export results in:
  - `.json` (machine-readable)  
  - `.csv` (Excel-compatible)  
  - `.txt` (formatted, human-readable)  
- Highlights vulnerable services in reports

### 🧩 Custom Profiles & Extensibility
- Scan using custom port profiles (`.json`)  
- Modular structure allows easy future upgrades (e.g., API mode, screenshots)

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/shivakasula48/PortHunter3.0.git
cd PortHunter3.0
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

> 💡 *Note: Flask is optional for future API mode. Core functions use Python Standard Library.*

---

## ⚙️ Usage Guide

### 🔹 Basic Command

```bash
python porthunter.py <target>
```

### 🔹 Advanced Examples

| Command | Description |
|--------|-------------|
| `python porthunter.py 192.168.1.1 -p 1-1000` | Scan ports 1 through 1000 |
| `python porthunter.py example.com --top --json` | Top 1000 ports, save as JSON |
| `python porthunter.py target.com --profile custom_profile.json` | Use custom port profile |
| `python porthunter.py 10.10.10.10 -v -c` | Verbose mode + CSV export |
| `python porthunter.py 172.16.1.5 --stealth` | Enable stealth mode *(prototype)* |

### 🔹 Available Flags

| Flag | Description |
|------|-------------|
| `<target>` | IP or Hostname |
| `-p, --ports` | Port ranges (e.g., `22,80,443`, `1-1024`) |
| `-t, --top` | Scan Top 1000 ports |
| `-P, --profile` | Use custom `.json` port profile |
| `-v, --verbose` | Show closed ports and logs |
| `-j, --json` | Save output as JSON |
| `-c, --csv` | Save output as CSV |
| `-s, --stealth` | Stealth scanning *(decoys, delays)* |

---

## 📋 Output Reports

### 📄 TXT Report
Formatted scan result with color-coded vulnerabilities.

### 📂 JSON Report
Structured report (fields: Port, Status, Service, Version, Vulnerabilities).

### 📊 CSV Report
Spreadsheet-friendly for documentation or audit reports.

---

## 🧠 How PortHunter3.0 Works

1. **Target Resolution** – Converts hostname to IP.
2. **Parallel Port Scanning** – Uses `ThreadPoolExecutor` for speed.
3. **Banner Grabbing** – Extracts service banners from open ports.
4. **Service Fingerprinting** – Regex patterns identify known services.
5. **Vulnerability Enumeration** – Checks:
   - Anonymous FTP login
   - SMB Null Sessions
   - Weak SSL ciphers
   - Open Directory Listing
   - HTTP Methods allowed
6. **Result Saving** – Displays results in terminal, saves to file(s).

---

## 🗃 Folder Structure

```
PortHunter3.0/
├── porthunter.py          # Main scanner code
├── requirements.txt       # Required Python packages
├── LICENSE                # Project License (MIT)
└── README.md              # Documentation
```

---

## ⚠️ Legal & Disclaimer

> PortHunter3.0 is intended **strictly for ethical hacking**, security research, educational purposes, and **authorized penetration testing**.  
**Never use this tool against systems you do not own or have permission to test.**  
The author is not responsible for misuse.

---

## 👨‍💻 Author Information

**Kasula Shiva**  
🎓 B.Tech CSE (Cybersecurity)  
🔗 GitHub: [shivakasula48](https://github.com/shivakasula48)  
📧 Email: [shivakasula10@gmail.com](mailto:shivakasula10@gmail.com)

---

## 🤝 Contributing

Pull Requests, Issues, and Feedback are welcome!

- Fork the repo  
- Make improvements  
- Submit a PR  

---

## ⭐ Give it a Star!

If this project helped you or was educational, please consider **⭐ starring** it on GitHub.

---

## 🛠️ Future Roadmap

- 🕵️ Full Stealth Mode (decoys, randomized delays)  
- 🌐 API Interface via Flask  
- 📸 HTTP Screenshot Module (using Selenium)  
- 🧬 OS Fingerprinting  
- 🔍 Shodan API Integration for passive intelligence

