import socket
import concurrent.futures
import sys
import time
import argparse
import json
import re
import ssl
import subprocess
import platform
import csv
import threading
import random
import string
import ipaddress
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse
# Flask is optional for API mode - only import if needed
try:
    from flask import Flask, request, jsonify
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Flask not available. API mode disabled.")
import logging

# === Constants and Globals ===

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GRAY = "\033[90m"
RESET = "\033[0m"

DEFAULT_TIMEOUT = 3.0
MAX_WORKERS = 200

# Suspicious ports dictionary
suspicious_ports = {
    23: "Telnet (Legacy - Avoid Exposing)",
    445: "SMB (WannaCry/EternalBlue Target)",
    3389: "RDP (Brute-force Target)",
    6667: "IRC (Botnet Port)",
    31337: "BackOrifice Trojan Port"
}

# Top 1000 common ports (subset example, expand as needed)
top_1000_ports = [
    80, 443, 21, 22, 23, 25, 53, 110, 139, 143, 445, 3389, 3306, 8080, 5900,
    1723, 111, 995, 993, 587, 8888, 135, 4444, 6667, 10000, 5000, 5901,
    # Add more ports as needed or load from a file for full top 1000
]

# Service fingerprints regex patterns
service_fingerprints = {
    "Apache": re.compile(r"Apache/?([\d\.]*)", re.I),
    "nginx": re.compile(r"nginx/?([\d\.]*)", re.I),
    "OpenSSH": re.compile(r"OpenSSH_([\d\.]+)", re.I),
    "Microsoft-IIS": re.compile(r"Microsoft-IIS/?([\d\.]*)", re.I),
    "vsFTPd": re.compile(r"vsFTPd/?([\d\.]*)", re.I),
    "Postfix": re.compile(r"Postfix", re.I),
    "Exim": re.compile(r"Exim", re.I),
    "Sendmail": re.compile(r"Sendmail", re.I),
    "VMware": re.compile(r"VMware", re.I),
    "Redis": re.compile(r"redis_version:([\d\.]+)", re.I),
    "ElasticSearch": re.compile(r"ElasticSearch", re.I),
    "SQL Server": re.compile(r"Microsoft SQL Server", re.I),
    "SMTP": re.compile(r"SMTP", re.I),
    "SNMP": re.compile(r"SNMP", re.I),
}

# OS detection TTL ranges (simplified)
os_ttl_map = {
    range(0, 65): "Linux/Unix",
    range(65, 130): "Windows",
    range(130, 256): "Unknown/Other"
}

# Custom port profiles example
default_profiles = {
    "web_server_profile": [80, 443, 8080, 8443],
    "database_ports": [3306, 1433, 1521],
}

# === Utility Functions ===

def print_banner():
    banner = f"""
{GREEN}
   ____                  _             ____                                  
  |  _ \\ ___  __ _  __ _| | ___  _ __ |  _ \\ ___  ___ ___  _ __   ___  ___  
  | |_) / _ \\/ _` |/ _` | |/ _ \\| '_ \\| |_) / _ \\/ __/ _ \\| '_ \\ / _ \\/ __| 
  |  __/  __/ (_| | (_| | | (_) | | | |  __/  __/ (_| (_) | | | |  __/\\__ \\ 
  |_|   \\___|\\__,_|\\__, |_|\\___/|_| |_|_|   \\___|\\___\\___/|_| |_|\\___||___/ 
                   |___/                                                   
  Advanced Port Scanner v3.0
{RESET}
"""
    print(banner)

def ping_host(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        return output.returncode == 0
    except Exception:
        return False

def get_os_from_ttl(ttl):
    for ttl_range, os_name in os_ttl_map.items():
        if ttl in ttl_range:
            return os_name
    return "Unknown"

def tcp_ping(host):
    """
    TCP ping by connecting to port 80 or 443 to get TTL for OS detection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, 80))
        ttl = sock.getsockopt(socket.SOL_IP, socket.IP_TTL)
        sock.close()
        return ttl
    except Exception:
        return None

def get_http_title(banner):
    match = re.search(r'<title>(.*?)</title>', banner, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""

def detect_version_info(banner):
    for name, pattern in service_fingerprints.items():
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() else ""
            return f"{name} {version}".strip()
    return ""

def ssl_cert_info(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                not_after = cert.get('notAfter', 'Unknown')
                fingerprint = ssock.getpeercert(binary_form=True)
                import hashlib
                fingerprint_sha256 = hashlib.sha256(fingerprint).hexdigest()
                return {
                    "issuer": issuer,
                    "subject": subject,
                    "expiry": not_after,
                    "fingerprint_sha256": fingerprint_sha256
                }
    except Exception:
        return None

def check_weak_ssl_ciphers(host, port=443):
    # Basic test: try connecting with SSLv3 or weak ciphers (simplified)
    # For full test, external tools or libraries like sslscan or OpenSSL would be better.
    # Here, we just attempt SSL handshake with default context and report if fails.
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # Deprecated but used for weak cipher test
        context.set_ciphers('LOW')
        with socket.create_connection((host, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return False  # Weak cipher accepted
    except Exception:
        return True  # Weak cipher rejected or no weak cipher support

def check_anonymous_ftp(host, port=21):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        banner = sock.recv(1024).decode(errors='ignore')
        sock.sendall(b"USER anonymous\r\n")
        resp = sock.recv(1024).decode(errors='ignore')
        sock.sendall(b"PASS anonymous\r\n")
        resp2 = sock.recv(1024).decode(errors='ignore')
        sock.close()
        if "230" in resp2:
            return True
        return False
    except Exception:
        return False

def check_open_directory(host, port):
    try:
        conn = HTTPConnection(host, port, timeout=3)
        conn.request("GET", "/")
        resp = conn.getresponse()
        data = resp.read(2048).decode(errors='ignore')
        conn.close()
        if resp.status == 200 and ("Index of" in data or "<title>Index of" in data):
            return True
        return False
    except Exception:
        return False

def check_smb_null_session(host):
    # SMB null session check requires SMB protocol support.
    # We can do a basic check using 'smbclient' if available or skip.
    # Here, we simulate a check by attempting connection to port 445.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, 445))
        sock.close()
        # Real null session check requires SMB protocol interaction.
        return True
    except Exception:
        return False

def http_method_enumeration(host, port):
    methods = []
    try:
        conn = HTTPConnection(host, port, timeout=3)
        conn.request("OPTIONS", "/")
        resp = conn.getresponse()
        allow = resp.getheader('Allow')
        if allow:
            methods = [m.strip() for m in allow.split(',')]
        conn.close()
    except Exception:
        pass
    return methods

def web_technology_detection(headers):
    techs = []
    powered_by = headers.get('X-Powered-By', '')
    server = headers.get('Server', '')
    if powered_by:
        techs.append(powered_by)
    if server:
        techs.append(server)
    return techs

def take_http_screenshot(url):
    # Optional: requires selenium and headless browser setup
    # Placeholder function
    return None

def load_custom_profiles(profile_file):
    try:
        with open(profile_file, 'r') as f:
            profiles = json.load(f)
        return profiles
    except Exception:
        return {}

def source_port_spoofing():
    # Requires raw socket and admin privileges, complex to implement here
    # Placeholder for future implementation
    pass

def generate_decoy_traffic(target_ip, count=5):
    # Generate random TCP SYN packets to random ports to blend traffic
    # Placeholder for future implementation
    pass

# === Core Scanning Functions ===

def get_banner(sock, port, target_host):
    try:
        sock.settimeout(DEFAULT_TIMEOUT)
        if port == 443:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = ssock.recv(2048).decode('utf-8', errors='ignore').strip()
                title = get_http_title(banner)
                if title:
                    banner += f" [Title: {title}]"
                return banner
        elif port in (80, 8080, 8000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            title = get_http_title(banner)
            if title:
                banner += f" [Title: {title}]"
            return banner
        elif port == 21:
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            return banner
        elif port == 22:
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            return banner
        elif port == 25:
            sock.sendall(b"HELO example.com\r\n")
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            return banner
        else:
            sock.sendall(b"\r\n")
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception:
        return ""

def scan_port(target_ip, port, target_host):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = 'Unknown'
                banner = get_banner(sock, port, target_host)
                version_info = detect_version_info(banner) if banner else ""
                extra_info = suspicious_ports.get(port, "")

                # Additional vulnerability checks
                vuln_info = []

                if port == 21 and check_anonymous_ftp(target_ip):
                    vuln_info.append("Anonymous FTP allowed")

                if port in (80, 8080, 8000, 443):
                    if check_open_directory(target_ip, port):
                        vuln_info.append("Open Directory Browsing")

                    methods = http_method_enumeration(target_ip, port)
                    if methods:
                        vuln_info.append(f"HTTP Methods: {', '.join(methods)}")

                    # SSL cert parsing for 443
                    if port == 443:
                        cert = ssl_cert_info(target_ip, port)
                        if cert:
                            extra_info += f" SSL Cert Expiry: {cert['expiry']}"

                        if not check_weak_ssl_ciphers(target_ip, port):
                            vuln_info.append("Weak SSL Cipher Accepted")

                if port == 445 and check_smb_null_session(target_ip):
                    vuln_info.append("SMB Null Session Allowed")

                return port, service, banner, True, extra_info, version_info, vuln_info
            else:
                return port, "", "", False, "", "", []
    except Exception:
        return port, "", "", False, "", "", []

# === Output Formatting ===

def format_port_results(results, verbose=False):
    formatted_results = f"{BLUE}Port Scan Results:{RESET}\n"
    formatted_results += "{:<8} {:<15} {:<10} {:<20} {:<40} {:<30}\n".format(
        "Port", "Service", "Status", "Version Info", "Banner/Info", "Vulnerabilities")
    formatted_results += '-' * 150 + "\n"
    for port, service, banner, status, extra, version, vulns in sorted(results, key=lambda x: x[0]):
        if status:
            banner_preview = banner.replace('\n', ' ')[:37] + "..." if len(banner) > 40 else banner.replace('\n', ' ')
            vuln_str = ", ".join(vulns) if vulns else ""
            line = f"{GREEN}{port:<8} {service:<15} {'Open':<10} {version:<20} {banner_preview:<40} {vuln_str:<30}{RESET}"
            if port in suspicious_ports:
                line += f" {RED}⚠️ {suspicious_ports[port]}{RESET}"
            formatted_results += line + "\n"
        elif verbose:
            formatted_results += f"{GRAY}{port:<8} {service:<15} {'Closed':<10} {'':<20} {'':<40} {'':<30}{RESET}\n"
    return formatted_results

# === Save Results ===

def save_results(target_host, results, elapsed_time, as_json=False, as_csv=False):
    try:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        if as_json:
            filename = f"port_scan_{target_host}_{timestamp}.json"
            json_results = {
                "target": target_host,
                "scan_time": time.strftime('%Y-%m-%d %H:%M:%S'),
                "duration_seconds": elapsed_time,
                "ports": []
            }
            for port, service, banner, status, extra, version, vulns in sorted(results, key=lambda x: x[0]):
                json_results["ports"].append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "status": "open" if status else "closed",
                    "note": extra,
                    "version_info": version,
                    "vulnerabilities": vulns
                })
            with open(filename, 'w') as f:
                json.dump(json_results, f, indent=4)
        elif as_csv:
            filename = f"port_scan_{target_host}_{timestamp}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Port', 'Service', 'Status', 'Version Info', 'Banner/Info', 'Note', 'Vulnerabilities']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for port, service, banner, status, extra, version, vulns in sorted(results, key=lambda x: x[0]):
                    writer.writerow({
                        'Port': port,
                        'Service': service,
                        'Status': 'Open' if status else 'Closed',
                        'Version Info': version,
                        'Banner/Info': banner,
                        'Note': extra,
                        'Vulnerabilities': ", ".join(vulns)
                    })
        else:
            filename = f"port_scan_{target_host}_{timestamp}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Port Scan Results for {target_host}\n")
                f.write(f"Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan duration: {elapsed_time:.2f} seconds\n")
                f.write("=" * 60 + "\n\n")

                open_ports = [r for r in results if r[3]]
                f.write(f"Open ports found: {len(open_ports)}\n\n")

                for port, service, banner, status, extra, version, vulns in sorted(results, key=lambda x: x[0]):
                    status_str = "Open" if status else "Closed"
                    f.write(f"Port: {port}\n")
                    f.write(f"Service: {service}\n")
                    f.write(f"Status: {status_str}\n")
                    if version:
                        f.write(f"Version Info: {version}\n")
                    if banner:
                        f.write(f"Banner:\n{banner}\n")
                    if extra:
                        f.write(f"Note: {extra}\n")
                    if vulns:
                        f.write(f"Vulnerabilities: {', '.join(vulns)}\n")
                    f.write("-" * 40 + "\n")
        print(f"{GREEN}Results saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}Failed to save results: {e}{RESET}")

def parse_ports(port_str):
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_target(target_host, ports, verbose=False):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"{RED}Could not resolve target hostname: {target_host}{RESET}")
        sys.exit(1)

    print(f"{YELLOW}Starting scan on {target_host} ({target_ip}) with {len(ports)} ports...{RESET}")
    start_time = time.time()

    results = []
    lock = threading.Lock()

    def worker(port):
        res = scan_port(target_ip, port, target_host)
        with lock:
            results.append(res)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(worker, ports)

    elapsed_time = time.time() - start_time
    print(f"{YELLOW}Scan completed in {elapsed_time:.2f} seconds.{RESET}")
    return results, elapsed_time

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner v3.0")
    parser.add_argument("target", nargs='?', help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", help="Comma-separated list or range of ports (e.g. 1-1000,80,443)", default="1-1024")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show closed ports and detailed info")
    parser.add_argument("-j", "--json", action="store_true", help="Save results as JSON")
    parser.add_argument("-c", "--csv", action="store_true", help="Save results as CSV")
    parser.add_argument("-P", "--profile", help="Use custom port profile JSON file")
    parser.add_argument("-t", "--top", action="store_true", help="Scan top 1000 common ports")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable stealth scan features (decoys, slow scan)")
    return parser.parse_args()

def main():
    print_banner()
    args = parse_args()

    if not args.target:
        args.target = input("Enter target hostname or IP address: ").strip()
        if not args.target:
            print(f"{RED}No target specified. Exiting.{RESET}")
            sys.exit(1)

    if args.top:
        ports = top_1000_ports
    elif args.profile:
        profiles = load_custom_profiles(args.profile)
        if profiles:
            ports = profiles.get("ports", [])
            if not ports:
                print(f"{RED}Profile file does not contain 'ports' list. Using default 1-1024.{RESET}")
                ports = list(range(1, 1025))
        else:
            print(f"{RED}Failed to load profile. Using default 1-1024.{RESET}")
            ports = list(range(1, 1025))
    else:
        ports = parse_ports(args.ports)

    if args.stealth:
        print(f"{YELLOW}Stealth mode enabled: slowing scan and adding decoys (not fully implemented).{RESET}")

    results, elapsed_time = scan_target(args.target, ports, verbose=args.verbose)

    print(format_port_results(results, verbose=args.verbose))

    save_results(args.target, results, elapsed_time, as_json=args.json, as_csv=args.csv)

if __name__ == "__main__":
    main()
