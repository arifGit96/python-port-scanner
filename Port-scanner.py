import socket
import time
from concurrent.futures import ThreadPoolExecutor

COMMON_SERVICES = {
21: "FTP",
22: "SSH",
23: "TELNET",
25: "SMTP",
53: "DNS",
80: "HTTP",
110: "POP3",
143: "IMAP",
443: "HTTPS",
445: "SMB",
3389: "RDP",
20: "FTP-DATA",
161: "SNMP",
162: "SNMP-TRAP",
8080: "HTTP-ALT",
8443: "HTTPS-ALT",
3306: "MySQL",
5432: "PostgreSQL",
6379: "Redis",
27017: "MongoDB",
1723: "PPTP",
}

open_ports = []
results = []

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024)
            return banner.decode(errors="ignore").strip()
    except:
        return None

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
            scanner.settimeout(0.5)
            result = scanner.connect_ex((target_ip, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                print(f"[+] Port {port:<5} OPEN ({service})")
                banner = grab_banner(target_ip, port)
                open_ports.append((port, service))
                results.append(f"Port {port} OPEN ({service})")
                if banner:
                    print(f"    Banner: {banner}")
                    results.append(f"Banner: {banner}")
    except Exception:
        pass


print("=" * 50)
print("PYTHON PORT SCANNER (MULTITHREADED)")
print("=" * 50)

target = input("Enter Target IP or Hostname: ")

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("[-] Invalid hostname or IP address.")
    exit()

try:
    start_port = int(input("Enter Start Port: "))
    end_port = int(input("Enter End Port: "))
except ValueError:
    print("[-] Invalid port number.")
    exit()

print("\n" + "=" * 50)
print(f"Target      : {target}")
print(f"Resolved IP : {target_ip}")
print(f"Port Range  : {start_port}-{end_port}")
print("=" * 50)

start_time = time.time()

with ThreadPoolExecutor(max_workers=100) as executor:
    executor.map(scan_port, range(start_port, end_port + 1))

end_time = time.time()

print("\n" + "=" * 50)
print("SCAN RESULTS")
print("=" * 50)

if open_ports:
    print(f"Total Open Ports Found: {len(open_ports)}\n")
    for port, service in sorted(open_ports):
        print(f"{port}/tcp\t{service}")
else:
    print("No open ports found.")

with open("scan_results.txt", "w") as file:
    file.write(f"Target: {target}\n")
    file.write(f"IP Address: {target_ip}\n")
    file.write(f"Port Range: {start_port}-{end_port}\n\n")
    for line in results:
        file.write(line + "\n")

print("\nResults saved to scan_results.txt")
print(f"\nScan completed in {end_time - start_time:.2f} seconds")
