import socket
import threading
import queue
from datetime import datetime

common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139, 143, 161, 389, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9200]

port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch"
}

port_threats = {
    22: "SSH: Brute-force risk. Use key-auth and Fail2Ban.",
    80: "HTTP: Unencrypted. Use HSTS and redirect to 443.",
    443: "HTTPS: Check for weak TLS 1.0/1.1 protocols.",
    3389: "RDP: High Ransomware risk. Use VPN/Gateway.",
    445: "SMB: EternalBlue target. Firewall port 445.",
    21: "FTP: Cleartext creds. Use SFTP (Port 22).",
    23: "Telnet: Highly insecure. Replace with SSH.",
}

severity_map = {23: "Critical", 21: "High", 445: "High", 3389: "High", 22: "Medium", 80: "Medium", 443: "Low", 3306:"Critical"}

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = ""
        try:
            data = sock.recv(1024)
            if data: banner += data.decode('utf-8', errors='ignore').strip()
        except: pass
        if port in [80, 443, 8080, 8443]:
            try:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = sock.recv(1024)
                if response:
                    decoded = response.decode('utf-8', errors='ignore').split('\r\n')[0]
                    banner += f" ({decoded})"
            except: pass
        sock.close()
        return banner[:100] if banner else "No banner response"
    except: return "No banner response"

def scan_target(target_ip, deep_scan, callback=None):
    ports = list(range(1, 1025)) if deep_scan else common_ports
    results = []
    q = queue.Queue()
    for port in ports: q.put(port)
    
    total_ports = len(ports)
    scanned_count = 0
    lock = threading.Lock()

    def worker():
        nonlocal scanned_count
        while not q.empty():
            port = q.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(target_ip, port)
                    severity = severity_map.get(port, "Low")
                    threat = port_threats.get(port, "General exposure risk detected.")
                    res = (port, service, banner, severity, threat)
                    results.append(res)
                    if callback:
                        callback('port_found', {'port': port, 'service': service, 'banner': banner})
                sock.close()
            except: pass
            
            with lock:
                scanned_count += 1
                if callback and scanned_count % 10 == 0: # Update progress every 10 ports to reduce overhead
                    callback('scan_progress', {'current': scanned_count, 'total': total_ports, 'port': port})
            
            q.task_done()

    threads = []
    for _ in range(100):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    q.join()
    return {
        'target_ip': target_ip,
        'ports': sorted(results, key=lambda x: x[0]),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def resolve_target(target):
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except: return None, target

def check_subdomain(domain, sub):
    try:
        socket.gethostbyname(f"{sub}.{domain}")
        return True
    except:
        return False
