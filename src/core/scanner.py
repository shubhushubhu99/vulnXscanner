import socket
import threading
import queue
import re
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

def is_ipv6(address):
    """Check if an address is IPv6 format"""
    if not address or not isinstance(address, str):
        return False
    try:
        # Use socket.inet_pton for strict validation
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except (socket.error, OSError, AttributeError):
        # Fallback: check for basic IPv6 format (but be stricter)
        # Must have colons and valid hex characters
        if '::' in address:
            # Compressed format - check it's valid
            parts = address.split('::')
            if len(parts) > 2:
                return False  # Can only have one ::
            # Check each part
            for part in address.split(':'):
                if part and not re.match(r'^[0-9a-fA-F]{1,4}$', part):
                    return False
            return True
        else:
            # Full format - must have exactly 7 colons and 8 parts
            parts = address.split(':')
            if len(parts) != 8:
                return False
            for part in parts:
                if not re.match(r'^[0-9a-fA-F]{1,4}$', part):
                    return False
            return True

def is_ipv4(address):
    """Check if an address is IPv4 format"""
    if not address or not isinstance(address, str):
        return False
    # Validate format first (must have 4 octets)
    parts = address.split('.')
    if len(parts) != 4:
        return False
    try:
        # Check each part is a valid number 0-255
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        # Use socket.inet_aton for final validation
        socket.inet_aton(address)
        return True
    except (socket.error, ValueError):
        return False

def get_address_family(address):
    """Determine the socket address family for an IP address"""
    if is_ipv6(address):
        return socket.AF_INET6
    elif is_ipv4(address):
        return socket.AF_INET
    else:
        return None

def grab_banner(ip, port, address_family=None, timeout=3):
    """Grab banner from a port with protocol-specific handling, supporting both IPv4 and IPv6"""
    if address_family is None:
        address_family = get_address_family(ip)
        if address_family is None:
            return "Invalid IP address"
    
    try:
        sock = socket.socket(address_family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = ""
        
        # Protocol-specific banner grabbing
        if port == 21:  # FTP
            try:
                # FTP usually sends banner immediately, but we can try a simple command
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                else:
                    # Try sending a minimal command to elicit response
                    sock.send(b"USER anonymous\r\n")
                    response = sock.recv(1024)
                    if response:
                        banner = response.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                return f"FTP banner timeout ({timeout}s)"
            except:
                return "FTP service detected (no banner)"
                
        elif port == 22:  # SSH
            try:
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    # SSH banners often contain version info
                    if "SSH-" in banner:
                        return f"SSH: {banner[:100]}"
            except socket.timeout:
                return f"SSH banner timeout ({timeout}s)"
            except:
                pass
                
        elif port == 23:  # Telnet
            try:
                data = sock.recv(1024)
                if data:
                    # Telnet banners might contain binary data, clean it up
                    banner = data.decode('utf-8', errors='ignore').strip()
                    # Remove non-printable characters
                    banner = ''.join(c for c in banner if c.isprintable())
                    if banner:
                        return f"Telnet: {banner[:100]}"
            except socket.timeout:
                return f"Telnet banner timeout ({timeout}s)"
            except:
                pass
                
        elif port == 25:  # SMTP
            try:
                # SMTP usually sends banner immediately
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner.startswith("220"):
                        return f"SMTP: {banner[:100]}"
                else:
                    # Try EHLO command
                    sock.send(b"EHLO vulnscanner\r\n")
                    response = sock.recv(1024)
                    if response:
                        banner = response.decode('utf-8', errors='ignore').strip()
                        return f"SMTP: {banner[:100]}"
            except socket.timeout:
                return f"SMTP banner timeout ({timeout}s)"
            except:
                return "SMTP service detected (no banner)"
                
        elif port == 110:  # POP3
            try:
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner.startswith("+OK"):
                        return f"POP3: {banner[:100]}"
            except socket.timeout:
                return f"POP3 banner timeout ({timeout}s)"
            except:
                return "POP3 service detected (no banner)"
                
        elif port == 143:  # IMAP
            try:
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    if banner.startswith("* OK"):
                        return f"IMAP: {banner[:100]}"
            except socket.timeout:
                return f"IMAP banner timeout ({timeout}s)"
            except:
                return "IMAP service detected (no banner)"
                
        elif port == 3306:  # MySQL
            try:
                data = sock.recv(1024)
                if data and len(data) > 3:
                    # MySQL handshake packet contains version info
                    version_end = data.find(b'\x00', 5)
                    if version_end > 5:
                        version = data[5:version_end].decode('utf-8', errors='ignore')
                        return f"MySQL: {version[:50]}"
            except socket.timeout:
                return f"MySQL banner timeout ({timeout}s)"
            except:
                return "MySQL service detected (no banner)"
                
        elif port == 5432:  # PostgreSQL
            try:
                # PostgreSQL doesn't send unsolicited banner, but we can try a startup message
                # For now, just check if connection succeeds
                return "PostgreSQL service detected"
            except socket.timeout:
                return f"PostgreSQL banner timeout ({timeout}s)"
            except:
                return "PostgreSQL service detected (no banner)"
                
        elif port in [80, 443, 8080, 8443]:  # HTTP/HTTPS
            try:
                # For IPv6, use bracket notation in Host header
                host_header = f"[{ip}]" if address_family == socket.AF_INET6 else ip
                request = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: VulnXScanner/1.0\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(1024)
                if response:
                    decoded = response.decode('utf-8', errors='ignore')
                    lines = decoded.split('\r\n')
                    if lines and lines[0].startswith('HTTP'):
                        status_line = lines[0]
                        server_header = ""
                        for line in lines[1:]:
                            if line.lower().startswith('server:'):
                                server_header = line.split(':', 1)[1].strip()
                                break
                        if server_header:
                            return f"HTTP: {status_line} (Server: {server_header})"
                        else:
                            return f"HTTP: {status_line}"
            except socket.timeout:
                return f"HTTP banner timeout ({timeout}s)"
            except:
                return "HTTP service detected (no banner)"
        
        # Generic banner grabbing for other ports
        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                # Clean up non-printable characters
                banner = ''.join(c for c in banner if c.isprintable() and c not in '\r\n\t')
                if banner:
                    return f"Service banner: {banner[:100]}"
        except socket.timeout:
            return f"Banner timeout ({timeout}s)"
        except:
            pass
            
        sock.close()
        return "Service detected (no banner)"
        
    except socket.timeout:
        return f"Connection timeout ({timeout}s)"
    except ConnectionRefusedError:
        return "Connection refused"
    except OSError as e:
        return f"Connection error: {str(e)}"
    except Exception as e:
        return f"Banner grab failed: {str(e)}"

def scan_target(target_ip, deep_scan, callback=None):
    """Scan target IP (IPv4 or IPv6) for open ports"""
    # Determine address family
    address_family = get_address_family(target_ip)
    if address_family is None:
        raise ValueError(f"Invalid IP address format: {target_ip}")
    
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
                sock = socket.socket(address_family, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(target_ip, port, address_family)
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
    """Resolve target to IP address, supporting both IPv4 and IPv6"""
    if not target or not isinstance(target, str):
        return None, target if target else ""
    
    target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    
    # Handle empty string after stripping
    if not target:
        return None, ""
    
    # Remove brackets from IPv6 addresses if present (e.g., [2001:db8::1])
    if target.startswith('[') and target.endswith(']'):
        target = target[1:-1]
    
    # Check if it's already an IP address
    if is_ipv4(target) or is_ipv6(target):
        return target, target
    
    # Try to resolve as hostname - prefer IPv4 first, then IPv6
    try:
        # Try IPv4 first
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        # If IPv4 fails, try IPv6
        try:
            # Get IPv6 address using getaddrinfo
            addrinfo = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
            if addrinfo:
                ip = addrinfo[0][4][0]
                return ip, target
        except (socket.gaierror, OSError):
            pass
    
    return None, target

def check_subdomain(domain, sub):
    try:
        socket.gethostbyname(f"{sub}.{domain}")
        return True
    except:
        return False
