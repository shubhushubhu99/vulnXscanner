# CyberScan Elite - FIXED & Enhanced (No Errors, Better Banner Grabbing)

from flask import Flask, render_template_string, request
import socket
import threading
from datetime import datetime
import queue

app = Flask(__name__)

# === Port & Service Data ===
common_ports = [22, 80, 443, 3389, 445, 21, 23, 25, 53, 110, 135, 137, 138, 139, 143, 161, 162, 389, 3306, 5432, 5900, 8080, 8443, 9200]

port_services = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS RPC", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS/SMB", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP Alternate", 8443: "HTTPS Alternate",
    9200: "Elasticsearch",
}

port_threats = {
    22: "SSH: Prime target for brute-force & exploits. Patch & use key auth!",
    80: "HTTP: Unencrypted. Prone to injection attacks & MITM.",
    443: "HTTPS: Secure TLS needed; watch for weak ciphers & app flaws.",
    3389: "RDP: Ransomware favorite! Disable if unused, enforce NLA.",
    445: "SMB: EternalBlue legacy. Block externally & patch!",
    21: "FTP: Plaintext creds. Switch to SFTP immediately.",
    23: "Telnet: Zero encryption. Replace with SSH now!",
}

# === FIXED grab_banner function ===
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Slightly increased for reliability
        sock.connect((ip, port))
        
        banner = ""
        
        # First, try to receive any automatic banner
        try:
            initial = sock.recv(1024)
            if initial:
                banner += initial.decode('utf-8', errors='ignore').strip()
        except:
            pass
        
        # For HTTP/HTTPS ports, send GET request if needed
        if port in [80, 443, 8080, 8443]:
            try:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(2048)  # Larger buffer for headers
                if response:
                    decoded = response.decode('utf-8', errors='ignore').strip()
                    if decoded:
                        banner += ("\n" + decoded) if banner else decoded
            except:
                pass
        
        sock.close()
        
        if banner:
            return banner[:500]  # Increased limit slightly for better info
        else:
            return "No banner grabbed"
    except:
        return "No banner grabbed"

# === Rest of the functions (unchanged) ===
def scan_target(target_ip, port_range):
    ports_to_scan = {
        "common": common_ports,
        "1-1024": list(range(1, 1025)),
        "1-10000": list(range(1, 10001))
    }[port_range]

    results = []
    q = queue.Queue()
    for port in ports_to_scan:
        q.put(port)

    def worker():
        while not q.empty():
            port = q.get()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    service = port_services.get(port, "Unknown")
                    banner = grab_banner(target_ip, port)
                    results.append((port, service, banner))
                sock.close()
            except:
                pass
            q.task_done()

    for _ in range(60):  # Slightly more threads for speed
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
    q.join()

    results.sort(key=lambda x: x[0])
    return results

def resolve_target(target):
    target = target.strip()
    try:
        socket.inet_aton(target)
        return target, target
    except:
        try:
            resolved_ip = socket.gethostbyname(target)
            return resolved_ip, target
        except:
            return None, target

# === Same Stunning Cyberpunk UI (No Changes Needed) ===
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberScan Elite</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=Rajdhani:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0e17;
            --glass: rgba(20, 25, 40, 0.6);
            --border: rgba(0, 255, 255, 0.3);
            --neon-cyan: #00ffff;
            --neon-pink: #ff00ff;
            --neon-green: #39ff14;
            --text: #e0ffff;
            --warning: #ff2d55;
        }
        body {
            font-family: 'Rajdhani', sans-serif;
            background: var(--bg) url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100" height="100" fill="%230a0e17"/><path d="M0,50 L100,50" stroke="%23002233" stroke-width="0.5"/><path d="M50,0 L50,100" stroke="%23002233" stroke-width="0.5"/></svg>') repeat;
            color: var(--text);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }
        body::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: radial-gradient(circle at 50% 50%, rgba(0,255,255,0.05) 0%, transparent 70%);
            pointer-events: none;
            animation: pulse 10s infinite alternate;
        }
        @keyframes pulse { 0% { opacity: 0.3; } 100% { opacity: 0.6; } }
        .container { max-width: 1100px; margin: 40px auto; position: relative; z-index: 1; }
        header { text-align: center; margin-bottom: 50px; }
        h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 4rem;
            background: linear-gradient(90deg, var(--neon-cyan), var(--neon-pink));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 20px var(--neon-cyan);
            animation: glow 2s infinite alternate;
        }
        @keyframes glow { from { text-shadow: 0 0 20px var(--neon-cyan); } to { text-shadow: 0 0 40px var(--neon-pink); } }
        .subtitle { font-size: 1.4rem; color: var(--neon-green); text-shadow: 0 0 10px var(--neon-green); }
        .warning-box {
            background: rgba(255, 45, 85, 0.15);
            border: 1px solid var(--warning);
            padding: 20px;
            border-radius: 15px;
            margin: 30px 0;
            text-align: center;
            box-shadow: 0 0 20px rgba(255,45,85,0.3);
        }
        .scan-card {
            background: var(--glass);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 8px 32px rgba(0,255,255,0.2);
            margin-bottom: 40px;
        }
        label { display: block; margin: 25px 0 10px; font-size: 1.3rem; color: var(--neon-cyan); text-shadow: 0 0 10px var(--neon-cyan); }
        input, select {
            width: 100%;
            padding: 16px;
            background: rgba(0,0,0,0.4);
            border: 1px solid var(--neon-cyan);
            border-radius: 12px;
            color: white;
            font-size: 1.1rem;
            box-shadow: 0 0 15px rgba(0,255,255,0.3);
            transition: all 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            box-shadow: 0 0 25px var(--neon-cyan);
        }
        button {
            margin-top: 30px;
            width: 100%;
            padding: 18px;
            background: linear-gradient(45deg, var(--neon-cyan), var(--neon-pink));
            color: black;
            font-weight: bold;
            font-size: 1.4rem;
            border: none;
            border-radius: 15px;
            cursor: pointer;
            box-shadow: 0 0 30px rgba(0,255,255,0.6);
            transition: all 0.4s;
        }
        button:hover {
            transform: translateY(-5px);
            box-shadow: 0 0 50px rgba(255,0,255,0.8);
        }
        .result-info { background: rgba(0,255,255,0.1); padding: 20px; border-radius: 15px; border-left: 5px solid var(--neon-cyan); }
        .port-card {
            background: var(--glass);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            box-shadow: 0 8px 25px rgba(0,0,0,0.4);
            transition: all 0.4s;
        }
        .port-card:hover { transform: translateY(-8px); box-shadow: 0 15px 40px rgba(0,255,255,0.4); }
        .open { color: var(--neon-green); font-weight: bold; text-shadow: 0 0 15px var(--neon-green); }
        .threat { background: rgba(255,45,85,0.2); padding: 15px; border-radius: 10px; margin-top: 15px; border-left: 4px solid var(--warning); }
        code { background: rgba(0,0,0,0.5); padding: 12px; border-radius: 8px; display: block; overflow-x: auto; white-space: pre-wrap; box-shadow: 0 0 15px rgba(0,255,255,0.2); }
        footer { text-align: center; margin-top: 80px; color: #666; font-size: 1rem; text-shadow: 0 0 5px var(--neon-cyan); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CYBERSCAN ELITE</h1>
            <p class="subtitle">Next-Gen Port Intelligence • Neon Threat Matrix • Elite Recon Tool</p>
        </header>

        <div class="warning-box">
            ⚠️ <strong>ETHICAL SCANNING ONLY</strong> • Target systems you own or have permission for.<br>
            Example targets: 127.0.0.1 • scanme.nmap.org • github.com
        </div>

        <div class="scan-card">
            <form method="post">
                <label>🎯 TARGET LOCK (IP / Domain)</label>
                <input type="text" name="target" placeholder="e.g., scanme.nmap.org" required value="{{ original_target }}">

                <label>🔥 SCAN MODE</label>
                <select name="range">
                    <option value="common">RAPID STRIKE (Common Ports)</option>
                    <option value="1-1024">PRECISION SWEEP (1-1024)</option>
                    <option value="1-10000">DEEP INFILTRATION (1-10000)</option>
                </select>

                <button type="submit">⚡ INITIATE BREACH SCAN</button>
            </form>
        </div>

        {% if results is not none %}
            <div class="scan-card">
                {% if resolved_ip %}
                    <div class="result-info">
                        <strong>LOCKED ON:</strong> {{ original_target }} → <strong>IP:</strong> {{ resolved_ip }}
                    </div>
                {% else %}
                    <div class="warning-box">❌ TARGET RESOLUTION FAILED</div>
                {% endif %}

                {% if results %}
                    <h2 style="color: var(--neon-green); text-align: center; text-shadow: 0 0 20px;">{{ results|length }} VULNERABLE PORTS EXPOSED</h2>
                    {% for port, service, banner in results %}
                        <div class="port-card">
                            <h3><span class="open">PORT {{ port }}/TCP • BREACHED</span> — {{ service }}</h3>
                            {% if "No banner" not in banner %}
                                <p><strong>SERVICE FINGERPRINT:</strong><br><code>{{ banner }}</code></p>
                            {% endif %}
                            <div class="threat">
                                <strong>🔴 THREAT VECTOR:</strong> {{ port_threats.get(port, "Exposed port expands attack surface – fortify immediately!") }}
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    {% if resolved_ip %}
                        <div style="text-align:center; padding:60px; color:var(--neon-green);">
                            <h2>🔒 HARDENED TARGET – NO OPEN PORTS</h2>
                            <p>Firewall active or services stealth-mode. Impressive defenses.</p>
                        </div>
                    {% endif %}
                {% endif %}
            </div>
        {% endif %}

        <footer>
            CyberScan Elite • 2025 • Futuristic Recon Engine • Ethical Hacking Only
        </footer>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    original_target = ""
    resolved_ip = None

    if request.method == 'POST':
        original_target = request.form['target'].strip()
        port_range = request.form['range']

        resolved_ip, _ = resolve_target(original_target)

        if resolved_ip:
            results = scan_target(resolved_ip, port_range)
        else:
            results = []

    return render_template_string(
        HTML_TEMPLATE,
        results=results,
        original_target=original_target,
        resolved_ip=resolved_ip,
        port_threats=port_threats
    )

if __name__ == '__main__':
    print("⚡ CyberScan Elite launching... [FIXED VERSION]")
    print("Enter the matrix: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)