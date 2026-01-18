from datetime import datetime
import importlib.util
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from core.scanner import resolve_target, scan_target, check_subdomain
from core.reporter import generate_pdf_report
import json
import os
import secrets
import uuid
from flask import send_file
from dotenv import load_dotenv
from google import genai



# Load environment variables (GEMINI_API_KEY should be in .env)
load_dotenv()

# Configure the Gemini SDK correctly (global configuration)

app = Flask(__name__)

# Global Gemini client (created once)
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY not found in environment variables")

client = genai.Client(api_key=api_key)
app = Flask(__name__, 
    template_folder='../templates',
    static_folder='../static')
# Prefer env-provided secret key; generate a per-process fallback if missing
app.config['SECRET_KEY'] = (
    os.environ.get('FLASK_SECRET_KEY')
    or os.environ.get('SECRET_KEY')
    or secrets.token_hex(32)
)
# Use threading mode for broad compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Ensure absolute path for history file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Let's put it in the root (one level up from src)
HISTORY_FILE = os.path.join(os.path.dirname(BASE_DIR), "scan_history.json")


@app.context_processor
def inject_current_year():
    return {"current_year": datetime.now().year}

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"Error loading history: {e}")
            return []
    return []

def save_history(history):
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except: return None, target

# --- Professional & Mobile-Responsive UI Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnX | Security Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-main: #0a0c10;
            --bg-card: #12151c;
            --border: #232833;
            --accent: #10b981;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .hamburger {
            display: none;
            cursor: pointer;
            padding: 15px;
            position: fixed;
            top: 10px;
            left: 10px;
            z-index: 1001;
            background: var(--bg-card);
            border-radius: 8px;
        }
        .hamburger div {
            width: 30px;
            height: 3px;
            background: var(--text-primary);
            margin: 6px 0;
            transition: 0.4s;
        }
        .sidebar {
            width: 240px;
            background: #010409;
            border-right: 1px solid var(--border);
            padding: 24px;
            position: fixed;
            height: 100vh;
            top: 0;
            left: 0;
            z-index: 1000;
            transition: transform 0.3s ease;
            overflow-y: auto;
        }
        .logo {
            font-weight: 800;
            font-size: 1.5rem;
            color: var(--accent);
            letter-spacing: -1px;
            margin-bottom: 40px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .nav-item {
            padding: 12px;
            border-radius: 8px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 0.9rem;
            margin-bottom: 8px;
            display: block;
            transition: 0.2s;
        }
        .nav-item:hover, .nav-item.active {
            background: var(--bg-card);
            color: var(--text-primary);
        }
        .content {
            flex: 1;
            padding: 20px;
            margin-left: 240px;
            transition: margin-left 0.3s ease;
        }
        .header { margin-bottom: 40px; text-align: center; }
        .header h1 { font-size: 2rem; }
        .header p { color: var(--text-secondary); }
        .search-container {
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 40px;
        }
        .input-group {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 20px;
        }
        input[type="text"] {
            background: #0d1117;
            border: 1px solid var(--border);
            padding: 14px 18px;
            border-radius: 8px;
            color: white;
            font-size: 1rem;
        }
        .btn-primary {
            background: var(--accent);
            color: #000;
            font-weight: 600;
            padding: 14px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
        }
        .btn-clear {
            background: transparent;
            border: 2px solid var(--critical);
            color: var(--critical);
            padding: 14px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            width: 100%;
            font-size: 1rem;
            transition: all 0.2s;
        }
        .btn-clear:hover {
            background: rgba(239, 68, 68, 0.1);
        }
        .options-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        .terminal {
            background: #010409;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #8b949e;
            margin-bottom: 30px;
            max-height: 200px;
            overflow-y: auto;
        }
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            position: relative;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: scale(1.03);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.2);
        }
        .severity-badge {
            position: absolute;
            top: 24px;
            right: 24px;
            font-size: 0.7rem;
            text-transform: uppercase;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 20px;
        }
        .Critical { background: rgba(239, 68, 68, 0.1); color: var(--critical); }
        .High { background: rgba(249, 115, 22, 0.1); color: var(--high); }
        .Medium { background: rgba(245, 158, 11, 0.1); color: var(--medium); }
        .Low { background: rgba(16, 185, 129, 0.1); color: var(--low); }
        .port-info { font-size: 1.1rem; font-weight: 700; margin-bottom: 4px; }
        .service-name { color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 16px; }
        .banner-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            background: #0d1117;
            padding: 8px;
            border-radius: 6px;
            margin-bottom: 16px;
            word-break: break-all;
        }
        .remediation { border-top: 1px solid var(--border); padding-top: 16px; font-size: 0.85rem; }
        .remediation-label { font-weight: 600; color: var(--text-primary); display: block; margin-bottom: 4px; }
        .ai-hint {
            margin-top: 12px;
            font-size: 0.85rem;
            color: var(--accent);
            text-align: center;
        }
        footer { margin-top: 60px; padding: 20px; font-size: 0.8rem; color: #4b5563; text-align: center; }
        @media (max-width: 768px) {
            .hamburger { display: block; }
            .sidebar { transform: translateX(-100%); }
            .sidebar.open { transform: translateX(0); }
            .content { margin-left: 0; padding-top: 60px; }
            .input-group { flex-direction: column; }
            .btn-primary, .btn-clear { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="hamburger" onclick="this.parentElement.querySelector('.sidebar').classList.toggle('open')">
        <div></div><div></div><div></div>
    </div>
    <div class="sidebar">
        <div class="logo"><span>◈</span> VulnX</div>
        <a href="/" class="nav-item active">Dashboard</a>
        <a href="#" class="nav-item">Scan History</a>
        <a href="#" class="nav-item">Vulnerability Database</a>
        <a href="/subdomain" class="nav-item">Subdomain Finder</a>
        <a href="#" class="nav-item" style="margin-top:auto">Settings</a>
    </div>
    <div class="content">
        <div class="header">
            <h1>Security Scanner</h1>
            <p>Perform real-time port analysis and service finger-printing.</p>
        </div>
        <div class="search-container">
            <form method="post">
                <div class="input-group">
                    <input type="text" name="target" placeholder="Enter IP or Hostname (e.g. scanme.nmap.org)" required value="{{ original_target }}">
                    <button type="submit" class="btn-primary">Analyze Target</button>
                </div>
                <div class="options-bar">
                    <label><input type="checkbox" name="deep" {{ 'checked' if deep_scan else '' }}> Deep Scan (1-1024)</label>
                    <label><input type="checkbox" checked> OS Detection</label>
                    <label><input type="checkbox" checked> Aggressive Mode</label>
                </div>
            </form>
            {% if results is not none or log_lines %}
            <form method="post" action="/clear">
                <button type="submit" class="btn-clear">
                    🗑️ Clear Results
                </button>
            </form>
            {% endif %}
        </div>
        {% if log_lines %}
            <div class="terminal">
                {% for line in log_lines %}
                    <div>> {{ line }}</div>
                {% endfor %}
            </div>
        {% endif %}
        {% if results is not none %}
            <div class="results-grid">
                {% for port, service, banner, severity, threat in results %}
                    <div class="card" onclick="showDetailedAnalysis({{ port }}, '{{ service|replace(\"'\", \"\\'\") }}', '{{ banner|replace(\"'\", \"\\'\") }}', '{{ severity }}')">
                        <span class="severity-badge {{ severity }}">{{ severity }}</span>
                        <div class="port-info">Port {{ port }}</div>
                        <div class="service-name">{{ service }} Service Detected</div>
                        <div class="banner-text">{{ banner }}</div>
                        <div class="remediation">
                            <span class="remediation-label">Remediation Guide</span>
                            {{ threat }}
                        </div>
                        <div class="ai-hint">
                            🔍 Click for AI expert analysis
                        </div>
                    </div>
                {% endfor %}
            </div>
            {% if not results %}
                <div style="text-align: center; padding: 40px; background: var(--bg-card); border-radius: 12px;">
                    <p style="color: var(--accent); font-weight: 600;">No open ports found.</p>
                </div>
            {% endif %}
        {% endif %}
        <footer>
            VulnX Security Engine • Enterprise Version 2.0 • 2025
        </footer>
    </div>

    <script>
    // Generative AI-style analysis data pools
    const phrases = {
        intro: [
            "This open port presents significant security implications.",
            "Exposure of this service increases the attack surface.",
            "The detected service requires immediate attention.",
            "Public exposure of this port is not recommended."
        ],
        risks: [
            "brute-force attacks from automated bots",
            "credential stuffing using leaked databases",
            "exploitation of known software vulnerabilities",
            "man-in-the-middle interception",
            "unauthorized remote access attempts",
            "potential ransomware deployment vector"
        ],
        exploits: [
            "dictionary-based password attacks",
            "version-specific remote code execution",
            "privilege escalation via misconfiguration",
            "session hijacking techniques",
            "zero-day exploitation if unpatched"
        ],
        recommendations: [
            "Restrict access to trusted IP ranges only",
            "Implement strong, unique credentials",
            "Enable multi-factor authentication where possible",
            "Keep the service fully patched and updated",
            "Use encryption for all communications",
            "Monitor logs for suspicious activity",
            "Consider disabling if not strictly required",
            "Deploy intrusion detection systems"
        ],
        notes: [
            "Common target in recent ransomware campaigns",
            "Frequently scanned by threat actors",
            "Version-specific CVEs may apply",
            "High-value target for lateral movement"
        ],
        closing: [
            "Immediate hardening is strongly advised.",
            "Risk mitigation should be prioritized.",
            "Regular security audits recommended.",
            "Exposure should be minimized promptly."
        ]
    };

    function showDetailedAnalysis(port, service, banner, severity) {
        // Randomly select phrases for variety
        const intro = phrases.intro[Math.floor(Math.random() * phrases.intro.length)];
        const risks = phrases.risks.sort(() => 0.5 - Math.random()).slice(0, 3 + Math.floor(Math.random() * 2));
        const exploits = phrases.exploits.sort(() => 0.5 - Math.random()).slice(0, 2 + Math.floor(Math.random() * 2));
        const recs = phrases.recommendations.sort(() => 0.5 - Math.random()).slice(0, 4 + Math.floor(Math.random() * 3));
        const note = phrases.notes[Math.floor(Math.random() * phrases.notes.length)];
        const closing = phrases.closing[Math.floor(Math.random() * phrases.closing.length)];

        const bannerInfo = banner && banner !== "No banner response" ?
            `<strong>Detected Banner:</strong> ${banner}<br><br>` : "<strong>No version banner captured.</strong><br><br>";

        const analysis = `
            <h3 style="color:var(--accent);margin-bottom:20px;">🤖 VulnX AI Expert Analysis</h3>
            <strong>Port:</strong> ${port} (${service})<br>
            <strong>Severity:</strong> ${severity}<br><br>
            ${bannerInfo}
            <strong>Security Assessment</strong><br>
            ${intro}<br><br>

            <strong>Primary Risks</strong><br>
            • ${risks.join('<br>• ')}<br><br>

            <strong>Common Exploit Scenarios</strong><br>
            • ${exploits.join('<br>• ')}<br><br>

            <strong>Expert Recommendations</strong><br>
            • ${recs.join('<br>• ')}<br><br>

            <strong>Additional Intelligence</strong><br>
            • ${note}<br><br>

            <em>${closing}</em><br><br>
            <em>Analysis generated by VulnX Offline AI Engine • ${new Date().toLocaleString()}</em>
        `;

        // Create modal
        const modal = document.createElement('div');
        modal.id = "analysisModal";
        modal.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.85); display: flex; align-items: center;
            justify-content: center; z-index: 9999;
        `;
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        const content = document.createElement('div');
        content.style.cssText = `
            background: var(--bg-card); padding: 30px; border-radius: 12px;
            max-width: 720px; max-height: 85vh; overflow-y: auto;
            border: 1px solid var(--border); color: var(--text-primary);
        `;
        content.innerHTML = analysis + `
            <div style="text-align:center;margin-top:25px;">
                <button onclick="closeAnalysis()"
                        style="padding:12px 28px; background:var(--accent); color:black; border:none; border-radius:8px; cursor:pointer; font-weight:600;">
                    Close Analysis
                </button>
            </div>
        `;

        modal.appendChild(content);
        document.body.appendChild(modal);
    }
    </script>
    <script>
    function closeAnalysis() {
        const modal = document.getElementById("analysisModal");
        if (modal) modal.remove();
    }
    </script>
</body>
</html>
"""
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
        print(f"File saved: {HISTORY_FILE}")
    except Exception as e:
        print(f"Error saving history: {e}")

# Global storage for state
latest_results = {
    'results': None,
    'target': '',
    'deep_scan': False
}

@app.route('/', methods=['GET'])
def landing():
    return render_template('landing.html')

@app.route('/dashboard', methods=['GET'])
def index():
    return render_template(
        'dashboard.html',
        results=latest_results['results'],
        original_target=latest_results['target'],
        deep_scan=latest_results['deep_scan'],
        active_page='dashboard'
    )

@app.route('/history', methods=['GET'])
def history_page():
    history = load_history()
    print(f"Loading history page. Found {len(history)} items.")
    return render_template(
        'history.html',
        history=history,
        active_page='history'
    )

@app.route('/clear', methods=['POST'])
def clear():
    global latest_results
    latest_results = {'results': None, 'target': '', 'deep_scan': False}
    # Also clear history file for fresh start if requested? No, usually clear just UI.
    return redirect(url_for('index'))
    #return jsonify({'status': 'cleared'})  Earlier return statement commented out

@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_page():
    subdomains = []
    message = ""
    default_list = ["www", "mail", "ftp", "dev", "test", "cpanel", "api", "blog", "shop", "admin", "beta", "stage"]
    if request.method == "POST":
        domain = request.form.get("domain").strip()
        if domain:
            for sub in default_list:
                full = f"{sub}.{domain}"
                if check_subdomain(domain, sub):
                    subdomains.append(full)
            if not subdomains:
                message = "❌ No subdomains detected"
    
    return render_template('subdomain.html', subdomains=subdomains, message=message, active_page='subdomain')

@app.route('/export/<scan_id>', methods=['GET'])
def export_report(scan_id):
    history = load_history()
    scan_data = next((item for item in history if item.get('id') == scan_id), None)
    
    if not scan_data:
        return "Scan not found", 404
        
    pdf_buffer = generate_pdf_report(scan_data)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"vulnx_report_{scan_data.get('target', 'unknown')}_{scan_data.get('timestamp')}.pdf",
        mimetype='application/pdf'
    )

# WebSocket Events
@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    
    # Run scan in a background task to avoid blocking the socket handler
    socketio.start_background_task(run_scan_task, target, deep_scan)

def run_scan_task(target, deep_scan):
    print(f"Starting background scan for: {target}")
    socketio.emit('scan_log', {'message': f"Resolving target {target}..."})
    
    ip, resolved_host = resolve_target(target)
    
    if not ip:
        socketio.emit('scan_log', {'message': "❌ DNS resolution failed. Aborting."})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})
        return

    socketio.emit('scan_log', {'message': f"Target resolved to {ip}. Initializing scanning engine..."})
    
    def scan_callback(event, data):
        socketio.emit(event, data)

    try:
        scan_data = scan_target(ip, deep_scan, callback=scan_callback)
        
        # Store results
        res_list = scan_data['ports']
        latest_results['results'] = res_list
        latest_results['target'] = target
        latest_results['deep_scan'] = deep_scan
        
        history_item = {
            'id': str(uuid.uuid4()),
            'target': target,
            'ip': ip,
            'ports_found': len(res_list),
            'results': res_list, # Need to save full results for the report!
            'timestamp': scan_data['timestamp'],
            'deep_scan': deep_scan
        }
        
        # Persistent saving
        current_history = load_history()
        current_history.insert(0, history_item)
        save_history(current_history[:50])
        
        print(f"✅ Scan completed for {target}. Total ports: {len(res_list)}")
        
        socketio.emit('scan_complete', {
            'total_open': len(res_list),
            'results': res_list
        })
    except Exception as e:
        print(f"Error during scan: {e}")
        socketio.emit('scan_log', {'message': f"❌ Error: {str(e)}"})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})

if __name__ == '__main__':
    print("🚀 VulnX Professional Edition starting...")
    print(f"📍 History file location: {HISTORY_FILE}")
    print("📍 URL: http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)
