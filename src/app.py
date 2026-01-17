from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from core.scanner import resolve_target, scan_target, check_subdomain
import json
import os
from dotenv import load_dotenv
from google import genai
from datetime import datetime   
import traceback                

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
app.config['SECRET_KEY'] = 'vulnx_secret_key_123'
# Use threading mode for broad compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Ensure absolute path for history file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Let's put it in the root (one level up from src)
HISTORY_FILE = os.path.join(os.path.dirname(BASE_DIR), "scan_history.json")

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

@app.route('/ai_analysis', methods=['POST'])
def ai_analysis():
    data = request.json
    port = data.get('port')
    service = data.get('service')
    banner = data.get('banner')
    severity = data.get('severity')

    if not all([port, service, severity]):
        return jsonify({'error': 'Missing required parameters'}), 400

    # Debug prints (will show in terminal when request comes in)
    print("API Key loaded: True (hard-coded for testing)")
    
    try:
        prompt = f"""
You are a professional cybersecurity expert. Analyze the following open port information:
Port: {port}
Service: {service}
Banner: "{banner if banner and banner != 'No banner response' else 'No version banner captured'}"
Severity: {severity}
Provide a **structured**, **professional**, **clean** security analysis in **HTML format only** (no markdown symbols like ##, **, *, etc.).
Use the following exact structure with appropriate HTML classes for styling:
<h3 class="ai-heading">VulnX AI Security Analysis</h3>
<p class="ai-port-info"><strong>Port:</strong> {port} ({service})<br>
<strong>Severity:</strong> <span class="severity-badge {severity}">{severity}</span></p>
<div class="ai-section">
    <h4 class="ai-section-title">Security Assessment</h4>
    <p class="ai-text">[Your 2-3 sentence professional assessment here]</p>
</div>
<div class="ai-section">
    <h4 class="ai-section-title">Primary Risks</h4>
    <ul class="ai-bullet-list">
        <li>[Risk 1]</li>
        <li>[Risk 2]</li>
        <li>[Risk 3]</li>
        <li>[Risk 4 if applicable]</li>
    </ul>
</div>
<div class="ai-section">
    <h4 class="ai-section-title">Common Exploit Scenarios</h4>
    <ul class="ai-bullet-list">
        <li>[Exploit 1]</li>
        <li>[Exploit 2]</li>
        <li>[Exploit 3]</li>
    </ul>
</div>
<div class="ai-section">
    <h4 class="ai-section-title">Expert Recommendations</h4>
    <ul class="ai-bullet-list">
        <li>[Recommendation 1]</li>
        <li>[Recommendation 2]</li>
        <li>[Recommendation 3]</li>
        <li>[Recommendation 4]</li>
        <li>[Recommendation 5]</li>
    </ul>
</div>
<div class="ai-section">
    <h4 class="ai-section-title">Additional Intelligence</h4>
    <p class="ai-text">[1-2 sentences about recent trends, CVEs, or notes]</p>
</div>
<p class="ai-closing"><em>{severity} severity issue – Immediate action recommended.</em></p>
<p class="ai-footer">
    <em>Generated by VulnX AI • {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</em>
</p>
Use professional language, be concise, and focus on real cybersecurity best practices.
        """

        response = client.models.generate_content(   # ← Correct: client.models.
            model="gemini-2.5-flash",               # or "gemini-2.5-flash-latest"
            contents=[prompt]                       # ← List!
        )

        raw_html = response.text.strip()
        raw_html = raw_html.replace('**', '').replace('__', '').replace(' - ', ' • ')

        return jsonify({
            'analysis_html': raw_html,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    except Exception as e:
        print("Gemini API Error:", str(e))
        traceback.print_exc()
        return jsonify({
            'error': 'Failed to generate AI analysis',
            'detail': str(e)
        }), 500



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
            'target': target,
            'ip': ip,
            'ports_found': len(res_list),
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
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)