from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from core.scanner import resolve_target, scan_target, check_subdomain
import json
import os

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
    return jsonify({'status': 'cleared'})

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