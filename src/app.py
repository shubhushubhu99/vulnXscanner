# from datetime import datetime
# import importlib.util
# from flask import Flask, render_template, request, jsonify, redirect, url_for
# from flask_socketio import SocketIO, emit
# from core.scanner import resolve_target, scan_target, check_subdomain
# from core.reporter import generate_pdf_report
# from dotenv import load_dotenv              # ✅ FIX 1
# import google.generativeai as genai          # ✅ FIX 2
# import json
# import os
# import secrets
# import uuid
# from flask import send_file

# # edited down two lines
# from dotenv import load_dotenv
# import google.generativeai as genai

# # Load environment variables (GEMINI_API_KEY should be in .env)
# load_dotenv()

# # Configure the Gemini SDK correctly (global configuration)

# app = Flask(__name__)

# # Global Gemini client (created once)
# api_key = os.getenv("GEMINI_API_KEY")

# if not api_key:
#     raise ValueError("GEMINI_API_KEY not found in environment variables")

# client = genai.Client(api_key=api_key)
# app = Flask(__name__, 
#     template_folder='../templates',
#     static_folder='../static')
# # Prefer env-provided secret key; generate a per-process fallback if missing
# app.config['SECRET_KEY'] = (
#     os.environ.get('FLASK_SECRET_KEY')
#     or os.environ.get('SECRET_KEY')
#     or secrets.token_hex(32)
# )
# # Use threading mode for broad compatibility
# socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# # Ensure absolute path for history file
# BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# # Let's put it in the root (one level up from src)
# HISTORY_FILE = os.path.join(os.path.dirname(BASE_DIR), "scan_history.json")


# @app.context_processor
# def inject_current_year():
#     return {"current_year": datetime.now().year}

# def load_history():
#     if os.path.exists(HISTORY_FILE):
#         try:
#             with open(HISTORY_FILE, 'r') as f:
#                 data = json.load(f)
#                 return data if isinstance(data, list) else []
#         except Exception as e:
#             print(f"Error loading history: {e}")
#             return []
#     return []

# def save_history(history):
#     try:
#         with open(HISTORY_FILE, 'w') as f:
#             json.dump(history, f, indent=4)
#         print(f"File saved: {HISTORY_FILE}")
#     except Exception as e:
#         print(f"Error saving history: {e}")

# # Global storage for state
# latest_results = {
#     'results': None,
#     'target': '',
#     'deep_scan': False
# }
# # edited🔽
# # @app.route('/', methods=['GET'])
# # def landing():
# #     return render_template('landing.html')

# @app.route('/', methods=['GET'])
# def animation():
#     return render_template('animation.html')

# @app.route('/home', methods=['GET'])
# def landing():
#     return render_template('landing.html')
# # newly done⬆️

# @app.route('/dashboard', methods=['GET'])
# def index():
#     return render_template(
#         'dashboard.html',
#         results=latest_results['results'],
#         original_target=latest_results['target'],
#         deep_scan=latest_results['deep_scan'],
#         active_page='dashboard'
#     )

# @app.route('/history', methods=['GET'])
# def history_page():
#     history = load_history()
#     print(f"Loading history page. Found {len(history)} items.")
#     return render_template(
#         'history.html',
#         history=history,
#         active_page='history'
#     )

# @app.route('/clear', methods=['POST'])
# def clear():
#     global latest_results
#     latest_results = {'results': None, 'target': '', 'deep_scan': False}
#     # Also clear history file for fresh start if requested? No, usually clear just UI.
#     return redirect(url_for('index'))
#     #return jsonify({'status': 'cleared'})  Earlier return statement commented out

# @app.route('/subdomain', methods=['GET', 'POST'])
# def subdomain_page():
#     subdomains = []
#     message = ""
#     default_list = ["www", "mail", "ftp", "dev", "test", "cpanel", "api", "blog", "shop", "admin", "beta", "stage"]
#     if request.method == "POST":
#         domain = request.form.get("domain").strip()
#         if domain:
#             for sub in default_list:
#                 full = f"{sub}.{domain}"
#                 if check_subdomain(domain, sub):
#                     subdomains.append(full)
#             if not subdomains:
#                 message = "❌ No subdomains detected"
    
#     return render_template('subdomain.html', subdomains=subdomains, message=message, active_page='subdomain')

# @app.route('/export/<scan_id>', methods=['GET'])
# def export_report(scan_id):
#     history = load_history()
#     scan_data = next((item for item in history if item.get('id') == scan_id), None)
    
#     if not scan_data:
#         return "Scan not found", 404
        
#     pdf_buffer = generate_pdf_report(scan_data)
    
#     return send_file(
#         pdf_buffer,
#         as_attachment=True,
#         download_name=f"vulnx_report_{scan_data.get('target', 'unknown')}_{scan_data.get('timestamp')}.pdf",
#         mimetype='application/pdf'
#     )

# # WebSocket Events
# @socketio.on('start_scan')
# def handle_scan(data):
#     target = data.get('target')
#     deep_scan = data.get('deep_scan', False)
    
#     # Run scan in a background task to avoid blocking the socket handler
#     socketio.start_background_task(run_scan_task, target, deep_scan)

# def run_scan_task(target, deep_scan):
#     print(f"Starting background scan for: {target}")
#     socketio.emit('scan_log', {'message': f"Resolving target {target}..."})
    
#     ip, resolved_host = resolve_target(target)
    
#     if not ip:
#         socketio.emit('scan_log', {'message': "❌ DNS resolution failed. Aborting."})
#         socketio.emit('scan_complete', {'total_open': 0, 'results': []})
#         return

#     socketio.emit('scan_log', {'message': f"Target resolved to {ip}. Initializing scanning engine..."})
    
#     def scan_callback(event, data):
#         socketio.emit(event, data)

#     try:
#         scan_data = scan_target(ip, deep_scan, callback=scan_callback)
        
#         # Store results
#         res_list = scan_data['ports']
#         latest_results['results'] = res_list
#         latest_results['target'] = target
#         latest_results['deep_scan'] = deep_scan
        
#         history_item = {
#             'id': str(uuid.uuid4()),
#             'target': target,
#             'ip': ip,
#             'ports_found': len(res_list),
#             'results': res_list, # Need to save full results for the report!
#             'timestamp': scan_data['timestamp'],
#             'deep_scan': deep_scan
#         }
        
#         # Persistent saving
#         current_history = load_history()
#         current_history.insert(0, history_item)
#         save_history(current_history[:50])
        
#         print(f"✅ Scan completed for {target}. Total ports: {len(res_list)}")
        
#         socketio.emit('scan_complete', {
#             'total_open': len(res_list),
#             'results': res_list
#         })
#     except Exception as e:
#         print(f"Error during scan: {e}")
#         socketio.emit('scan_log', {'message': f"❌ Error: {str(e)}"})
#         socketio.emit('scan_complete', {'total_open': 0, 'results': []})

# if __name__ == '__main__':
#     print("🚀 VulnX Professional Edition starting...")
#     print(f"📍 History file location: {HISTORY_FILE}")
#     print("📍 URL: http://127.0.0.1:5000")
#     socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)
# ----------------------------------------------------
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_socketio import SocketIO
from core.scanner import resolve_target, scan_target, check_subdomain
from core.reporter import generate_pdf_report

import json
import os
import secrets
import uuid

# 🟢 Load environment variables (SAFE)
from dotenv import load_dotenv
load_dotenv()

# 🟢 SINGLE Flask app init (FIXED)
app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static'
)

# 🟢 Secure secret key
app.config['SECRET_KEY'] = (
    os.environ.get('FLASK_SECRET_KEY')
    or os.environ.get('SECRET_KEY')
    or secrets.token_hex(32)
)

# 🟢 SocketIO (stable mode)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# 🟢 Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(os.path.dirname(BASE_DIR), "scan_history.json")

# 🟢 Inject current year into templates
@app.context_processor
def inject_current_year():
    return {"current_year": datetime.now().year}

# ---------------- HISTORY ---------------- #

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"Error loading history: {e}")
    return []

def save_history(history):
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
        print(f"File saved: {HISTORY_FILE}")
    except Exception as e:
        print(f"Error saving history: {e}")

# ---------------- STATE ---------------- #

latest_results = {
    'results': None,
    'target': '',
    'deep_scan': False
}

# ---------------- ROUTES ---------------- #

# 🎬 Animation page (ROOT)
@app.route('/', methods=['GET'])
def animation():
    return render_template('animation.html')

# 🛡️ Dashboard
@app.route('/dashboard', methods=['GET'])
def index():
    return render_template(
        'dashboard.html',
        results=latest_results['results'],
        original_target=latest_results['target'],
        deep_scan=latest_results['deep_scan'],
        active_page='dashboard'
    )

# 📜 History
@app.route('/history', methods=['GET'])
def history_page():
    history = load_history()
    return render_template(
        'history.html',
        history=history,
        active_page='history'
    )

# 🧹 Clear current scan
@app.route('/clear', methods=['POST'])
def clear():
    global latest_results
    latest_results = {'results': None, 'target': '', 'deep_scan': False}
    return redirect(url_for('index'))

# 🌐 Subdomain checker
@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_page():
    subdomains = []
    message = ""
    default_list = ["www", "mail", "ftp", "dev", "test", "cpanel", "api", "blog", "shop", "admin", "beta", "stage"]

    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if domain:
            for sub in default_list:
                if check_subdomain(domain, sub):
                    subdomains.append(f"{sub}.{domain}")
            if not subdomains:
                message = "❌ No subdomains detected"

    return render_template(
        'subdomain.html',
        subdomains=subdomains,
        message=message,
        active_page='subdomain'
    )

# 📄 Export PDF
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
        download_name=f"vulnx_report_{scan_data.get('target','unknown')}_{scan_data.get('timestamp')}.pdf",
        mimetype='application/pdf'
    )

# ---------------- SOCKET EVENTS ---------------- #

@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    socketio.start_background_task(run_scan_task, target, deep_scan)

def run_scan_task(target, deep_scan):
    socketio.emit('scan_log', {'message': f"Resolving target {target}..."})

    ip, _ = resolve_target(target)
    if not ip:
        socketio.emit('scan_log', {'message': "❌ DNS resolution failed"})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})
        return

    socketio.emit('scan_log', {'message': f"Target resolved to {ip}. Scanning..."})

    def scan_callback(event, data):
        socketio.emit(event, data)

    try:
        scan_data = scan_target(ip, deep_scan, callback=scan_callback)

        res_list = scan_data['ports']
        latest_results.update({
            'results': res_list,
            'target': target,
            'deep_scan': deep_scan
        })

        history_item = {
            'id': str(uuid.uuid4()),
            'target': target,
            'ip': ip,
            'ports_found': len(res_list),
            'results': res_list,
            'timestamp': scan_data['timestamp'],
            'deep_scan': deep_scan
        }

        history = load_history()
        history.insert(0, history_item)
        save_history(history[:50])

        socketio.emit('scan_complete', {
            'total_open': len(res_list),
            'results': res_list
        })

    except Exception as e:
        socketio.emit('scan_log', {'message': f"❌ Error: {str(e)}"})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})

# ---------------- RUN ---------------- #

if __name__ == '__main__':
    print("🚀 VulnX Scanner started")
    print("🌐 http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)
