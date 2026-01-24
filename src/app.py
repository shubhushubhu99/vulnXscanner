from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_socketio import SocketIO
from src.core.scanner import resolve_target, scan_target, check_subdomain
from src.core.reporter import generate_pdf_report

# from core.scanner import resolve_target, scan_target, check_subdomain
# from core.reporter import generate_pdf_report


import importlib.util
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from core.scanner import resolve_target, scan_target, check_subdomain
from core.reporter import generate_pdf_report
import google.generativeai as genai
from dotenv import load_dotenv

import json
import os
import secrets
import uuid

from dotenv import load_dotenv
from google import genai

from flask import send_file
from dotenv import load_dotenv
from google import genai




# 🟢 Load environment variables (SAFE)
load_dotenv()


# 🟢 SINGLE Flask app init (FIXED)
app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../static'
)

# 🟢 Secure secret key

# Configure the Gemini SDK correctly (global configuration)
app = Flask(__name__, 
    template_folder='../templates',
    static_folder='../static')

# Global Gemini client (created once)
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY not found in environment variables")

client = genai.Client(api_key=api_key)
# Prefer env-provided secret key; generate a per-process fallback if missing

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
MESSAGES_FILE = os.path.join(os.path.dirname(BASE_DIR), "messages.json")

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

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        try:
            with open(MESSAGES_FILE, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            print(f"Error loading messages: {e}")
            return []
    return []

def save_message(message_data):
    try:
        messages = load_messages()
        message_data['id'] = str(uuid.uuid4())
        message_data['timestamp'] = datetime.now().isoformat()
        messages.insert(0, message_data)
        with open(MESSAGES_FILE, 'w') as f:
            json.dump(messages, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving message: {e}")
        return False

# Global storage for state

latest_results = {
    'results': None,
    'target': '',
    'deep_scan': False
}

# ---------------- ROUTES ---------------- #
# Splash screen / animation route
# Splash screen / animation route
@app.route('/', methods=['GET'])
def splash():
    # Always show animation.html first
    return render_template('animation.html')

@app.route('/dashboard', methods=['GET'])
def index():
    # Dashboard page content
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
    return render_template(
        'history.html',
        history=history,
        active_page='history'
    )

@app.route('/clear', methods=['POST'])
def clear():
    global latest_results
    latest_results = {'results': None, 'target': '', 'deep_scan': False}
    return redirect(url_for('index'))

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

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not all([name, email, subject, message]):
            return render_template('contact.html', error="All fields are required.", active_page='contact')

        message_data = {
            'name': name,
            'email': email,
            'subject': subject,
            'message': message
        }

        if save_message(message_data):
            return render_template('contact.html', success="Your message has been sent successfully!", active_page='contact')
        else:
            return render_template('contact.html', error="There was an error sending your message. Please try again later.", active_page='contact')

    return render_template('contact.html', active_page='contact')

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

@app.route('/ai_analysis', methods=['POST'])
def ai_analysis():
    """Generate AI-powered security analysis for a specific port using Google Gemini"""
    try:
        data = request.get_json()
        port = data.get('port')
        service = data.get('service', 'Unknown')
        banner = data.get('banner', 'No banner')
        severity = data.get('severity', 'Low')
        
        if not port:
            return jsonify({'error': 'Port number is required'}), 400
        
        # Create a detailed prompt for Gemini
        prompt = f"""You are a cybersecurity expert analyzing a network port scan result. Provide a comprehensive security analysis for the following:

Port: {port}
Service: {service}
Banner Information: {banner}
Severity Level: {severity}

Please provide:
1. A brief overview of what this port/service indicates
2. Common vulnerabilities associated with this service
3. Potential attack vectors
4. Security recommendations and remediation steps
5. Best practices for securing this service

Format your response in HTML with proper headings, bullet points, and emphasis on critical security concerns. Use <h3> for section headings, <ul> and <li> for lists, and <strong> for important warnings."""

        # Generate content using Gemini
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        analysis_html = response.text.strip()
        
        return jsonify({
            'analysis_html': analysis_html,
            'port': port,
            'service': service
        })
        
    except Exception as e:
        print(f"Error in AI analysis: {e}")
        return jsonify({
            'error': 'Failed to generate AI analysis',
            'detail': str(e)
        }), 500

# WebSocket Events

@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    socketio.start_background_task(run_scan_task, target, deep_scan)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

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
    print("🚀 VulnX Professional Edition starting...")
    print(f"📍 History file location: {HISTORY_FILE}")
    print("📍 URL: http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, allow_unsafe_werkzeug=True)




