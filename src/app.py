from datetime import datetime
import importlib.util
import sys
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit
from core.scanner import resolve_target, scan_target, check_subdomain
from core.reporter import generate_pdf_report
from core.deep_subdomain_scanner import scan_subdomains_blocking
from core.database_vulnerability_scanner import scan_database_vulnerabilities_blocking
import json
import os
import secrets
import uuid
from flask import send_file
from dotenv import load_dotenv
import requests
import logging
import traceback

from core.mapper import TopologyMapper
from core.osint_engine import OSINTEngine
try:
    # New GenAI SDK
    from google import genai
except Exception:
    genai = None
from core.whois_lookup import WhoisLookup


# Load environment variables (GEMINI_API_KEY should be in .env)
load_dotenv()

# Configure Flask app
app = Flask(__name__, 
    template_folder='../templates',
    static_folder='../static')

# Gemini API key (may be absent in some environments)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_OAUTH_TOKEN = os.getenv("GEMINI_OAUTH_TOKEN")
# Optional explicit auth type: 'api_key' or 'bearer'. If unset, we auto-detect.
GEMINI_AUTH_TYPE = os.getenv("GEMINI_AUTH_TYPE")
# Model name (configurable)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnx.gemini")
if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not set; AI analysis endpoints will return a helpful error.")
else:
    if genai is not None:
        try:
            try:
                # initialize client from new SDK only when using API key auth
                if GEMINI_API_KEY and (GEMINI_AUTH_TYPE != 'bearer'):
                    genai_client = genai.Client(api_key=GEMINI_API_KEY)
                    logger.info('Initialized google.genai client')
                else:
                    genai_client = None
            except Exception as e:
                genai_client = None
                logger.warning('google.genai client init failed: %s', e)
        except Exception:
            genai_client = None
    else:
        genai_client = None
# Prefer env-provided secret key; generate a per-process fallback if missing
app.config['SECRET_KEY'] = (
    os.environ.get('FLASK_SECRET_KEY')

    or os.environ.get('SECRET_KEY')
    or secrets.token_hex(32)
)
# Use threading mode for broad compatibility
# Configure with longer timeouts and ping/pong to keep connection alive during long scans
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    ping_timeout=120,  # 120 seconds before ping is considered lost
    ping_interval=30,  # Send ping every 30 seconds to keep connection alive
    engineio_logger=False,
    socketio_logger=False
)

# Ensure absolute path for history file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Let's put it in the root (one level up from src)
HISTORY_FILE = os.path.join(os.path.dirname(BASE_DIR), "scan_history.json")
MESSAGES_FILE = os.path.join(os.path.dirname(BASE_DIR), "messages.json")


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
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=4)
        print(f"File saved: {HISTORY_FILE}")
    except Exception as e:
        print(f"Error saving history: {e}")

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

@app.route('/', methods=['GET'])
def landing():
    return render_template('landing.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
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
    return redirect(url_for('dashboard'))
    #return jsonify({'status': 'cleared'})  Earlier return statement commented out

@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear all scan history"""
    try:
        global latest_results
        # Clear the history file
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'w') as f:
                json.dump([], f, indent=4)
        return jsonify({'status': 'success', 'message': 'All scan history cleared successfully'})
    except Exception as e:
        print(f"Error clearing history: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/subdomain', methods=['GET', 'POST'])
def subdomain_page():
    subdomains = []
    message = ""
    deep_scan = False
    
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        deep_scan = request.form.get("deep_scan") == "on"
        
        if domain:
            try:
                # Use the new deep subdomain scanner
                results = scan_subdomains_blocking(domain, deep_scan=deep_scan)
                
                if results:
                    # Format results for display
                    formatted_results = []
                    for result in results:
                        if isinstance(result, dict):
                            formatted_results.append(result)
                        else:
                            formatted_results.append({
                                'subdomain': str(result),
                                'status_code': None,
                                'status_text': 'Found',
                                'dns_records': {}
                            })
                    
                    subdomains = formatted_results
                    message = f"✅ Found {len(subdomains)} subdomain(s)"
                else:
                    message = "❌ No subdomains detected"
                    
            except Exception as e:
                logger.error(f"Subdomain scan error: {e}")
                message = "❌ Scan error: " + str(e)
    
    return render_template('subdomain.html', subdomains=subdomains, message=message, active_page='subdomain')

@app.route('/database-vulnerability', methods=['GET', 'POST'])
def database_vulnerability_page():
    """Database vulnerability scanner page"""
    vulnerabilities = []
    message = ""
    
    return render_template('database_vulnerability.html', vulnerabilities=vulnerabilities, message=message, active_page='database-vulnerability')

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
        download_name=f"vulnx_report_{scan_data.get('target', 'unknown')}_{scan_data.get('timestamp')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/topology')
def topology_page():
    return render_template('topology.html', active_page='topology')

@app.route('/api/topology-data')
def api_topology_data():
    # In a real scenario, this pulls from your scan history
    # For testing, we return a structured graph
    mapper = TopologyMapper() 
    return jsonify(mapper.generate_graph_data())


@app.route('/ai_analysis', methods=['POST'])
def ai_analysis():
    """Generate AI-powered security analysis for a specific port using Google Gemini"""
    data = request.get_json() or {}
    port = data.get('port')
    service = data.get('service', 'Unknown')
    banner = data.get('banner', 'No banner')
    severity = data.get('severity', 'Low')

    if not port:
        return jsonify({'success': False, 'error': 'Port number is required'}), 400

    # Validate API key availability
    if not GEMINI_API_KEY:
        logger.error('Gemini API key not configured when calling /ai_analysis')
        return jsonify({'success': False, 'error': 'Gemini API key not configured'}), 503

    # Build optimized, concise prompt for fast response with PLAIN TEXT ONLY output
    prompt = f"""Analyze this port scan result in SIMPLE words for non-technical users.

CRITICAL: Output ONLY plain text. NO HTML tags. NO markdown. NO formatting symbols.

Port: {port}
Service: {service}
Banner: {banner}
Risk: {severity}

RESPONSE FORMAT (EXACTLY as shown):

1. **What is this port?**
[1-2 lines explaining simply]

2. **Why is it risky?**
* [Risk point]
* [Risk point]
* [Risk point]

3. **How to secure it?**
* [Action]
* [Action]
* [Action]
* [Action]

4. **Risk score:** [LOW/MEDIUM/HIGH/CRITICAL]

RULES:
- Use ONLY asterisks (*) for bullet points
- Use ONLY numbers and dots (1. 2. 3.) for lists
- NO HTML tags whatsoever
- SHORT sentences only
- Simple English, NO technical jargon
- Keep under 200 words total"""

    # Prefer the new GenAI SDK when available (cleaner auth + built-in retries)
    if genai is not None and 'genai_client' in globals() and genai_client:
        try:
            logger.info('Calling Gemini via google.genai SDK')
            # Use same pattern as working test script: pass contents as a string
            sdk_resp = genai_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt
            )

            # Many SDK responses expose .text for the generated content
            analysis_text = None
            if hasattr(sdk_resp, 'text') and sdk_resp.text:
                analysis_text = sdk_resp.text
            else:
                # Fallback: try to normalize to JSON-like structure and extract text
                try:
                    if hasattr(sdk_resp, 'to_dict'):
                        resp_json = sdk_resp.to_dict()
                    elif hasattr(sdk_resp, '__dict__'):
                        resp_json = json.loads(json.dumps(sdk_resp, default=lambda o: getattr(o, '__dict__', str(o))))
                    else:
                        resp_json = json.loads(json.dumps(sdk_resp))
                except Exception:
                    resp_json = str(sdk_resp)

                def extract_text(obj):
                    if not obj:
                        return ''
                    if isinstance(obj, str):
                        return obj
                    if isinstance(obj, dict):
                        for key in ('candidates', 'content', 'text', 'output', 'response'):
                            if key in obj:
                                val = obj[key]
                                if isinstance(val, list) and val:
                                    parts = [extract_text(v) for v in val]
                                    return ' '.join([p for p in parts if p])
                                if isinstance(val, dict):
                                    return extract_text(val)
                                if isinstance(val, str):
                                    return val
                        for v in obj.values():
                            t = extract_text(v)
                            if t:
                                return t
                    if isinstance(obj, list):
                        for item in obj:
                            t = extract_text(item)
                            if t:
                                return t
                    return ''

                analysis_text = extract_text(resp_json)

            if not analysis_text:
                analysis_text = json.dumps(resp_json)

            return jsonify({'success': True, 'data': {'analysis_html': analysis_text, 'port': port, 'service': service}})

        except Exception as e:
            logger.error('google.genai SDK call failed: %s', e)
            logger.debug(traceback.format_exc())
            # fall through to REST fallback

    # Prepare request to the Gemini REST endpoint (fallback)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
    # Default: send API key as query param. Some Gemini setups accept API key (?key=),
    # while service-account/OAuth needs an Authorization: Bearer <access_token> header.
    params = {'key': GEMINI_API_KEY}
    headers = {'Content-Type': 'application/json'}

    # Heuristic: if the provided key looks like an OAuth access token, use it as Bearer.
    if isinstance(GEMINI_API_KEY, str) and (GEMINI_API_KEY.startswith('ya29.') or GEMINI_API_KEY.lower().startswith('bearer ')):
        token = GEMINI_API_KEY
        if token.lower().startswith('bearer '):
            token = token.split(' ', 1)[1]
        headers['Authorization'] = f'Bearer {token}'
    else:
        logger.debug('Using GEMINI_API_KEY as query param (no Authorization header).')

    payload = {
        'contents': [
            {
                'parts': [
                    {'text': prompt}
                ]
            }
        ]
    }

    # Timeout in seconds
    timeout_seconds = 12

    try:
        logger.info('Sending request to Gemini endpoint for port %s', port)
        resp = requests.post(url, headers=headers, params=params, json=payload, timeout=timeout_seconds)

        # Detailed logging for debugging
        logger.info('Gemini response status: %s', resp.status_code)

        if resp.status_code == 429:
            logger.warning('Gemini rate limit hit (429)')
            return jsonify({'success': False, 'error': 'Rate limit exceeded. Please try again later.'}), 429

        if resp.status_code == 401:
            logger.error('Gemini returned 401 Unauthorized. Check GEMINI_API_KEY value and type (API key vs OAuth token).')
            return jsonify({'success': False, 'error': 'Unauthorized: invalid Gemini API key or token. Check configuration.'}), 401

        if resp.status_code >= 400:
            # Log body for investigation, but avoid leaking secrets
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            logger.error('Gemini API returned error %s: %s', resp.status_code, body)
            return jsonify({'success': False, 'error': 'Gemini API error', 'status': resp.status_code, 'detail': body}), resp.status_code

        # Parse response JSON and try to extract generated text
        resp_json = resp.json()

        # Helper: attempt to find a textual output in common response shapes
        def extract_text(obj):
            if not obj:
                return ''
            if isinstance(obj, str):
                return obj.strip()
            if isinstance(obj, dict):
                # common fields
                for key in ('content', 'text', 'output', 'candidates', 'response'):
                    if key in obj:
                        val = obj[key]
                        if isinstance(val, list) and val:
                            # join texts recursively
                            parts = [extract_text(v) for v in val if extract_text(v)]
                            return ' '.join(parts)
                        if isinstance(val, dict):
                            return extract_text(val)
                        if isinstance(val, str):
                            return val.strip()
                # otherwise search deeper
                for v in obj.values():
                    t = extract_text(v)
                    if t:
                        return t
            if isinstance(obj, list):
                for item in obj:
                    t = extract_text(item)
                    if t:
                        return t
            return ''

        analysis_text = extract_text(resp_json)
        if not analysis_text:
            analysis_text = json.dumps(resp_json)

        # Return plain text (no HTML wrapping), frontend will handle display
        return jsonify({'success': True, 'data': {'analysis_html': analysis_text, 'port': port, 'service': service}})

    except requests.Timeout:
        logger.exception('Gemini request timed out')
        return jsonify({'success': False, 'error': 'Gemini request timed out'}), 504
    except requests.RequestException as e:
        # Generic network/transport error
        logger.error('Network error when calling Gemini: %s', e)
        logger.debug(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Network error when calling Gemini', 'detail': str(e)}), 502
    except Exception as e:
        # Catch-all to prevent server crash
        logger.error('Unexpected error during AI analysis: %s', e)
        logger.debug(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to generate AI analysis', 'detail': str(e)}), 500


@app.route('/download_report', methods=['POST'])
def download_report():
    """Generate a downloadable report from AI analysis"""
    data = request.get_json() or {}
    analysis_text = data.get('analysis', '')
    port = data.get('port', 'Unknown')
    service = data.get('service', 'Unknown')
    
    if not analysis_text:
        return jsonify({'success': False, 'error': 'No analysis provided'}), 400
    
    try:
        from io import BytesIO
        
        # Try to import reportlab for PDF generation
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
            from reportlab.lib import colors
            
            # Create PDF in memory
            pdf_buffer = BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            story = []
            
            # Define styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#10b981'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#10b981'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Add header
            story.append(Paragraph('VulnX Security Analysis Report', title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Add metadata table
            metadata = [
                ['Port', str(port)],
                ['Service', str(service)],
                ['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Tool', 'VulnX AI Scanner']
            ]
            
            metadata_table = Table(metadata, colWidths=[1.5*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0fdf4')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0d3f2a')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db'))
            ]))
            
            story.append(metadata_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Add analysis heading
            story.append(Paragraph('AI Security Analysis', heading_style))
            
            # Format analysis text into readable paragraphs
            analysis_paragraphs = analysis_text.split('\n')
            for para in analysis_paragraphs:
                if para.strip():
                    story.append(Paragraph(para.strip(), styles['Normal']))
                    story.append(Spacer(1, 0.05*inch))
            
            # Add footer
            story.append(Spacer(1, 0.3*inch))
            story.append(Paragraph(
                '<font size=8 color="#999999">Report generated by VulnX AI Security Scanner | Powered by Google Gemini</font>',
                styles['Normal']
            ))
            
            # Build PDF
            doc.build(story)
            pdf_buffer.seek(0)
            
            return send_file(
                pdf_buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'VulnX_Analysis_Port_{port}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
            )
            
        except ImportError:
            # Fallback to TXT format if reportlab not available
            logger.info('reportlab not available, generating TXT report instead')
            
            report_content = f"""{'='*70}
VulnX SECURITY ANALYSIS REPORT
{'='*70}

SCAN DETAILS:
Port: {port}
Service: {service}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool: VulnX AI Scanner

{'='*70}
AI ANALYSIS:
{'='*70}

{analysis_text}

{'='*70}
Report generated by VulnX AI Security Scanner | Powered by Google Gemini
{'='*70}"""
            
            txt_buffer = BytesIO(report_content.encode('utf-8'))
            
            return send_file(
                txt_buffer,
                mimetype='text/plain',
                as_attachment=True,
                download_name=f'VulnX_Analysis_Port_{port}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
            )
    
    except Exception as e:
        logger.error('Error generating report: %s', e)
        logger.debug(traceback.format_exc())
        return jsonify({'success': False, 'error': 'Failed to generate report', 'detail': str(e)}), 500

        
# --- OSINT & RECON MODULE (NEW FEATURE) ---

@app.route('/osint')
def osint_page():
    """Renders the new OSINT Reconnaissance dashboard."""
    return render_template('osint.html', active_page='osint')

@app.route('/api/osint/<target>')
def api_osint(target):
    """
    API endpoint for OSINT data. 
    Keeps logic separate from the main port scanner.
    """
    try:
        engine = OSINTEngine(target)
        whois = WhoisLookup()
        
        results = {
            "dns": engine.get_dns_records(),
            "social": engine.scan_social_presence(),
            "whois": whois.get_data(target)
        }
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------------------------

# WebSocket Events
@socketio.on('start_scan')
def handle_scan(data):
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    
    # Run scan in a background task to avoid blocking the socket handler
    socketio.start_background_task(run_scan_task, target, deep_scan)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

def run_scan_task(target, deep_scan):
    print(f"Starting background scan for: {target}")
    
    if deep_scan:
        socketio.emit('scan_log', {'message': "DEEP SCAN MODE: Scanning port range 1-65535"})
        socketio.emit('scan_log', {'message': "Estimated time: 5-15 minutes (depending on server responsiveness)"})
        socketio.emit('scan_log', {'message': "High resource usage - scanning all 65,535 ports"})
        socketio.emit('scan_log', {'message': ""})
    else:
        socketio.emit('scan_log', {'message': "STANDARD SCAN: Scanning common ports 1-1024"})
        socketio.emit('scan_log', {'message': ""})
    
    socketio.emit('scan_log', {'message': f"Resolving target {target}..."})
    
    ip, resolved_host = resolve_target(target)
    
    if not ip:
        socketio.emit('scan_log', {'message': "❌ DNS resolution failed. Aborting."})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})
        return

    socketio.emit('scan_log', {'message': f"Target resolved to {ip}. Initializing scanning engine..."})
    socketio.emit('scan_log', {'message': f"Using {'500 threads' if deep_scan else '100 threads'} for parallel scanning..."})
    socketio.emit('scan_log', {'message': ""})
    
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
        
        print(f"Scan completed for {target}. Total ports found: {len(res_list)}")
        
        socketio.emit('scan_complete', {
            'total_open': len(res_list),
            'results': res_list
        })
    except Exception as e:
        print(f"Error during scan: {e}")
        socketio.emit('scan_log', {'message': f"❌ Error: {str(e)}"})
        socketio.emit('scan_complete', {'total_open': 0, 'results': []})

@socketio.on('start_subdomain_scan')
def handle_subdomain_scan(data):
    domain = data.get('domain')
    deep_scan = data.get('deep_scan', False)
    
    # Run scan in a background task
    socketio.start_background_task(run_subdomain_scan_task, domain, deep_scan)

def run_subdomain_scan_task(domain, deep_scan):
    print(f"Starting background subdomain scan for: {domain}")
    
    try:
        if deep_scan:
            socketio.emit('subdomain_log', {'message': "DEEP SCAN MODE: Full DNS brute-force enumeration"})
            socketio.emit('subdomain_log', {'message': "Scanning 50k+ wordlist with permutations and recursive scanning"})
        else:
            socketio.emit('subdomain_log', {'message': "STANDARD SCAN: Checking common 12 subdomains"})
        
        socketio.emit('subdomain_log', {'message': ""})
        socketio.emit('subdomain_log', {'message': f"Target: {domain}"})
        socketio.emit('subdomain_log', {'message': ""})
        
        def progress_callback(progress_data):
            """Callback to emit socket events during scanning"""
            try:
                percentage = progress_data.get('percentage', 0)
                current = progress_data.get('current', 0)
                total = progress_data.get('total', 1)
                message = progress_data.get('message', '')
                
                socketio.emit('subdomain_progress', {
                    'progress_percent': percentage,
                    'current': current,
                    'total': total,
                    'current_subdomain': message
                })
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
        
        # Use the blocking function with custom callback for progress
        results = scan_subdomains_blocking(domain, deep_scan=deep_scan, progress_callback=progress_callback)
        
        # Emit completion progress
        socketio.emit('subdomain_progress', {
            'progress_percent': 100,
            'current': len(results),
            'total': len(results),
            'current_subdomain': 'Finalizing results'
        })
        
        if results:
            socketio.emit('subdomain_log', {'message': f"✓ Scan completed successfully!"})
            socketio.emit('subdomain_log', {'message': f"Found {len(results)} valid subdomain(s)"})
            socketio.emit('subdomain_log', {'message': ""})
            
            for result in results:
                try:
                    if isinstance(result, dict):
                        status = result.get('status_text', 'Found')
                        socketio.emit('subdomain_found', {
                            'subdomain': result.get('subdomain', ''),
                            'status_text': status
                        })
                except Exception as e:
                    logger.error(f"Error emitting subdomain result: {e}")
        else:
            socketio.emit('subdomain_log', {'message': "No subdomains found"})
        
        # Emit completion event with all results
        socketio.emit('scan_complete', {
            'domain': domain,
            'total_found': len(results),
            'results': results
        })
        print(f"Subdomain scan completed for {domain}. Found {len(results)} results")
        
    except Exception as e:
        print(f"Error during subdomain scan: {e}")
        logger.error(f"Subdomain scan error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        try:
            socketio.emit('subdomain_log', {'message': f"❌ Error: {str(e)}"})
            socketio.emit('scan_complete', {'domain': domain, 'total_found': 0, 'results': []})
        except Exception as emit_error:
            logger.error(f"Failed to emit error message: {emit_error}")

# ============================================================================
# DATABASE VULNERABILITY SCANNING
# ============================================================================

@socketio.on('start_db_scan')
def handle_db_scan(data):
    """Handle database vulnerability scan request"""
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    
    if not target:
        emit('db_scan_log', {'message': "[ERROR] No target specified"})
        return
    
    # Run scan in background task
    socketio.start_background_task(run_db_scan_task, target, deep_scan)

def run_db_scan_task(target, deep_scan):
    """Background task for database vulnerability scanning"""
    print(f"Starting background database vulnerability scan for: {target}")
    
    try:
        socketio.emit('db_scan_log', {'message': f"Starting database vulnerability scan for {target}"})
        socketio.emit('db_scan_log', {'message': ""})
        
        if deep_scan:
            socketio.emit('db_scan_log', {'message': "DEEP SCAN MODE: Extended checks enabled"})
            socketio.emit('db_scan_log', {'message': "Testing SQL injection, exposed ports, sensitive files, headers, and CORS"})
        else:
            socketio.emit('db_scan_log', {'message': "STANDARD SCAN: Running basic vulnerability checks"})
        
        socketio.emit('db_scan_log', {'message': ""})
        
        def progress_callback(progress_data):
            """Callback to emit socket events during scanning"""
            try:
                percentage = progress_data.get('percentage', 0)
                current = progress_data.get('current', 0)
                total = progress_data.get('total', 1)
                message = progress_data.get('message', '')
                
                socketio.emit('db_scan_progress', {
                    'progress_percent': percentage,
                    'current': current,
                    'total': total,
                    'message': message
                })
            except Exception as e:
                logger.error(f"Error in DB progress callback: {e}")
        
        # Run the blocking scan function
        results = scan_database_vulnerabilities_blocking(
            target, 
            deep_scan=deep_scan, 
            progress_callback=progress_callback
        )
        
        # Emit completion
        socketio.emit('db_scan_progress', {
            'progress_percent': 100,
            'current': 1,
            'total': 1,
            'message': 'Finalizing results'
        })
        
        if results:
            socketio.emit('db_scan_log', {'message': f"Scan completed successfully!"})
            socketio.emit('db_scan_log', {'message': f"Found {len(results)} vulnerability(ies)"})
            socketio.emit('db_scan_log', {'message': ""})
            
            # Count vulnerabilities by risk
            critical_count = sum(1 for r in results if r.get('risk') == 'Critical')
            high_count = sum(1 for r in results if r.get('risk') == 'High')
            medium_count = sum(1 for r in results if r.get('risk') == 'Medium')
            low_count = sum(1 for r in results if r.get('risk') == 'Low')
            
            if critical_count > 0:
                socketio.emit('db_scan_log', {'message': f"[CRITICAL] Critical: {critical_count}"})
            if high_count > 0:
                socketio.emit('db_scan_log', {'message': f"[HIGH] High: {high_count}"})
            if medium_count > 0:
                socketio.emit('db_scan_log', {'message': f"[MEDIUM] Medium: {medium_count}"})
            if low_count > 0:
                socketio.emit('db_scan_log', {'message': f"[LOW] Low: {low_count}"})
        else:
            socketio.emit('db_scan_log', {'message': "No vulnerabilities detected!"})
        
        # Emit completion with all results
        socketio.emit('db_scan_complete', {
            'target': target,
            'total_vulnerabilities': len(results),
            'results': results
        })
        
        print(f"Database vulnerability scan completed for {target}. Found {len(results)} vulnerabilities")
        
    except Exception as e:
        print(f"Error during database vulnerability scan: {e}")
        logger.error(f"Database scan error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        try:
            socketio.emit('db_scan_log', {'message': f"[ERROR] {str(e)}"})

            socketio.emit('db_scan_complete', {'target': target, 'total_vulnerabilities': 0, 'results': []})
        except Exception as emit_error:
            logger.error(f"Failed to emit error message: {emit_error}")

if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    print("="*60)
    print("🚀 VulnX Professional Security Scanner")
    print("="*60)
    print(f"📍 URL: http://{HOST}:{PORT}")
    print(f"📝 History file: {HISTORY_FILE}")
    print("="*60)
    print("Press CTRL+C to stop the server\n")
    socketio.run(app, host=HOST, port=PORT, debug=True, allow_unsafe_werkzeug=True)

