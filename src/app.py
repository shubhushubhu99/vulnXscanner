# stdlib
import os
import sys
import json
import secrets
import uuid
import requests
import traceback
import socket
import ssl
from datetime import datetime
from pathlib import Path

# third-party
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask import send_file
from flask_socketio import emit

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# local
from extensions import socketio, logger, latest_results
from core.scanner import resolve_target, scan_target
from core.deep_subdomain_scanner import scan_subdomains_blocking
from core.database_vulnerability_scanner import scan_database_vulnerabilities_blocking
from core.directory_scanner import scan_directories_blocking
from core.osint_engine import OSINTEngine
from core.whois_lookup import WhoisLookup
from services.report_service import export_scan_report
from services.storage_service import HISTORY_FILE, load_history, save_history
# Configure Flask app
app = Flask(__name__, 
    template_folder='../templates',
    static_folder='../static')

socketio.init_app(app)

# Prefer env-provided secret key; generate a per-process fallback if missing
app.config['SECRET_KEY'] = (
    os.environ.get('FLASK_SECRET_KEY')

    or os.environ.get('SECRET_KEY')
    or secrets.token_hex(32)
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' wss: ws:; "
        "font-src 'self';"
    )
    response.headers.remove('Server')
    return response


@app.context_processor
def inject_current_year():
    return {"current_year": datetime.now().year}

# @app.route('/landing-v2', methods=['GET'])
# def landing_v2():
#     return render_template('landing_v2.html')


@app.route('/clear', methods=['POST'])
def clear():
    latest_results['results'] = None
    latest_results['target'] = ''
    latest_results['deep_scan'] = False
    return redirect(url_for('views.dashboard'))


@app.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear all scan history"""
    try:
        save_history([])
        return jsonify({'status': 'success', 'message': 'All scan history cleared successfully'})
    except Exception as e:
        print(f"Error clearing history: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/export/<scan_id>', methods=['GET'])
def export_report(scan_id):
    result = export_scan_report(scan_id)
    if not result["success"]:
        return result["error"], result.get("_status_code", 500)

    return send_file(
        result["buffer"],
        as_attachment=True,
        download_name=result["filename"],
        mimetype='application/pdf'
    )

@app.route('/topology')
def topology_page():
    return render_template('topology.html', active_page='topology')

@app.route('/download_report', methods=['POST'])
def download_report():
    """Generate a downloadable report from AI analysis (Works for Port & DB Vulns)"""
    data = request.get_json() or {}
    analysis_text = data.get('analysis', '')
    
    if not analysis_text:
        return jsonify({'success': False, 'error': 'No analysis provided'}), 400
    
    try:
        from io import BytesIO
        
        # Try to import reportlab for PDF generation
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
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

{analysis_text}

{'='*70}
Report generated by VulnX AI Security Scanner | Powered by Google Gemini
{'='*70}"""
            
            txt_buffer = BytesIO(report_content.encode('utf-8'))
            
            return send_file(
                txt_buffer,
                mimetype='text/plain',
                as_attachment=True,
                download_name=f'VulnX_Analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
            )
    
    except Exception as e:
        logger.error('Error generating report: %s', e)
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

@app.route('/api/analyze', methods=['GET'])
def api_analyze():
    """
    API endpoint to analyze HTTP security headers and SSL certificate health
    """
    try:
        url = request.args.get('url', '').strip()
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Security headers to check
        required_headers = {
            'Content-Security-Policy': 'High',
            'Strict-Transport-Security': 'High',
            'X-Content-Type-Options': 'Medium',
            'X-Frame-Options': 'Medium',
            'X-XSS-Protection': 'Medium',
        }
        
        exposed_headers = {
            'X-Powered-By': 'Low',
            'Server': 'Low',
            'X-AspNet-Version': 'Low',
        }
        
        results = []
        score = 50  # Start with base score
        
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Check for required security headers
            missing_headers = 0
            for header, severity in required_headers.items():
                if header in headers:
                    results.append({
                        'header': header,
                        'description': f'Good: {header} is configured correctly',
                        'status': 'Present',
                        'safe': True
                    })
                    score += 3
                else:
                    results.append({
                        'header': header,
                        'description': f'Missing: {header} should be configured for better security',
                        'status': 'Missing',
                        'safe': False
                    })
                    missing_headers += 1
            
            # Check for exposed headers (security risks)
            for header, severity in exposed_headers.items():
                if header in headers:
                    results.append({
                        'header': header,
                        'description': f'Risk: {header} reveals server information. Consider removing it.',
                        'status': f'Exposed: {headers.get(header, "N/A")[:30]}',
                        'safe': False
                    })
                    score -= 2
                else:
                    results.append({
                        'header': header,
                        'description': f'Good: {header} is not exposed',
                        'status': 'Not Exposed',
                        'safe': True
                    })
                    score += 1
            
            # Check for HTTPS
            if url.startswith('https://'):
                try:
                    # Attempt SSL/TLS check
                    no_underscore_url = url.replace('https://', '').split('/')[0]
                    sock = socket.create_connection((no_underscore_url, 443), timeout=5)
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=no_underscore_url) as ssock:
                        cert = ssock.getpeercert()
                        results.append({
                            'header': 'SSL/TLS',
                            'description': 'Good: HTTPS is enabled with valid SSL/TLS certificate',
                            'status': 'Secure',
                            'safe': True
                        })
                        score += 5
                except Exception as e:
                    results.append({
                        'header': 'SSL/TLS',
                        'description': f'Warning: SSL/TLS verification failed: {str(e)[:50]}',
                        'status': 'Warning',
                        'safe': False
                    })
            else:
                results.append({
                    'header': 'SSL/TLS',
                    'description': 'Risk: Site is not using HTTPS. All data is transmitted in plaintext.',
                    'status': 'Insecure',
                    'safe': False
                })
                score -= 10
            
            # Normalize score between 0-100
            score = max(0, min(100, score))
            
            return jsonify({
                'success': True,
                'score': score,
                'results': results,
                'url': url
            })
        
        except requests.Timeout:
            return jsonify({'success': False, 'error': 'Request timed out. Site may be unreachable.'}), 504
        except requests.ConnectionError:
            return jsonify({'success': False, 'error': 'Connection error. Cannot reach the target URL.'}), 502
        except Exception as e:
            return jsonify({'success': False, 'error': f'Failed to analyze: {str(e)[:100]}'}), 500
    
    except Exception as e:
        logger.error(f'Error in API analyze: {e}')
        return jsonify({'success': False, 'error': 'Server error'}), 500

# ------------------------------------------

# WebSocket Events
@socketio.on('start_scan')
def handle_scan(data):
    print("handle_scan HIT with data:", data)
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)
    
    # Extract settings from session (available in this request context)
    custom_threads = None
    try:
        settings = session.get('scanner_settings', {})
        if settings:
            port_settings = settings.get('portScanner', {})
            if deep_scan:
                custom_threads = port_settings.get('threadsExtended')
            else:
                custom_threads = port_settings.get('threadsDefault')
    except:
        custom_threads = None
    
    # Run scan in a background task to avoid blocking the socket handler
    socketio.start_background_task(run_scan_task, target, deep_scan, custom_threads)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

def run_scan_task(target, deep_scan, custom_threads=None):
    print(f"run_scan_task HIT: Starting background scan for: {target}")
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
    thread_count = custom_threads if custom_threads else (500 if deep_scan else 100)
    socketio.emit('scan_log', {'message': f"Using {thread_count} threads for parallel scanning..."})
    socketio.emit('scan_log', {'message': ""})
    
    def scan_callback(event, data):
        socketio.emit(event, data)

    try:
        scan_data = scan_target(ip, deep_scan, callback=scan_callback, custom_threads=custom_threads)
        
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
    
    # Extract settings from session (available in this request context)
    custom_threads = None
    try:
        settings = session.get('scanner_settings', {})
        if settings:
            subdomain_settings = settings.get('subdomainFinder', {})
            if deep_scan:
                custom_threads = subdomain_settings.get('threadsDeep')
            else:
                custom_threads = subdomain_settings.get('threadsNormal')
    except:
        custom_threads = None
    
    # Run scan in a background task
    socketio.start_background_task(run_subdomain_scan_task, domain, deep_scan, custom_threads)

def run_subdomain_scan_task(domain, deep_scan, custom_threads=None):
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
        results = scan_subdomains_blocking(domain, deep_scan=deep_scan, progress_callback=progress_callback, max_workers=custom_threads)
        
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
# DIRECTORY SCANNING
# ============================================================================

@socketio.on('start_dir_scan')
def handle_dir_scan(data):
    target = data.get('target')
    deep_scan = data.get('deep_scan', False)

    # Extract settings from session (available in this request context)
    custom_threads = None
    try:
        settings = session.get('scanner_settings', {})
        if settings:
            directory_settings = settings.get('directoryFinder', {})
            if deep_scan:
                custom_threads = directory_settings.get('threadsDeep')
            else:
                custom_threads = directory_settings.get('threadsNormal')
    except:
        custom_threads = None

    socketio.start_background_task(run_dir_scan_task, target, deep_scan, custom_threads)

def run_dir_scan_task(target, deep_scan, custom_threads=None):
    print(f"Starting background directory scan for: {target}")

    try:
        if deep_scan:
            socketio.emit('dir_scan_log', {'message': "DEEP SCAN MODE: Full directory brute-force with extensions"})
            socketio.emit('dir_scan_log', {'message': "Scanning with 20+ extensions, recursive discovery & soft-404 detection"})
        else:
            socketio.emit('dir_scan_log', {'message': "STANDARD SCAN: Checking common directories"})

        socketio.emit('dir_scan_log', {'message': ""})
        socketio.emit('dir_scan_log', {'message': f"Target: {target}"})
        socketio.emit('dir_scan_log', {'message': ""})

        def progress_callback(progress_data):
            try:
                percentage = progress_data.get('percentage', 0)
                current = progress_data.get('current', 0)
                total = progress_data.get('total', 1)
                message = progress_data.get('message', '')

                socketio.emit('dir_scan_progress', {
                    'progress_percent': percentage,
                    'current': current,
                    'total': total,
                    'current_path': message
                })
            except Exception as e:
                logger.error(f"Error in dir progress callback: {e}")

        results = scan_directories_blocking(target, deep_scan=deep_scan, progress_callback=progress_callback, max_workers=custom_threads)

        socketio.emit('dir_scan_progress', {
            'progress_percent': 100,
            'current': len(results),
            'total': len(results),
            'current_path': 'Finalizing results'
        })

        if results:
            socketio.emit('dir_scan_log', {'message': f"✓ Scan completed successfully!"})
            socketio.emit('dir_scan_log', {'message': f"Found {len(results)} path(s)"})
            socketio.emit('dir_scan_log', {'message': ""})

            for result in results:
                try:
                    if isinstance(result, dict):
                        socketio.emit('dir_found', {
                            'path': result.get('path', ''),
                            'status_code': result.get('status_code'),
                            'status_text': result.get('status_text', 'Found')
                        })
                except Exception as e:
                    logger.error(f"Error emitting dir result: {e}")
        else:
            socketio.emit('dir_scan_log', {'message': "No directories found"})

        socketio.emit('dir_scan_complete', {
            'target': target,
            'total_found': len(results),
            'results': results
        })
        print(f"Directory scan completed for {target}. Found {len(results)} results")

    except Exception as e:
        print(f"Error during directory scan: {e}")
        logger.error(f"Directory scan error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        try:
            socketio.emit('dir_scan_log', {'message': f"❌ Error: {str(e)}"})
            socketio.emit('dir_scan_complete', {'target': target, 'total_found': 0, 'results': []})
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
    
    # Extract settings from session (available in this request context)
    custom_threads = None
    try:
        settings = session.get('scanner_settings', {})
        if settings:
            database_settings = settings.get('databaseScanner', {})
            custom_threads = database_settings.get('threads')
    except:
        custom_threads = None
    
    # Run scan in background task
    socketio.start_background_task(run_db_scan_task, target, deep_scan, custom_threads)

def run_db_scan_task(target, deep_scan, custom_threads=None):
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
            progress_callback=progress_callback,
            max_workers=custom_threads
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

from routes.views import views_bp
app.register_blueprint(views_bp)
from routes.api import api_bp
app.register_blueprint(api_bp)
from routes.scanners import scanners_bp
app.register_blueprint(scanners_bp)

if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '127.0.0.1')
    print("="*60)
    print("-> VulnX Professional Security Scanner")
    print("="*60)
    print(f"-> URL: http://{HOST}:{PORT}")
    print(f"-> History file: {HISTORY_FILE}")
    print("="*60)
    print("Press CTRL+C to stop the server\n")
    socketio.run(app, host=HOST, port=PORT, debug=True, allow_unsafe_werkzeug=True)
