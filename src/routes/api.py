import socket
import ssl

import requests
from flask import Blueprint, request, jsonify, session, send_file

from services.ai_service import generate_port_analysis, generate_db_analysis
from core.mapper import TopologyMapper
from core.osint_engine import OSINTEngine
from core.whois_lookup import WhoisLookup
from core.ip_geolocation import IPGeolocation
from core.dns_relationship_map import DNSRelationshipMap
from core.technology_detection import TechnologyDetection
from core.url_domain_intelligence import URLDomainIntelligence
from core.osint_scan import run_osint_scan
from extensions import logger
from services.report_service import export_scan_report, generate_ai_report
from services.storage_service import save_history


api_bp = Blueprint('api', __name__)


@api_bp.route('/api/save-settings', methods=['POST'])
def save_settings_api():
    """API endpoint to save scanner settings to session"""
    try:
        settings = request.get_json()
        session['scanner_settings'] = settings
        return jsonify({'status': 'success', 'message': 'Settings saved'}), 200
    except Exception as e:
        logger.exception("Error saving settings")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/get-settings', methods=['GET'])
def get_settings_api():
    """API endpoint to retrieve scanner settings from session"""
    try:
        settings = session.get('scanner_settings', {})
        return jsonify(settings), 200
    except Exception as e:
        logger.exception("Error retrieving settings")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/topology-data')
def api_topology_data():
    # In a real scenario, this pulls from your scan history
    # For testing, we return a structured graph
    mapper = TopologyMapper()
    return jsonify(mapper.generate_graph_data())


@api_bp.route('/ai_analysis', methods=['POST'])
def ai_analysis():
    """AI-powered security analysis for a specific port using Google Gemini."""
    data = request.get_json() or {}
    port = data.get('port')
    service = data.get('service', 'Unknown')
    banner = data.get('banner', 'No banner')
    severity = data.get('severity', 'Low')
    result = generate_port_analysis(port, service, banner, severity)
    status_code = result.pop('_status_code', 200)
    return jsonify(result), status_code


@api_bp.route('/db_analysis', methods=['POST'])
def db_analysis():
    """AI-powered security analysis for database vulnerabilities using Google Gemini."""
    data = request.get_json() or {}
    vuln_name = data.get('name', 'Unknown')
    vuln_description = data.get('description', '')
    vuln_evidence = data.get('evidence', '')
    risk_level = data.get('risk', 'Low')
    vuln_recommendation = data.get('recommendation', '')
    result = generate_db_analysis(
        vuln_name,
        vuln_description,
        vuln_evidence,
        risk_level,
        vuln_recommendation,
    )
    status_code = result.pop('_status_code', 200)
    return jsonify(result), status_code


@api_bp.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear all scan history"""
    try:
        save_history([])
        return jsonify({'status': 'success', 'message': 'All scan history cleared successfully'})
    except Exception as e:
        logger.exception("Error clearing history")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/export/<scan_id>', methods=['GET'])
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


@api_bp.route('/download_report', methods=['POST'])
def download_report():
    """Generate a downloadable report from AI analysis (Works for Port & DB Vulns)"""
    data = request.get_json() or {}
    analysis_text = data.get('analysis', '')
    
    if not analysis_text:
        return jsonify({'success': False, 'error': 'No analysis provided'}), 400
    
    try:
        result = generate_ai_report(analysis_text)
        if not result.get("success"):
            return jsonify({'success': False, 'error': result.get('error', 'Failed to generate report')}), result.get("_status_code", 500)
        return send_file(
            result["buffer"],
            mimetype=result["mimetype"],
            as_attachment=True,
            download_name=result["filename"],
        )
    
    except Exception as e:
        logger.exception("Error generating report")
        return jsonify({'success': False, 'error': 'Failed to generate report', 'detail': str(e)}), 500


@api_bp.route('/api/osint/<target>')
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
        logger.exception("Error in OSINT endpoint")
        return jsonify({"error": str(e)}), 500


@api_bp.route('/api/whois/lookup', methods=['POST'])
def api_whois_lookup():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '')

    try:
        result = WhoisLookup().lookup(domain)
    except ValueError as error:
        return jsonify({'status': 'ERROR', 'error': str(error)}), 400

    if result['status'] == 'ERROR':
        return jsonify(result), 503
    return jsonify(result), 200


@api_bp.route('/api/ip-geolocation', methods=['POST'])
def api_ip_geolocation():
    data = request.get_json(silent=True) or {}
    ip_address = data.get('ip', '')

    try:
        result = IPGeolocation().lookup(ip_address)
    except ValueError as error:
        return jsonify({'status': 'ERROR', 'error': str(error)}), 400

    if result['status'] in {'ERROR', 'FAILED'}:
        return jsonify(result), 503
    return jsonify(result), 200


@api_bp.route('/api/osint/dns-map', methods=['POST'])
def api_dns_relationship_map():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(DNSRelationshipMap().build(data.get('domain', ''))), 200
    except ValueError as error:
        return jsonify({'status': 'ERROR', 'error': str(error)}), 400


@api_bp.route('/api/technology-detection', methods=['POST'])
def api_technology_detection():
    data = request.get_json(silent=True) or {}
    try:
        result = TechnologyDetection().detect(data.get('domain', ''))
    except ValueError as error:
        return jsonify({'status': 'FAILED', 'error': str(error)}), 400
    return jsonify(result), 200 if result['status'] != 'FAILED' else 503


@api_bp.route('/api/url-domain-intelligence', methods=['POST'])
def api_url_domain_intelligence():
    data = request.get_json(silent=True) or {}
    try:
        result = URLDomainIntelligence().analyze(data.get('target', data.get('domain', '')), inspect_http=True)
    except ValueError as error:
        return jsonify({'status': 'FAILED', 'error': str(error)}), 400
    return jsonify(result), 200


@api_bp.route('/api/osint/scan', methods=['POST'])
def api_osint_scan():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(run_osint_scan(data.get('domain', ''))), 200
    except ValueError as error:
        return jsonify({'status': 'ERROR', 'error': str(error)}), 400
    except Exception:
        logger.exception("Error in unified OSINT scan")
        return jsonify({'status': 'ERROR', 'error': 'OSINT scan failed'}), 500


@api_bp.route('/api/analyze', methods=['GET'])
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
            response = requests.get(url, timeout=10, allow_redirects=True)
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
        logger.exception("Error in API analyze")
        return jsonify({'success': False, 'error': 'Server error'}), 500
