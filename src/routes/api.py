from flask import Blueprint, request, jsonify, session

from services.ai_service import generate_port_analysis, generate_db_analysis
from core.mapper import TopologyMapper
from extensions import logger


api_bp = Blueprint('api', __name__)


@api_bp.route('/api/save-settings', methods=['POST'])
def save_settings_api():
    """API endpoint to save scanner settings to session"""
    try:
        settings = request.get_json()
        session['scanner_settings'] = settings
        return jsonify({'status': 'success', 'message': 'Settings saved'}), 200
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/api/get-settings', methods=['GET'])
def get_settings_api():
    """API endpoint to retrieve scanner settings from session"""
    try:
        settings = session.get('scanner_settings', {})
        return jsonify(settings), 200
    except Exception as e:
        logger.error(f"Error retrieving settings: {e}")
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
