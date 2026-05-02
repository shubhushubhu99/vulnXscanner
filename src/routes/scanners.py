from flask import Blueprint, render_template, request

from core.deep_subdomain_scanner import scan_subdomains_blocking
from core.directory_scanner import scan_directories_blocking
from core.database_vulnerability_scanner import scan_database_vulnerabilities_blocking
from extensions import logger


scanners_bp = Blueprint('scanners', __name__)


@scanners_bp.route('/subdomain', methods=['GET', 'POST'])
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


@scanners_bp.route('/directory', methods=['GET', 'POST'])
def directory_page():
    """Directory finder page"""
    directories = []
    message = ""
    deep_scan = False

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        deep_scan = request.form.get("deep_scan") == "on"

        if target:
            try:
                results = scan_directories_blocking(target, deep_scan=deep_scan)
                if results:
                    directories = results
                    message = f"✅ Found {len(directories)} path(s)"
                else:
                    message = "❌ No directories detected"
            except Exception as e:
                logger.error(f"Directory scan error: {e}")
                message = "❌ Scan error: " + str(e)

    return render_template('directory.html', directories=directories, message=message, active_page='directory')


@scanners_bp.route('/database-vulnerability', methods=['GET', 'POST'])
def database_vulnerability_page():
    """Database vulnerability scanner page"""
    vulnerabilities = []
    message = ""

    return render_template(
        'database_vulnerability.html',
        vulnerabilities=vulnerabilities,
        message=message,
        active_page='database-vulnerability'
    )
