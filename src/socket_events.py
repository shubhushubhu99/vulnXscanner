import uuid
import traceback

from flask import session
from flask_socketio import emit

from core.database_vulnerability_scanner import scan_database_vulnerabilities_blocking
from core.deep_subdomain_scanner import scan_subdomains_blocking
from core.directory_scanner import scan_directories_blocking
from core.scanner import resolve_target, scan_target
from extensions import socketio, logger, latest_results
from services.storage_service import load_history, save_history
from services.vulnerability.cve_service import get_cves_for_service


def _emit_log(port, message):
    socketio.emit('cve_log', {'port': port, 'message': message})

def run_cve_enrichment_task(target, port, service, banner):
    import time
    from services.vulnerability.banner_parser import parse_banner
    from services.vulnerability.cpe_mapper import map_to_cpe
    from services.vulnerability.cve_service import fetch_cves_for_cpe

    _emit_log(port, f"🔍 Parsing banner for port {port} ({service})...")
    time.sleep(0.1)

    if not banner or banner.strip() in ["", "No banner response"]:
        _emit_log(port, "⚠️ No banner available. Cannot determine product version.")
        _emit_log(port, "❌ CVE lookup aborted — no banner data.")
        socketio.emit('cve_results', {
            'status': 'no_cpe_match', 'target': target, 'port': port,
            'service': service, 'product': None, 'version': None,
            'resolved_cpe': None, 'cve_count': 0, 'cves': []
        })
        return

    vendor, product, version = parse_banner(service, banner)
    if product:
        _emit_log(port, f"✅ Identified: {vendor or '?'} / {product} / {version or 'unknown'}")
    else:
        _emit_log(port, f"⚠️ Could not extract product from banner: '{banner[:60]}'")
        _emit_log(port, "❌ CVE lookup aborted — banner not recognized.")
        socketio.emit('cve_results', {
            'status': 'no_cpe_match', 'target': target, 'port': port,
            'service': service, 'product': None, 'version': None,
            'resolved_cpe': None, 'cve_count': 0, 'cves': []
        })
        return

    _emit_log(port, f"🔗 Looking up CPE in NVD dictionary for: {product} {version}...")
    cpe = map_to_cpe(vendor, product, version)

    if cpe:
        _emit_log(port, f"✅ CPE resolved: {cpe}")
    else:
        _emit_log(port, "❌ Could not resolve CPE. Skipping CVE lookup.")
        socketio.emit('cve_results', {
            'status': 'no_cpe_match', 'target': target, 'port': port,
            'service': service, 'product': product, 'version': version,
            'resolved_cpe': None, 'cve_count': 0, 'cves': []
        })
        return

    _emit_log(port, f"🛡️ Querying NVD CVE 2.0 API...")
    _emit_log(port, f"   → Endpoint: services.nvd.nist.gov")
    _emit_log(port, f"   → CPE: {cpe}")

    try:
        cves = fetch_cves_for_cpe(cpe)
        _emit_log(port, f"📦 Received {len(cves)} vulnerabilit{'y' if len(cves)==1 else 'ies'} from NVD.")
        if cves:
            critical = sum(1 for c in cves if c.severity == 'CRITICAL')
            high = sum(1 for c in cves if c.severity == 'HIGH')
            _emit_log(port, f"   🔴 Critical: {critical}  🟠 High: {high}  🟡 Others: {len(cves)-critical-high}")
        _emit_log(port, "✅ Done. Rendering results...")

        cve_data = {
            'status': 'success', 'target': target, 'port': port, 'service': service,
            'product': product, 'version': version, 'resolved_cpe': cpe,
            'cve_count': len(cves), 'cves': [c.to_dict() for c in cves]
        }
        socketio.emit('cve_results', cve_data)

    except Exception as e:
        logger.error(f"Error fetching CVEs for port {port}: {e}")
        _emit_log(port, f"❌ NVD API error: {str(e)[:80]}")
        socketio.emit('cve_results', {
            'status': 'error', 'target': target, 'port': port,
            'service': service, 'cve_count': 0, 'cves': []
        })


def register_socket_events():
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
                'results': res_list,  # Need to save full results for the report!
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

    @socketio.on('fetch_cve')
    def handle_fetch_cve(data):
        target = data.get('target', 'Unknown')
        port = data.get('port')
        service = data.get('service')
        banner = data.get('banner')
        if port and service:
            socketio.start_background_task(run_cve_enrichment_task, target, port, service, banner)

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
            logger.error(traceback.format_exc())
            try:
                socketio.emit('subdomain_log', {'message': f"❌ Error: {str(e)}"})
                socketio.emit('scan_complete', {'domain': domain, 'total_found': 0, 'results': []})
            except Exception as emit_error:
                logger.error(f"Failed to emit error message: {emit_error}")

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
            logger.error(traceback.format_exc())
            try:
                socketio.emit('dir_scan_log', {'message': f"❌ Error: {str(e)}"})
                socketio.emit('dir_scan_complete', {'target': target, 'total_found': 0, 'results': []})
            except Exception as emit_error:
                logger.error(f"Failed to emit error message: {emit_error}")

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
            logger.error(traceback.format_exc())
            
            try:
                socketio.emit('db_scan_log', {'message': f"[ERROR] {str(e)}"})
                socketio.emit('db_scan_complete', {'target': target, 'total_vulnerabilities': 0, 'results': []})
            except Exception as emit_error:
                logger.error(f"Failed to emit error message: {emit_error}")
