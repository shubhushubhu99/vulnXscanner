from io import BytesIO

from core.reporter import generate_pdf_report
from services.storage_service import load_history


def generate_scan_report(scan_data) -> BytesIO:
    """Generate a PDF report buffer for a single scan payload."""
    return generate_pdf_report(scan_data)


def get_scan_by_id(scan_id) -> dict | None:
    """Fetch a scan record by id from persisted history."""
    history = load_history()
    return next((item for item in history if item.get('id') == scan_id), None)


def export_scan_report(scan_id):
    """Prepare exported report data for a scan id."""
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        return {"success": False, "error": "Scan not found", "_status_code": 404}

    pdf_buffer = generate_scan_report(scan_data)
    filename = f"vulnx_report_{scan_data.get('target', 'unknown')}_{scan_data.get('timestamp')}.pdf"

    return {
        "success": True,
        "buffer": pdf_buffer,
        "filename": filename,
    }
