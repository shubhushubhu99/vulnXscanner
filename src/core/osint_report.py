"""Report data normalization and PDF rendering for a unified OSINT scan."""

from datetime import datetime
from io import BytesIO
from re import sub
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    PageBreak,
    Spacer,
    Table,
    TableStyle,
)


PAGE_WIDTH, PAGE_HEIGHT = letter
DARK = colors.HexColor("#0b1220")
DARKER = colors.HexColor("#070b13")
PANEL = colors.HexColor("#111827")
BORDER = colors.HexColor("#334155")
TEXT = colors.HexColor("#e2e8f0")
MUTED = colors.HexColor("#94a3b8")
GREEN = colors.HexColor("#34d399")

MODULE_KEYS = (
    ("Domain Intelligence", "url_domain_intelligence"),
    ("WHOIS", "whois"),
    ("DNS", "dns_relationship_map"),
    ("DNS Relationship Map", "dns_relationship_map"),
    ("IP Geolocation", "ip_geolocation"),
    ("Technology Detection", "technology_detection"),
)


def _usable(value):
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in {"", "null", "undefined", "not available", "not publicly available"}
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _text(value):
    if not _usable(value):
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(item for item in (_text(item) for item in value) if item)
    if isinstance(value, dict):
        return ", ".join(f"{_text(key)}: {_text(item)}" for key, item in value.items() if _usable(item))
    return str(value)


def _paragraph(value, style):
    return Paragraph(escape(_text(value)).replace("\n", "<br/>") or "", style)


def _status(value):
    return str((value or {}).get("status", "UNAVAILABLE")).upper()


def _safe_filename(value):
    cleaned = sub(r"[^A-Za-z0-9._-]+", "-", _text(value))
    return cleaned.strip(".-") or "unknown"


def _dns_records(scan_data):
    dns_map = scan_data.get("dns_relationship_map") or {}
    nodes = {node.get("id"): node for node in dns_map.get("nodes", []) if isinstance(node, dict)}
    edges = [edge for edge in dns_map.get("edges", []) if isinstance(edge, dict)]
    records = []
    for edge in edges:
        record_type = edge.get("relationship")
        if not record_type:
            continue
        record_node_id = edge.get("target")
        for value_edge in edges:
            if value_edge.get("source") != record_node_id:
                continue
            value = nodes.get(value_edge.get("target"), {}).get("label")
            if _usable(value):
                records.append((record_type, value, ""))
    return records


def build_osint_report_data(scan_data, generated_at=None):
    """Normalize the current unified OSINT response for report rendering."""
    scan_data = scan_data if isinstance(scan_data, dict) else {}
    module_status = []
    for label, key in MODULE_KEYS:
        module = scan_data.get(key) or {}
        module_status.append({"module": label, "status": _status(module)})
    successful = sum(item["status"] in {"SUCCESS", "PARTIAL", "COMPLETED", "CALCULATED"} for item in module_status)
    dns_records = _dns_records(scan_data)
    addresses = (scan_data.get("ip_resolution") or {}).get("addresses") or []
    technologies = [item for item in (scan_data.get("technology_detection") or {}).get("technologies", []) if isinstance(item, dict)]
    observations = []
    if dns_records:
        observations.append("Public DNS infrastructure identified.")
    nameserver_count = sum(record_type == "NS" for record_type, _, _ in dns_records)
    if nameserver_count > 1:
        observations.append("Multiple nameservers identified.")
    if any(record_type == "MX" for record_type, _, _ in dns_records):
        observations.append("Public mail infrastructure identified.")
    if technologies:
        observations.append("Technology fingerprints detected.")
    if addresses:
        observations.append("Public IP infrastructure identified.")
    generated_at = generated_at or datetime.now()
    return {
        "target": _text(scan_data.get("target")) or "unknown target",
        "generated_at": generated_at,
        "domain_intelligence": scan_data.get("url_domain_intelligence") or {},
        "whois": scan_data.get("whois") or {},
        "dns": dns_records,
        "dns_map": scan_data.get("dns_relationship_map") or {},
        "resolution": scan_data.get("ip_resolution") or {},
        "geolocation": scan_data.get("ip_geolocation") or {},
        "technologies": technologies,
        "technology_status": _status(scan_data.get("technology_detection")),
        "findings": observations,
        "overview": {
            "dns_records": len(dns_records),
            "ip_addresses": len(addresses),
            "nameservers": nameserver_count,
            "mail_servers": sum(record_type == "MX" for record_type, _, _ in dns_records),
            "technologies": len(technologies),
        },
        "module_status": module_status,
        "successful_modules": successful,
        "failed_modules": len(module_status) - successful,
    }


class _ReportDocTemplate(BaseDocTemplate):
    def __init__(self, buffer, target, generated_at, **kwargs):
        super().__init__(buffer, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="normal")
        self.addPageTemplates([PageTemplate(id="osint", frames=frame, onPage=self._draw_page)])
        self.target = target
        self.generated_at = generated_at

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        if doc.page == 1:
            canvas.setFillColor(DARKER)
            canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)
            canvas.setFillColor(GREEN)
            canvas.rect(0.55 * inch, PAGE_HEIGHT - 1.15 * inch, 0.08 * inch, 0.55 * inch, fill=1, stroke=0)
            canvas.setFillColor(MUTED)
            canvas.setFont("Helvetica", 8)
            canvas.drawString(0.7 * inch, 0.45 * inch, "AUTHORIZED USE ONLY  |  VULNXSCANNER OSINT INTELLIGENCE")
        else:
            canvas.setStrokeColor(BORDER)
            canvas.line(0.55 * inch, PAGE_HEIGHT - 0.48 * inch, PAGE_WIDTH - 0.55 * inch, PAGE_HEIGHT - 0.48 * inch)
            canvas.setFillColor(GREEN)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(0.55 * inch, PAGE_HEIGHT - 0.34 * inch, "VULNXSCANNER")
            canvas.setFillColor(MUTED)
            canvas.setFont("Helvetica", 8)
            canvas.drawRightString(PAGE_WIDTH - 0.55 * inch, PAGE_HEIGHT - 0.34 * inch, "OSINT REPORT")
            canvas.setStrokeColor(BORDER)
            canvas.line(0.55 * inch, 0.52 * inch, PAGE_WIDTH - 0.55 * inch, 0.52 * inch)
            canvas.setFillColor(MUTED)
            canvas.drawString(0.55 * inch, 0.34 * inch, f"Target: {self.target}")
            canvas.drawCentredString(PAGE_WIDTH / 2, 0.34 * inch, f"Generated: {self.generated_at.strftime('%d %B %Y')}")
            canvas.drawRightString(PAGE_WIDTH - 0.55 * inch, 0.34 * inch, f"Page {doc.page}")
        canvas.restoreState()


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverBrand", fontName="Helvetica-Bold", fontSize=14, textColor=GREEN, leading=18, alignment=1, spaceAfter=22))
    styles.add(ParagraphStyle("CoverTitle", fontName="Helvetica-Bold", fontSize=27, textColor=TEXT, leading=33, alignment=1, spaceAfter=30))
    styles.add(ParagraphStyle("CoverLabel", fontName="Helvetica-Bold", fontSize=8, textColor=MUTED, leading=11, alignment=1, spaceBefore=12, spaceAfter=5))
    styles.add(ParagraphStyle("CoverTarget", fontName="Helvetica-Bold", fontSize=19, textColor=TEXT, leading=24, alignment=1))
    styles.add(ParagraphStyle("CoverAssessment", fontName="Helvetica-Bold", fontSize=13, textColor=GREEN, leading=16, alignment=1, spaceAfter=0))
    styles.add(ParagraphStyle("Section", fontName="Helvetica-Bold", fontSize=16, textColor=GREEN, leading=20, spaceBefore=8, spaceAfter=12))
    styles.add(ParagraphStyle("Body", fontName="Helvetica", fontSize=9, textColor=TEXT, leading=13, spaceAfter=5))
    styles.add(ParagraphStyle("Small", fontName="Helvetica", fontSize=8, textColor=TEXT, leading=11))
    styles.add(ParagraphStyle("SmallMuted", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=11))
    styles.add(ParagraphStyle("Cell", fontName="Helvetica", fontSize=8, textColor=TEXT, leading=10))
    styles.add(ParagraphStyle("CellHeader", fontName="Helvetica-Bold", fontSize=8, textColor=DARKER, leading=10))
    styles.add(ParagraphStyle("Empty", fontName="Helvetica-Oblique", fontSize=9, textColor=MUTED, leading=13))
    return styles


def _table(rows, styles, widths=None):
    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4d5b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), TEXT),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, DARK]),
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _key_value_table(items, styles):
    rows = [[_paragraph("Field", styles["CellHeader"]), _paragraph("Observed value", styles["CellHeader"])]]
    rows.extend([[_paragraph(label, styles["Cell"]), _paragraph(value, styles["Cell"])] for label, value in items if _usable(value)])
    return _table(rows, styles, [1.65 * inch, 4.85 * inch]) if len(rows) > 1 else Paragraph("No data available for this module in the current scan.", styles["Empty"])


def _section(title, styles):
    return [
        Paragraph(title, styles["Section"]),
        Table([[""]], colWidths=[6.5 * inch], rowHeights=[2], style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2dd4bf")),
            ("LINEBELOW", (0, 0), (-1, -1), 0, GREEN),
        ])),
        Spacer(1, 0.08 * inch),
    ]


def generate_osint_pdf(scan_data):
    """Generate a styled PDF snapshot from an existing unified OSINT response."""
    report = build_osint_report_data(scan_data)
    styles = _styles()
    buffer = BytesIO()
    doc = _ReportDocTemplate(
        buffer,
        report["target"],
        report["generated_at"],
        pagesize=letter,
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.72 * inch,
        title="vulnXscanner OSINT Intelligence Report",
        author="vulnXscanner",
        subject="OSINT Intelligence Report",
    )
    story = [Spacer(1, 1.15 * inch), Paragraph("VULNXSCANNER", styles["CoverBrand"]), Paragraph("OSINT INTELLIGENCE REPORT", styles["CoverTitle"])]
    story.extend([Paragraph("TARGET", styles["CoverLabel"]), Paragraph(escape(report["target"]), styles["CoverTarget"])])
    story.extend([
        Spacer(1, 0.35 * inch),
            Table([[Paragraph("INTELLIGENCE ASSESSMENT", styles["CoverAssessment"])]], colWidths=[6.5 * inch], style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ])),
        Spacer(1, 0.3 * inch),
        Paragraph("GENERATED", styles["CoverLabel"]),
        Paragraph(report["generated_at"].strftime("%d %B %Y, %H:%M"), styles["CoverTarget"]),
        PageBreak(),
    ])

    story.extend(_section("EXECUTIVE SUMMARY", styles))
    story.append(Paragraph(escape("The scan collected publicly observable intelligence associated with the target. This report is an intelligence snapshot and does not by itself indicate compromise or vulnerability."), styles["Body"]))
    story.append(_key_value_table([
        ("Target domain", report["target"]),
        ("Scan date/time", report["generated_at"].strftime("%d %B %Y, %H:%M")),
        ("Successful modules", report["successful_modules"]),
        ("Failed/unavailable modules", report["failed_modules"]),
    ], styles))
    overview = report["overview"]
    overview_rows = [[
        _paragraph("DNS records", styles["CellHeader"]),
        _paragraph("IP addresses", styles["CellHeader"]),
        _paragraph("Nameservers", styles["CellHeader"]),
        _paragraph("Mail servers", styles["CellHeader"]),
        _paragraph("Technologies", styles["CellHeader"]),
    ], [
        _paragraph(overview["dns_records"], styles["Cell"]),
        _paragraph(overview["ip_addresses"], styles["Cell"]),
        _paragraph(overview["nameservers"], styles["Cell"]),
        _paragraph(overview["mail_servers"], styles["Cell"]),
        _paragraph(overview["technologies"], styles["Cell"]),
    ]]
    overview_table = Table(overview_rows, colWidths=[1.3 * inch] * 5, repeatRows=1)
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4d5b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), TEXT),
        ("BACKGROUND", (0, 1), (-1, -1), DARK),
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([Spacer(1, 0.2 * inch), overview_table])

    story.extend(_section("DOMAIN INTELLIGENCE", styles))
    domain = report["domain_intelligence"]
    domain_items = [(label, domain.get(key)) for label, key in (("Original input", "original_input"), ("Normalized URL", "normalized_url"), ("Hostname", "hostname"), ("Registered domain", "registered_domain"), ("Protocol", "scheme"), ("Port", "port"), ("Path", "path"), ("Status", "status"))]
    story.append(_key_value_table(domain_items, styles))

    story.extend(_section("WHOIS INTELLIGENCE", styles))
    whois = report["whois"]
    whois_items = [(label, whois.get(key)) for label, key in (("Registrar", "registrar"), ("Created", "creation_date"), ("Updated", "updated_date"), ("Expires", "expiration_date"), ("Domain status", "domain_status"), ("Nameservers", "name_servers"), ("WHOIS server", "whois_server"), ("DNSSEC", "dnssec"))]
    story.append(_key_value_table(whois_items, styles) if _status(whois) not in {"ERROR", "FAILED", "NOT AVAILABLE", "UNKNOWN"} else Paragraph("Data unavailable for this scan.", styles["Empty"]))

    story.extend(_section("DNS INTELLIGENCE", styles))
    if report["dns"]:
        dns_rows = [[_paragraph("Record type", styles["CellHeader"]), _paragraph("Value", styles["CellHeader"]), _paragraph("Additional information", styles["CellHeader"])]]
        dns_rows.extend([[_paragraph(record_type, styles["Cell"]), _paragraph(value, styles["Cell"]), _paragraph(extra, styles["Cell"])] for record_type, value, extra in report["dns"]])
        story.append(_table(dns_rows, styles, [1.05 * inch, 3.7 * inch, 1.75 * inch]))
    else:
        story.append(Paragraph("No data available for this module in the current scan.", styles["Empty"]))

    story.extend([PageBreak()])
    story.extend(_section("DNS RELATIONSHIP MAP", styles))
    dns_map = report["dns_map"]
    if dns_map.get("edges"):
        map_rows = [[_paragraph("Domain", styles["CellHeader"]), _paragraph("Relationship", styles["CellHeader"]), _paragraph("Actual value", styles["CellHeader"])]]
        for record_type, value, _ in report["dns"]:
            map_rows.append([_paragraph(dns_map.get("domain", report["target"]), styles["Cell"]), _paragraph(record_type, styles["Cell"]), _paragraph(value, styles["Cell"])])
        story.append(_table(map_rows, styles, [2.2 * inch, 1.25 * inch, 3.05 * inch]))
    else:
        story.append(Paragraph("No DNS relationship data available.", styles["Empty"]))

    story.extend(_section("IP GEOLOCATION", styles))
    resolution = report["resolution"]
    geo = report["geolocation"]
    addresses = resolution.get("addresses") or ([resolution.get("ip")] if _usable(resolution.get("ip")) else [])
    geo_rows = [[_paragraph("IP address", styles["CellHeader"]), _paragraph("Country / region / city", styles["CellHeader"]), _paragraph("Provider / network", styles["CellHeader"])]]
    for address in addresses:
        location = ", ".join(item for item in (_text(geo.get("country")), _text(geo.get("region")), _text(geo.get("city"))) if item)
        provider = ", ".join(item for item in (_text(geo.get("isp")), _text(geo.get("organization")), _text(geo.get("asn"))) if item)
        geo_rows.append([_paragraph(address, styles["Cell"]), _paragraph(location, styles["Cell"]), _paragraph(provider, styles["Cell"])])
    story.append(_table(geo_rows, styles, [1.55 * inch, 2.6 * inch, 2.35 * inch]) if len(geo_rows) > 1 else Paragraph("No data available for this module in the current scan.", styles["Empty"]))

    story.extend(_section("TECHNOLOGY INTELLIGENCE", styles))
    if report["technology_status"] in {"ERROR", "FAILED", "NOT AVAILABLE", "UNKNOWN"}:
        story.append(Paragraph("Technology detection unavailable for this scan.", styles["Empty"]))
    elif report["technologies"]:
        tech_rows = [[_paragraph("Technology", styles["CellHeader"]), _paragraph("Category", styles["CellHeader"]), _paragraph("Version / confidence", styles["CellHeader"])]]
        for technology in report["technologies"]:
            tech_rows.append([_paragraph(technology.get("name"), styles["Cell"]), _paragraph(technology.get("category"), styles["Cell"]), _paragraph(technology.get("version") or technology.get("confidence"), styles["Cell"])])
        story.append(_table(tech_rows, styles, [2.2 * inch, 2.1 * inch, 2.2 * inch]))
    else:
        story.append(Paragraph("No technologies were detected in this scan.", styles["Empty"]))

    story.extend(_section("OSINT FINDINGS", styles))
    if report["findings"]:
        for finding in report["findings"]:
            story.append(Paragraph(f"<font color='#34d399'>•</font>  {escape(_text(finding))}", styles["Body"]))
    else:
        story.append(Paragraph("No additional findings were generated from the available scan data.", styles["Empty"]))

    story.extend(_section("SCAN MODULE STATUS", styles))
    status_rows = [[_paragraph("Module", styles["CellHeader"]), _paragraph("Status", styles["CellHeader"])]]
    for item in report["module_status"]:
        status_rows.append([_paragraph(item["module"], styles["Cell"]), _paragraph(item["status"], styles["Cell"])])
    story.append(_table(status_rows, styles, [4.25 * inch, 2.25 * inch]))

    doc.build(story)
    buffer.seek(0)
    return buffer, f"vulnxscanner_{_safe_filename(report['target'])}_OSINT_Report.pdf"
