from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime

# --- VulnX Design Tokens ---
VULNX_GREEN = colors.HexColor('#10b981')
VULNX_DARK = colors.HexColor('#0a0c10')
VULNX_GRAY = colors.HexColor('#6b7280')
VULNX_LIGHT_BG = colors.HexColor('#f9fafb')

# Severity Colors
SEVERITY_COLORS = {
    'CRITICAL': colors.HexColor('#7f1d1d'), # Dark Red
    'HIGH': colors.HexColor('#b91c1c'),     # Red
    'MEDIUM': colors.HexColor('#d97706'),   # Orange
    'LOW': colors.HexColor('#059669'),      # Green
    'INFO': colors.HexColor('#2563eb'),     # Blue
    'UNKNOWN': colors.HexColor('#4b5563')   # Gray
}

def get_vulnx_styles():
    """Returns a unified stylesheet for VulnX reports with modern typography"""
    styles = getSampleStyleSheet()
    
    # Custom VulnX Styles
    if 'VulnXTitle' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXTitle',
            parent=styles['Heading1'],
            fontSize=26,
            fontName='Helvetica-Bold',
            textColor=VULNX_GREEN,
            spaceAfter=10,
            alignment=1  # Center
        ))
    
    if 'VulnXSubtitle' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=VULNX_GRAY,
            alignment=1,
            spaceAfter=30
        ))
    
    if 'VulnXHeading' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXHeading',
            parent=styles['Heading2'],
            fontSize=16,
            fontName='Helvetica-Bold',
            textColor=VULNX_DARK,
            spaceBefore=20,
            spaceAfter=12,
            borderPadding=5,
            leftIndent=0
        ))
    
    if 'VulnXLabel' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXLabel',
            parent=styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=VULNX_DARK
        ))

    if 'VulnXHeaderLabel' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXHeaderLabel',
            parent=styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke,
            alignment=0 # Left align
        ))

    if 'VulnXFooter' not in styles:
        styles.add(ParagraphStyle(
            name='VulnXFooter',
            parent=styles['Normal'],
            alignment=1,
            fontSize=8,
            textColor=VULNX_GRAY
        ))

    return styles

def _get_severity_style(severity):
    """Returns a Paragraph style for colored severity badges"""
    sev_upper = str(severity).upper()
    color = SEVERITY_COLORS.get(sev_upper, SEVERITY_COLORS['UNKNOWN'])
    return ParagraphStyle(
        f'Sev_{sev_upper}',
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=colors.whitesmoke,
        backColor=color,
        borderPadding=3,
        alignment=1,
        borderRadius=3
    )

def generate_analysis_pdf(analysis_text, metadata, title="Vulnerability Analysis Report"):
    """
    Generates a premium AI analysis report for any vulnerability type.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = get_vulnx_styles()
    
    # 1. Header Section
    story.append(Paragraph("VULNX SECURITY", styles['VulnXTitle']))
    story.append(Paragraph(title, styles['VulnXSubtitle']))
    
    # 2. Information Grid
    story.append(Paragraph("Report Details", styles['VulnXHeading']))
    
    info_data = []
    for key, value in metadata.items():
        info_data.append([Paragraph(f"<b>{key}:</b>", styles['Normal']), Paragraph(str(value), styles['Normal'])])
    
    info_data.append([Paragraph("<b>Generated:</b>", styles['Normal']), Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), styles['Normal'])])
    
    info_table = Table(info_data, colWidths=[1.5*inch, 4.5*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), VULNX_LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 0.3*inch))
    
    # 3. AI Analysis Content
    story.append(Paragraph('Vulnerability Assessment & Intelligence', styles['VulnXHeading']))
    
    # Split text into paragraphs and handle bullet points
    lines = analysis_text.split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.startswith('*') or line.startswith('-'):
            story.append(Paragraph(f"• {line[1:].strip()}", styles['Normal']))
        elif line[0].isdigit() and line[1] == '.':
            story.append(Paragraph(f"<b>{line}</b>", styles['Normal']))
        else:
            story.append(Paragraph(line, styles['Normal']))
        story.append(Spacer(1, 0.08*inch))
            
    # 4. Footer
    story.append(Spacer(1, 0.5*inch))
    story.append(Table([[Paragraph('<hr color="#e5e7eb"/>', styles['Normal'])]], colWidths=[6.5*inch]))
    story.append(Paragraph(
        'Generated by VulnX AI Security Suite | Powered by Google Gemini 2.5 Flash | Authorized Use Only',
        styles['VulnXFooter']
    ))
    
    doc.build(story)
    buffer.seek(0)
    return buffer

def generate_pdf_report(scan_data):
    """Generates the full network scan history report with enhanced visual summary"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    elements = []
    styles = get_vulnx_styles()
    
    # Header
    elements.append(Paragraph("VULNX SCAN REPORT", styles['VulnXTitle']))
    elements.append(Paragraph(f"Comprehensive Security Assessment for {scan_data.get('target', 'Target System')}", styles['VulnXSubtitle']))
    
    # Scan Summary Section
    elements.append(Paragraph("Scan Metadata", styles['VulnXHeading']))
    meta = [
        ["Target Host", scan_data.get('target', 'N/A')],
        ["Resolved IP", scan_data.get('ip', 'N/A')],
        ["Timestamp", scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M'))],
        ["Scan Mode", "Deep (1-1024)" if scan_data.get('deep_scan') else "Quick (Common Ports)"]
    ]
    meta_table = Table(meta, colWidths=[1.5*inch, 4.5*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), VULNX_LIGHT_BG),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(meta_table)
    
    # Findings Summary Badges
    ports = scan_data.get('results', [])
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for p in ports:
        sev = str(p[3]).upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts['INFO'] += 1

    elements.append(Paragraph("Risk Distribution", styles['VulnXHeading']))
    summary_data = [
        [Paragraph(f"<font color='white'><b>CRITICAL: {severity_counts['CRITICAL']}</b></font>", _get_severity_style('CRITICAL')),
         Paragraph(f"<font color='white'><b>HIGH: {severity_counts['HIGH']}</b></font>", _get_severity_style('HIGH')),
         Paragraph(f"<font color='white'><b>MEDIUM: {severity_counts['MEDIUM']}</b></font>", _get_severity_style('MEDIUM')),
         Paragraph(f"<font color='white'><b>LOW: {severity_counts['LOW']}</b></font>", _get_severity_style('LOW')),
         Paragraph(f"<font color='white'><b>INFO: {severity_counts['INFO']}</b></font>", _get_severity_style('INFO'))]
    ]
    summary_table = Table(summary_data, colWidths=[1.2*inch]*5)
    elements.append(summary_table)
    elements.append(Spacer(1, 0.2*inch))

    # Findings Table
    elements.append(Paragraph(f"Discovered Services ({len(ports)})", styles['VulnXHeading']))
    if ports:
        header = [Paragraph('<b>Port</b>', styles['VulnXHeaderLabel']), 
                  Paragraph('<b>Service</b>', styles['VulnXHeaderLabel']), 
                  Paragraph('<b>Banner</b>', styles['VulnXHeaderLabel']), 
                  Paragraph('<b>Severity</b>', styles['VulnXHeaderLabel']), 
                  Paragraph('<b>Threat Assessment</b>', styles['VulnXHeaderLabel'])]
        
        data = [header]
        for p in ports:
            port_num = Paragraph(str(p[0]), styles['Normal'])
            service = Paragraph(str(p[1]), styles['Normal'])
            banner = Paragraph(str(p[2]), styles['Normal'])
            sev_label = str(p[3]).upper()
            threat = Paragraph(str(p[4]), styles['Normal'])
            
            # Use colored badge for severity in table
            rev_para = Paragraph(sev_label, _get_severity_style(sev_label))
            
            data.append([port_num, service, banner, rev_para, threat])
            
        # Total width 6.5 inches (Compact and safe for all orientations)
        table = Table(data, colWidths=[0.6*inch, 0.8*inch, 1.8*inch, 0.9*inch, 2.4*inch])
        
        # Zebra Striping and Professional Borders
        ts = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), VULNX_DARK),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.1, colors.grey),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ])
        
        # Add Zebra Striping
        for i in range(1, len(data)):
            if i % 2 == 0:
                ts.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f3f4f6'))
        
        table.setStyle(ts)
        elements.append(table)
    else:
        elements.append(Paragraph("No active security threats were identified in the scanned port range.", styles['Normal']))

    # Professional Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Table([[Paragraph('<hr color="#e5e7eb"/>', styles['Normal'])]], colWidths=[6.5*inch]))
    elements.append(Paragraph("CONFIDENTIAL SECURITY DOCUMENT - FOR AUTHORIZED PERSONNEL ONLY", styles['VulnXFooter']))
    elements.append(Paragraph(f"Generated by VulnX Pro | {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['VulnXFooter']))

    doc.build(elements)
    buffer.seek(0)
    return buffer
