document.getElementById('whoisForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const target = document.getElementById('osintTarget').value.trim();
    const button = document.getElementById('startOsint');
    const resultsDiv = document.getElementById('osintResults');
    const message = document.getElementById('whoisMessage');

    button.disabled = true;
    button.textContent = 'LOOKING UP...';
    message.textContent = '';
    resultsDiv.innerHTML = '<div class="whois-loading">Querying WHOIS servers...</div>';

    try {
        const response = await fetch('/api/whois/lookup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: target})
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'WHOIS lookup failed');
        }
        renderWhois(data);
    } catch (error) {
        resultsDiv.innerHTML = '';
        message.textContent = error.message;
        message.className = 'whois-message error';
    } finally {
        button.disabled = false;
        button.textContent = 'LOOKUP';
    }
});

function displayValue(value) {
    if (Array.isArray(value)) return value.join(', ');
    return value || 'Not publicly available';
}

function escapeHtml(value) {
    return String(value)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function renderWhois(data) {
    const message = document.getElementById('whoisMessage');
    message.textContent = data.status;
    message.className = `whois-message ${data.status === 'SUCCESS' ? 'success' : 'warning'}`;
    
    const sections = [
        ['DOMAIN INFORMATION', [
            ['Domain', data.domain], ['Registrar', data.registrar],
            ['Created', data.creation_date], ['Updated', data.updated_date],
            ['Expires', data.expiration_date]
        ]],
        ['DOMAIN STATUS', [['Status', data.domain_status]]],
        ['NAME SERVERS', [['Nameservers', data.name_servers]]],
        ['REGISTRANT INFORMATION', [
            ['Organization', data.registrant_organization],
            ['Country', data.registrant_country]
        ]],
        ['TECHNICAL INFORMATION', [
            ['WHOIS Server', data.whois_server], ['DNSSEC', data.dnssec]
        ]]
    ];

    document.getElementById('osintResults').innerHTML = sections.map(([title, rows]) => `
        <section class="whois-card">
            <h3>${title}</h3>
            ${rows.map(([label, value]) => `<div class="whois-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(displayValue(value))}</strong></div>`).join('')}
        </section>
    `).join('');
}

document.getElementById('ipgeoForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const target = document.getElementById('ipgeoTarget').value.trim();
    const button = document.getElementById('startIpGeo');
    const resultsDiv = document.getElementById('ipgeoResults');
    const message = document.getElementById('ipgeoMessage');

    button.disabled = true;
    button.textContent = 'LOOKING UP...';
    message.textContent = '';
    resultsDiv.innerHTML = '<div class="ipgeo-loading">Querying geolocation service...</div>';

    try {
        const response = await fetch('/api/ip-geolocation', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: target})
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || data.message || 'IP geolocation lookup failed');
        }
        renderIpGeo(data);
    } catch (error) {
        resultsDiv.innerHTML = '';
        message.textContent = error.message;
        message.className = 'ipgeo-message error';
    } finally {
        button.disabled = false;
        button.textContent = 'LOOKUP IP';
    }
});

function renderIpGeo(data) {
    const message = document.getElementById('ipgeoMessage');
    message.textContent = data.status === 'PRIVATE/RESERVED' ? 'Private/Reserved IP' : data.status;
    message.className = `ipgeo-message ${data.status === 'SUCCESS' ? 'success' : 'warning'}`;

    const sections = [
        ['IP INFORMATION', [
            ['IP Address', data.ip], ['IP Version', data.version],
            ['Status', data.status]
        ]],
        ['LOCATION', [
            ['Approximate Country', data.country], ['Country Code', data.country_code],
            ['Approximate Region', data.region], ['Approximate City', data.city],
            ['Latitude', data.latitude], ['Longitude', data.longitude],
            ['Timezone', data.timezone], ['Network Type', data.network_type],
            ['Location Note', data.location_note]
        ]],
        ['NETWORK', [
            ['ISP', data.isp], ['Organization', data.organization],
            ['ASN', data.asn], ['Connection Type', data.connection_type],
            ['Hosting/Datacenter', data.hosting]
        ]]
    ];

    document.getElementById('ipgeoResults').innerHTML = sections.map(([title, rows]) => `
        <section class="ipgeo-card">
            <h3>${escapeHtml(title)}</h3>
            ${rows.map(([label, value]) => `<div class="ipgeo-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(displayValue(value))}</strong></div>`).join('')}
        </section>
    `).join('') + '<p class="ipgeo-disclaimer">Approximate location only. IP geolocation does not identify an exact physical location.</p>';
}

let unifiedScanSequence = 0;
let currentUnifiedOsintData = null;

document.getElementById('unifiedOsintForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const scanSequence = ++unifiedScanSequence;
    const domain = document.getElementById('unifiedOsintTarget').value.trim();
    const button = document.getElementById('startUnifiedOsint');
    const message = document.getElementById('unifiedOsintMessage');
    const progress = document.getElementById('unifiedOsintProgress');
    const results = document.getElementById('unifiedOsintResults');

    button.disabled = true;
    button.textContent = 'SCANNING...';
    message.textContent = '';
    results.innerHTML = '';
    progress.innerHTML = '<div>Starting OSINT scan...</div><div>○ URL / Domain Intelligence</div><div>○ WHOIS Recon</div><div>○ DNS Resolution</div><div>○ IP Geolocation</div><div>○ Technology Detection</div>';

    try {
        const response = await fetch('/api/osint/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await response.json();
        if (scanSequence !== unifiedScanSequence) return;
        if (!response.ok) throw new Error(data.error || 'OSINT scan failed');
        currentUnifiedOsintData = data;
        renderUnifiedOsint(data);
    } catch (error) {
        if (scanSequence !== unifiedScanSequence) return;
        message.textContent = error.message;
        message.className = 'unified-osint-message error';
        progress.innerHTML = '<div>✗ OSINT scan failed</div>';
    } finally {
        if (scanSequence === unifiedScanSequence) {
            button.disabled = false;
            button.textContent = 'START OSINT SCAN';
        }
    }
});

function renderUnifiedOsint(data) {
    const whois = data.whois || {};
    const resolution = data.ip_resolution || {};
    const geo = data.ip_geolocation || {};
    const technology = data.technology_detection || {};
    const urlIntel = data.url_domain_intelligence || {};
    const dnsMap = data.dns_relationship_map || {};
    const message = document.getElementById('unifiedOsintMessage');
    const moduleStatus = status => status === 'SUCCESS' ? '✓' : '⚠';
    const moduleLabel = status => status === 'SUCCESS' ? 'success' : status.toLowerCase();
    message.textContent = data.status;
    message.className = 'unified-osint-message success';
    document.getElementById('unifiedOsintProgress').innerHTML = `
        <div>✓ URL / Domain Intelligence ${urlIntel.status.toLowerCase()}</div>
        <div>${moduleStatus(whois.status)} WHOIS ${whois.status.toLowerCase()}</div>
        <div>${moduleStatus(resolution.status)} DNS ${resolution.status.toLowerCase()}</div>
        <div>${moduleStatus(geo.status)} IP Geolocation ${moduleLabel(geo.status)}</div>
        <div>${moduleStatus(dnsMap.status)} DNS Relationship Map ${dnsMap.status.toLowerCase()}</div>
        <div>${moduleStatus(technology.status)} Technology Detection ${technology.status.toLowerCase()}</div>
        <div>✓ OSINT scan completed</div>`;

    const rows = (items) => items.map(([label, value]) =>
        `<div class="unified-osint-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(displayValue(value))}</strong></div>`
    ).join('');
    const section = (title, items) => `<section class="unified-osint-card"><h3>${title}</h3>${rows(items)}</section>`;

    document.getElementById('unifiedOsintResults').innerHTML = [
            section('MODULE 1 — URL / DOMAIN INTELLIGENCE', [
                ['Original Input', urlIntel.original_input], ['Input Type', urlIntel.input_type],
                ['Normalized URL', urlIntel.normalized_url], ['Hostname', urlIntel.hostname],
                ['Registered Domain', urlIntel.registered_domain], ['Scheme', urlIntel.scheme],
                ['Port', urlIntel.port], ['Path', urlIntel.path],
                ['Query', urlIntel.query_present ? 'Present' : 'Not Present'],
                ['Fragment', urlIntel.fragment_present ? 'Present' : 'Not Present'],
                ['Subdomain', urlIntel.subdomain || 'None'], ['TLD', urlIntel.tld]
            ]),
            section('MODULE 2 — DOMAIN WHOIS', [
                ['Domain', whois.domain || data.target], ['Registrar', whois.registrar],
                ['Created', whois.creation_date], ['Updated', whois.updated_date],
                ['Expires', whois.expiration_date], ['Status', whois.domain_status],
                ['Name Servers', whois.name_servers], ['WHOIS Server', whois.whois_server],
                ['DNSSEC', whois.dnssec]
            ]),
            section('MODULE 3 — IP GEOLOCATION', [
                ['Resolved IP', resolution.ip], ['IP Version', resolution.version],
                ['Approximate Country', geo.country], ['Country Code', geo.country_code],
                ['Approximate Region', geo.region], ['Approximate City', geo.city], ['Latitude', geo.latitude],
                ['Longitude', geo.longitude], ['ISP', geo.isp], ['Organization', geo.organization],
                ['ASN', geo.asn], ['Timezone', geo.timezone]
            ]),
            section('MODULE 4 — TECHNOLOGY DETECTION', [
            ['Technologies', (technology.technologies || []).map(item => `${item.name} (${item.category}, ${item.confidence})`).join(', ') || 'No publicly detectable technologies found'],
            ['Security Headers', (technology.security_headers || []).join(', ') || 'Not Available'],
            ['Status', technology.status]
        ]),
        `<section class="unified-osint-card dns-map-card"><h3>DNS RELATIONSHIP MAP</h3><div id="dnsRelationshipMap"></div></section>`,
        `<section class="unified-osint-card"><div class="osint-summary-heading"><h3>SCAN SUMMARY</h3><button type="button" class="osint-report-button" id="osintReportButton">↓ Generate PDF Report</button></div>${rows([
            ['Domain', data.summary.domain], ['Resolved IP', data.summary.resolved_ip],
            ['WHOIS', data.summary.whois], ['IP Geolocation', data.summary.ip_geolocation],
            ['Technology Detection', data.summary.technology_detection],
            ['Overall Scan Status', data.summary.overall]
        ])}</section>`
    ].join('');
    const reportButton = document.getElementById('osintReportButton');
    if (reportButton) reportButton.addEventListener('click', generateOsintReport);
    renderDnsRelationshipMap(dnsMap);
}

async function generateOsintReport() {
    const button = document.getElementById('osintReportButton');
    if (!button || !currentUnifiedOsintData) return;
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Generating OSINT Report...';
    try {
        const response = await fetch('/api/osint/report', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(currentUnifiedOsintData)
        });
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || 'OSINT PDF report generation failed');
        }
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `vulnxscanner_${currentUnifiedOsintData.target || 'unknown'}_OSINT_Report.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        button.textContent = 'OSINT Report generated successfully.';
    } catch (error) {
        button.textContent = error.message;
    } finally {
        setTimeout(() => {
            if (button) {
                button.disabled = false;
                button.textContent = originalText;
            }
        }, 2500);
    }
}

function renderDnsRelationshipMap(data) {
    const container = document.getElementById('dnsRelationshipMap');
    if (!container) return;
    const hasEdges = Boolean(data.edges && data.edges.length);

    const nodes = data.nodes || [];
    const center = nodes.find(node => node.type === 'DOMAIN');
    if (!center) {
        container.innerHTML = `<p class="dns-map-empty">${escapeHtml(data.status === 'FAILED' ? 'Unable to build relationship map.' : 'No DNS relationships available for this domain.')}</p>`;
        return;
    }
    const children = nodes.filter(node => node.id !== center.id);
    const width = 900;
    const height = Math.max(420, children.length * 75);
    const positions = new Map([[center.id, {x: 130, y: height / 2}]]);
    children.forEach((node, index) => positions.set(node.id, {
        x: 620 + (index % 2) * 170,
        y: 55 + index * ((height - 110) / Math.max(children.length - 1, 1))
    }));

    const edges = data.edges.map(edge => {
        const source = positions.get(edge.source);
        const target = positions.get(edge.target);
        return `<line class="dns-map-edge" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"/><text class="dns-map-edge-label" x="${(source.x + target.x) / 2}" y="${(source.y + target.y) / 2 - 6}">${escapeHtml(edge.relationship)}</text>`;
    }).join('');
    const nodeMarkup = nodes.map(node => {
        const position = positions.get(node.id);
        return `<g class="dns-map-node dns-map-${node.type.toLowerCase()}" transform="translate(${position.x},${position.y})"><title>Type: ${escapeHtml(node.type)}\nValue: ${escapeHtml(node.label)}</title><circle r="${node.type === 'DOMAIN' ? 42 : 30}"/><text text-anchor="middle" y="4">${escapeHtml(node.label.length > 24 ? `${node.label.slice(0, 21)}...` : node.label)}</text></g>`;
    }).join('');
    const nodeTypes = [...new Set(nodes.map(node => node.type))];
    const legend = nodeTypes.map(type => `<span class="dns-map-legend-item"><i class="dns-map-legend-dot dns-map-${type.toLowerCase()}"></i>${escapeHtml(type)}</span>`).join('');
    const summary = Object.entries(data.record_summary || {}).map(([type, count]) => `<span class="dns-map-summary-item"><b>${escapeHtml(type)}</b><strong>${count}</strong></span>`).join('');
    const metadata = Object.entries(data.metadata || {}).map(([type, values]) => {
        if (type === 'CAA') return `<section class="dns-map-metadata-card"><h4>CAA</h4>${values.map(item => `<div><span>Certificate Authority</span><strong>${escapeHtml(item.issuer)}</strong></div>`).join('')}</section>`;
        if (type === 'SOA') return `<section class="dns-map-metadata-card"><h4>SOA</h4>${values.map(item => `<div><span>Primary Nameserver</span><strong>${escapeHtml(item.primary_nameserver)}</strong></div>`).join('')}</section>`;
        return `<section class="dns-map-metadata-card"><h4>TXT RECORDS</h4><p>${values.length} records found</p><details><summary>View values</summary>${values.map(item => `<div title="${escapeHtml(item.value)}"><strong>${escapeHtml(item.value.length > 110 ? `${item.value.slice(0, 107)}...` : item.value)}</strong></div>`).join('')}</details></section>`;
    }).join('');
    const panel = `<div class="dns-map-detail" id="dnsMapDetail" hidden></div>`;
    const graph = hasEdges
        ? `<svg class="dns-map-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="DNS relationship graph"><defs><marker id="dns-map-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"/></marker></defs><g class="dns-map-layer">${edges}${nodeMarkup}</g></svg><div class="dns-map-legend">${legend}</div>`
        : `<p class="dns-map-empty">${escapeHtml(data.status === 'FAILED' ? 'Unable to build relationship map.' : 'No DNS relationships available for this domain.')}</p>`;
    container.innerHTML = `<div class="dns-map-summary"><h4>DNS RECORD SUMMARY</h4><div>${summary || '<span>No DNS records found</span>'}</div></div>${graph}${Object.keys(data.metadata || {}).length ? `<div class="dns-map-metadata"><h4>DNS SECURITY &amp; METADATA</h4>${metadata}</div>` : ''}${panel}`;
    const svg = container.querySelector('svg');
    if (!svg) return;
    const layer = container.querySelector('.dns-map-layer');
    let scale = 1;
    let offsetX = 0;
    let offsetY = 0;
    let dragging = false;
    let lastX = 0;
    let lastY = 0;
    const updateTransform = () => { layer.setAttribute('transform', `translate(${offsetX} ${offsetY}) scale(${scale})`); };
    svg.addEventListener('wheel', event => { event.preventDefault(); scale = Math.min(2.5, Math.max(0.6, scale + (event.deltaY < 0 ? 0.1 : -0.1))); updateTransform(); });
    svg.addEventListener('pointerdown', event => { dragging = true; lastX = event.clientX; lastY = event.clientY; svg.setPointerCapture(event.pointerId); });
    svg.addEventListener('pointermove', event => { if (!dragging) return; offsetX += (event.clientX - lastX) / 2; offsetY += (event.clientY - lastY) / 2; lastX = event.clientX; lastY = event.clientY; updateTransform(); });
    svg.addEventListener('pointerup', () => { dragging = false; });
    container.querySelectorAll('.dns-map-node').forEach(node => node.addEventListener('click', () => {
        const detail = container.querySelector('#dnsMapDetail');
        const nodeData = nodes.find(item => item.label === node.querySelector('text').textContent || item.label.slice(0, 21) + '...' === node.querySelector('text').textContent);
        if (!nodeData) return;
        detail.hidden = false;
        detail.innerHTML = `<b>DNS RECORD</b><span>Type: ${escapeHtml(nodeData.type)}</span><span>Value: ${escapeHtml(nodeData.label)}</span><span>Domain: ${escapeHtml(data.domain)}</span>`;
    }));
}