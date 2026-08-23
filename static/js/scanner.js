let socket;

function initSocket() {
    socket = io({
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5
    });

    socket.on('connect', () => console.log('WebSocket connected'));
    
    socket.on('connect_error', (error) => {
        console.error('WebSocket connection error:', error);
    });
    
    socket.on('disconnect', (reason) => {
        console.warn('WebSocket disconnected:', reason);
    });

    socket.on('scan_log', (data) => addTerminalLine(data.message));

    socket.on('scan_progress', (data) => {
        const progress = data.progress_percent ? `[${data.progress_percent}%]` : '';
        addTerminalLine(`[${data.current}/${data.total}] Scanning port ${data.port}... ${progress}`);
    });

    socket.on('port_found', (data) => {
        addTerminalLine(`✓ OPEN: Port ${data.port} (${data.service}) - ${data.banner}`);
    });

    socket.on('cve_results', (data) => {
        handleCveResults(data);
    });

    socket.on('cve_log', (data) => {
        const modal = document.getElementById('cveModal');
        const headerTitle = document.getElementById('cveModalTitle');
        if (modal && modal.style.display === 'flex' && headerTitle && headerTitle.innerText.includes(`Port ${data.port}`)) {
            const logEl = document.getElementById('cveModalLog');
            if (logEl) {
                const line = document.createElement('div');
                line.style.cssText = 'padding: 2px 0; animation: fadeInLine 0.2s ease;';
                line.textContent = '> ' + data.message;
                // Color coding
                if (data.message.includes('✅')) line.style.color = '#10b981';
                else if (data.message.includes('❌')) line.style.color = '#ef4444';
                else if (data.message.includes('⚠️')) line.style.color = '#f59e0b';
                else if (data.message.includes('🛡️') || data.message.includes('→')) line.style.color = '#60a5fa';
                else if (data.message.includes('📦') || data.message.includes('🔴') || data.message.includes('🟠')) line.style.color = '#c084fc';
                else line.style.color = '#94a3b8';
                logEl.appendChild(line);
                logEl.scrollTop = logEl.scrollHeight;
            }
        }
    });

    socket.on('scan_complete', (data) => {
        addTerminalLine(`\n✅ Scan completed! Found ${data.total_open} open ports.`);
        const btn = document.getElementById('analyzeBtn');
        btn.disabled = false;
        btn.innerText = 'Analyze Target';
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';

        // Dynamically render the results cards instead of reloading
        renderResults(data.results);
    });
}

function renderResults(results) {
    const container = document.getElementById('resultsContainer');
    if (!container) return;

    container.innerHTML = '';

    if (results.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; background: var(--bg-card); border-radius: 12px; width: 100%;">
                <p style="color: var(--accent); font-weight: 600;">No open ports found.</p>
            </div>`;
        return;
    }

    const grid = document.createElement('div');
    grid.className = 'results-grid';

    results.forEach(([port, service, banner, severity, threat]) => {
        const card = document.createElement('div');
        card.className = 'card';
        card.onclick = () => window.showDetailedAnalysis(port, service, banner, severity);

        card.innerHTML = `
            <span class="severity-badge ${severity}">${severity}</span>
            <div class="port-info">Port ${port}</div>
            <div class="service-name">${service} Service Detected</div>
            <div class="banner-text">${banner || "No banner response"}</div>
            <div class="remediation">
                <span class="remediation-label">Remediation Guide</span>
                ${threat}
            </div>
            <div class="action-buttons-row" style="display: flex; gap: 10px; margin-top: 15px;">
                <div class="ai-hint" role="button" tabindex="0" style="flex: 1; margin-top: 0;">
                    <svg class="ai-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M12 2l1.5 3.3L17 6l-3 2.2L14 11l-2-1.6L10 11l.9-2.8L8 6l3.5-.7L12 2z"></path>
                        <path d="M5 12l.7 1.6L7.5 14l-1.8 1.1L5 16.5 4.3 15.1 3 14l1.3-1 1.7-.6z"></path>
                        <path d="M20 12l.5 1.1L21.5 14l-1.3.8L20 16l-.5-1.2L18 14l1.5-1.8L20 12z"></path>
                    </svg>
                    <span>Click for AI expert analysis</span>
                </div>
                <div class="cve-btn" id="cve-btn-${port}" role="button" tabindex="0" style="flex: 1; display: flex; align-items: center; justify-content: center; gap: 8px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 8px; padding: 12px; cursor: pointer; transition: all 0.2s ease;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    <span id="cve-status-${port}" style="color: #60a5fa; font-weight: 500; font-size: 0.9rem;">CVE Reports</span>
                </div>
            </div>
        `;

        grid.appendChild(card);

        // CRITICAL: Attach the CVE click AFTER the card is in DOM.
        // Using stopImmediatePropagation prevents the parent card.onclick
        // (AI analysis) from ever firing when the CVE button is clicked.
        const cveBtn = card.querySelector(`#cve-btn-${port}`);
        if (cveBtn) {
            cveBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                e.stopImmediatePropagation();
                openCveReport(null, port, service, banner);
            });
        }
    });


    container.appendChild(grid);
}

// Global state for CVEs
window.cveDataCache = {};

function handleCveResults(data) {
    const statusEl = document.getElementById(`cve-status-${data.port}`);
    
    window.cveDataCache[data.port] = data;
    
    if (data.status === 'success') {
        if (statusEl) {
            statusEl.innerText = `${data.cve_count} CVEs Found`;
            statusEl.style.color = data.cve_count > 0 ? '#ef4444' : '#10b981';
        }
    } else {
        if (statusEl) {
            statusEl.innerText = 'No CVEs';
            statusEl.style.color = '#9ca3af';
        }
    }
    
    // If the modal is currently open and showing the loading state for THIS port, update it automatically
    const modal = document.getElementById('cveModal');
    const headerTitle = document.getElementById('cveModalTitle');
    if (modal && modal.style.display === 'flex' && headerTitle && headerTitle.innerText.includes(`Port ${data.port}`)) {
        const content = document.getElementById('cveModalContent');
        if (content) {
            renderCveModalContent(data, content);
        }
    }
}

function openCveReport(event, port, service, banner) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    
    const modal = document.getElementById('cveModal');
    if (!modal) return;
    
    const headerTitle = document.getElementById('cveModalTitle');
    const content = document.getElementById('cveModalContent');
    
    headerTitle.innerText = `CVE Report: Port ${port} (${service})`;
    modal.style.display = 'flex';
    
    const data = window.cveDataCache[port];
    
    if (!data) {
        content.innerHTML = `
            <div style="padding: 20px 0;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border);">
                    <div class="cve-spinner" style="width:20px;height:20px;flex-shrink:0;"></div>
                    <span style="color: var(--text-secondary); font-size: 0.9rem; font-weight: 500;">Querying NVD database in real-time...</span>
                </div>
                <div id="cveModalLog" style="
                    background: #0a0a0f;
                    border: 1px solid rgba(59,130,246,0.15);
                    border-radius: 8px;
                    padding: 14px 16px;
                    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
                    font-size: 0.82rem;
                    line-height: 1.7;
                    max-height: 280px;
                    overflow-y: auto;
                    color: #94a3b8;
                "></div>
            </div>
        `;
        
        const targetInput = document.getElementById('targetInput');
        const target = targetInput ? targetInput.value.trim() : 'Unknown';
        
        socket.emit('fetch_cve', {
            target: target,
            port: port,
            service: service,
            banner: banner
        });
        
        return;
    }
    
    renderCveModalContent(data, content);
}

// ── Per-CVE AI explanation cache ─────────────────────────────────────────────
// Keys: cve_id (string). Values: { success, data } from /cve_explain response.
window.cveExplanationCache = {};

function renderCveModalContent(data, contentContainer) {
    if (data.status === 'no_cpe_match') {
        contentContainer.innerHTML = `
            <div style="text-align: center; padding: 30px;">
                <p style="color: var(--text-secondary);">Unable to definitively resolve product version from banner.</p>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 10px;">Product: ${data.product || 'Unknown'}, Version: ${data.version || 'Unknown'}</p>
            </div>
        `;
        return;
    }

    if (data.cve_count === 0) {
        contentContainer.innerHTML = `
            <div style="text-align: center; padding: 30px;">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 15px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                <h3 style="color: #10b981; margin-bottom: 10px;">No Known Vulnerabilities</h3>
                <p style="color: var(--text-secondary);">No known CVEs found for ${data.resolved_cpe}.</p>
            </div>
        `;
        return;
    }

    let html = `
        <div style="margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid var(--border);">
            <p style="color: var(--text-secondary); font-size: 0.9rem;">Resolved CPE: <code style="color: var(--accent); background: rgba(16,185,129,0.1); padding: 2px 6px; border-radius: 4px;">${data.resolved_cpe}</code></p>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 8px;">Found <strong style="color: var(--critical);">${data.cve_count}</strong> vulnerabilities.</p>
        </div>
        <div style="display: flex; flex-direction: column; gap: 15px;">
    `;

    data.cves.forEach(cve => {
        const scoreColor = cve.cvss_score >= 9.0 ? 'var(--critical)' :
                          (cve.cvss_score >= 7.0 ? 'var(--high)' : 'var(--medium)');
        const safeId = cve.id.replace(/[^a-zA-Z0-9-]/g, '_');

        html += `
            <div id="cve-card-${safeId}" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; transition: border-color 0.2s ease;">
                <!-- NVD FACTS -->
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                        <h4 style="color: var(--text-main); font-size: 1.05rem; margin: 0; font-family: 'JetBrains Mono', monospace;">${cve.id}</h4>
                        <span style="background: ${scoreColor}22; color: ${scoreColor}; padding: 3px 9px; border-radius: 12px; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.05em;">${cve.severity}</span>
                    </div>
                    <span style="background: ${scoreColor}22; color: ${scoreColor}; padding: 4px 10px; border-radius: 12px; font-weight: 700; font-size: 0.9rem;">CVSS ${cve.cvss_score}</span>
                </div>
                <div style="margin-bottom: 12px;">
                    <span style="display: inline-block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em; color: #60a5fa; text-transform: uppercase; margin-bottom: 6px; background: rgba(59,130,246,0.08); padding: 2px 8px; border-radius: 4px;">NVD Facts</span>
                    <p style="color: var(--text-secondary); font-size: 0.92rem; line-height: 1.55; margin: 0;">${cve.description}</p>
                    <div style="display: flex; flex-wrap: wrap; gap: 12px; font-size: 0.78rem; color: var(--text-muted); margin-top: 10px;">
                        <span><strong style="color: var(--text-secondary);">Published:</strong> ${(cve.published || '').split('T')[0] || 'N/A'}</span>
                        <span><strong style="color: var(--text-secondary);">Vector:</strong> ${cve.cvss_vector || 'N/A'}</span>
                        ${cve.cpe ? '<span><strong style="color: var(--text-secondary);">CPE:</strong> <code style="font-size:0.72rem;">' + cve.cpe + '</code></span>' : ''}
                    </div>
                </div>
                <!-- AI Explain Button -->
                <button
                    id="ai-explain-btn-${safeId}"
                    data-cve-id="${cve.id}"
                    data-safe-id="${safeId}"
                    style="
                        display: flex; align-items: center; gap: 8px;
                        background: linear-gradient(135deg, rgba(139,92,246,0.15), rgba(59,130,246,0.10));
                        border: 1px solid rgba(139,92,246,0.35);
                        border-radius: 8px; padding: 9px 16px; cursor: pointer;
                        color: #c4b5fd; font-size: 0.88rem; font-weight: 600;
                        transition: all 0.2s ease; width: 100%; justify-content: center;
                        margin-top: 4px;
                    "
                >
                    Explain with AI
                </button>
                <!-- AI Explanation Panel (injected on demand) -->
                <div id="ai-panel-${safeId}" style="display: none; margin-top: 14px;"></div>
            </div>
        `;
    });

    html += `</div>`;
    contentContainer.innerHTML = html;

    // Attach button event listeners after HTML is in DOM
    data.cves.forEach(cve => {
        const safeId = cve.id.replace(/[^a-zA-Z0-9-]/g, '_');
        const btn = document.getElementById('ai-explain-btn-' + safeId);
        if (btn) {
            btn.addEventListener('mouseover', function() {
                if (!this.disabled) {
                    this.style.background = 'linear-gradient(135deg,rgba(139,92,246,0.28),rgba(59,130,246,0.18))';
                    this.style.borderColor = 'rgba(139,92,246,0.6)';
                }
            });
            btn.addEventListener('mouseout', function() {
                if (!this.disabled) {
                    this.style.background = 'linear-gradient(135deg,rgba(139,92,246,0.15),rgba(59,130,246,0.10))';
                    this.style.borderColor = 'rgba(139,92,246,0.35)';
                }
            });
            btn.addEventListener('click', function() {
                requestCveExplanation(this.dataset.cveId, this.dataset.safeId);
            });
        }
        // Re-attach cached explanations if the modal was re-opened
        if (window.cveExplanationCache[cve.id]) {
            _renderCveExplanationPanel(safeId, cve.id, window.cveExplanationCache[cve.id]);
        }
    });
}

/**
 * Called when the user clicks "Explain with AI" for a specific CVE.
 * Checks cache first; otherwise POSTs to /cve_explain.
 */
function requestCveExplanation(cveId, safeId) {
    // Cache hit: render immediately without a network call
    if (window.cveExplanationCache[cveId]) {
        _renderCveExplanationPanel(safeId, cveId, window.cveExplanationCache[cveId]);
        return;
    }

    const btn = document.getElementById('ai-explain-btn-' + safeId);
    const panel = document.getElementById('ai-panel-' + safeId);
    if (!panel) return;

    // Loading state
    if (btn) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.style.cursor = 'not-allowed';
        btn.textContent = 'Generating explanation\u2026';
    }
    panel.style.display = 'block';
    panel.innerHTML = '<div style="background: rgba(139,92,246,0.06); border: 1px solid rgba(139,92,246,0.2); border-radius: 8px; padding: 16px; text-align: center; color: var(--text-muted); font-size: 0.88rem;">Contacting AI\u2026 this may take a few seconds.</div>';

    // Find full CVE data from the port data cache
    let cveData = null;
    for (const portKey of Object.keys(window.cveDataCache || {})) {
        const portData = window.cveDataCache[portKey];
        if (portData && portData.cves) {
            const match = portData.cves.find(function(c) { return c.id === cveId; });
            if (match) { cveData = match; break; }
        }
    }
    if (!cveData) { cveData = { id: cveId }; }

    // POST to backend
    fetch('/cve_explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve_data: cveData })
    })
    .then(function(res) { return res.json(); })
    .then(function(result) {
        window.cveExplanationCache[cveId] = result;
        _renderCveExplanationPanel(safeId, cveId, result);
    })
    .catch(function(err) {
        console.error('CVE explain fetch failed:', err);
        _renderCveExplanationPanel(safeId, cveId, {
            success: false,
            error: 'Network error — could not reach the AI service. The NVD vulnerability information above is still accurate.'
        });
    })
    .finally(function() {
        if (btn) {
            btn.disabled = false;
            btn.style.opacity = '1';
            btn.style.cursor = 'pointer';
            btn.textContent = 'Explain with AI';
        }
    });
}

/**
 * Renders the AI explanation result inside the panel div for a given CVE card.
 */
function _renderCveExplanationPanel(safeId, cveId, result) {
    const panel = document.getElementById('ai-panel-' + safeId);
    if (!panel) return;
    panel.style.display = 'block';

    // Error state
    if (!result || !result.success) {
        const msg = (result && result.error)
            ? result.error
            : 'AI explanation is currently unavailable. The original NVD vulnerability information above is still accurate.';
        panel.innerHTML =
            '<div style="background: rgba(239,68,68,0.07); border: 1px solid rgba(239,68,68,0.25); border-radius: 8px; padding: 14px 16px; font-size: 0.87rem; color: #fca5a5; line-height: 1.5;">' +
                '<strong>\u26A0\uFE0F AI Unavailable</strong><br>' + _escHtml(msg) +
            '</div>' +
            '<button onclick="document.getElementById(\'ai-panel-' + safeId + '\').style.display=\'none\'" ' +
                'style="margin-top:8px;background:none;border:none;color:var(--text-muted);font-size:0.8rem;cursor:pointer;padding:0;">Hide</button>';
        return;
    }

    var d = result.data || {};
    var rows = [
        { icon: '\uD83D\uDD0D', label: 'What is this?',       field: 'what_is_this'            },
        { icon: '\u26A0\uFE0F', label: 'Why should I care?', field: 'why_should_i_care'     },
        { icon: '\uD83C\uDFAF', label: 'What could happen?',     field: 'what_could_happen'   },
        { icon: '\uD83D\uDDA5\uFE0F', label: 'Am I affected?', field: 'am_i_affected'   },
        { icon: '\uD83D\uDD27', label: 'What should I do?',    field: 'what_should_i_do' },
        { icon: '\u2705',       label: 'How do I verify the fix?', field: 'how_do_i_verify_the_fix' }
    ];

    var rowsHtml = rows.map(function(r) {
        var text = d[r.field];
        if (!text) return '';
        return '<div style="padding: 10px 0; border-bottom: 1px solid rgba(139,92,246,0.1);">' +
            '<div style="font-size: 0.78rem; font-weight: 700; color: #a78bfa; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 4px;">' +
                r.icon + ' ' + _escHtml(r.label) +
            '</div>' +
            '<div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.6;">' +
                _escHtml(text) +
            '</div>' +
        '</div>';
    }).join('');

    panel.innerHTML =
        '<div style="background: linear-gradient(135deg, rgba(139,92,246,0.06), rgba(59,130,246,0.04)); border: 1px solid rgba(139,92,246,0.25); border-radius: 10px; padding: 16px 18px;">' +
            '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid rgba(139,92,246,0.2);">' +
                '<span style="font-size: 0.8rem; font-weight: 700; color: #a78bfa; text-transform: uppercase; letter-spacing: 0.08em;">' +
                    '\u2728 AI Explanation' +
                '</span>' +
                '<button onclick="document.getElementById(\'ai-panel-' + safeId + '\').style.display=\'none\'" ' +
                    'style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:0.8rem;padding:2px 6px;border-radius:4px;">' +
                    'Hide \u2715' +
                '</button>' +
            '</div>' +
            '<div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 10px; font-style: italic;">' +
                'Generated by AI based on NVD data. Not a substitute for authoritative security advisories.' +
            '</div>' +
            rowsHtml +
        '</div>';
}

/** Escapes HTML special chars to prevent XSS from AI-generated content. */
function _escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function closeCveModal() {
    var modal = document.getElementById('cveModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function addTerminalLine(message) {
    const terminal = document.getElementById('terminal');
    if (!terminal) return;
    const line = document.createElement('div');
    line.textContent = '> ' + message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function startScan(event) {
    console.log('startScan called');
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    const targetInput = document.getElementById('targetInput');
    const target = targetInput.value.trim();
    if (!target) {
        console.warn('No target provided');
        return;
    }

    const deepScan = document.getElementById('deepScan').checked;
    const btn = document.getElementById('analyzeBtn');

    btn.disabled = true;
    btn.innerText = 'Scanning...';
    btn.style.opacity = '0.6';
    btn.style.cursor = 'not-allowed';

    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<div style="color: var(--accent)">> Initializing socket connection...</div>';

    // Ensure socket is initialized
    if (!socket || !socket.connected) {
        console.log('Socket not connected, initializing...');
        initSocket();
        // Give socket a moment to connect
        setTimeout(() => {
            socket.emit('start_scan', { target: target, deep_scan: deepScan });
        }, 100);
    } else {
        console.log('Socket already connected, emitting scan');
        socket.emit('start_scan', { target: target, deep_scan: deepScan });
    }
    
    return false;
}

function toggleDeepScanWarning() {
    const deepScanCheckbox = document.getElementById('deepScan');
    const warningBox = document.getElementById('deepScanWarning');
    
    if (deepScanCheckbox.checked) {
        warningBox.style.display = 'flex';
    } else {
        warningBox.style.display = 'none';
    }
}

// Initialize socket when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('Dashboard loaded - initializing socket');
    if (!socket) {
        initSocket();
    }
    
    // Initialize warning visibility on page load
    const deepScanCheckbox = document.getElementById('deepScan');
    if (deepScanCheckbox && deepScanCheckbox.checked) {
        toggleDeepScanWarning();
    }
});
