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
                <div class="cve-btn" role="button" tabindex="0" onclick="openCveReport(event, ${port}, '${service}', '${banner}')" style="flex: 1; display: flex; align-items: center; justify-content: center; gap: 8px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 8px; padding: 12px; cursor: pointer; transition: all 0.2s ease;">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                    <span id="cve-status-${port}" style="color: #60a5fa; font-weight: 500; font-size: 0.9rem;">CVE Reports</span>
                </div>
            </div>
        `;
        grid.appendChild(card);
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
    event.stopPropagation();
    
    const modal = document.getElementById('cveModal');
    if (!modal) return;
    
    const headerTitle = document.getElementById('cveModalTitle');
    const content = document.getElementById('cveModalContent');
    
    headerTitle.innerText = `CVE Report: Port ${port} (${service})`;
    modal.style.display = 'flex';
    
    const data = window.cveDataCache[port];
    
    if (!data) {
        content.innerHTML = `
            <div style="text-align: center; padding: 40px;">
                <div class="cve-spinner"></div>
                <p style="color: var(--text-secondary); margin-top: 15px;">Querying NVD Database...</p>
            </div>
        `;
        // The backend might still be processing. 
        // We just wait for the websocket event to update this cache.
        return;
    }
    
    renderCveModalContent(data, content);
}

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
                          
        html += `
            <div style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                    <h4 style="color: var(--text-main); font-size: 1.1rem; margin: 0;">${cve.id}</h4>
                    <span style="background: ${scoreColor}22; color: ${scoreColor}; padding: 4px 10px; border-radius: 12px; font-weight: 600; font-size: 0.85rem;">CVSS: ${cve.cvss_score}</span>
                </div>
                <p style="color: var(--text-secondary); font-size: 0.95rem; line-height: 1.5; margin-bottom: 15px;">${cve.description}</p>
                <div style="display: flex; flex-wrap: wrap; gap: 10px; font-size: 0.8rem; color: var(--text-muted);">
                    <span><strong style="color: var(--text-secondary);">Published:</strong> ${cve.published.split('T')[0]}</span>
                    <span><strong style="color: var(--text-secondary);">Vector:</strong> ${cve.cvss_vector}</span>
                </div>
            </div>
        `;
    });
    
    html += `</div>`;
    contentContainer.innerHTML = html;
}

function closeCveModal() {
    const modal = document.getElementById('cveModal');
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
