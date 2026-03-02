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
            <div class="ai-hint" role="button" tabindex="0">
                <svg class="ai-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M12 2l1.5 3.3L17 6l-3 2.2L14 11l-2-1.6L10 11l.9-2.8L8 6l3.5-.7L12 2z"></path>
                    <path d="M5 12l.7 1.6L7.5 14l-1.8 1.1L5 16.5 4.3 15.1 3 14l1.3-1 1.7-.6z"></path>
                    <path d="M20 12l.5 1.1L21.5 14l-1.3.8L20 16l-.5-1.2L18 14l1.5-1.8L20 12z"></path>
                </svg>
                <span>Click for AI expert analysis</span>
            </div>
        `;
        grid.appendChild(card);
    });

    container.appendChild(grid);
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
    if (event) event.preventDefault();

    const targetInput = document.getElementById('targetInput');
    const target = targetInput.value.trim();
    if (!target) return;

    const deepScan = document.getElementById('deepScan').checked;
    const btn = document.getElementById('analyzeBtn');

    btn.disabled = true;
    btn.innerText = 'Scanning...';
    btn.style.opacity = '0.6';
    btn.style.cursor = 'not-allowed';

    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<div style="color: var(--accent)">> Initializing socket connection...</div>';

    if (!socket || !socket.connected) {
        initSocket();
    }

    socket.emit('start_scan', { target: target, deep_scan: deepScan });
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

document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    // Initialize warning visibility on page load
    const deepScanCheckbox = document.getElementById('deepScan');
    if (deepScanCheckbox && deepScanCheckbox.checked) {
        toggleDeepScanWarning();
    }
});
