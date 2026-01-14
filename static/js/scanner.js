let socket;

function initSocket() {
    socket = io();

    socket.on('connect', () => console.log('WebSocket connected'));

    socket.on('scan_log', (data) => addTerminalLine(data.message));

    socket.on('scan_progress', (data) => {
        addTerminalLine(`[${data.current}/${data.total}] Scanning port ${data.port}...`);
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
        card.onclick = () => showDetailedAnalysis(port, service, banner, severity);

        card.innerHTML = `
            <span class="severity-badge ${severity}">${severity}</span>
            <div class="port-info">Port ${port}</div>
            <div class="service-name">${service} Service Detected</div>
            <div class="banner-text">${banner || "No banner response"}</div>
            <div class="remediation">
                <span class="remediation-label">Remediation Guide</span>
                ${threat}
            </div>
            <div class="ai-hint">🔍 Click for AI expert analysis</div>
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

document.addEventListener('DOMContentLoaded', initSocket);
