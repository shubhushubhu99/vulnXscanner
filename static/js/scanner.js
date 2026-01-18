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

function validateTarget(target) {
    if (!target || typeof target !== 'string') {
        return { valid: false, message: "Target is empty or invalid" };
    }
    
    target = target.trim();
    if (!target) {
        return { valid: false, message: "Target is empty" };
    }
    
    if (target.length > 253) {
        return { valid: false, message: "Target is too long" };
    }
    
    // Remove http/https prefixes
    let targetClean = target.replace(/^https?:\/\//, '').split('/')[0];
    
    // Check for IPv4
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(targetClean)) {
        return { valid: true };
    }
    
    // Check for IPv6
    if (targetClean.startsWith('[') && targetClean.endsWith(']')) {
        targetClean = targetClean.slice(1, -1);
    }
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){2,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){3,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){4,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){5,6}$|^:(?::[0-9a-fA-F]{1,4}){1,7}$/;
    if (ipv6Regex.test(targetClean)) {
        return { valid: true };
    }
    
    // Check for domain name
    const domainRegex = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$/;
    if (domainRegex.test(targetClean)) {
        const parts = targetClean.split('.');
        if (parts.length >= 2 && parts[parts.length - 1].length >= 2) {
            return { valid: true };
        }
    }
    
    // Check for dangerous characters
    const dangerousChars = /[;&|`$\(\)<>\n\r]/;
    if (dangerousChars.test(target)) {
        return { valid: false, message: "Target contains potentially dangerous characters" };
    }
    
    return { valid: false, message: "Invalid IP address or domain name format" };
}

function startScan(event) {
    if (event) event.preventDefault();

    const targetInput = document.getElementById('targetInput');
    const target = targetInput.value.trim();
    
    // Validate target
    const validation = validateTarget(target);
    if (!validation.valid) {
        addTerminalLine(`❌ Validation failed: ${validation.message}`);
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

    if (!socket || !socket.connected) {
        initSocket();
    }

    socket.emit('start_scan', { target: target, deep_scan: deepScan });
}

document.addEventListener('DOMContentLoaded', initSocket);
