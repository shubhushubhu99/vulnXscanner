// Get or create socket (avoid duplicate declarations)
let subdomainSocket = null;

function getSubdomainSocket() {
    if (!subdomainSocket) {
        subdomainSocket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: 5
        });
        setupSubdomainSocketListeners();
    }
    return subdomainSocket;
}

function setupSubdomainSocketListeners() {
    subdomainSocket.on('connect', () => {
        console.log('Subdomain scanner WebSocket connected');
    });

    subdomainSocket.on('subdomain_log', (data) => addTerminalLine(data.message));

    subdomainSocket.on('subdomain_found', (data) => {
        addTerminalLine(`Found: ${data.subdomain} (${data.status_text})`);
    });

    subdomainSocket.on('subdomain_progress', (data) => {
        const progress = data.progress_percent ? `[${data.progress_percent}%]` : '';
        addTerminalLine(`Checking ${data.current}/${data.total} - ${data.current_subdomain}... ${progress}`);
        updateProgress(data.progress_percent || 0, `${data.current}/${data.total} subdomains checked`);
    });

    subdomainSocket.on('scan_complete', (data) => {
        updateProgress(100, 'Scan complete');
        addTerminalLine(`\nCompleted! Found ${data.total_found} valid subdomain(s).`);
        const btn = document.getElementById('subdomainBtn');
        btn.disabled = false;
        btn.innerText = 'Find Subdomains';
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        renderResults(data.results, data.domain);
    });
}

function renderResults(results, domain) {
    const container = document.getElementById('resultsContainer');
    if (!container) return;

    container.innerHTML = '';

    if (results.length === 0) {
        container.innerHTML = `
            <div class="result-box" style="text-align: center;">
                <p style="color: var(--accent); font-weight: 600;">No subdomains found for ${domain}</p>
            </div>`;
        return;
    }

    const resultBox = document.createElement('div');
    resultBox.className = 'result-box';

    const header = document.createElement('div');
    header.className = 'result-header';
    header.innerHTML = `
        <h3>Found ${results.length} Subdomain(s)</h3>
        <button type="button" class="export-btn" onclick="exportResults()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block; margin-right: 6px; vertical-align: -2px;">
                <polyline points="8 17 12 21 16 17"></polyline>
                <line x1="12" y1="12" x2="12" y2="21"></line>
                <path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"></path>
            </svg>
            Export
        </button>
    `;
    resultBox.appendChild(header);

    const resultList = document.createElement('div');
    resultList.className = 'result-list';

    results.forEach(result => {
        const item = document.createElement('div');
        item.className = 'result-item';

        const subdomain = document.createElement('div');
        subdomain.className = 'result-subdomain';
        subdomain.textContent = result.subdomain || result;

        const status = document.createElement('div');
        status.className = 'result-status';

        if (typeof result === 'object' && result.status_code) {
            const statusCode = document.createElement('span');
            statusCode.className = 'status-code';
            statusCode.textContent = result.status_code;
            status.appendChild(statusCode);

            const statusText = document.createElement('span');
            statusText.className = 'status-text';
            
            if (result.status_code === 200) {
                statusText.classList.add('live');
            } else if ([301, 302].includes(result.status_code)) {
                statusText.classList.add('redirected');
            } else if ([401, 403].includes(result.status_code)) {
                statusText.classList.add('restricted');
            } else {
                statusText.classList.add('unreachable');
            }
            
            statusText.textContent = result.status_text || 'Found';
            status.appendChild(statusText);
        } else {
            const statusText = document.createElement('span');
            statusText.className = 'status-text found';
            statusText.textContent = 'Found';
            status.appendChild(statusText);
        }

        item.appendChild(subdomain);
        item.appendChild(status);
        resultList.appendChild(item);
    });

    resultBox.appendChild(resultList);
    container.appendChild(resultBox);
}

function addTerminalLine(message) {
    const terminal = document.getElementById('terminal');
    if (!terminal) return;

    const line = document.createElement('div');
    line.textContent = '> ' + message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function updateProgress(percentage, message = '') {
    const fillEl = document.getElementById('progressFill');
    const percentEl = document.getElementById('progressPercent');
    const msgEl = document.getElementById('progressMessage');
    
    if (fillEl) fillEl.style.width = percentage + '%';
    if (percentEl) percentEl.textContent = percentage + '%';
    if (msgEl && message) msgEl.textContent = message;
}

function startSubdomainScan(event) {
    event.preventDefault();

    const domainInput = document.querySelector('input[name="domain"]');
    const domain = domainInput.value.trim();
    
    if (!domain) {
        alert('Please enter a domain');
        return;
    }

    const deepScan = document.getElementById('deepScanCheck').checked;
    const btn = document.getElementById('subdomainBtn');

    btn.disabled = true;
    btn.innerText = 'Scanning...';
    btn.style.opacity = '0.6';
    btn.style.cursor = 'not-allowed';

    // Show and reset terminal
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<div style="color: var(--accent);">> Initializing scan...</div>';
    document.getElementById('progressContainer').style.display = 'block';
    updateProgress(0);

    // Clear previous results
    document.getElementById('resultsContainer').innerHTML = '';

    // Get or create socket and emit scan
    const sock = getSubdomainSocket();
    
    // Wait a short moment to ensure connection, then emit
    if (sock.connected) {
        sock.emit('start_subdomain_scan', { domain: domain, deep_scan: deepScan });
    } else {
        // Wait for connection before emitting
        sock.once('connect', () => {
            console.log('Socket connected, emitting scan request for: ' + domain);
            sock.emit('start_subdomain_scan', { domain: domain, deep_scan: deepScan });
        });
    }
}

function exportResults() {
    const items = document.querySelectorAll('.result-item');
    let data = 'Subdomain\tStatus Code\tStatus\n';
    
    items.forEach(item => {
        const subdomain = item.querySelector('.result-subdomain')?.textContent || '';
        const statusCode = item.querySelector('.status-code')?.textContent || '-';
        const statusText = item.querySelector('.status-text')?.textContent || '';
        data += `${subdomain}\t${statusCode}\t${statusText}\n`;
    });
    
    const blob = new Blob([data], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'subdomains-' + Date.now() + '.txt';
    a.click();
    window.URL.revokeObjectURL(url);
}

document.addEventListener('DOMContentLoaded', () => {
    initializeSubdomainPage();
});

function initializeSubdomainPage() {
    // Initialize socket connection for subdomain scanning
    getSubdomainSocket();
    
    // Handle form submission
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', startSubdomainScan);
    }
    
    console.log('Subdomain page initialized');
}

// Also initialize immediately in case script loads after DOMContentLoaded
// (e.g., when navigating via SPA)
if (document.readyState === 'loading') {
    // DOM is still loading, wait for DOMContentLoaded
    document.addEventListener('DOMContentLoaded', initializeSubdomainPage);
} else {
    // DOM is already loaded, initialize now
    initializeSubdomainPage();
}
