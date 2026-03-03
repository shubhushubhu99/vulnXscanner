// Directory Scanner WebSocket client
let dirSocket = null;

function getDirSocket() {
    if (!dirSocket) {
        dirSocket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: 5
        });
        setupDirSocketListeners();
    }
    return dirSocket;
}

function setupDirSocketListeners() {
    dirSocket.on('connect', () => {
        console.log('Directory scanner WebSocket connected');
    });

    dirSocket.on('dir_scan_log', (data) => addDirTerminalLine(data.message));

    dirSocket.on('dir_found', (data) => {
        const code = data.status_code ? `[${data.status_code}]` : '';
        addDirTerminalLine(`Found: /${data.path} ${code} ${data.status_text || ''}`);
    });

    dirSocket.on('dir_scan_progress', (data) => {
        const progress = data.progress_percent ? `[${data.progress_percent}%]` : '';
        addDirTerminalLine(`Checking ${data.current}/${data.total} - /${data.current_path}... ${progress}`);
        updateDirProgress(data.progress_percent || 0, `${data.current}/${data.total} paths checked`);
    });

    dirSocket.on('dir_scan_complete', (data) => {
        updateDirProgress(100, 'Scan complete');
        addDirTerminalLine(`\nCompleted! Found ${data.total_found} path(s).`);
        const btn = document.getElementById('dirScanBtn');
        btn.disabled = false;
        btn.innerText = 'Find Directories';
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        renderDirResults(data.results, data.target);
    });
}

function renderDirResults(results, target) {
    const container = document.getElementById('resultsContainer');
    if (!container) return;

    container.innerHTML = '';

    if (results.length === 0) {
        container.innerHTML = `
            <div class="result-box" style="text-align: center;">
                <p style="color: var(--accent); font-weight: 600;">No directories found for ${target}</p>
            </div>`;
        return;
    }

    const resultBox = document.createElement('div');
    resultBox.className = 'result-box';

    const header = document.createElement('div');
    header.className = 'result-header';
    header.innerHTML = `
        <h3>Found ${results.length} Path(s)</h3>
        <button type="button" class="export-btn" onclick="exportDirResults()">
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

        const pathEl = document.createElement('div');
        pathEl.className = 'result-path';

        if (result.url) {
            const link = document.createElement('a');
            link.href = result.url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.textContent = '/' + (result.path || '');
            pathEl.appendChild(link);
        } else {
            pathEl.textContent = '/' + (result.path || result);
        }

        const status = document.createElement('div');
        status.className = 'result-status';

        if (typeof result === 'object' && result.status_code) {
            const statusCode = document.createElement('span');
            statusCode.className = 'status-code';

            // Color-code by status range
            const code = result.status_code;
            if (code >= 200 && code < 300) statusCode.classList.add('code-2xx');
            else if (code >= 300 && code < 400) statusCode.classList.add('code-3xx');
            else if (code >= 400 && code < 500) statusCode.classList.add('code-4xx');
            else if (code >= 500) statusCode.classList.add('code-5xx');

            statusCode.textContent = result.status_code;
            status.appendChild(statusCode);

            const statusText = document.createElement('span');
            statusText.className = 'status-text';

            if (result.status_code === 200) {
                statusText.classList.add('live');
            } else if ([301, 302, 303, 307, 308].includes(result.status_code)) {
                statusText.classList.add('redirected');
            } else if ([401, 403].includes(result.status_code)) {
                statusText.classList.add('restricted');
            } else {
                statusText.classList.add('unreachable');
            }

            statusText.textContent = result.status_text || 'Found';
            status.appendChild(statusText);

            // Show content length
            if (result.content_length) {
                const cl = document.createElement('span');
                cl.className = 'content-length';
                cl.textContent = formatBytes(result.content_length);
                status.appendChild(cl);
            }
        } else {
            const statusText = document.createElement('span');
            statusText.className = 'status-text found';
            statusText.textContent = 'Found';
            status.appendChild(statusText);
        }

        item.appendChild(pathEl);
        item.appendChild(status);
        resultList.appendChild(item);
    });

    resultBox.appendChild(resultList);
    container.appendChild(resultBox);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function addDirTerminalLine(message) {
    const terminal = document.getElementById('terminal');
    if (!terminal) return;

    const line = document.createElement('div');
    line.textContent = '> ' + message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function updateDirProgress(percentage, message) {
    const fillEl = document.getElementById('progressFill');
    const percentEl = document.getElementById('progressPercent');
    const msgEl = document.getElementById('progressMessage');

    if (fillEl) fillEl.style.width = percentage + '%';
    if (percentEl) percentEl.textContent = percentage + '%';
    if (msgEl && message) msgEl.textContent = message;
}

function startDirScan(event) {
    event.preventDefault();

    const targetInput = document.querySelector('input[name="target"]');
    const target = targetInput.value.trim();

    if (!target) {
        alert('Please enter a target URL');
        return;
    }

    const deepScan = document.getElementById('deepScanCheck').checked;
    const btn = document.getElementById('dirScanBtn');

    btn.disabled = true;
    btn.innerText = 'Scanning...';
    btn.style.opacity = '0.6';
    btn.style.cursor = 'not-allowed';

    // Show and reset terminal
    const terminal = document.getElementById('terminal');
    terminal.innerHTML = '<div style="color: var(--accent);">> Initializing directory scan...</div>';
    document.getElementById('progressContainer').style.display = 'block';
    updateDirProgress(0);

    // Clear previous results
    document.getElementById('resultsContainer').innerHTML = '';

    // Get or create socket and emit scan
    const sock = getDirSocket();

    if (sock.connected) {
        sock.emit('start_dir_scan', { target: target, deep_scan: deepScan });
    } else {
        sock.once('connect', () => {
            console.log('Socket connected, emitting dir scan request for: ' + target);
            sock.emit('start_dir_scan', { target: target, deep_scan: deepScan });
        });
    }
}

function exportDirResults() {
    const items = document.querySelectorAll('.result-item');
    let data = 'Path\tStatus Code\tStatus\tSize\n';

    items.forEach(item => {
        const path = item.querySelector('.result-path')?.textContent || '';
        const statusCode = item.querySelector('.status-code')?.textContent || '-';
        const statusText = item.querySelector('.status-text')?.textContent || '';
        const size = item.querySelector('.content-length')?.textContent || '-';
        data += `${path}\t${statusCode}\t${statusText}\t${size}\n`;
    });

    const blob = new Blob([data], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'directories-' + Date.now() + '.txt';
    a.click();
    window.URL.revokeObjectURL(url);
}

document.addEventListener('DOMContentLoaded', () => {
    initializeDirPage();
});

function initializeDirPage() {
    getDirSocket();

    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', startDirScan);
    }

    console.log('Directory page initialized');
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDirPage);
} else {
    initializeDirPage();
}
