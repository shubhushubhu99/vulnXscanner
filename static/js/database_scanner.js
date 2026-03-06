// Database Vulnerability Scanner JavaScript Handler
let dbSocket = null;
let currentResults = [];

function getDbSocket() {
    if (!dbSocket) {
        if (typeof io === 'undefined') {
            console.error('Socket.IO library not loaded');
            throw new Error('Socket.IO library not available');
        }
        dbSocket = io({
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionDelayMax: 5000,
            reconnectionAttempts: 5
        });
        setupDbSocketListeners();
    }
    return dbSocket;
}

function setupDbSocketListeners() {
    dbSocket.on('connect', () => {
        console.log('Database scanner WebSocket connected');
    });

    dbSocket.on('db_scan_log', (data) => addDbTerminalLine(data.message));

    dbSocket.on('db_scan_progress', (data) => {
        const progress = data.progress_percent ? `[${data.progress_percent}%]` : '';
        if (data.message) {
            addDbTerminalLine(`${data.message} ${progress}`);
        }
        updateDbProgress(data.progress_percent || 0, `${data.current}/${data.total} checks completed`);
    });

    dbSocket.on('db_scan_complete', (data) => {
        updateDbProgress(100, 'Scan complete');
        addDbTerminalLine(`Scan completed! Found ${data.total_vulnerabilities} vulnerability(ies).`);
        
        const btn = document.getElementById('dbScanBtn');
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="scan" style="display: inline-block; width: 16px; height: 16px; vertical-align: -2px; margin-right: 6px;"></i> Scan for Vulnerabilities';
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        
        // Reinitialize lucide icons
        if (typeof lucide !== 'undefined') lucide.createIcons();
        
        currentResults = data.results;
        renderDbResults(data.results);
        displayDbSummary(data.results);
    });
}

function renderDbResults(results) {
    const container = document.getElementById('dbResultsContainer');
    if (!container) return;

    container.innerHTML = '';

    if (results.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; background: rgba(16, 185, 129, 0.05); border-radius: 12px; border: 1px solid rgba(16, 185, 129, 0.2);">
                <p style="color: var(--accent); font-weight: 600; font-size: 1.1em;"><i data-lucide="shield-check" style="display: inline-block; width: 20px; height: 20px; vertical-align: -4px; margin-right: 6px;"></i> No vulnerabilities detected!</p>
                <p style="color: var(--text-secondary); margin-top: 8px;">Your application appears to have good security controls.</p>
            </div>`;
        if (typeof lucide !== 'undefined') lucide.createIcons();
        return;
    }

    const grid = document.createElement('div');
    grid.className = 'results-grid';

    results.forEach(vuln => {
        const card = document.createElement('div');
        card.className = `vulnerability-card ${vuln.risk.toLowerCase()}`;

        const header = document.createElement('div');
        header.className = 'vuln-header';
        header.innerHTML = `
            <div class="vuln-name">${vuln.name}</div>
            <span class="risk-badge ${vuln.risk.toLowerCase()}">${vuln.risk}</span>
        `;

        const description = document.createElement('div');
        description.className = 'vuln-description';
        description.textContent = vuln.description;

        const evidence = document.createElement('div');
        evidence.className = 'vuln-evidence';
        evidence.textContent = vuln.evidence || 'N/A';

        const recommendation = document.createElement('div');
        recommendation.className = 'vuln-recommendation';
        recommendation.textContent = vuln.recommendation || 'Review security best practices';

        // Create AI Analysis Button
        const aiHint = document.createElement('div');
        aiHint.className = 'ai-hint';
        aiHint.setAttribute('role', 'button');
        aiHint.setAttribute('tabindex', '0');
        aiHint.innerHTML = `
            <svg class="ai-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 2l1.5 3.3L17 6l-3 2.2L14 11l-2-1.6L10 11l.9-2.8L8 6l3.5-.7L12 2z"></path>
                <path d="M5 12l.7 1.6L7.5 14l-1.8 1.1L5 16.5 4.3 15.1 3 14l1.3-1 1.7-.6z"></path>
                <path d="M20 12l.5 1.1L21.5 14l-1.3.8L20 16l-.5-1.2L18 14l1.5-1.8L20 12z"></path>
            </svg>
            <span>Click for AI expert analysis</span>
        `;
        
        // Add click handler to AI button
        aiHint.addEventListener('click', (e) => {
            e.stopPropagation();
            if (typeof window.showDatabaseVulnerabilityAnalysis === 'function') {
                window.showDatabaseVulnerabilityAnalysis(
                    vuln.name,
                    vuln.description,
                    vuln.evidence || 'N/A',
                    vuln.risk,
                    vuln.recommendation || 'Review security best practices'
                );
            } else {
                console.error('AI analysis function not available');
                alert('AI analysis feature is not ready. Please refresh the page.');
            }
        });
        
        // Add keyboard support
        aiHint.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                aiHint.click();
            }
        });

        card.appendChild(header);
        card.appendChild(description);
        card.appendChild(evidence);
        card.appendChild(recommendation);
        card.appendChild(aiHint);
        grid.appendChild(card);
    });

    container.appendChild(grid);
}

function displayDbSummary(results) {
    const summaryContainer = document.getElementById('dbSummaryContainer');
    if (!summaryContainer) return;

    const critical = results.filter(r => r.risk === 'Critical').length;
    const high = results.filter(r => r.risk === 'High').length;
    const medium = results.filter(r => r.risk === 'Medium').length;
    const low = results.filter(r => r.risk === 'Low').length;

    document.getElementById('totalVulns').textContent = results.length;
    document.getElementById('criticalCount').textContent = critical;
    document.getElementById('highCount').textContent = high;
    document.getElementById('mediumCount').textContent = medium;
    document.getElementById('lowCount').textContent = low;

    summaryContainer.style.display = 'block';
}

function addDbTerminalLine(message) {
    const terminal = document.getElementById('dbTerminal');
    if (!terminal) return;

    const line = document.createElement('div');
    line.textContent = '> ' + message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function updateDbProgress(percentage, message = '') {
    const container = document.getElementById('dbProgressContainer');
    const fillEl = document.getElementById('dbProgressFill');
    const percentEl = document.getElementById('dbProgressPercent');
    const msgEl = document.getElementById('dbProgressMessage');
    const textEl = document.getElementById('dbProgressText');
    
    if (container) container.style.display = 'block';
    if (fillEl) fillEl.style.width = percentage + '%';
    if (percentEl) percentEl.textContent = percentage + '%';
    if (msgEl && message) msgEl.textContent = message;
    
    if (percentage >= 100 && textEl) {
        textEl.innerHTML = '<i data-lucide="check-circle" style="display: inline-block; width: 14px; height: 14px; vertical-align: -2px; margin-right: 6px;"></i> Complete';
        if (typeof lucide !== 'undefined') lucide.createIcons();
    }
}

function startDbScan(event) {
    event.preventDefault();

    const targetInput = document.getElementById('dbTarget');
    const target = targetInput.value.trim();
    
    if (!target) {
        alert('Please enter a target');
        return;
    }

    const deepScan = document.getElementById('dbDeepScan').checked;
    const btn = document.getElementById('dbScanBtn');

    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" class="spin-icon" style="display: inline-block; width: 16px; height: 16px; vertical-align: -2px; margin-right: 6px;"></i> Scanning...';
    btn.style.opacity = '0.6';
    btn.style.cursor = 'not-allowed';
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Show and reset terminal
    const terminal = document.getElementById('dbTerminal');
    terminal.innerHTML = '<div style="color: var(--accent);">\> Initializing database vulnerability scan...</div>';
    document.getElementById('dbProgressContainer').style.display = 'block';
    document.getElementById('dbSummaryContainer').style.display = 'none';
    updateDbProgress(0);
    // Reset progress text
    const textEl = document.getElementById('dbProgressText');
    if (textEl) textEl.innerHTML = '<i data-lucide="loader" class="spin-icon" style="display: inline-block; width: 14px; height: 14px; vertical-align: -2px; margin-right: 6px;"></i> Scanning...';
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Clear previous results
    document.getElementById('dbResultsContainer').innerHTML = '';

    // Get or create socket and emit scan
    const sock = getDbSocket();
    
    if (sock.connected) {
        sock.emit('start_db_scan', { target: target, deep_scan: deepScan });
    } else {
        sock.once('connect', () => {
            console.log('Socket connected, starting DB scan for: ' + target);
            sock.emit('start_db_scan', { target: target, deep_scan: deepScan });
        });
    }
}

function exportDatabaseResults() {
    if (!currentResults || currentResults.length === 0) {
        alert('No results to export');
        return;
    }

    const jsonStr = JSON.stringify(currentResults, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'database-vulnerabilities-' + Date.now() + '.json';
    a.click();
    window.URL.revokeObjectURL(url);
}

function initializeDbScannerPage() {
    console.log('Initializing database vulnerability scanner...');
    
    // Check if the form exists before initializing
    const form = document.getElementById('dbScanForm');
    if (!form) {
        console.warn('Database scanner form not found - page might not be fully loaded');
        return;
    }
    
    // Initialize socket connection
    try {
        getDbSocket();
    } catch (error) {
        console.error('Failed to initialize socket:', error);
        return;
    }
    
    console.log('Database vulnerability scanner initialized');
}

// Initialize when script loads (handles both initial page load and SPA navigation)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDbScannerPage);
} else {
    initializeDbScannerPage();
}
