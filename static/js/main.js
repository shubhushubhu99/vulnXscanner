
// main.js - Real Gemini AI Analysis Modal
// Define AI analysis function 
// Convert HTML response into clean plain text while preserving headings, lists and line breaks
function htmlToPlainText(html) {
    // If response is already plain text (no HTML tags), return as-is
    if (!html || typeof html !== 'string') {
        return String(html || '');
    }
    
    // Quick check: if no HTML tags detected, return plain text as-is
    if (!/<[^>]*>/g.test(html)) {
        return html.trim();
    }
    
    // Has HTML tags, so parse and convert
    const container = document.createElement('div');
    container.innerHTML = html;

    function walk(node) {
        let out = '';
        node.childNodes.forEach((child) => {
            if (child.nodeType === Node.TEXT_NODE) {
                const text = child.nodeValue || '';
                out += text;
            } else if (child.nodeType === Node.ELEMENT_NODE) {
                const tag = child.tagName.toLowerCase();
                if (/^h[1-6]$/.test(tag)) {
                    // Headings: uppercase plaintext with spacing
                    const text = (child.innerText || '').trim();
                    if (text) out += '\n\n' + text.toUpperCase() + '\n\n';
                } else if (tag === 'p') {
                    // Paragraphs: with spacing
                    const text = (child.innerText || '').trim();
                    if (text) out += '\n\n' + text + '\n\n';
                } else if (tag === 'br') {
                    // Line breaks
                    out += '\n';
                } else if (tag === 'li') {
                    // List items: bullet format
                    const text = (child.innerText || '').trim();
                    if (text) out += '- ' + text + '\n';
                } else if (tag === 'ul' || tag === 'ol') {
                    // Lists: extract items
                    child.childNodes.forEach((li) => {
                        if (li.tagName && li.tagName.toLowerCase() === 'li') {
                            const text = (li.innerText || '').trim();
                            if (text) out += '- ' + text + '\n';
                        }
                    });
                    out += '\n';
                } else if (tag === 'pre' || tag === 'code') {
                    // Code blocks: preserve
                    const text = child.innerText || '';
                    if (text) out += '\n\n' + text + '\n\n';
                } else {
                    // Recursively process other tags
                    out += walk(child);
                }
            }
        });
        return out;
    }

    const text = walk(container)
        .replace(/\n{3,}/g, '\n\n')  // Collapse excess newlines
        .trim();
    return text;
}

async function executeAIAnalysis(config) {
    const modal = document.createElement('div');
    modal.className = 'ai-modal';
    modal.innerHTML = `
        <div class="ai-modal-content">
            <div class="ai-loading">🤖 VulnX AI Security Analysis</div>
            <div class="ai-analysis-output" style="display: none;"></div>
            <div class="ai-modal-footer">
                <button class="ai-download-btn" style="display: none; margin-right: 12px;">📥 Download Report</button>
                <button class="ai-close-btn">Close Analysis</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal || e.target.classList.contains('ai-close-btn')) {
            modal.remove();
        }
    });

    const outputElement = modal.querySelector('.ai-analysis-output');
    const loadingElement = modal.querySelector('.ai-loading');

    try {
        const response = await fetch(config.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config.payload)
        });

        // Attempt to parse JSON response even when response.ok is false
        let data = null;
        try {
            data = await response.json();
        } catch (e) {
            // non-JSON body
            data = null;
        }

        if (!response.ok) {
            const msg = (data && (data.error || data.detail || data.message)) || `API error: ${response.status}`;
            throw new Error(msg);
        }

        // Support both legacy shape ({ analysis_html }) and new shape ({ success: true, data: { analysis_html } })
        let analysisHtml = '';
        if (data) {
            if (data.success === true && data.data) {
                analysisHtml = data.data.analysis_html || data.data.analysis_text || '';
            } else {
                analysisHtml = data.analysis_html || data.analysis_text || '';
            }
        }

        if (!analysisHtml) {
            const msg = (data && (data.error || data.detail)) || 'No analysis returned from AI';
            throw new Error(msg);
        }

        const plainText = htmlToPlainText(analysisHtml);

        // Hide loading and show output container (which has fixed height + scroll in CSS)
        loadingElement.style.display = 'none';
        outputElement.style.display = 'block';
        
        // Store data for download button and show it
        const downloadBtn = modal.querySelector('.ai-download-btn');
        downloadBtn.style.display = 'inline-block';
        
        downloadBtn.addEventListener('click', async () => {
            downloadBtn.disabled = true;
            downloadBtn.textContent = '⏳ Generating PDF...';
            
            try {
                const response = await fetch('/download_report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        analysis: plainText,
                        port: config.pdf.mapData.port,
                        service: config.pdf.mapData.service
                    })
                });
                
                if (!response.ok) {
                    throw new Error(`Download failed: ${response.status}`);
                }
                
                // Get the filename from response header if available
                const contentDisposition = response.headers.get('content-disposition');
                let filename = config.pdf.filename;
                if (contentDisposition) {
                    const matches = contentDisposition.match(/filename="?(.+?)"?$/);
                    if (matches && matches[1]) filename = matches[1];
                }
                
                // Trigger download
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                
                downloadBtn.textContent = '📥 Download Report';
                downloadBtn.disabled = false;
            } catch (error) {
                console.error('Download error:', error);
                downloadBtn.textContent = '❌ Download Failed';
                downloadBtn.disabled = false;
                setTimeout(() => {
                    downloadBtn.textContent = '📥 Download Report';
                }, 3000);
            }
        });

        // Start typing animation
        typeWriter(outputElement, plainText, 18);

    } catch (error) {
        loadingElement.innerHTML = `
            <p style="color: var(--critical);">Failed to load AI analysis</p>
            <p style="color: #e74c3c; font-size: 0.9em;">${error.message}</p>
            <p>Please try again or check your Gemini API connection.</p>
        `;
        console.error(config.errorLabel || 'AI Analysis Error:', error);
    }
}

function showDetailedAnalysis(port, service, banner, severity) {
    executeAIAnalysis({
        endpoint: '/ai_analysis',
        payload: { port, service, banner, severity },
        errorLabel: 'AI Analysis Error:',
        pdf: {
            mapData: { port, service },
            filename: 'VulnX_Analysis_Report.pdf'
        }
    });
}

// Make function globally accessible AFTER declaration
window.showDetailedAnalysis = showDetailedAnalysis;

// Database Vulnerability AI Analysis Function
function showDatabaseVulnerabilityAnalysis(vulnName, vulnDescription, vulnEvidence, riskLevel, vulnRecommendation) {
    executeAIAnalysis({
        endpoint: '/db_analysis',
        payload: { 
            name: vulnName, 
            description: vulnDescription, 
            evidence: vulnEvidence,
            risk: riskLevel,
            recommendation: vulnRecommendation
        },
        errorLabel: 'Database Vulnerability AI Analysis Error:',
        pdf: {
            mapData: { 
                port: vulnName, 
                service: riskLevel 
            },
            filename: 'VulnX_Database_Vulnerability_Report.pdf'
        }
    });
}

// Make database vulnerability analysis function globally accessible
window.showDatabaseVulnerabilityAnalysis = showDatabaseVulnerabilityAnalysis;

function typeWriter(element, htmlContent, speed = 20) {
    // Guard against null/undefined or non-string content
    const content = (htmlContent === null || htmlContent === undefined) ? '' : String(htmlContent);
    if (!content) {
        element.textContent = 'No AI analysis available.';
        return;
    }

    let i = 0;
    element.textContent = '';
    
    function typeNext() {
        if (i < content.length) {
            // Append character by character for typing effect
            element.textContent = content.substring(0, i + 1);
            element.scrollTop = element.scrollHeight;
            i++;
            setTimeout(typeNext, speed);
        }
    }
    typeNext();
}

console.log("main.js loaded - AI analysis ready ✓");

// ============================================
// Single-Page Navigation System
// ============================================

// Map of page routes to URLs
const navigationRoutes = {
    'dashboard': '/dashboard',
    'history': '/history',
    'database-vulnerability': '/database-vulnerability',
    'subdomain': '/subdomain',
    'directory': '/directory',
    'analyzer': '/analyzer',
    'topology': '/topology',
    'osint': '/osint'
};

// Handle navigation link clicks
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    
    // Initialize Lucide icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
});

// Reinitialize navigation when DOM changes
const observer = new MutationObserver(() => {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    attachNavListeners();
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});

function initializeNavigation() {
    attachNavListeners();
}

function attachNavListeners() {
    // Attach click handlers to all navigation links with data-nav-link
    document.querySelectorAll('[data-nav-link]').forEach(link => {
        link.removeEventListener('click', handleNavClick);
        link.addEventListener('click', handleNavClick);
    });
}

async function handleNavClick(e) {
    const navLink = e.currentTarget;
    const pageId = navLink.getAttribute('data-nav-link');
    const url = navigationRoutes[pageId];
    
    if (!url) return; // Unknown page
    
    e.preventDefault();
    
    // Declare contentArea once at the top of the function to avoid duplicates
    const contentArea = document.querySelector('.content');
    
    try {
        // Fetch the new page content with AJAX header
        const response = await fetch(url, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) throw new Error(`Failed to load ${url}`);
        
        let html = await response.text();
        
        // If full page HTML returned, extract content carefully
        if (html.includes('<!DOCTYPE') || html.includes('<html')) {
            const parser = new DOMParser();
            const newDoc = parser.parseFromString(html, 'text/html');
            
            // Extract only the .content div's innerHTML (excluding footer)
            const newContentDiv = newDoc.querySelector('.content');
            if (newContentDiv) {
                // Extract all content except the footer
                const footer = newContentDiv.querySelector('.site-footer');
                const contentWithoutFooter = newContentDiv.cloneNode(true);
                
                // Remove footer from clone if it exists
                const footerClone = contentWithoutFooter.querySelector('.site-footer');
                if (footerClone) {
                    footerClone.remove();
                }
                
                html = contentWithoutFooter.innerHTML;
            } else {
                throw new Error('Could not extract content from page');
            }
        }
        
        // Extract scripts before updating DOM (they won't execute if added via innerHTML)
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = html;
        const scripts = Array.from(tempDiv.querySelectorAll('script'));
        const htmlWithoutScripts = tempDiv.innerHTML;
        
        // Clear content immediately and update in one operation to avoid flashing
        contentArea.innerHTML = '';  // Clear immediately to prevent flashing old content
        contentArea.innerHTML = htmlWithoutScripts;
        
        // Execute only page-specific scripts, not library scripts
        const scriptsToExecute = scripts.filter(script => {
            // Skip library/global scripts that should only load once
            if (script.src) {
                const src = script.src.toLowerCase();
                // Skip socket.io, lucide, and main.js - these are already loaded globally
                // BUT keep page-specific handlers like database_scanner.js, subdomain.js, etc.
                if (src.includes('socket.io') || src.includes('lucide') || src.includes('/js/main.js')) {
                    return false;
                }
            }
            // Execute all other scripts (page-specific handlers)
            return true;
        });
        
        scriptsToExecute.forEach(script => {
            const newScript = document.createElement('script');
            if (script.src) {
                newScript.src = script.src;
            } else {
                newScript.textContent = script.textContent;
            }
            contentArea.appendChild(newScript);
        });

        // --- Ensure showDetailedAnalysis is globally available after navigation ---
        // If the function is defined in the new context, attach to window
        setTimeout(() => {
            if (typeof showDetailedAnalysis === 'function') {
                window.showDetailedAnalysis = showDetailedAnalysis;
            }
        }, 0);
        
        // Update active navigation state
        document.querySelectorAll('[data-nav-link]').forEach(link => {
            link.classList.remove('active');
        });
        navLink.classList.add('active');
        
        // Close mobile sidebar if open
        const sidebar = document.querySelector('.sidebar');
        if (sidebar && sidebar.classList.contains('open')) {
            sidebar.classList.remove('open');
        }
        
        // Scroll to top
        window.scrollTo(0, 0);
        
        // Reinitialize icons and scripts
        if (typeof lucide !== 'undefined') {
            setTimeout(() => lucide.createIcons(), 100);
        }
        
        // Re-attach event listeners for forms and buttons in new content
        reattachEventListeners();
        
        console.log(`✓ Navigated to ${pageId} without page reload`);
        
    } catch (error) {
        console.error('Navigation error:', error);
        
        // Restore content and try full page load
        contentArea.style.opacity = '1';
        
        setTimeout(() => {
            window.location.href = navigationRoutes[pageId];
        }, 200);
    }
}

function reattachEventListeners() {
    // Re-initialize any page-specific scripts after navigation
    
    // For subdomain page - reinitialize form listeners and socket
    if (document.getElementById('subdomainBtn')) {
        console.log('Subdomain page loaded via navigation');
        if (typeof initializeSubdomainPage !== 'undefined') {
            initializeSubdomainPage();
        }
    }
    
    // For database vulnerability page
    if (document.getElementById('dbScanBtn')) {
        console.log('Database vulnerability scanner loaded via navigation');
        if (typeof initializeDbScannerPage !== 'undefined') {
            initializeDbScannerPage();
        }
    }
    
    // For analyzer page
    if (document.getElementById('runAudit')) {
        console.log('Analyzer page loaded');
    }
    
    // For scanner page - socket initialization is handled by scanner.js
    if (document.getElementById('analyzeBtn')) {
        console.log('Scanner page loaded - scanner.js will handle socket init');
    }
    
    // For dashboard with results
    if (document.getElementById('resultsContainer')) {
        console.log('Results container found');
    }
}

// FINAL SAFETY CHECK: Ensure showDetailedAnalysis is globally accessible
// This handles both inline onclick="showDetailedAnalysis(...)" and dynamic calls
if (typeof window !== 'undefined') {
    if (typeof showDetailedAnalysis !== 'undefined') {
        window.showDetailedAnalysis = showDetailedAnalysis;
    }
}