
// main.js - Real Gemini AI Analysis Modal

async function showDetailedAnalysis(port, service, banner, severity) {
    const modal = document.createElement('div');
    modal.className = 'ai-modal';
    modal.innerHTML = `
        <div class="ai-modal-content">
            <div class="ai-loading">🤖 Loading VulnX AI Security Analysis...</div>
            <div class="ai-analysis-output" style="display: none;"></div>
            <div class="ai-modal-footer">
                <button class="btn-primary ai-close-btn">Close</button>
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
        const response = await fetch('/ai_analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port, service, banner, severity })
        });

        if (!response.ok) throw new Error(`API error: ${response.status}`);

        const data = await response.json();

        if (data.error) throw new Error(data.detail || data.error);

        loadingElement.style.display = 'none';
        outputElement.style.display = 'block';

        typeWriter(outputElement, data.analysis_html, 20);

    } catch (error) {
        loadingElement.innerHTML = `
            <p style="color: var(--critical);">Failed to load AI analysis</p>
            <p style="color: #e74c3c; font-size: 0.9em;">${error.message}</p>
            <p>Please try again or check your Gemini API connection.</p>
        `;
        console.error('AI Analysis Error:', error);
    }
}

function typeWriter(element, htmlContent, speed = 20) {
    let i = 0;
    element.innerHTML = '';
    function typeNext() {
        if (i < htmlContent.length) {
            element.innerHTML += htmlContent.charAt(i);
            element.scrollTop = element.scrollHeight;
            i++;
            setTimeout(typeNext, speed);
        }
    }
    typeNext();
}

console.log("main.js loaded - AI analysis ready ✓");