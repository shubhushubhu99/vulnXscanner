document.getElementById('runAudit').addEventListener('click', async () => {
    const url = document.getElementById('targetUrl').value;
    const resultsDiv = document.getElementById('auditResults');
    
    resultsDiv.innerHTML = '<p class="text-white">Analyzing headers... Please wait.</p>';

    try {
        const response = await fetch(`/api/analyze?url=${encodeURIComponent(url)}`);
        const data = await response.json();

        let html = `<div class="score-badge">Security Score: ${data.score}/100</div><div class="row">`;
        data.results.forEach(res => {
            html += `
                <div class="col-md-6 mb-3">
                    <div class="card bg-dark border-secondary p-3">
                        <h5 class="${res.safe ? 'text-success' : 'text-danger'}">${res.header}</h5>
                        <p class="text-white small">${res.description}</p>
                        <span class="badge ${res.safe ? 'bg-success' : 'bg-danger'}">${res.status}</span>
                    </div>
                </div>`;
        });
        html += '</div>';
        resultsDiv.innerHTML = html;
    } catch (err) {
        resultsDiv.innerHTML = '<p class="text-danger">Error analyzing site. Ensure URL is valid.</p>';
    }
});