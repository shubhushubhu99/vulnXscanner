document.addEventListener('DOMContentLoaded', function() {
    const container = document.getElementById('network-map');
    if (!container) return;

    fetch('/api/topology-data')
        .then(res => res.json())
        .then(graphData => {
            const options = {
                nodes: {
                    shape: 'dot',
                    size: 20,
                    font: { color: '#ffffff', size: 14 },
                    borderWidth: 2
                },
                edges: {
                    color: '#30363d',
                    arrows: { to: { enabled: true } }
                },
                interaction: {
                    navigationButtons: false, // This removes the balls in the corners
                    keyboard: false,         // Keeps the UI clean from corner icons
                    dragNodes: true,
                    zoomView: true
                },
                physics: {
                    enabled: true,
                    stabilization: { iterations: 100 }
                }
            };

            const network = new vis.Network(container, graphData, options);
        })
        .catch(err => console.error("Topology Error:", err));
});