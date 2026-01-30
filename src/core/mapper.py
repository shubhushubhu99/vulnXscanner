class TopologyMapper:
    def generate_graph_data(self):
        # Initial central node (the host)
        nodes = [{"id": 1, "label": "Target Host", "color": "#22c55e", "size": 30}]
        edges = []
        
        # In a real scan, this would loop through discovered ports/subdomains
        # Mock data for initial testing:
        mock_assets = [
            {"id": 2, "label": "Port 80 (HTTP)"},
            {"id": 3, "label": "Port 443 (HTTPS)"},
            {"id": 4, "label": "api.target.com"}
        ]
        
        for asset in mock_assets:
            nodes.append({"id": asset["id"], "label": asset["label"], "color": "#3b82f6"})
            edges.append({"from": 1, "to": asset["id"]})
            
        return {"nodes": nodes, "edges": edges}