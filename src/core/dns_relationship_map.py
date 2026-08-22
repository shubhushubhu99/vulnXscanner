import ipaddress

import dns.exception
import dns.resolver

from core.whois_lookup import validate_domain


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def _node_id(node_type, value):
    return f"{node_type.lower()}:{value}"


def _add_node(nodes, node_ids, node_type, value):
    value = str(value).strip().rstrip(".")
    if not value:
        return None
    node_id = _node_id(node_type, value)
    if node_id not in node_ids:
        nodes.append({"id": node_id, "label": value, "type": node_type})
        node_ids.add(node_id)
    return node_id


class DNSRelationshipMap:
    def __init__(self, resolver=None, lifetime=5):
        self.resolver = resolver or dns.resolver.Resolver()
        self.lifetime = lifetime

    def _query(self, domain, record_type):
        try:
            answers = self.resolver.resolve(domain, record_type, lifetime=self.lifetime)
            return [str(answer.to_text()) for answer in answers]
        except (dns.exception.DNSException, OSError):
            return []

    def build(self, domain, resolution=None):
        normalized_domain = validate_domain(domain)
        root_id = _node_id("DOMAIN", normalized_domain)
        nodes = [{"id": root_id, "label": normalized_domain, "type": "DOMAIN"}]
        node_ids = {root_id}
        edges = []
        edge_ids = set()
        records = {}

        resolved_addresses = (resolution or {}).get("addresses", [])
        if resolved_addresses:
            records["A"] = [address for address in resolved_addresses if ":" not in address]
            records["AAAA"] = [address for address in resolved_addresses if ":" in address]

        for record_type in RECORD_TYPES:
            if record_type not in records:
                records[record_type] = self._query(normalized_domain, record_type)

        def connect(record_type, value, node_type):
            target_id = _add_node(nodes, node_ids, node_type, value)
            edge_id = (record_type, target_id)
            if target_id and edge_id not in edge_ids:
                edges.append({"source": root_id, "target": target_id, "relationship": record_type})
                edge_ids.add(edge_id)

        for value in records.get("A", []):
            try:
                if ipaddress.ip_address(value).version == 4:
                    connect("A", value, "IP")
            except ValueError:
                continue
        for value in records.get("AAAA", []):
            try:
                if ipaddress.ip_address(value).version == 6:
                    connect("AAAA", value, "IP")
            except ValueError:
                continue
        for value in records.get("CNAME", []):
            connect("CNAME", value, "CNAME")
        for value in records.get("MX", []):
            exchange = value.split()[-1] if value.split() else value
            connect("MX", exchange, "MAIL")
        for value in records.get("NS", []):
            connect("NS", value, "NAMESERVER")
        status = "SUCCESS" if edges else "NOT AVAILABLE"
        existing_records = {key: values for key, values in records.items() if values}
        record_summary = {key: len(values) for key, values in existing_records.items()}
        metadata = {}
        if records.get("CAA"):
            metadata["CAA"] = [
                {
                    "issuer": value.split('"', 2)[1] if '"' in value else value,
                    "raw": value,
                }
                for value in records["CAA"]
            ]
        if records.get("SOA"):
            metadata["SOA"] = [
                {"primary_nameserver": value.split()[0].rstrip(".") if value.split() else value, "raw": value}
                for value in records["SOA"]
            ]
        if records.get("TXT"):
            metadata["TXT"] = [{"value": value} for value in records["TXT"]]
        return {
            "status": status,
            "domain": normalized_domain,
            "nodes": nodes,
            "edges": edges,
            "record_summary": record_summary,
            "metadata": metadata,
        }

    def lookup(self, domain, resolution=None):
        return self.build(domain, resolution=resolution)