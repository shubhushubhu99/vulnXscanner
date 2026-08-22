import ipaddress
import socket

from core.ip_geolocation import IPGeolocation
from core.dns_relationship_map import DNSRelationshipMap
from core.technology_detection import TechnologyDetection
from core.url_domain_intelligence import URLDomainIntelligence
from core.whois_lookup import WhoisLookup, validate_domain


def resolve_domain(domain):
    """Resolve a validated domain through DNS only and return public addresses."""
    addresses = []
    try:
        records = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for record in records:
            address = ipaddress.ip_address(record[4][0])
            if str(address) not in addresses:
                addresses.append(str(address))
    except (socket.gaierror, OSError, ValueError):
        return {
            "status": "ERROR",
            "ip": None,
            "version": None,
            "addresses": [],
            "message": "Domain could not be resolved",
        }

    public_addresses = [
        address for address in addresses if ipaddress.ip_address(address).is_global
    ]
    if public_addresses:
        primary = ipaddress.ip_address(public_addresses[0])
        return {
            "status": "SUCCESS",
            "ip": public_addresses[0],
            "version": f"IPv{primary.version}",
            "addresses": public_addresses,
        }

    return {
        "status": "PRIVATE/RESERVED",
        "ip": addresses[0] if addresses else None,
        "version": f"IPv{ipaddress.ip_address(addresses[0]).version}" if addresses else None,
        "addresses": addresses,
        "message": "Domain resolved only to private or reserved IP addresses",
    }


def run_osint_scan(domain, whois_lookup=None, ip_geolocation=None, technology_detection=None, url_intelligence=None):
    """Run independent URL intelligence, WHOIS, DNS, IP geolocation, and technology modules."""
    url_result = (url_intelligence or URLDomainIntelligence()).analyze(domain)
    normalized_domain = validate_domain(url_result["registered_domain"])
    whois_result = {"status": "UNKNOWN"}
    try:
        whois_result = (whois_lookup or WhoisLookup()).lookup(normalized_domain)
    except Exception as error:
        whois_result = {"status": "ERROR", "message": str(error) or "WHOIS lookup failed"}

    resolution = resolve_domain(normalized_domain)
    if resolution["status"] == "SUCCESS":
        try:
            geolocation = (ip_geolocation or IPGeolocation()).lookup(resolution["ip"])
        except Exception as error:
            geolocation = {
                "ip": resolution["ip"],
                "version": resolution["version"],
                "status": "ERROR",
                "message": str(error) or "IP geolocation failed",
            }
    else:
        geolocation = {
            "ip": resolution["ip"],
            "version": resolution["version"],
            "status": "NOT AVAILABLE",
            "message": resolution.get("message", "No public IP available for geolocation"),
        }

    try:
        dns_map = DNSRelationshipMap().build(normalized_domain, resolution=resolution)
    except Exception as error:
        dns_map = {
            "status": "FAILED",
            "domain": normalized_domain,
            "nodes": [],
            "edges": [],
            "message": str(error) or "DNS relationship map failed",
        }

    try:
        technology = (technology_detection or TechnologyDetection()).detect(normalized_domain)
    except Exception as error:
        technology = {
            "status": "FAILED",
            "target": normalized_domain,
            "technologies": [],
            "security_headers": [],
            "message": str(error) or "Technology detection failed",
        }

    return {
        "target": normalized_domain,
        "status": "COMPLETED",
        "url_domain_intelligence": url_result,
        "whois": whois_result,
        "ip_resolution": resolution,
        "ip_geolocation": geolocation,
        "dns_relationship_map": dns_map,
        "technology_detection": technology,
        "summary": {
            "domain": normalized_domain,
            "resolved_ip": resolution["ip"],
            "whois": whois_result.get("status", "UNKNOWN"),
            "ip_geolocation": geolocation.get("status", "UNKNOWN"),
            "technology_detection": technology.get("status", "UNKNOWN"),
            "overall": "COMPLETED",
        },
    }