import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

from core.whois_lookup import validate_domain


NOT_AVAILABLE = "Not Available"
ALLOWED_SCHEMES = {"http", "https"}
COMMON_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "com.br", "com.cn", "com.mx", "co.in",
}


def _is_public_hostname(hostname):
    try:
        records = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return any(ipaddress.ip_address(record[4][0]).is_global for record in records)
    except (OSError, ValueError):
        return False


def _registered_domain(hostname):
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    suffix = ".".join(labels[-2:])
    if suffix in COMMON_MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def parse_target(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A domain or URL is required")

    original_input = value.strip()
    has_scheme = "://" in original_input
    candidate = original_input if has_scheme else f"https://{original_input}"
    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Unsupported scheme; use HTTP or HTTPS")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("Malformed URL")

    try:
        hostname = parsed.hostname.lower().rstrip(".")
        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid port") from error

    validate_domain(hostname)
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None or hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Private or local targets are not allowed")

    registered_domain = _registered_domain(hostname)
    path = parsed.path or "/"
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return {
        "status": "SUCCESS",
        "original_input": original_input,
        "input_type": "URL" if has_scheme else "Domain",
        "normalized_url": f"{parsed.scheme.lower()}://{hostname}:{effective_port}{path}"
        + (f"?{parsed.query}" if parsed.query else "")
        + (f"#{parsed.fragment}" if parsed.fragment else ""),
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "registered_domain": registered_domain,
        "port": effective_port,
        "path": path,
        "query_present": bool(parsed.query),
        "fragment_present": bool(parsed.fragment),
        "subdomain": hostname[:-len(registered_domain) - 1] or None
        if hostname != registered_domain else None,
        "tld": "." + ".".join(registered_domain.split(".")[1:]),
    }


class URLDomainIntelligence:
    def __init__(self, timeout=10, session=None):
        self.timeout = timeout
        self.session = session or requests

    def analyze(self, value, inspect_http=False):
        result = parse_target(value)
        if not inspect_http:
            return result

        if not _is_public_hostname(result["hostname"]):
            result["http"] = {"status": "NOT AVAILABLE", "message": "Target is not publicly resolvable"}
            return result

        try:
            url = result["normalized_url"]
            redirect_count = 0
            while True:
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers={"User-Agent": "VulnX URL Intelligence/1.0"},
                )
                if response.status_code not in {301, 302, 303, 307, 308}:
                    break
                if redirect_count >= 3 or not response.headers.get("Location"):
                    break
                redirect_url = urlsplit(urljoin(url, response.headers["Location"]))
                if redirect_url.scheme not in ALLOWED_SCHEMES or not redirect_url.hostname:
                    raise ValueError("Unsafe redirect refused")
                redirect_host = validate_domain(redirect_url.hostname)
                if not _is_public_hostname(redirect_host):
                    raise ValueError("Redirect to a non-public address refused")
                url = f"{redirect_url.scheme}://{redirect_host}{redirect_url.path or '/'}"
                if redirect_url.query:
                    url += f"?{redirect_url.query}"
                redirect_count += 1
            result["http"] = {
                "status": "SUCCESS",
                "status_code": response.status_code,
                "redirect_count": redirect_count,
                "final_url": url,
                "content_type": response.headers.get("Content-Type", NOT_AVAILABLE),
                "server": response.headers.get("Server", NOT_AVAILABLE),
                "content_length": response.headers.get("Content-Length", NOT_AVAILABLE),
            }
        except (requests.Timeout, requests.RequestException) as error:
            result["http"] = {"status": "FAILED", "message": "HTTP inspection failed"}
        return result

    def lookup(self, value, inspect_http=False):
        return self.analyze(value, inspect_http=inspect_http)