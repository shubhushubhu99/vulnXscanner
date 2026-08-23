import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests

from core.whois_lookup import validate_domain


NOT_AVAILABLE = "Not Available"
MAX_REDIRECTS = 3
SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)


def _public_host(hostname):
    try:
        addresses = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return any(ipaddress.ip_address(record[4][0]).is_global for record in addresses)
    except (OSError, ValueError):
        return False


def _technology(name, category, confidence, evidence):
    return {
        "name": name,
        "category": category,
        "confidence": confidence,
        "evidence": evidence,
    }


class TechnologyDetection:
    def __init__(self, timeout=10, session=None):
        self.timeout = timeout
        self.session = session or requests

    def _safe_url(self, domain, scheme):
        host = validate_domain(domain)
        if not _public_host(host):
            raise ValueError("Domain does not resolve to a public address")
        return f"{scheme}://{host}/"

    def _fetch(self, domain):
        url = self._safe_url(domain, "https")
        response = None
        for _ in range(MAX_REDIRECTS + 1):
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                headers={"User-Agent": "VulnX Technology Detection/1.0"},
            )
            response.raise_for_status()
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response

            location = response.headers.get("Location")
            if not location:
                return response
            parsed = urlparse(urljoin(url, location))
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("Unsafe redirect refused")
            redirect_host = validate_domain(parsed.hostname)
            if not _public_host(redirect_host):
                raise ValueError("Redirect to a non-public address refused")
            url = f"{parsed.scheme}://{redirect_host}{parsed.path or '/'}"
            if parsed.query:
                url += f"?{parsed.query}"
        raise requests.TooManyRedirects("Too many redirects")

    def detect(self, domain):
        target = validate_domain(domain)
        result = {
            "status": "UNKNOWN",
            "target": target,
            "technologies": [],
            "security_headers": [],
        }

        try:
            response = self._fetch(target)
            headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
            body = response.text[:1_000_000] if isinstance(response.text, str) else ""
            body_lower = body.lower()

            server = headers.get("server", "")
            if re.search(r"nginx", server, re.IGNORECASE):
                result["technologies"].append(_technology("nginx", "Web Server", "High", "Server header"))
            elif re.search(r"apache", server, re.IGNORECASE):
                result["technologies"].append(_technology("Apache", "Web Server", "High", "Server header"))
            elif re.search(r"microsoft-iis|iis", server, re.IGNORECASE):
                result["technologies"].append(_technology("IIS", "Web Server", "High", "Server header"))

            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                result["technologies"].append(_technology(powered_by, "Framework", "High", "X-Powered-By header"))
            if "cf-ray" in headers or "cloudflare" in server.lower():
                result["technologies"].append(_technology("Cloudflare", "CDN", "High", "Cloudflare response headers"))
            elif "fastly" in headers.get("via", "").lower() or "fastly" in headers.get("x-served-by", "").lower():
                result["technologies"].append(_technology("Fastly", "CDN", "Medium", "CDN response headers"))
            if "x-vercel-id" in headers:
                result["technologies"].append(_technology("Vercel", "Hosting/Platform", "High", "X-Vercel-Id header"))

            fingerprints = (
                ("WordPress", "CMS", "High", "HTML references wp-content", "wp-content"),
                ("Drupal", "CMS", "Medium", "DrupalSettings or Drupal HTML marker", "drupalsettings"),
                ("React", "JavaScript", "Medium", "React HTML marker or script", "react"),
                ("Vue", "JavaScript", "Medium", "Vue HTML marker or script", "vue"),
                ("Angular", "JavaScript", "Medium", "Angular HTML marker or script", "ng-version"),
                ("jQuery", "JavaScript", "Medium", "jQuery script reference", "jquery"),
                ("Google Analytics", "Analytics", "Medium", "Google Analytics script or marker", "google-analytics"),
                ("Segment", "Analytics", "Medium", "Segment script reference", "segment.com/analytics.js"),
            )
            for name, category, confidence, evidence, marker in fingerprints:
                if marker in body_lower:
                    result["technologies"].append(_technology(name, category, confidence, evidence))

            result["security_headers"] = [
                header for header in SECURITY_HEADERS if header.lower() in headers
            ]
            result["status"] = "SUCCESS"
            if not result["technologies"] and not result["security_headers"]:
                result["message"] = "No publicly detectable technologies found"
            return result
        except (requests.Timeout, requests.RequestException) as error:
            result["status"] = "FAILED"
            result["message"] = "Technology detection request failed"
            return result
        except (AttributeError, TypeError, ValueError, OSError, socket.gaierror) as error:
            result["status"] = "FAILED"
            result["message"] = str(error) or "Technology detection failed"
            return result

    def lookup(self, domain):
        return self.detect(domain)