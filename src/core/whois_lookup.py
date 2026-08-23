import ipaddress
import re
import socket
from datetime import date, datetime

try:
    import whois
except ImportError:
    whois = None


NOT_AVAILABLE = "Not publicly available"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _not_available(value):
    if value is None or value == "" or value == []:
        return NOT_AVAILABLE
    return value


def _format_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (list, tuple, set)):
        return [_format_value(item) for item in value]
    return value


def validate_domain(value):
    if not isinstance(value, str):
        raise ValueError("A domain is required")

    domain = value.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    if (
        not domain
        or "://" in domain
        or "/" in domain
        or "\\" in domain
        or "@" in domain
        or " " in domain
        or domain in {"localhost", "localhost.localdomain"}
    ):
        raise ValueError("Enter a public domain such as example.com")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not accepted; enter a domain")

    if not DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Enter a valid public domain such as example.com")

    labels = domain.split(".")
    if any(label in {"local", "localhost", "internal", "intranet", "test"} for label in labels):
        raise ValueError("Internal domains are not accepted")

    return domain


def _first(value):
    if isinstance(value, (list, tuple, set)):
        return next(iter(value), None)
    return value


class WhoisLookup:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def lookup(self, domain):
        normalized_domain = validate_domain(domain)
        result = {
            "status": "UNKNOWN",
            "domain": normalized_domain,
            "registrar": NOT_AVAILABLE,
            "creation_date": NOT_AVAILABLE,
            "updated_date": NOT_AVAILABLE,
            "expiration_date": NOT_AVAILABLE,
            "domain_status": NOT_AVAILABLE,
            "name_servers": NOT_AVAILABLE,
            "whois_server": NOT_AVAILABLE,
            "dnssec": NOT_AVAILABLE,
            "registrant_organization": NOT_AVAILABLE,
            "registrant_country": NOT_AVAILABLE,
        }

        if whois is None:
            result["status"] = "ERROR"
            result["error"] = "WHOIS support is unavailable"
            return result

        original_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.timeout)
            record = whois.whois(normalized_domain)
            if not record:
                result["status"] = "NOT AVAILABLE"
                return result

            fields = {
                "registrar": getattr(record, "registrar", None),
                "creation_date": _first(getattr(record, "creation_date", None)),
                "updated_date": _first(getattr(record, "updated_date", None)),
                "expiration_date": _first(getattr(record, "expiration_date", None)),
                "domain_status": getattr(record, "status", None),
                "name_servers": getattr(record, "name_servers", None),
                "whois_server": getattr(record, "whois_server", None),
                "dnssec": getattr(record, "dnssec", None),
                "registrant_organization": getattr(record, "org", None),
                "registrant_country": getattr(record, "country", None),
            }
            for key, value in fields.items():
                result[key] = _not_available(_format_value(value))

            result["status"] = "SUCCESS" if any(
                value != NOT_AVAILABLE for key, value in result.items() if key != "status"
            ) else "NOT AVAILABLE"
            return result
        except (socket.timeout, TimeoutError):
            result["status"] = "ERROR"
            result["error"] = "WHOIS lookup timed out"
            return result
        except Exception as error:
            result["status"] = "ERROR"
            result["error"] = str(error) or "WHOIS server unavailable"
            return result
        finally:
            socket.setdefaulttimeout(original_timeout)

    def get_data(self, domain):
        return self.lookup(domain)