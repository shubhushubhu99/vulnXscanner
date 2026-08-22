import ipaddress
import re
from urllib.parse import quote

import requests


NOT_AVAILABLE = "Not publicly available"
GEOLOCATION_URL = "https://ipwho.is/{}"


def parse_ip(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("An IPv4 or IPv6 address is required")

    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 or IPv6 address") from error


def _value(value):
    return NOT_AVAILABLE if value is None or value == "" else value


def _valid_coordinate(value, minimum, maximum):
    if isinstance(value, bool):
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return minimum <= number <= maximum


def _network_type(connection, security):
    if security.get("hosting") is True or security.get("proxy") is True:
        return "Hosting / CDN / Datacenter"

    provider_text = " ".join(
        str(connection.get(key, "")) for key in ("isp", "org", "domain")
    ).lower()
    hosting_markers = (
        "amazon", "aws", "azure", "cloudflare", "fastly", "akamai",
        "google cloud", "microsoft", "vercel", "digitalocean", "ovh",
    )
    if any(marker in provider_text for marker in hosting_markers):
        return "Hosting / CDN / Datacenter"
    return NOT_AVAILABLE


class IPGeolocation:
    def __init__(self, timeout=10, session=None):
        self.timeout = timeout
        self.session = session or requests

    def lookup(self, value):
        address = parse_ip(value)
        ip = str(address)
        result = {
            "ip": ip,
            "version": f"IPv{address.version}",
            "status": "UNKNOWN",
            "country": NOT_AVAILABLE,
            "country_code": NOT_AVAILABLE,
            "region": NOT_AVAILABLE,
            "city": NOT_AVAILABLE,
            "latitude": NOT_AVAILABLE,
            "longitude": NOT_AVAILABLE,
            "isp": NOT_AVAILABLE,
            "organization": NOT_AVAILABLE,
            "asn": NOT_AVAILABLE,
            "timezone": NOT_AVAILABLE,
            "connection_type": NOT_AVAILABLE,
            "hosting": NOT_AVAILABLE,
            "network_type": NOT_AVAILABLE,
            "approximate": True,
            "location_note": (
                "IP-based geolocation is approximate and may represent a hosting, "
                "CDN, or edge server rather than the website owner's physical location."
            ),
        }

        if not address.is_global:
            result["status"] = "PRIVATE/RESERVED"
            result["message"] = "Private/Reserved IP"
            return result

        try:
            response = self.session.get(
                GEOLOCATION_URL.format(quote(ip, safe="")),
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or payload.get("success") is False:
                result["status"] = "FAILED"
                result["message"] = _value(
                    payload.get("message") if isinstance(payload, dict) else None
                )
                return result

            provider_ip = payload.get("ip")
            if provider_ip:
                try:
                    if ipaddress.ip_address(str(provider_ip)) != address:
                        result["status"] = "FAILED"
                        result["message"] = "Geolocation provider returned a different IP"
                        return result
                except ValueError:
                    result["status"] = "FAILED"
                    result["message"] = "Geolocation provider returned an invalid IP"
                    return result

            connection = payload.get("connection") or {}
            timezone = payload.get("timezone") or {}
            security = payload.get("security") or {}
            country = payload.get("country")
            country_code = payload.get("country_code")
            latitude = payload.get("latitude")
            longitude = payload.get("longitude")
            valid_country = isinstance(country, str) and bool(country.strip())
            valid_country_code = (
                isinstance(country_code, str)
                and bool(re.fullmatch(r"[A-Za-z]{2}", country_code.strip()))
            )
            valid_coordinates = (
                _valid_coordinate(latitude, -90, 90)
                and _valid_coordinate(longitude, -180, 180)
            )
            has_network_data = any(
                connection.get(key) not in (None, "")
                for key in ("isp", "org", "asn")
            )
            if not valid_country and not valid_country_code and not has_network_data:
                result["status"] = "FAILED"
                result["message"] = "Geolocation provider returned no usable IP data"
                return result

            result.update({
                "country": _value(country) if valid_country else NOT_AVAILABLE,
                "country_code": _value(country_code.upper()) if valid_country_code else NOT_AVAILABLE,
                "region": _value(payload.get("region")),
                "city": _value(payload.get("city")),
                "latitude": latitude if valid_coordinates else NOT_AVAILABLE,
                "longitude": longitude if valid_coordinates else NOT_AVAILABLE,
                "isp": _value(connection.get("isp")),
                "organization": _value(connection.get("org")),
                "asn": _value(connection.get("asn")),
                "timezone": _value(timezone.get("id")),
                "connection_type": _value(connection.get("type")),
                "hosting": _value(security.get("hosting")),
                "network_type": _network_type(connection, security),
            })
            result["status"] = "SUCCESS" if (
                valid_country and valid_country_code and valid_coordinates
            ) else "PARTIAL"
            return result
        except requests.Timeout:
            result["status"] = "ERROR"
            result["message"] = "IP geolocation lookup timed out"
            return result
        except requests.RequestException:
            result["status"] = "ERROR"
            result["message"] = "IP geolocation service unavailable"
            return result
        except (AttributeError, TypeError, ValueError):
            result["status"] = "ERROR"
            result["message"] = "IP geolocation returned malformed data"
            return result

    def get_data(self, value):
        return self.lookup(value)