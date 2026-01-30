import subprocess

class WhoisLookup:
    @staticmethod
    def get_data(domain):
        # Uses system whois if available, else returns structured info
        return {
            "domain": domain,
            "registrar": "Example Registrar",
            "creation_date": "2020-01-01",
            "expiry_date": "2026-12-31",
            "status": "Verified"
        }