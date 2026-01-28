import requests

class HeaderAnalyzer:
    def __init__(self, url):
        # Ensure the URL is properly formatted for requests
        if not url.startswith('http'):
            self.url = f"https://{url}"
        else:
            self.url = url

    def analyze(self):
        try:
            # We use a 10-second timeout and verify=True to check SSL
            response = requests.get(self.url, timeout=10, verify=True)
            headers = response.headers
            
            # Key security headers to check
            security_headers = {
                "Strict-Transport-Security": "Enforces HTTPS connections to prevent MITM.",
                "Content-Security-Policy": "Prevents XSS and unauthorized script execution.",
                "X-Frame-Options": "Protects users against Clickjacking attacks.",
                "X-Content-Type-Options": "Prevents the browser from MIME-sniffing.",
                "Referrer-Policy": "Protects user privacy by controlling referrer info."
            }
            
            results = []
            score = 100
            
            for header, desc in security_headers.items():
                found = header in headers
                if not found:
                    score -= 20 # Deduct points for missing security
                
                results.append({
                    "header": header,
                    "description": desc,
                    "status": "✅ Found" if found else "❌ Missing",
                    "safe": found
                })
            
            return {
                "results": results, 
                "score": score, 
                "url": self.url,
                "status_code": response.status_code
            }
        except requests.exceptions.SSLError:
            return {"error": "SSL Certificate Error: The site may have an invalid or expired certificate."}
        except Exception as e:
            return {"error": f"Connection failed: {str(e)}"}