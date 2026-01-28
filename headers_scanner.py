import requests
from colorama import Fore, Style, init

init(autoreset=True)

class HeaderScanner:
    def __init__(self, target):
        # Ensure the URL has a scheme
        if not target.startswith(("http://", "https://")):
            self.target = f"https://{target}" # Defaulting to https for better results
        else:
            self.target = target
            
        self.headers_to_check = {
            "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
            "Strict-Transport-Security": "Enforces HTTPS connections.",
            "X-Frame-Options": "Prevents Clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME sniffing.",
            "Referrer-Policy": "Controls how much referrer information is shared.",
            "Permissions-Policy": "Restricts use of browser features (camera, geo)."
        }

    def scan(self):
        print(f"\n{Fore.CYAN}[*] Starting Security Headers Analysis on: {self.target}")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Adding a browser-like User-Agent so we don't get blocked
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) vulnXscanner/1.0'}
        
        try:
            # allow_redirects=True is key for accurate results!
            response = requests.get(self.target, headers=headers, timeout=10, allow_redirects=True)
            found_headers = response.headers
            
            missing_count = 0
            for header, description in self.headers_to_check.items():
                # Checking case-insensitively just to be safe
                header_exists = any(h.lower() == header.lower() for h in found_headers.keys())
                
                if header_exists:
                    print(f"{Fore.GREEN}[+] {header}: FOUND")
                else:
                    print(f"{Fore.RED}[-] {header}: MISSING")
                    print(f"    {Fore.YELLOW}└─ Suggestion: {description}")
                    missing_count += 1
            
            print(f"{Fore.CYAN}{'='*60}")
            if missing_count == 0:
                print(f"{Fore.GREEN}[!] Summary: Perfect! All security headers are present.")
            else:
                print(f"{Fore.YELLOW}[!] Summary: {missing_count} security headers are missing/misconfigured.")

        except Exception as e:
            print(f"{Fore.RED}[!] Error connecting to target: {e}")

if __name__ == "__main__":
    print(f"{Fore.MAGENTA}--- vulnXscanner: Security Header Module ---")
    target_url = input(f"{Fore.BLUE}Enter target URL (e.g., google.com): ")
    scanner = HeaderScanner(target_url)
    scanner.scan()       