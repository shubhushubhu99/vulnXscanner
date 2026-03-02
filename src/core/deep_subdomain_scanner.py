"""
Enhanced Subdomain Scanner with Deep Scan capabilities
- DNS brute-force with large wordlist
- Subdomain permutation logic
- Recursive scanning
- Multiple DNS record types
- HTTP/HTTPS status checking
- Wildcard detection
- Progress tracking
"""

import socket
import dns.resolver
import dns.exception
import requests
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from typing import List, Dict, Tuple, Set
import time
import logging
from pathlib import Path

logger = logging.getLogger("vulnx.deep_subdomain")

# DNS record types to check
DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']

class SubdomainResult:
    """Data class for subdomain results"""
    def __init__(self, subdomain: str, status_code: int = None, status_text: str = "Unknown", 
                 dns_records: Dict = None, is_wildcard: bool = False):
        self.subdomain = subdomain
        self.status_code = status_code
        self.status_text = status_text
        self.dns_records = dns_records or {}
        self.is_wildcard = is_wildcard
    
    def to_dict(self):
        return {
            'subdomain': self.subdomain,
            'status_code': self.status_code,
            'status_text': self.status_text,
            'dns_records': self.dns_records,
            'is_wildcard': self.is_wildcard
        }


class DeepSubdomainScanner:
    """Enhanced subdomain scanner with deep scan capabilities"""
    
    def __init__(self, domain: str, deep_scan: bool = False, progress_callback=None):
        """
        Initialize the scanner
        
        Args:
            domain: Target domain
            deep_scan: Enable deep scan mode
            progress_callback: Callback function for progress updates (optional)
        """
        self.domain = domain.strip().lower()
        self.use_deep_scan = deep_scan
        self.progress_callback = progress_callback
        self.results: Set[SubdomainResult] = set()
        self.found_subdomains: Set[str] = set()
        self.wildcard_ip = None
        self.max_workers = 150 if self.use_deep_scan else 50
        self.timeout = 5
        
        # Get wordlist path
        self.wordlist_path = Path(__file__).parent.parent.parent / "data" / "subdomains.txt"
        self.default_list = ["www", "mail", "ftp", "dev", "test", "cpanel", "api", "blog", 
                            "shop", "admin", "beta", "stage"]
        
    def update_progress(self, current: int, total: int, message: str = ""):
        """Update progress via callback"""
        if self.progress_callback:
            percentage = int((current / total) * 100) if total > 0 else 0
            self.progress_callback({
                'percentage': percentage,
                'current': current,
                'total': total,
                'message': message
            })
    
    def detect_wildcard(self) -> Tuple[bool, str]:
        """
        Detect if domain uses wildcard DNS
        
        Returns:
            Tuple of (is_wildcard, wildcard_ip)
        """
        try:
            # Try to resolve a random non-existent subdomain
            random_sub = f"xyzrandom{int(time.time())}.{self.domain}"
            ip = self.resolve_dns(random_sub)
            if ip:
                return True, ip
        except Exception as e:
            logger.debug(f"Wildcard detection error: {e}")
        return False, None
    
    def resolve_dns(self, hostname: str) -> str:
        """
        Resolve hostname to IP using dns.resolver
        
        Args:
            hostname: The hostname to resolve
            
        Returns:
            IP address or None
        """
        try:
            answers = dns.resolver.resolve(hostname, 'A', lifetime=self.timeout)
            if answers:
                return str(answers[0])
        except (dns.exception.Timeout, dns.resolver.NXDOMAIN, 
                dns.resolver.NoAnswer, dns.exception.DNSException):
            pass
        except Exception:
            pass
        return None
    
    def get_dns_records(self, hostname: str) -> Dict:
        """
        Get multiple DNS record types for a hostname
        
        Args:
            hostname: The hostname to query
            
        Returns:
            Dictionary of DNS records by type
        """
        records = {}
        for record_type in DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(hostname, record_type, lifetime=self.timeout)
                records[record_type] = [str(rdata.to_text()) for rdata in answers]
            except (dns.exception.Timeout, dns.resolver.NXDOMAIN, 
                    dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            except Exception:
                pass
        return records
    
    def check_http_status(self, subdomain: str) -> Tuple[int, str]:
        """
        Check HTTP and HTTPS status for subdomain
        
        Args:
            subdomain: The subdomain to check
            
        Returns:
            Tuple of (status_code, status_text)
        """
        status_text = "Unknown"
        status_code = None
        
        # Check if subdomain resolves to wildcard
        ip = self.resolve_dns(subdomain)
        
        # Skip if it's a wildcard IP (but this is now handled in scan_subdomain)
        if self.wildcard_ip and ip and ip == self.wildcard_ip:
            return None, "WILDCARD"
        
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.head(url, timeout=self.timeout, allow_redirects=False)
                status_code = response.status_code
                
                # Map status code to text
                if status_code == 200:
                    status_text = "Live"
                elif status_code in [301, 302]:
                    status_text = "Redirected"
                elif status_code in [401, 403]:
                    status_text = "Restricted"
                elif status_code == 404:
                    status_text = "Not Found"
                elif status_code >= 500:
                    status_text = "Server Error"
                else:
                    status_text = f"HTTP {status_code}"
                
                return status_code, status_text
                
            except (requests.Timeout, requests.ConnectionError, requests.RequestException):
                status_text = "Unreachable"
                continue
            except Exception as e:
                logger.debug(f"Error checking {subdomain}: {e}")
                continue
        
        # If both HTTP attempts failed but subdomain exists in DNS
        if ip:
            return None, "No HTTP Response"
        
        return status_code, status_text
    
    def load_wordlist(self) -> List[str]:
        """
        Load wordlist for DNS brute-force
        
        Returns:
            List of subdomains to try
        """
        wordlist = self.default_list.copy()
        
        if self.wordlist_path.exists():
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_words = [line.strip().lower() for line in f if line.strip()]
                    wordlist.extend(file_words[:50000])  # Limit to 50k entries
            except Exception as e:
                logger.error(f"Error loading wordlist: {e}")
        
        return list(set(wordlist))  # Remove duplicates
    
    def generate_permutations(self, base_subdomains: List[str]) -> List[str]:
        """
        Generate subdomain permutations
        
        Args:
            base_subdomains: List of base subdomains
            
        Returns:
            List of permuted subdomains
        """
        permutations = []
        prefixes = ['dev', 'test', 'stage', 'prod', 'api', 'admin', 'backup']
        suffixes = ['api', 'web', 'app', 'v1', 'v2', 'db', 'cache']
        
        for sub in base_subdomains[:100]:  # Limit permutations for performance
            # Add prefixed versions
            for prefix in prefixes:
                permutations.append(f"{prefix}-{sub}")
                permutations.append(f"{prefix}{sub}")
            
            # Add suffixed versions
            for suffix in suffixes:
                permutations.append(f"{sub}-{suffix}")
                permutations.append(f"{sub}{suffix}")
        
        return permutations
    
    def check_subdomain_exists(self, subdomain: str) -> bool:
        """
        Check if subdomain exists via DNS resolution
        
        Args:
            subdomain: The subdomain to check
            
        Returns:
            True if subdomain exists, False otherwise
        """
        try:
            # Try multiple DNS record types
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                try:
                    answers = dns.resolver.resolve(subdomain, record_type, lifetime=self.timeout)
                    if answers:
                        return True
                except (dns.exception.Timeout, dns.resolver.NXDOMAIN, 
                        dns.resolver.NoAnswer, dns.exception.DNSException):
                    continue
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def scan_subdomain(self, sub: str) -> SubdomainResult:
        """
        Scan a single subdomain
        
        Args:
            sub: The subdomain to scan
            
        Returns:
            SubdomainResult object
        """
        full_domain = f"{sub}.{self.domain}"
        
        try:
            # Check if subdomain exists via DNS
            if not self.check_subdomain_exists(full_domain):
                return None
            
            # Get DNS records
            dns_records = self.get_dns_records(full_domain)
            
            # Try to get A record for wildcard comparison
            ip = self.resolve_dns(full_domain)
            
            # Check if it matches wildcard (if wildcard was detected)
            if self.wildcard_ip and ip and ip == self.wildcard_ip:
                # Skip wildcard match
                return None
            
            # Check HTTP status (may be successful or unreachable, both are valid finds)
            status_code, status_text = self.check_http_status(full_domain)
            
            # Create result - include result even if HTTP check fails
            result = SubdomainResult(
                subdomain=full_domain,
                status_code=status_code,
                status_text=status_text if status_text else "Found",
                dns_records=dns_records
            )
            
            return result
            
        except Exception as e:
            logger.debug(f"Error scanning {full_domain}: {e}")
            return None
    
    def simple_scan(self) -> List[SubdomainResult]:
        """
        Perform simple scan using default list
        
        Returns:
            List of SubdomainResult objects
        """
        results = []
        total = len(self.default_list)
        
        for idx, sub in enumerate(self.default_list):
            self.update_progress(idx + 1, total, f"Scanning {sub}.{self.domain}")
            
            try:
                if self.check_subdomain_exists(f"{sub}.{self.domain}"):
                    results.append(SubdomainResult(
                        subdomain=f"{sub}.{self.domain}",
                        status_text="Found"
                    ))
            except Exception as e:
                logger.debug(f"Error checking {sub}: {e}")
        
        return results
    
    def deep_scan(self) -> List[SubdomainResult]:
        """
        Perform deep scan with wordlist, permutations, and recursive scanning
        
        Returns:
            List of SubdomainResult objects
        """
        logger.info(f"Starting deep scan for {self.domain}")
        
        # Step 1: Detect wildcard
        logger.info("Detecting wildcard DNS...")
        is_wildcard, self.wildcard_ip = self.detect_wildcard()
        
        # Step 2: Load wordlist
        logger.info("Loading wordlist...")
        wordlist = self.load_wordlist()
        
        # Step 3: Generate permutations
        logger.info("Generating permutations...")
        permutations = self.generate_permutations(wordlist)
        
        # Combine all candidates
        candidates = list(set(wordlist + permutations))
        total_candidates = len(candidates)
        
        logger.info(f"Total candidates to check: {total_candidates}")
        
        # Step 4: Parallel scanning
        results = []
        processed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_subdomain, sub): sub for sub in candidates}
            
            for future in as_completed(futures):
                processed += 1
                sub = futures[future]
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found_subdomains.add(result.subdomain)
                        logger.info(f"Found: {result.subdomain}")
                except Exception as e:
                    logger.debug(f"Error processing {sub}: {e}")
                
                # Update progress
                self.update_progress(processed, total_candidates, 
                                   f"Scanned {len(results)} subdomains")
        
        # Step 5: Recursive scanning (scan subdomains of discovered subdomains)
        if len(results) > 0 and len(results) < 20:
            logger.info("Starting recursive scan...")
            recursive_candidates = []
            
            for result in results:
                # Extract subdomain part (first part before next dot)
                parts = result.subdomain.split('.')
                if len(parts) > 2:
                    continue  # Skip already deep subdomains
                
                # Try recursive scan on this subdomain
                for prefix in ['api', 'admin', 'dev', 'test']:
                    recursive_candidates.append(f"{prefix}.{result.subdomain}")
            
            # Scan recursive candidates
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                recursive_futures = {executor.submit(self.scan_subdomain, sub.replace(f".{self.domain}", "")): sub 
                                    for sub in recursive_candidates}
                
                for future in as_completed(recursive_futures):
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            logger.info(f"Recursive found: {result.subdomain}")
                    except Exception as e:
                        logger.debug(f"Error in recursive scan: {e}")
        
        logger.info(f"Deep scan complete. Found {len(results)} subdomains")
        return results
    
    def scan(self) -> List[Dict]:
        """
        Run the scan (simple or deep)
        
        Returns:
            List of subdomain results as dictionaries
        """
        try:
            if self.use_deep_scan:
                results = self.deep_scan()
            else:
                results = self.simple_scan()
            
            # Convert to dictionaries and sort by subdomain
            result_dicts = [r.to_dict() for r in results]
            result_dicts.sort(key=lambda x: x['subdomain'])
            
            return result_dicts
            
        except Exception as e:
            import traceback
            logger.error(f"Scan failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []


def scan_subdomains_blocking(domain: str, deep_scan: bool = False, progress_callback=None) -> List[Dict]:
    """
    Blocking function to scan subdomains
    
    Args:
        domain: Target domain
        deep_scan: Enable deep scan mode
        progress_callback: Optional callback for progress updates
        
    Returns:
        List of subdomain results
    """
    scanner = DeepSubdomainScanner(domain, deep_scan=deep_scan, progress_callback=progress_callback)
    return scanner.scan()
