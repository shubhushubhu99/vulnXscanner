"""
Directory Scanner with Deep Scan capabilities
- HTTP brute-force with large wordlist
- Multiple HTTP methods checking
- Status code detection
- Content-length analysis
- Redirect following
- Progress tracking
- Wildcard/soft-404 detection
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
import time
import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("vulnx.directory_scanner")

# Common extensions to append during deep scan
DEEP_EXTENSIONS = [
    '', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.txt',
    '.json', '.xml', '.yml', '.yaml', '.conf', '.cfg', '.ini',
    '.log', '.bak', '.old', '.sql', '.db', '.env', '.git',
    '.py', '.rb', '.js', '.css'
]

QUICK_EXTENSIONS = ['', '.php', '.html', '.txt']


class DirectoryResult:
    """Data class for directory results"""
    def __init__(self, path: str, url: str, status_code: int = None,
                 status_text: str = "Unknown", content_length: int = 0,
                 redirect_url: str = None):
        self.path = path
        self.url = url
        self.status_code = status_code
        self.status_text = status_text
        self.content_length = content_length
        self.redirect_url = redirect_url

    def to_dict(self):
        return {
            'path': self.path,
            'url': self.url,
            'status_code': self.status_code,
            'status_text': self.status_text,
            'content_length': self.content_length,
            'redirect_url': self.redirect_url
        }


class DirectoryScanner:
    """Directory/path brute-force scanner"""

    def __init__(self, target: str, deep_scan: bool = False, progress_callback=None, max_workers: int = None):
        """
        Initialize the scanner.

        Args:
            target: Target URL (with or without scheme)
            deep_scan: Enable deep scan mode (more extensions, bigger wordlist)
            progress_callback: Callback function for progress updates
            max_workers: Custom number of worker threads (optional)
        """
        self.raw_target = target.strip().rstrip('/')
        self.target = self._normalize_url(self.raw_target)
        self.use_deep_scan = deep_scan
        self.progress_callback = progress_callback
        self.found_paths: Set[str] = set()
        # Use custom max_workers if provided, otherwise use defaults
        if max_workers is not None:
            self.max_workers = max_workers
        else:
            self.max_workers = 750 if self.use_deep_scan else 450
        self.timeout = 8
        self.soft_404_signatures: List[str] = []
        self.soft_404_length: int = None
        # Generic redirect detection
        self.generic_redirect_url: str = None   # redirect Location for non-existent paths
        self.generic_redirect_code: int = None  # status code for non-existent paths
        self.baseline_content_length: int = None  # content-length for generic responses

        # User-Agent to avoid basic bot detection
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }

        # Wordlist path
        self.wordlist_path = Path(__file__).parent.parent.parent / "data" / "directories.txt"

    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_url(target: str) -> str:
        """Ensure the target has a scheme."""
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
        return target.rstrip('/')

    # ------------------------------------------------------------------
    def update_progress(self, current: int, total: int, message: str = ""):
        if self.progress_callback:
            percentage = int((current / total) * 100) if total > 0 else 0
            self.progress_callback({
                'percentage': percentage,
                'current': current,
                'total': total,
                'message': message
            })

    # ------------------------------------------------------------------
    def detect_soft_404(self, _depth: int = 0):
        """Detect soft-404, generic-redirect, and domain-level redirect patterns."""
        if _depth > 3:
            logger.warning("Max redirect depth reached during soft-404 detection")
            return
        fake_paths = [
            f"{self.target}/thispagedoesnotexist_{int(time.time())}",
            f"{self.target}/zz_random_path_{int(time.time()) + 1}",
            f"{self.target}/absolutelynotreal_{int(time.time()) + 2}",
        ]
        redirect_locations = []
        redirect_codes = []
        soft_404_lengths = []

        for fake in fake_paths:
            try:
                resp = requests.get(fake, headers=self.headers, timeout=self.timeout,
                                    allow_redirects=False, verify=False)
                code = resp.status_code
                content_length = len(resp.content)

                if code == 200:
                    soft_404_lengths.append(content_length)
                elif code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location', '')
                    redirect_codes.append(code)
                    redirect_locations.append((fake, loc))
            except Exception:
                pass

        # --- Soft-404 (200 for non-existent pages) ---
        if len(soft_404_lengths) >= 2:
            avg = sum(soft_404_lengths) / len(soft_404_lengths)
            if all(abs(l - avg) < 100 for l in soft_404_lengths):
                self.soft_404_length = int(avg)
                logger.info(f"Soft-404 detected (avg length={self.soft_404_length})")

        # --- Redirect patterns ---
        if len(redirect_codes) >= 2 and len(set(redirect_codes)) == 1:
            self.generic_redirect_code = redirect_codes[0]
            locs = [loc for _, loc in redirect_locations]
            unique_locs = set(locs)

            # Case 1: All redirect to exact same URL
            if len(unique_locs) == 1:
                self.generic_redirect_url = locs[0]
                logger.info(f"Generic redirect detected: {self.generic_redirect_code} -> {self.generic_redirect_url}")
                return

            # Case 2: Domain-level redirect (host changes, path preserved)
            # e.g. cgc.ac.in/X -> www.cgc.ac.in/X  for every X
            src_host = urlparse(self.target).netloc
            redirect_hosts = set()
            is_host_redirect = True
            for req_url, loc_url in redirect_locations:
                if not loc_url.startswith('http'):
                    is_host_redirect = False
                    break
                loc_parsed = urlparse(loc_url)
                req_parsed = urlparse(req_url)
                redirect_hosts.add(loc_parsed.netloc)
                # Path must be the same (host-only change)
                if loc_parsed.path.rstrip('/') != req_parsed.path.rstrip('/'):
                    is_host_redirect = False
                    break

            if is_host_redirect and len(redirect_hosts) == 1:
                new_host = redirect_hosts.pop()
                if new_host != src_host:
                    # Re-target to the canonical host
                    old_parsed = urlparse(self.target)
                    new_target = f"{old_parsed.scheme}://{new_host}"
                    logger.info(f"Domain redirect detected: {self.target} -> {new_target}")
                    self.update_progress(0, 0,
                                         f"Domain redirect detected → scanning {new_host} instead")
                    self.target = new_target

                    # Now re-run soft-404 detection on the new target
                    self.generic_redirect_code = None
                    self.generic_redirect_url = None
                    self.detect_soft_404(_depth=_depth + 1)
                    return

            # Case 3: All redirect to same path (different from requested)
            redir_paths = set()
            for loc in locs:
                if loc.startswith('http'):
                    redir_paths.add(urlparse(loc).path.rstrip('/') or '/')
                else:
                    redir_paths.add(loc.rstrip('/') or '/')
            if len(redir_paths) == 1:
                self.generic_redirect_url = locs[0]
                logger.info(f"Generic redirect (same path): {self.generic_redirect_code} -> {self.generic_redirect_url}")
                return

            # Case 4: Trailing-slash appending
            all_slash_append = True
            for req_url, loc_url in redirect_locations:
                expected = req_url + '/'
                if loc_url != expected:
                    loc_path = urlparse(loc_url).path if loc_url.startswith('http') else loc_url
                    req_path = urlparse(req_url).path if req_url.startswith('http') else req_url
                    if loc_path != req_path + '/':
                        all_slash_append = False
                        break
            if all_slash_append:
                self.generic_redirect_url = '__trailing_slash__'
                logger.info(f"Trailing-slash redirect detected: {self.generic_redirect_code}")

    # ------------------------------------------------------------------
    def load_wordlist(self) -> List[str]:
        """Load directory wordlist."""
        wordlist: List[str] = []

        if self.wordlist_path.exists():
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                logger.error(f"Error loading wordlist: {e}")

        if not wordlist:
            wordlist = [
                'admin', 'login', 'dashboard', 'api', 'test', 'dev',
                'backup', 'config', '.env', '.git', 'uploads', 'images',
                'wp-admin', 'phpmyadmin', 'robots.txt', 'sitemap.xml',
            ]

        return list(set(wordlist))

    # ------------------------------------------------------------------
    def _build_candidates(self, wordlist: List[str]) -> List[str]:
        """Expand wordlist with extensions to produce candidate paths."""
        extensions = DEEP_EXTENSIONS if self.use_deep_scan else QUICK_EXTENSIONS
        candidates: List[str] = []

        for word in wordlist:
            # If the word already has an extension, keep it as-is
            if '.' in word.split('/')[-1]:
                candidates.append(word)
            else:
                for ext in extensions:
                    candidates.append(f"{word}{ext}")

        return list(set(candidates))

    # ------------------------------------------------------------------
    def check_path(self, path: str) -> DirectoryResult | None:
        """Check a single path against the target."""
        url = f"{self.target}/{path.lstrip('/')}"

        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout,
                                allow_redirects=True, verify=False)

            status_code = resp.status_code
            content_length = len(resp.content)
            final_url = resp.url

            # Filter out soft-404 pages
            if status_code == 200 and self.soft_404_length is not None:
                if abs(content_length - self.soft_404_length) < 100:
                    return None

            # Skip generic not-found / error codes
            if status_code in (404, 400, 500, 502, 503, 504):
                return None

            # Determine if there was a redirect by checking history
            was_redirected = len(resp.history) > 0
            redirect_url = None

            if was_redirected:
                # The original response code (before following redirects)
                original_code = resp.history[0].status_code
                redirect_url = final_url

                # --- Filter generic redirects ---
                if self.generic_redirect_code and original_code == self.generic_redirect_code:
                    first_loc = resp.history[0].headers.get('Location', '')

                    if self.generic_redirect_url == '__trailing_slash__':
                        if first_loc == url + '/' or first_loc.rstrip('/') == url.rstrip('/'):
                            if status_code in (404, 400, 500, 502, 503, 504):
                                return None
                            if status_code == 200 and self.soft_404_length is not None:
                                if abs(content_length - self.soft_404_length) < 100:
                                    return None
                    elif self.generic_redirect_url:
                        norm_loc = first_loc.rstrip('/')
                        norm_generic = self.generic_redirect_url.rstrip('/')
                        if norm_loc == norm_generic:
                            return None
                        loc_path = urlparse(first_loc).path.rstrip('/') or '/'
                        gen_path = urlparse(self.generic_redirect_url).path.rstrip('/') or '/'
                        if loc_path == gen_path:
                            return None

            # Map status code
            if status_code == 200:
                status_text = "OK"
            elif status_code in (301, 302, 303, 307, 308):
                # Still a redirect (not followed, e.g., cross-domain)
                redirect_url = resp.headers.get('Location', redirect_url or '')
                status_text = "Redirect"
            elif status_code == 401:
                status_text = "Unauthorized"
            elif status_code == 403:
                status_text = "Forbidden"
            elif status_code == 405:
                status_text = "Method Not Allowed"
            else:
                status_text = f"HTTP {status_code}"

            return DirectoryResult(
                path=path, url=url,
                status_code=status_code,
                status_text=status_text,
                content_length=content_length,
                redirect_url=redirect_url
            )

        except requests.Timeout:
            return None
        except requests.ConnectionError:
            return None
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
            return None

    # ------------------------------------------------------------------
    def simple_scan(self) -> List[DirectoryResult]:
        """Quick scan with small wordlist and few extensions."""
        # Detect generic redirects / soft-404 before scanning
        self.detect_soft_404()

        wordlist = self.load_wordlist()
        # In quick mode, limit to first 200 entries
        wordlist = wordlist[:200]
        candidates = self._build_candidates(wordlist)
        total = len(candidates)
        results: List[DirectoryResult] = []
        processed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_path, path): path for path in candidates}
            for future in as_completed(futures):
                processed += 1
                self.update_progress(processed, total,
                                     f"Checking /{futures[future]}")
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found_paths.add(result.path)
                except Exception:
                    pass

        return results

    # ------------------------------------------------------------------
    def deep_scan(self) -> List[DirectoryResult]:
        """Full scan with all extensions and recursive discovery."""
        logger.info(f"Starting deep directory scan for {self.target}")

        # Step 1: Detect soft-404
        logger.info("Detecting soft-404 pages...")
        self.detect_soft_404()

        # Step 2: Load wordlist
        logger.info("Loading wordlist...")
        wordlist = self.load_wordlist()

        # Step 3: Build candidates with all extensions
        logger.info("Building candidate paths...")
        candidates = self._build_candidates(wordlist)
        total = len(candidates)

        logger.info(f"Total candidates to check: {total}")

        # Step 4: Parallel scanning
        results: List[DirectoryResult] = []
        processed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_path, path): path for path in candidates}
            for future in as_completed(futures):
                processed += 1
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found_paths.add(result.path)
                        logger.info(f"Found: /{result.path} [{result.status_code}]")
                except Exception as e:
                    logger.debug(f"Error processing {path}: {e}")

                self.update_progress(processed, total,
                                     f"Scanned {len(results)} paths found")

        # Step 5: Recursive — try sub-paths on discovered directories
        if results and len(results) < 50:
            logger.info("Starting recursive directory scan...")
            recursive_candidates: List[str] = []
            common_subs = ['admin', 'api', 'config', 'backup', 'test', 'v1', 'v2', 'docs']

            for r in results:
                if r.status_code in (200, 301, 302, 403):
                    base = r.path.rstrip('/')
                    for sub in common_subs:
                        recursive_candidates.append(f"{base}/{sub}")

            recursive_candidates = list(set(recursive_candidates) - self.found_paths)

            if recursive_candidates:
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    rec_futures = {executor.submit(self.check_path, p): p
                                   for p in recursive_candidates}
                    for future in as_completed(rec_futures):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                                logger.info(f"Recursive found: /{result.path} [{result.status_code}]")
                        except Exception:
                            pass

        logger.info(f"Deep scan complete. Found {len(results)} paths")
        return results

    # ------------------------------------------------------------------
    def scan(self) -> List[Dict]:
        """Run the scan (simple or deep) and return dicts."""
        try:
            if self.use_deep_scan:
                results = self.deep_scan()
            else:
                results = self.simple_scan()

            result_dicts = [r.to_dict() for r in results]
            result_dicts.sort(key=lambda x: x['path'])
            return result_dicts

        except Exception as e:
            import traceback
            logger.error(f"Scan failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return []


# ======================================================================
# Blocking helper (matches pattern of scan_subdomains_blocking)
# ======================================================================

def scan_directories_blocking(target: str, deep_scan: bool = False,
                              progress_callback=None, max_workers: int = None) -> List[Dict]:
    """
    Blocking function to scan directories.

    Args:
        target: Target URL
        deep_scan: Enable deep scan mode
        progress_callback: Optional callback for progress updates
        max_workers: Custom number of worker threads (optional)

    Returns:
        List of directory results
    """
    scanner = DirectoryScanner(target, deep_scan=deep_scan,
                               progress_callback=progress_callback, max_workers=max_workers)
    return scanner.scan()
