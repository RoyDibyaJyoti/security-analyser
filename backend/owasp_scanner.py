"""
Enhanced OWASP Top 10 Vulnerability Scanner
Educational prototype with safety features
"""
import re
import time
import requests
import socket
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Optional, Tuple, Callable

from backend.models import OWASPScanResult, RiskLevel, OWASPScanResponse
from backend.config import settings
from backend.utils import safe_request, is_internal_ip

class OWASPScanner:
    """OWASP Top 10 vulnerability scanner with safety controls"""
    
    SQL_ERRORS = [
        "you have an error in your sql syntax",
        "warning: mysql", "warning: postgresql", "warning: sqlite",
        "unclosed quotation mark", "quoted string not properly terminated",
        "pg_query(): query failed", "ORA-00933", "SQLServer",
        "System.Data.SqlClient.SqlException", "SQLite3::SQLException"
    ]
    
    COMMON_CREDS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("user", "user"), ("test", "test"), ("root", "root"),
        ("administrator", "admin"), ("guest", "guest")
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert(1)</script>",
        "javascript:alert('XSS')"
    ]
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": settings.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close"
        })
        self.results: List[OWASPScanResult] = []
    
    def _is_safe_target(self, url: str) -> Tuple[bool, str]:
        """Validate target URL meets safety requirements"""
        parsed = urlparse(url)
        
        # Check protocol
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP/HTTPS protocols allowed"
        
        # Check internal IPs if configured
        if settings.BLOCK_INTERNAL_IPS and parsed.hostname:
            try:
                import socket
                ip = socket.gethostbyname(parsed.hostname)
                if is_internal_ip(ip):
                    return False, f"Scanning internal IP {ip} is disabled"
            except:
                pass
        
        # Check against allowed domains if configured
        if settings.ALLOWED_DOMAINS and parsed.hostname:
            if not any(parsed.hostname.endswith(domain) for domain in settings.ALLOWED_DOMAINS if domain):
                return False, f"Domain {parsed.hostname} not in allowed list"
        
        return True, "OK"
    
    def get_all_forms(self, url: str) -> List:
        """Safely retrieve forms from page"""
        try:
            response = safe_request(url)
            if not response:
                return []
            soup = bs(response.content, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[!] Error retrieving forms: {e}")
            return []
    
    def get_form_details(self, form) -> Dict:
        """Extract form details safely"""
        details = {
            "action": form.attrs.get("action", "").strip(),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        
        for input_tag in form.find_all("input"):
            input_details = {
                "type": input_tag.attrs.get("type", "text"),
                "name": input_tag.attrs.get("name"),
                "value": input_tag.attrs.get("value", "")
            }
            if input_details["name"]:  # Only include named inputs
                details["inputs"].append(input_details)
        
        return details
    
    def _check_sql_error(self, response_text: str) -> bool:
        """Check for SQL error patterns"""
        lower = response_text.lower()
        return any(err in lower for err in self.SQL_ERRORS)
    
    def scan_sql_injection(self, base_url: str) -> List[OWASPScanResult]:
        """Scan for SQL injection vulnerabilities (A03)"""
        results = []
        print(f"\n[+] Scanning for SQL Injection (A03) at {base_url}")
        
        # Test URL parameters
        test_chars = ["'", '"', ";", "--", "/*"]
        parsed = urlparse(base_url)
        
        # If URL has query params, test each one
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                for char in test_chars:
                    test_url = base_url.replace(f"{param}={params[param][0]}", f"{param}={char}")
                    try:
                        response = safe_request(test_url)
                        if response and self._check_sql_error(response.text):
                            results.append(OWASPScanResult(
                                vulnerability_id="A03:2021-SQLi-001",
                                title="Potential SQL Injection in URL Parameter",
                                category="A03:2021-Injection",
                                severity=RiskLevel.HIGH,
                                description=f"Parameter '{param}' may be vulnerable to SQL injection",
                                affected_endpoint=test_url[:200],
                                proof_of_concept=f"Payload: {param}={char}",
                                remediation="Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
                                cvss_score=8.1
                            ))
                            break
                    except Exception as e:
                        print(f"[!] Error testing SQLi on {param}: {e}")
        
        # Test forms
        forms = self.get_all_forms(base_url)
        for form in forms:
            details = self.get_form_details(form)
            form_url = urljoin(base_url, details["action"])
            
            for char in ["'", '"']:
                test_data = {}
                for inp in details["inputs"]:
                    name = inp["name"]
                    if not name:
                        continue
                    if inp["type"] in ["text", "search", "email"]:
                        test_data[name] = f"test{char}"
                    else:
                        test_data[name] = inp["value"]
                
                try:
                    if details["method"] == "post":
                        response = self.session.post(form_url, data=test_data, timeout=settings.REQUEST_TIMEOUT)
                    else:
                        response = self.session.get(form_url, params=test_data, timeout=settings.REQUEST_TIMEOUT)
                    
                    if response and self._check_sql_error(response.text):
                        results.append(OWASPScanResult(
                            vulnerability_id="A03:2021-SQLi-002",
                            title="Potential SQL Injection in Form",
                            category="A03:2021-Injection",
                            severity=RiskLevel.HIGH,
                            description=f"Form at {form_url} may be vulnerable to SQL injection",
                            affected_endpoint=form_url[:200],
                            proof_of_concept=f"Test payload: test{char}",
                            remediation="Implement input validation, use ORM/prepared statements, apply least privilege to DB accounts.",
                            cvss_score=8.1
                        ))
                        break
                except Exception as e:
                    print(f"[!] Error testing form SQLi: {e}")
        
        return results
    
    def scan_xss(self, base_url: str) -> List[OWASPScanResult]:
        """Scan for reflected XSS vulnerabilities (A03)"""
        results = []
        print(f"\n[+] Scanning for XSS (A03) at {base_url}")
        
        forms = self.get_all_forms(base_url)
        for form in forms:
            details = self.get_form_details(form)
            target_url = urljoin(base_url, details["action"])
            
            for payload in self.XSS_PAYLOADS[:2]:  # Limit payloads for safety
                test_data = {}
                for inp in details["inputs"]:
                    name = inp["name"]
                    if not name:
                        continue
                    if inp["type"] in ["text", "search"]:
                        test_data[name] = payload
                    else:
                        test_data[name] = inp["value"]
                
                try:
                    if details["method"] == "post":
                        response = self.session.post(target_url, data=test_data, timeout=settings.REQUEST_TIMEOUT)
                    else:
                        response = self.session.get(target_url, params=test_data, timeout=settings.REQUEST_TIMEOUT)
                    
                    if response and payload in response.text:
                        results.append(OWASPScanResult(
                            vulnerability_id="A03:2021-XSS-001",
                            title="Potential Reflected XSS",
                            category="A03:2021-Injection",
                            severity=RiskLevel.HIGH,
                            description=f"Form input may be reflected without proper encoding",
                            affected_endpoint=target_url[:200],
                            proof_of_concept=f"Payload: {payload[:30]}...",
                            remediation="Implement output encoding, use Content-Security-Policy headers, validate and sanitize inputs.",
                            cvss_score=7.1
                        ))
                        break
                except Exception as e:
                    print(f"[!] Error testing XSS: {e}")
        
        return results
    
    def scan_broken_auth(self, base_url: str) -> List[OWASPScanResult]:
        """Scan for broken authentication (A07)"""
        results = []
        print(f"\n[+] Scanning for Broken Authentication (A07) at {base_url}")
        
        forms = self.get_all_forms(base_url)
        for form in forms:
            details = self.get_form_details(form)
            
            # Heuristic: detect login forms
            input_names = [inp["name"] or "" for inp in details["inputs"]]
            names_lower = " ".join(n.lower() for n in input_names)
            
            if ("user" in names_lower or "email" in names_lower) and "pass" in names_lower:
                login_url = urljoin(base_url, details["action"])
                print(f"[+] Testing login form at: {login_url}")
                
                for username, password in self.COMMON_CREDS[:3]:  # Limit attempts
                    credentials = {}
                    for inp in details["inputs"]:
                        name = inp["name"]
                        if not name:
                            continue
                        lname = name.lower()
                        if "user" in lname or "email" in lname:
                            credentials[name] = username
                        elif "pass" in lname:
                            credentials[name] = password
                        else:
                            credentials[name] = inp["value"]
                    
                    try:
                        response = self.session.post(login_url, data=credentials, timeout=settings.REQUEST_TIMEOUT, allow_redirects=True)
                        text_lower = response.text.lower()
                        
                        # Check for successful login indicators (be conservative)
                        if any(k in text_lower for k in ["logout", "dashboard", "welcome", "my account"]):
                            if "login" not in text_lower and "sign in" not in text_lower:
                                results.append(OWASPScanResult(
                                    vulnerability_id="A07:2021-AUTH-001",
                                    title="Weak Authentication - Default Credentials Accepted",
                                    category="A07:2021-Identification and Authentication Failures",
                                    severity=RiskLevel.CRITICAL,
                                    description=f"Login form accepted default credentials: {username}/{password}",
                                    affected_endpoint=login_url[:200],
                                    proof_of_concept=f"Username: {username}, Password: {password}",
                                    remediation="Enforce strong password policies, implement account lockout, use MFA, remove default credentials.",
                                    cvss_score=9.8
                                ))
                                break
                    except Exception as e:
                        print(f"[!] Error testing auth: {e}")
        
        return results
    
    def scan_access_control(self, base_url: str) -> List[OWASPScanResult]:
        """Basic broken access control check (A01)"""
        results = []
        print(f"\n[+] Checking Broken Access Control (A01) at {base_url}")
        
        # Look for numeric IDs in URL
        if any(c.isdigit() for c in base_url):
            # Try incrementing the first number found
            import re
            match = re.search(r'(\d+)', base_url)
            if match:
                original_id = match.group(1)
                test_id = str(int(original_id) + 1)
                test_url = base_url.replace(original_id, test_id, 1)
                
                try:
                    original_resp = safe_request(base_url)
                    test_resp = safe_request(test_url)
                    
                    if original_resp and test_resp and original_resp.status_code == test_resp.status_code == 200:
                        # Very naive: if both return 200 and similar content length, might be IDOR
                        if abs(len(original_resp.text) - len(test_resp.text)) < 100:
                            results.append(OWASPScanResult(
                                vulnerability_id="A01:2021-IDOR-001",
                                title="Potential Insecure Direct Object Reference",
                                category="A01:2021-Broken Access Control",
                                severity=RiskLevel.MEDIUM,
                                description="Changing resource ID in URL may access other users' data",
                                affected_endpoint=test_url[:200],
                                proof_of_concept=f"Original: ...{original_id}, Test: ...{test_id}",
                                remediation="Implement proper authorization checks on every request, use indirect reference maps, validate user permissions server-side.",
                                cvss_score=6.5
                            ))
                except Exception as e:
                    print(f"[!] Error testing access control: {e}")
        
        return results
    
    def scan_misconfiguration(self, base_url: str) -> List[OWASPScanResult]:
        """Check for security misconfigurations (A05)"""
        results = []
        print(f"\n[+] Checking Security Misconfiguration (A05) at {base_url}")
        
        # Check for exposed admin panel
        admin_paths = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/.env", "/config.php"]
        base = base_url.rstrip("/")
        
        for path in admin_paths:
            test_url = base + path
            try:
                response = safe_request(test_url)
                if response and response.status_code == 200:
                    content_lower = response.text.lower()
                    # Check if it's actually an admin interface (not a login page)
                    if "login" not in content_lower and ("admin" in content_lower or "dashboard" in content_lower):
                        severity = RiskLevel.HIGH if path in ["/.env", "/config.php"] else RiskLevel.MEDIUM
                        results.append(OWASPScanResult(
                            vulnerability_id="A05:2021-MISCONFIG-001",
                            title=f"Exposed Administrative Interface: {path}",
                            category="A05:2021-Security Misconfiguration",
                            severity=severity,
                            description=f"Sensitive path {path} is publicly accessible",
                            affected_endpoint=test_url,
                            proof_of_concept=f"Direct access to {test_url}",
                            remediation="Restrict access to admin panels via IP whitelisting, authentication, or remove from production.",
                            cvss_score=7.5 if severity == RiskLevel.HIGH else 5.3
                        ))
            except Exception as e:
                print(f"[!] Error checking {path}: {e}")
        
        return results
    
    def scan_ssrf(self, base_url: str) -> List[OWASPScanResult]:
        """Basic SSRF detection (A10)"""
        results = []
        print(f"\n[+] Checking SSRF Potential (A10) at {base_url}")
        
        # Look for URL parameters that might fetch external resources
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        
        url_params = [p for p in params if any(kw in p.lower() for kw in ['url', 'page', 'redirect', 'file', 'path'])]
        
        for param in url_params:
            # Test with localhost (safe test)
            test_url = base_url.replace(f"{param}={params[param][0]}", f"{param}=http://127.0.0.1")
            try:
                response = safe_request(test_url)
                if response and ("127.0.0.1" in response.text or "localhost" in response.text.lower()):
                    results.append(OWASPScanResult(
                        vulnerability_id="A10:2021-SSRF-001",
                        title="Potential Server-Side Request Forgery",
                        category="A10:2022-Server-Side Request Forgery",
                        severity=RiskLevel.HIGH,
                        description=f"Parameter '{param}' may allow SSRF attacks",
                        affected_endpoint=test_url[:200],
                        proof_of_concept=f"Payload: {param}=http://127.0.0.1",
                        remediation="Validate and whitelist allowed URLs, disable unused URL schemes, use network segmentation, implement egress filtering.",
                        cvss_score=8.6
                    ))
            except Exception as e:
                print(f"[!] Error testing SSRF: {e}")
        
        return results
    
    def run_scan(self, target_url: str, scan_depth: str = "basic", 
                 include_remediation: bool = True,
                 progress_callback: Optional[Callable[[float, str], None]] = None) -> OWASPScanResponse:
        """Execute the vulnerability scan"""
        start_time = time.time()

        def update_progress(progress: float, message: str) -> None:
            if progress_callback:
                progress_callback(progress, message)
        
        # Safety check
        is_safe, message = self._is_safe_target(target_url)
        if not is_safe:
            raise ValueError(f"Target validation failed: {message}")
        
        print(f"\n{'='*60}")
        print(f" OWASP Scanner Starting – Target: {target_url}")
        print(f" Depth: {scan_depth} | Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        all_results = []
        
        # Always run core checks
        update_progress(0.25, "Scanning for SQL injection...")
        all_results.extend(self.scan_sql_injection(target_url))
        update_progress(0.45, "Scanning for reflected XSS...")
        all_results.extend(self.scan_xss(target_url))
        update_progress(0.65, "Checking authentication controls...")
        all_results.extend(self.scan_broken_auth(target_url))
        
        # Extended checks for standard/deep scans
        if scan_depth in ["standard", "deep"]:
            update_progress(0.8, "Checking access control and misconfiguration...")
            all_results.extend(self.scan_access_control(target_url))
            all_results.extend(self.scan_misconfiguration(target_url))
        
        # Deep scan only
        if scan_depth == "deep":
            update_progress(0.9, "Checking SSRF patterns...")
            all_results.extend(self.scan_ssrf(target_url))

        update_progress(0.98, "Compiling scan results...")
        
        # Calculate summary
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for r in all_results:
            severity_counts[r.severity.value] = severity_counts.get(r.severity.value, 0) + 1
        
        # Generate remediation summary
        remediation_summary = []
        if include_remediation and all_results:
            seen = set()
            for r in all_results:
                if r.remediation and r.vulnerability_id not in seen:
                    remediation_summary.append(f"• {r.title}: {r.remediation[:150]}...")
                    seen.add(r.vulnerability_id)
        
        duration = time.time() - start_time
        
        return OWASPScanResponse(
            target_url=target_url,
            scan_duration_seconds=round(duration, 2),
            vulnerabilities_found=len(all_results),
            results=all_results,
            summary=severity_counts,
            remediation_summary=remediation_summary[:10]  # Limit to top 10
        )

# Singleton instance
scanner = OWASPScanner()