import os
import requests
import socket
import sys
from urllib.parse import urlparse, quote
from datetime import datetime
import warnings
from colorama import Fore, Style, init
import threading
from queue import Queue
from pyfiglet import Figlet
import configparser
import re
from bs4 import BeautifulSoup

# Clear terminal on launch
os.system('cls' if os.name == 'nt' else 'clear')

warnings.filterwarnings("ignore")
init(autoreset=True)

# --- Configuration --- #
DEFAULT_WORDLIST_DIR = "wordlists"
COMMON_PATHS = [
    "/.env", "/.git/HEAD", "/.aws/credentials",
    "/admin", "/wp-admin", "/backup.zip",
    "/phpinfo.php", "/api/v1/users"
]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]
SQLI_PAYLOADS = ["' OR '1'='1'--", "1 AND (SELECT 1 FROM pg_sleep(5))--"]
SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"]
THREADS = 10

# Technology signatures
TECH_SIGNATURES = {
    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
    'Joomla': ['joomla', 'media/jui', 'media/system'],
    'Drupal': ['sites/all/modules', 'drupal.js'],
    'Laravel': ['laravel', '/vendor/laravel'],
    'React': ['react.', 'react-dom'],
    'Vue.js': ['vue.', 'vue-router'],
    'jQuery': ['jquery', 'jquery.min.js'],
    'Bootstrap': ['bootstrap', 'bootstrap.min.js'],
    'Nginx': ['nginx', 'server: nginx'],
    'Apache': ['apache', 'server: apache'],
    'PHP': ['php', 'x-powered-by: php'],
    'Node.js': ['x-powered-by: express', 'node.js']
}

# Vulnerability severity mapping
VULN_SEVERITY = {
    "Unencrypted HTTP": "High",
    "Broken Access Control": "High",
    "SQL Injection": "Critical",
    "XSS": "Medium",
    "SSRF": "High",
    "Misconfiguration": "Medium",
    "Wildcard CORS Misconfiguration": "Medium",
    "Remote Code Execution": "Critical",
    "Cloud Metadata Exposure": "High",
    "DOM XSS Pattern": "Medium",
    "Open Redirect": "Low",
    "Verbose Error": "Low",
    "Mixed Content": "Low",
    "Possible vulnerable jQuery": "Medium"
}

class UNIQUEScanner:
    def __init__(self, target, verbose=False):
        self.target = target.rstrip('/')
        self.base_url = self._normalize_url(target)
        self.session = requests.Session()
        self.session.verify = False
        self.vulnerabilities = []
        self.tech_stack = []
        self.verbose = verbose
        self.last_line_length = 0
        self.lock = threading.Lock()
        self.config = self._load_config()
        self.wordlists = self._load_wordlists()

    def _normalize_url(self, url):
        """Ensure URL has http/https prefix"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _load_config(self):
        """Load configuration from config.ini file"""
        config = configparser.ConfigParser()
        try:
            if os.path.exists('config.ini'):
                config.read('config.ini')
            else:
                self._log("config.ini not found, using default settings", "warning")
        except Exception as e:
            self._log(f"Error loading config: {str(e)}", "error")
        return config

    def _load_wordlists(self):
        """Load wordlists from config file or use defaults"""
        wordlists = {
            'paths': COMMON_PATHS,
            'params': [],
            'standard_headers': [],
            'nonstandard_headers': [],
            'all_headers': []
        }
        
        if not hasattr(self, 'config') or 'WORDLISTS' not in self.config:
            return wordlists

        for wordlist_type in wordlists.keys():
            try:
                path = self.config['WORDLISTS'].get(wordlist_type, '')
                if path and os.path.exists(path):
                    with open(path, 'r') as f:
                        wordlists[wordlist_type] = [line.strip() for line in f if line.strip()]
                    self._log(f"Loaded {wordlist_type} wordlist from {path}", "debug")
                elif path:
                    self._log(f"Wordlist not found: {path}", "warning")
            except Exception as e:
                self._log(f"Error loading {wordlist_type} wordlist: {str(e)}", "error")
        
        return wordlists

    def detect_technologies(self):
        """Detect web technologies being used"""
        try:
            self._log("Detecting technologies...", "info")
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            html = response.text
            
            detected_tech = set()
            
            # Check headers
            for tech, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    if pattern.lower() in str(headers).lower():
                        detected_tech.add(tech)
            
            # Check HTML content
            for tech, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    if pattern.lower() in html.lower():
                        detected_tech.add(tech)
            
            # Check common files
            tech_files = {
                'WordPress': '/wp-login.php',
                'Joomla': '/administrator',
                'Drupal': '/sites/default',
                'Laravel': '/.env'
            }
            
            for tech, path in tech_files.items():
                try:
                    r = self.session.get(self.base_url + path, timeout=5)
                    if r.status_code < 400:
                        detected_tech.add(tech)
                except:
                    continue
            
            self.tech_stack = sorted(list(detected_tech))
            if self.tech_stack:
                self._log(f"Detected technologies: {', '.join(self.tech_stack)}", "success")
            else:
                self._log("No technologies detected", "info")
                
        except Exception as e:
            if self.verbose:
                self._log(f"Technology detection error: {str(e)}", "debug")

    def _log(self, message, level="info", overwrite=False):
        prefix = {
            "info": f"{Fore.CYAN}[*]{Style.RESET_ALL}",
            "debug": f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL}",
            "warning": f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
            "success": f"{Fore.GREEN}[+]{Style.RESET_ALL}",
            "error": f"{Fore.RED}[-]{Style.RESET_ALL}"
        }.get(level, f"{Fore.CYAN}[*]{Style.RESET_ALL}")

        output = f"{prefix} {message}"

        if overwrite:
            sys.stdout.write('\r' + ' ' * self.last_line_length + '\r')
            sys.stdout.write(output)
            sys.stdout.flush()
            self.last_line_length = len(output)
        else:
            print(output)
            self.last_line_length = 0

    def show_banner(self):
        f = Figlet(font='standard')
        banner_lines = f.renderText('UNIQUE').splitlines()
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.MAGENTA, Fore.BLUE]
        colored_banner = ""
        for i, line in enumerate(banner_lines):
            color = colors[i % len(colors)]
            colored_banner += f"{color}{line}\n"
        print(f"{colored_banner}{Style.RESET_ALL}")

    def check_availability(self):
        try:
            self._log(f"Testing connection to {self.base_url}...", "info")
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code < 400:
                self._log("Target is reachable and responding", "success")
                self.detect_technologies()
                return True
            self._log(f"Target returned HTTP {response.status_code}", "warning")
        except Exception as e:
            self._log(f"Connection failed: {str(e)}", "error")
        return False

    def show_scan_menu(self):
        print(f"\n{Fore.GREEN}=== Vulnerability Scans ==={Style.RESET_ALL}")
        print("[1] Full Comprehensive Scan (All Checks)")
        print("[2] Broken Access Control (A01)")
        print("[3] Cryptographic Failures (A02)")
        print("[4] Injection (SQLi/XSS)")
        print("[5] Security Misconfig (A05)")
        print("[6] Vulnerable Components (A06)")
        print("[7] Auth Failures (A07)")
        print("[8] Integrity Failures (A08)")
        print("[9] Logging Failures (A09)")
        print("[10] SSRF (A10)")
        print("[11] DOM-based XSS")
        print("[12] Open Redirects")
        print("[13] CORS Misconfiguration")
        print("[14] Remote Code Execution (RCE)")
        print("[15] Cloud Metadata Exposure")
        print("[0] Exit")

        while True:
            choices = input("\nSelect scans (comma-separated numbers): ").strip()
            if choices == "0":
                return None
            selected = [c.strip() for c in choices.split(',') if c.strip().isdigit() and 1 <= int(c.strip()) <= 15]
            if selected:
                return selected
            print("Invalid selection. Please try again.")

    def run_selected_scans(self, choices):
        if not choices:
            return False
            
        self._log("Starting selected scans...", "info")
        mapping = {
            '1': self.scan_all,
            '2': self.check_access_control,
            '3': self.check_crypto,
            '4': self.scan_injection,
            '5': self.check_misconfig,
            '6': self.check_components,
            '7': self.check_auth,
            '8': self.check_integrity,
            '9': self.check_logging,
            '10': self.scan_ssrf,
            '11': self.check_dom_xss,
            '12': self.check_open_redirects,
            '13': self.check_cors,
            '14': self.check_rce,
            '15': self.check_cloud_metadata
        }
        for choice in choices:
            func = mapping.get(choice)
            if func:
                try:
                    func()
                except Exception as e:
                    self._log(f"Error running scan {choice}: {str(e)}", "error")
        return True

    # ===== SCANNING METHODS =====
    def check_access_control(self):
        self._log("Checking broken access control...", "info")
        paths = self.wordlists['paths'] or [
            "/admin", "/dashboard", "/api/users",
            "/.env", "/.git/HEAD", "/.aws/credentials",
            "/wp-admin", "/backup.zip", "/phpinfo.php"
        ]
        
        def check_path(path):
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    self._log(f"Accessible restricted path: {url}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((url, "Broken Access Control"))
            except Exception as e:
                if self.verbose:
                    self._log(f"Access control check error: {str(e)}", "debug")

        threads = []
        for path in paths:
            t = threading.Thread(target=check_path, args=(path,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

    def check_crypto(self):
        self._log("Checking cryptographic configuration...", "info")
        if self.base_url.startswith('http://'):
            self._log("Target is not using HTTPS", "warning")
            with self.lock:
                self.vulnerabilities.append((self.base_url, "Unencrypted HTTP"))

    def scan_injection(self):
        self._log("Checking for Injection (SQLi/XSS)...", "info")
        test_urls = [f"{self.base_url}/search?q=", f"{self.base_url}/product?id="]
        
        def test_injection(url, payload, payload_type):
            try:
                r = self.session.get(url + quote(payload), timeout=10)
                if payload_type == "SQLi" and "sql syntax" in r.text.lower():
                    self._log(f"Potential SQLi at {url}", "success")
                    with self.lock:
                        self.vulnerabilities.append((url, "SQL Injection"))
                elif payload_type == "XSS" and payload in r.text:
                    self._log(f"Potential XSS at {url}", "success")
                    with self.lock:
                        self.vulnerabilities.append((url, "XSS"))
            except Exception as e:
                if self.verbose:
                    self._log(f"Injection check error: {str(e)}", "debug")

        threads = []
        for url in test_urls:
            for payload in SQLI_PAYLOADS:
                t = threading.Thread(target=test_injection, args=(url, payload, "SQLi"))
                threads.append(t)
                t.start()
            
            for payload in XSS_PAYLOADS:
                t = threading.Thread(target=test_injection, args=(url, payload, "XSS"))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()

    def check_misconfig(self):
        self._log("Checking for misconfigurations...", "info")
        paths = self.wordlists['paths'] or [
            "/.git/HEAD", "/phpinfo.php", "/server-status",
            "/.env", "/.aws/credentials", "/wp-config.php"
        ]
        
        def check_path(path):
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    self._log(f"Potential sensitive info: {url}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((url, "Misconfiguration"))
            except Exception as e:
                if self.verbose:
                    self._log(f"Misconfig check error: {str(e)}", "debug")

        threads = []
        for path in paths:
            t = threading.Thread(target=check_path, args=(path,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

    def check_components(self):
        self._log("Checking for vulnerable components...", "info")
        try:
            r = self.session.get(self.base_url, timeout=5)
            if 'jquery' in r.text.lower():
                self._log("jQuery detected", "info")
                with self.lock:
                    self.vulnerabilities.append((self.base_url, "Possible vulnerable jQuery"))
        except Exception as e:
            if self.verbose:
                self._log(f"Components check error: {str(e)}", "debug")

    def check_auth(self):
        self._log("Checking for authentication failures...", "info")
        paths = ["/login", "/admin", "/wp-login.php"]
        
        def check_path(path):
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                if 'login' in r.text.lower():
                    self._log(f"Login page detected at {url}", "info")
            except Exception as e:
                if self.verbose:
                    self._log(f"Auth check error: {str(e)}", "debug")

        threads = []
        for path in paths:
            t = threading.Thread(target=check_path, args=(path,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

    def check_integrity(self):
        self._log("Checking for integrity failures...", "info")
        try:
            r = self.session.get(self.base_url, timeout=5)
            if 'http://' in r.text:
                self._log("Mixed content found", "warning")
                with self.lock:
                    self.vulnerabilities.append((self.base_url, "Mixed Content"))
        except Exception as e:
            if self.verbose:
                self._log(f"Integrity check error: {str(e)}", "debug")

    def check_logging(self):
        self._log("Checking for verbose error messages...", "info")
        test_urls = [f"{self.base_url}/nonexistent", f"{self.base_url}/'"]
        
        def check_url(url):
            try:
                r = self.session.get(url, timeout=5)
                if any(x in r.text.lower() for x in ['error', 'exception']):
                    self._log(f"Verbose errors at {url}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((url, "Verbose Error"))
            except Exception as e:
                if self.verbose:
                    self._log(f"Logging check error: {str(e)}", "debug")

        threads = []
        for url in test_urls:
            t = threading.Thread(target=check_url, args=(url,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()

    def scan_ssrf(self):
        self._log("Checking for SSRF...", "info")
        test_urls = [f"{self.base_url}/fetch?url=", f"{self.base_url}/proxy?url="]
        
        def test_ssrf(url, payload):
            try:
                r = self.session.get(url + quote(payload), timeout=10)
                if "root:" in r.text:
                    self._log(f"Potential SSRF at {url}", "success")
                    with self.lock:
                        self.vulnerabilities.append((url, "SSRF"))
            except Exception as e:
                if self.verbose:
                    self._log(f"SSRF check error: {str(e)}", "debug")

        threads = []
        for url in test_urls:
            for payload in SSRF_PAYLOADS:
                t = threading.Thread(target=test_ssrf, args=(url, payload))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()

    def check_dom_xss(self):
        self._log("Checking for DOM-based XSS...", "info")
        try:
            r = self.session.get(self.base_url, timeout=10)
            dom_keywords = [r"document\.location", r"document\.URL", r"document\.write", 
                          r"location\.hash", r"eval\(", "innerHTML"]
            for keyword in dom_keywords:
                if keyword in r.text:
                    self._log(f"DOM XSS indicator found: {keyword}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((self.base_url, f"DOM XSS Pattern: {keyword}"))
        except Exception as e:
            if self.verbose:
                self._log(f"DOM XSS check error: {str(e)}", "debug")

    def check_open_redirects(self):
        self._log("Checking for Open Redirects...", "info")
        test_urls = [f"{self.base_url}/redirect?url=http://evil.com", f"{self.base_url}/?next=http://evil.com"]
        for url in test_urls:
            try:
                r = self.session.get(url, allow_redirects=False, timeout=5)
                if 'Location' in r.headers and 'evil.com' in r.headers['Location']:
                    self._log(f"Potential open redirect: {url}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((url, "Open Redirect"))
            except Exception as e:
                if self.verbose:
                    self._log(f"Open redirect check error: {str(e)}", "debug")

    def check_cors(self):
        self._log("Checking for CORS misconfiguration...", "info")
        try:
            headers = {
                "Origin": "http://evil.com"
            }
            r = self.session.get(self.base_url, headers=headers, timeout=5)
            if "Access-Control-Allow-Origin" in r.headers and r.headers["Access-Control-Allow-Origin"] == "*":
                self._log("Wildcard CORS header detected", "warning")
                with self.lock:
                    self.vulnerabilities.append((self.base_url, "Wildcard CORS Misconfiguration"))
        except Exception as e:
            if self.verbose:
                self._log(f"CORS check error: {str(e)}", "debug")

    def check_rce(self):
        self._log("Checking for Remote Code Execution (RCE)...", "info")
        test_urls = [f"{self.base_url}/ping?host=127.0.0.1"]
        payloads = ["127.0.0.1;cat /etc/passwd", "127.0.0.1 && whoami"]
        
        def test_rce(url, payload):
            try:
                r = self.session.get(url.replace("127.0.0.1", quote(payload)), timeout=5)
                if "root:" in r.text or "uid=" in r.text:
                    self._log(f"Potential RCE at {url}", "warning")
                    with self.lock:
                        self.vulnerabilities.append((url, "Remote Code Execution"))
            except Exception as e:
                if self.verbose:
                    self._log(f"RCE check error: {str(e)}", "debug")

        threads = []
        for url in test_urls:
            for payload in payloads:
                t = threading.Thread(target=test_rce, args=(url, payload))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()

    def check_cloud_metadata(self):
        self._log("Checking for Cloud Metadata Exposure...", "info")
        try:
            r = self.session.get(f"{self.base_url}/latest/meta-data/", timeout=5)
            if any(key in r.text.lower() for key in ["ami", "instance", "hostname"]):
                self._log("Cloud metadata accessible!", "warning")
                with self.lock:
                    self.vulnerabilities.append((self.base_url + "/latest/meta-data/", "Cloud Metadata Exposure"))
        except Exception as e:
            if self.verbose:
                self._log(f"Cloud metadata check error: {str(e)}", "debug")

    def scan_all(self):
        self._log("Running full comprehensive scan...", "info")
        self.check_access_control()
        self.check_crypto()
        self.scan_injection()
        self.check_misconfig()
        self.check_components()
        self.check_auth()
        self.check_integrity()
        self.check_logging()
        self.scan_ssrf()
        self.check_dom_xss()
        self.check_open_redirects()
        self.check_cors()
        self.check_rce()
        self.check_cloud_metadata()

    def show_report(self):
        if not self.vulnerabilities:
            self._log("No vulnerabilities found", "success")
        else:
            # Group vulnerabilities by type
            vuln_groups = {}
            for url, issue in self.vulnerabilities:
                if issue not in vuln_groups:
                    vuln_groups[issue] = []
                vuln_groups[issue].append(url)

            # Prepare report text
            report_lines = [
                "=== Vulnerability Scan Report ===",
                f"Target: {self.base_url}",
                f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ]

            if self.tech_stack:
                report_lines.append("Detected Technologies:")
                for tech in self.tech_stack:
                    report_lines.append(f"- {tech}")
                report_lines.append("")

            report_lines.append("Vulnerability Findings:\n")

            # Add vulnerabilities in order of severity
            for issue, urls in vuln_groups.items():
                severity = VULN_SEVERITY.get(issue, "Medium")
                owasp_category = self._get_owasp_category(issue)
                
                report_lines.append(f"== {owasp_category}: {issue} ({severity}) ==")
                for url in urls:
                    report_lines.append(f"URL: {url}")
                    report_lines.append(f"Description: {self._get_vuln_description(issue)}")
                    report_lines.append(f"PoC: {self._get_poc_command(issue, url)}")
                    report_lines.append("")

            # Print to console
            print("\n".join(report_lines))

            # Save to file option
            save = input("\nWould you like to save the results? (y/n): ").strip().lower()
            if save == 'y':
                name = input("Enter filename (without extension): ").strip()
                try:
                    with open(f"{name}.txt", 'w') as f:
                        f.write("\n".join(report_lines))
                    self._log(f"Report saved as {name}.txt", "success")
                except Exception as e:
                    self._log(f"Error saving report: {e}", "error")

    def prompt_continue(self):
        while True:
            choice = input("\nWould you like to: \n[1] Return to main menu\n[2] Exit\n\nEnter your choice: ").strip()
            if choice == '1':
                self.vulnerabilities = []  # Clear previous results
                return True
            elif choice == '2':
                return False
            else:
                print("Invalid choice. Please enter 1 or 2")

    def _get_owasp_category(self, issue):
        mapping = {
            "Unencrypted HTTP": "A02",
            "Broken Access Control": "A01",
            "SQL Injection": "A03",
            "XSS": "A03",
            "SSRF": "A10",
            "Misconfiguration": "A05",
            "Wildcard CORS Misconfiguration": "A07",
            "Remote Code Execution": "A08",
            "Cloud Metadata Exposure": "A06",
            "DOM XSS Pattern": "A03",
            "Open Redirect": "A01",
            "Verbose Error": "A09",
            "Mixed Content": "A02",
            "Possible vulnerable jQuery": "A06"
        }
        return mapping.get(issue, "A11: Other")

    def _get_vuln_description(self, issue):
        descriptions = {
            "Unencrypted HTTP": "Website is not using HTTPS",
            "Broken Access Control": "Unauthorized access to restricted resource",
            "SQL Injection": "Potential SQL injection vulnerability",
            "XSS": "Potential Cross-Site Scripting vulnerability",
            "SSRF": "Potential Server-Side Request Forgery vulnerability",
            "Misconfiguration": "Sensitive information exposed through misconfiguration",
            "Wildcard CORS Misconfiguration": "CORS policy allows requests from any origin",
            "Remote Code Execution": "Potential remote code execution vulnerability",
            "Cloud Metadata Exposure": "Cloud instance metadata is accessible",
            "DOM XSS Pattern": "DOM-based XSS patterns detected in source code",
            "Open Redirect": "Open redirect vulnerability detected",
            "Verbose Error": "Verbose error messages may reveal sensitive information",
            "Mixed Content": "Mixed HTTP/HTTPS content detected",
            "Possible vulnerable jQuery": "Outdated or vulnerable jQuery version detected"
        }
        return descriptions.get(issue, "Potential security vulnerability")

    def _get_poc_command(self, issue, url):
        if issue == "Unencrypted HTTP":
            return f"curl -I '{url}'"
        elif issue == "Broken Access Control":
            return f"curl -X GET '{url}'"
        elif issue in ["SQL Injection", "XSS"]:
            return f"curl -X GET '{url}'"
        elif issue == "Verbose Error":
            return f"curl -X GET '{url}'"
        else:
            return f"Visit {url} in browser or test with curl"

if __name__ == "__main__":
    try:
        # Clear terminal again right before showing banner
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print(f"{Fore.MAGENTA}=== UNIQUE Vulnerability Scanner ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}Combines OWASP Vulnerability Assessment with Smart Detection{Style.RESET_ALL}\n")

        name = input("What name would you like to give this scan session?: ").strip()
        verbose_opt = input("Enable verbose output? (y/n): ").strip().lower() == 'y'
        target_url = input("Enter target URL: ").strip()

        scanner = UNIQUEScanner(target_url, verbose=verbose_opt)
        scanner.show_banner()

        if scanner.check_availability():
            while True:
                choices = scanner.show_scan_menu()
                if choices is None:  # User selected Exit (0)
                    break
                    
                if scanner.run_selected_scans(choices):
                    print(f"{Fore.GREEN}\n[+] Scan session: {name}{Style.RESET_ALL}")
                    scanner.show_report()
                
                if not scanner.prompt_continue():
                    break
                    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan aborted by user.{Style.RESET_ALL}")
        sys.exit(1)
