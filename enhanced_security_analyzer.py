import re
import requests
import os
from urllib.parse import urljoin, urlparse
from datetime import datetime

class WebSecurityAnalyzer:
    def __init__(self, target_url, max_depth=2):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.visited = set()
        self.found_hashes = set()
        self.found_secrets = set()
        self.log_file = self.get_next_log_filename()

    def get_next_log_filename(self):
        """Generate the next numbered log file name"""
        base_name = "priority_targets"
        counter = 1
        
        while True:
            filename = f"{base_name}{counter}.txt"
            if not os.path.exists(filename):
                return filename
            counter += 1

    def log_event(self, alert_type, data):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{timestamp}] {alert_type}\n")
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
                f.write(f"{'='*50}\n\n")
        except Exception as e:
            print(f"Logging error: {e}")

    def check_hidden_files(self):
        """Scan for sensitive configuration files"""
        print(f"\n[*] Scanning for exposed files...")
        paths = ['.env', '.git/config', '.htaccess', 'config.php.bak', 'phpinfo.php']
        for path in paths:
            url = urljoin(self.target_url, path)
            try:
                res = self.session.get(url, timeout=3)
                if res.status_code == 200:
                    print(f"[!] Sensitive file exposed: {url}")
                    self.log_event("EXPOSED_FILE", {"url": url})
            except:
                continue

    def scan_content(self, html, url):
        """Scan for sensitive data patterns"""
        
        cloud_patterns = {
            'Supabase/JWT Key': r'eyJ[a-zA-Z0-9._-]{50,}',
            'Firebase API Key': r'AIza[0-9A-Za-z_-]{35}',
            'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
            'Generic Secret': r'(?:key|secret|token|auth)\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']'
        }

        hash_patterns = {
            'MD5': r'\b[a-fA-F0-9]{32}\b',
            'Bcrypt': r'\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}'
        }
        
        admin_keywords = ['admin', 'root', 'superuser', 'login', 'config', 'master']

        for label, pattern in cloud_patterns.items():
            matches = re.finditer(pattern, html)
            for m in matches:
                val = m.group(0) if label != 'Generic Secret' else m.group(1)
                if val.lower() not in ['access_token', 'null', 'undefined', 'true']:
                    if val not in self.found_secrets:
                        print(f"[!] Potential {label}: {url}")
                        self.found_secrets.add(val)
                        self.log_event(f"CLOUD_SECRET: {label}", {"source": url, "value": val})

        for h_type, pattern in hash_patterns.items():
            for match in re.finditer(pattern, html):
                found_hash = match.group()
                if found_hash not in self.found_hashes:
                    start, end = max(0, match.start()-50), min(len(html), match.end()+50)
                    context = html[start:end].lower()
                    is_admin = any(kw in context for kw in admin_keywords)
                    
                    self.found_hashes.add(found_hash)
                    if is_admin:
                        print(f"[!] Admin hash found: {url}")
                        self.log_event("ADMIN_HASH", {"source": url, "hash": found_hash, "context": context.strip()})

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited:
            return

        self.visited.add(url)
        print(f"[*] Depth {depth}: {url}")

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                self.scan_content(response.text, url)
                
                if depth < self.max_depth:
                    links = re.findall(r'(?:href|src)=["\']([^"\'\s]+)["\']', response.text)
                    for link in links:
                        full_url = urljoin(url, link).split('#')[0]
                        if urlparse(full_url).netloc == self.base_domain:
                            self.crawl(full_url, depth + 1)
        except Exception as e:
            pass

    def run(self):
        print(f"Security Audit: {self.target_url}")
        print(f"Output file: {self.log_file}")
        
        self.check_hidden_files()
        print(f"\n[*] Starting web crawl...")
        self.crawl(self.target_url)
        print(f"\n[*] Audit completed")
        print(f"[*] Results: {self.log_file}")
        print(f"[*] Pages scanned: {len(self.visited)}")
        print(f"[*] Secrets found: {len(self.found_secrets)}")
        print(f"[*] Hashes found: {len(self.found_hashes)}")

if __name__ == "__main__":
    # TARGET = input("Enter target URL: ").strip()
    # if not TARGET:
    #     print("Error: Target URL required")
    #     exit(1)
    
    TARGET = "https://rosymbo.co.ke/admin/index.php"
    scanner = WebSecurityAnalyzer(TARGET, max_depth=2)
    scanner.run()
