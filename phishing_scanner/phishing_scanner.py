import requests
import tldextract
import re
from urllib.parse import urlparse

class PhishingScanner:
    def __init__(self):
        # List of known phishing indicators
        self.suspicious_keywords = ['login', 'account', 'verify', 'banking', 'paypal', 'ebay', 'amazon']
        self.shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd']
        self.known_phishing_domains = self.load_known_phishing_domains()
        
    def load_known_phishing_domains(self):
        # In a real implementation, you would load this from a database or API
        return ['phishingsite.com', 'bad-url.org', 'fake-login.net']
    
    def scan_url(self, url):
        results = {
            'url': url,
            'is_phishing': False,
            'warnings': [],
            'details': {}
        }
        
        # Check 1: URL structure analysis
        self.check_url_structure(url, results)
        
        # Check 2: Domain analysis
        self.check_domain(url, results)
        
        # Check 3: Check against known phishing domains
        self.check_known_phishing(url, results)
        
        # Check 4: Check for URL shortening services
        self.check_shortened_url(url, results)
        
        # Check 5: Check for suspicious keywords
        self.check_suspicious_keywords(url, results)
        
        # Check 6: Check for IP address in URL
        self.check_ip_address(url, results)
        
        # Check 7: Check for @ symbol in URL
        self.check_at_symbol(url, results)
        
        # Check 8: Check for HTTPS
        self.check_https(url, results)
        
        # Determine if phishing based on warnings
        if len(results['warnings']) > 2:  # Threshold can be adjusted
            results['is_phishing'] = True
            
        return results
    
    def check_url_structure(self, url, results):
        # Check for excessive subdomains
        parsed = tldextract.extract(url)
        if len(parsed.subdomain.split('.')) > 3:
            results['warnings'].append("Excessive subdomains detected")
            results['details']['subdomains'] = parsed.subdomain
    
    def check_domain(self, url, results):
        # Check for domain impersonation (e.g., paypal-security.com vs paypal.com)
        parsed = tldextract.extract(url)
        domain = f"{parsed.domain}.{parsed.suffix}"
        
        popular_domains = ['paypal', 'ebay', 'amazon', 'bankofamerica', 'wellsfargo', 'chase']
        
        for legit_domain in popular_domains:
            if legit_domain in domain and domain != legit_domain + '.' + parsed.suffix:
                results['warnings'].append(f"Possible domain impersonation: {domain} looks like {legit_domain}")
                results['details']['impersonation'] = {
                    'detected': domain,
                    'possible_original': legit_domain + '.' + parsed.suffix
                }
    
    def check_known_phishing(self, url, results):
        parsed = tldextract.extract(url)
        domain = f"{parsed.domain}.{parsed.suffix}"
        
        if domain in self.known_phishing_domains:
            results['warnings'].append("Domain matches known phishing site")
            results['details']['known_phishing'] = True
            results['is_phishing'] = True
    
    def check_shortened_url(self, url, results):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        for service in self.shortening_services:
            if service in domain:
                results['warnings'].append(f"URL uses shortening service: {service}")
                results['details']['shortened'] = True
                break
    
    def check_suspicious_keywords(self, url, results):
        url_lower = url.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                results['warnings'].append(f"Suspicious keyword in URL: {keyword}")
                results['details']['suspicious_keywords'] = results['details'].get('suspicious_keywords', []) + [keyword]
    
    def check_ip_address(self, url, results):
        # Check if URL contains an IP address directly
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            results['warnings'].append("URL contains IP address instead of domain name")
            results['details']['contains_ip'] = True
    
    def check_at_symbol(self, url, results):
        # Check for @ symbol which can be used to hide real domain
        if '@' in url:
            results['warnings'].append("URL contains '@' symbol which can hide real domain")
            results['details']['at_symbol'] = True
    
    def check_https(self, url, results):
        # Check if URL uses HTTPS
        if not url.lower().startswith('https://'):
            results['warnings'].append("URL does not use HTTPS (secure connection)")
            results['details']['https'] = False
        else:
            results['details']['https'] = True

def display_results(result):
    """Display the scan results in a user-friendly format"""
    print("\n" + "="*50)
    print(f"Scanning Results for: {result['url']}")
    print("="*50)
    
    if result['is_phishing']:
        print("\n🚨 WARNING: PHISHING LINK DETECTED 🚨")
    else:
        print("\n✅ No clear phishing indicators found")
    
    if result['warnings']:
        print("\n⚠️ Detected Warnings:")
        for warning in result['warnings']:
            print(f"- {warning}")
    
    print("\n🔍 Detailed Analysis:")
    for key, value in result['details'].items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    
    print("\n" + "="*50)

def main():
    print("""
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    """)
    print("Welcome to Phishing Link Scanner")
    print("Enter a URL to check if it's a phishing attempt (or 'q' to quit)\n")
    
    scanner = PhishingScanner()
    
    while True:
        url = input("\nEnter URL to scan: ").strip()
        
        if url.lower() == 'q':
            print("\nThank you for using Phishing Link Scanner!")
            break
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            result = scanner.scan_url(url)
            display_results(result)
        except Exception as e:
            print(f"\nError scanning URL: {e}")
            print("Please enter a valid URL")

if __name__ == "__main__":
    main()