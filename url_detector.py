import re
from urllib.parse import urlparse
import requests

class URLDetector:
    def __init__(self):
        # Common spam/phishing indicators
        self.suspicious_keywords = [
            # Account/Security related
            'login', 'signin', 'verify', 'account', 'suspended', 'confirm', 'update',
            'secure', 'security', 'authenticate', 'validation', 'restore', 'recover',
            'unlock', 'reactivate', 'blocked', 'unusual', 'activity', 'alert',
            # Financial/Banking
            'banking', 'paypal', 'payment', 'billing', 'invoice', 'refund',
            'transaction', 'wallet', 'crypto', 'bitcoin', 'transfer',
            # Brand impersonation
            'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
            'ebay', 'instagram', 'whatsapp', 'fedex', 'dhl', 'usps',
            # Credentials
            'password', 'credential', 'username', 'ssn', 'social-security',
            # Urgency/Scarcity
            'urgent', 'immediately', 'action-required', 'expire', 'expires',
            'limited', 'hurry', 'act-now', 'deadline', 'suspended',
            # Rewards/Prizes
            'winner', 'prize', 'reward', 'congratulations', 'selected',
            'lucky', 'won', 'claim', 'redeem', 'bonus',
            # Free offers
            'free', 'gift', 'offer', 'deal', 'discount', 'coupon',
            'promotion', 'giveaway', 'trial', 'sample',
            # Clickbait
            'click', 'here', 'now', 'today', 'download', 'install',
            'activate', 'enable', 'access', 'unlock',
            # Suspicious actions
            'webscr', 'cmd=', 'signin', 'account-update', 'verify-account',
            'confirm-identity', 'reset-password', 'customer-service'
        ]
        
        self.suspicious_tlds = [
            # Free/Spam TLDs
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.work',
            # Suspicious commercial
            '.xyz', '.click', '.link', '.download', '.stream', '.loan',
            '.win', '.bid', '.racing', '.party', '.review', '.trade',
            '.webcam', '.date', '.faith', '.science', '.accountant',
            # Country codes often abused
            '.ru', '.cn', '.br', '.in', '.pk', '.ng', '.ro',
            # Generic suspicious
            '.cc', '.info', '.biz', '.ws', '.mobi', '.name',
            '.pro', '.tel', '.asia', '.jobs', '.travel'
        ]
        
        self.legitimate_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'github.com', 'stackoverflow.com', 'microsoft.com', 'apple.com'
        ]
    
    def analyze_url(self, url):
        """Analyze URL for spam/malicious indicators"""
        risk_score = 0
        warnings = []
        details = []
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for IP address instead of domain
        ip_match = re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', domain)
        if ip_match:
            risk_score += 50
            warnings.append('Uses IP address instead of domain name - UNAUTHORIZED')
            
            # Check for private/local IP ranges (extra dangerous)
            octets = [int(ip_match.group(i)) for i in range(1, 5)]
            if (octets[0] == 10 or  # 10.0.0.0/8
                (octets[0] == 172 and 16 <= octets[1] <= 31) or  # 172.16.0.0/12
                (octets[0] == 192 and octets[1] == 168) or  # 192.168.0.0/16
                (octets[0] == 127)):  # 127.0.0.0/8 (localhost)
                risk_score += 30
                warnings.append('Private/Local IP address detected - HIGHLY SUSPICIOUS')
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                risk_score += 30
                warnings.append(f'Suspicious top-level domain: {tld}')
                break
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_score += 20
            warnings.append(f'Excessive subdomains ({subdomain_count})')
        
        # Check for suspicious keywords
        full_url = url.lower()
        found_keywords = [kw for kw in self.suspicious_keywords if kw in full_url]
        if found_keywords:
            risk_score += len(found_keywords) * 10
            warnings.append(f'Suspicious keywords found: {", ".join(found_keywords[:3])}')
            # Extra penalty for multiple keywords
            if len(found_keywords) >= 2:
                risk_score += 20
                warnings.append('Multiple phishing keywords detected')
        
        # Check for URL shorteners (potential obfuscation)
        shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'shorte.st',
            'bc.vc', 'soo.gd', 'clicky.me', 's2r.co', 'shrtco.de',
            'cutt.ly', 'rb.gy', 'short.io', 'tiny.cc', 'v.gd',
            'tr.im', 'cli.gs', 'u.nu', 'x.co', 'scrnch.me'
        ]
        if any(short in domain for short in shorteners):
            risk_score += 70
            warnings.append('URL shortener detected (hides real destination - DANGEROUS)')
        
        # Check for homograph attacks (lookalike characters)
        if self._has_homograph_chars(domain):
            risk_score += 35
            warnings.append('Contains lookalike characters (homograph attack)')
        
        # Check URL length
        if len(url) > 150:
            risk_score += 10
            warnings.append('Unusually long URL')
        
        # Check for @ symbol (can hide real domain)
        if '@' in url:
            risk_score += 40
            warnings.append('Contains @ symbol (domain obfuscation)')
        
        # Check for excessive hyphens
        if domain.count('-') > 3:
            risk_score += 15
            warnings.append('Excessive hyphens in domain')
        
        # Check if it's an IP-based URL for unauthorized status
        is_ip_based = bool(ip_match)
        
        # Determine threat level
        if is_ip_based:
            threat_level = 'UNAUTHORIZED'
            status = 'unauthorized'
        elif risk_score >= 70:
            threat_level = 'HIGH'
            status = 'dangerous'
        elif risk_score >= 40:
            threat_level = 'MEDIUM'
            status = 'suspicious'
        elif risk_score >= 20:
            threat_level = 'LOW'
            status = 'caution'
        else:
            threat_level = 'SAFE'
            status = 'safe'
        
        return {
            'url': url,
            'status': status,
            'threat_level': threat_level,
            'risk_score': min(risk_score, 100),
            'warnings': warnings,
            'domain': domain,
            'is_safe': risk_score < 20
        }
    
    def _has_homograph_chars(self, text):
        """Check for non-ASCII characters that could be homograph attacks"""
        # Check for Cyrillic, Greek, or other lookalike characters
        suspicious_chars = [
            'а', 'е', 'о', 'р', 'с', 'у', 'х',  # Cyrillic
            'α', 'β', 'γ', 'ο', 'ρ', 'ν',  # Greek
        ]
        return any(char in text for char in suspicious_chars)
