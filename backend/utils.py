"""
Utility functions for security analysis
Python 3.9 + Pydantic v2 Compatible
"""
import re
import socket
import ipaddress
import requests  # ← Added import for safe_request function
from urllib.parse import urlparse, parse_qs
from typing import List, Optional, Dict

# ← CRITICAL FIX: Import Indicator and RiskLevel from models
from backend.models import Indicator, RiskLevel
from backend.config import settings



def is_suspicious_url(url: str) -> List[str]:
    """Check URL for common phishing indicators"""
    indicators = []
    
    # Check for IP address instead of domain
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname and not hostname.replace('.', '').isdigit():
            try:
                ipaddress.ip_address(hostname)
                indicators.append("URL uses IP address instead of domain name")
            except ValueError:
                pass
    except:
        pass
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
    if any(url.lower().endswith(tld) for tld in suspicious_tlds):
        indicators.append("URL uses suspicious TLD")
    
    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'ow.ly', 'short.link']
    if any(s in url.lower() for s in shorteners):
        indicators.append("URL uses shortening service")
    
    # Check for excessive subdomains
    parsed = urlparse(url)
    if parsed.hostname:
        parts = parsed.hostname.split('.')
        if len(parts) > 4:
            indicators.append("URL has excessive subdomains (potential typosquatting)")
    
    # Check for @ symbol (credential harvesting trick)
    if '@' in url:
        indicators.append("URL contains @ symbol (may hide actual destination)")
    
    # Check for homograph attacks (simplified)
    if any(ord(c) > 127 for c in url):
        indicators.append("URL contains non-ASCII characters (potential homograph attack)")
    
    return indicators


def analyze_email_headers(headers: dict) -> List[Indicator]:
    """Analyze email headers for spoofing indicators"""
    indicators = []
    
    # Check SPF/DKIM/DMARC (simplified)
    if headers:
        received = headers.get('Received', '')
        if 'SPF=fail' in received or 'spf=fail' in received.lower():
            indicators.append(Indicator(
                name="SPF Check Failed",
                description="Sender Policy Framework validation failed",
                severity=RiskLevel.MEDIUM,
                evidence=received[:200]
            ))
    
    return indicators


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def safe_request(url: str, **kwargs) -> Optional[requests.Response]:
    """Make HTTP request with safety checks"""
    from backend.config import settings
    
    # Validate URL
    parsed = urlparse(url)
    if settings.BLOCK_INTERNAL_IPS and parsed.hostname:
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(parsed.hostname)
            if is_internal_ip(ip):
                print(f"⚠️  Blocked request to internal IP: {ip}")
                return None
        except:
            pass
    
    # Add safety headers
    headers = kwargs.pop('headers', {})
    headers['User-Agent'] = settings.USER_AGENT
    headers['Connection'] = 'close'
    
    try:
        response = requests.get(
            url, 
            timeout=settings.REQUEST_TIMEOUT,
            headers=headers,
            allow_redirects=True,
            **kwargs
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"⚠️  Request error: {e}")
        return None


def calculate_risk_score(indicators: List[Indicator], weights: dict = None) -> tuple:
    """Calculate overall risk score from indicators"""
    if weights is None:
        weights = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 1.0}
    
    if not indicators:
        return 0.0, RiskLevel.LOW
    
    total_weight = sum(weights.get(ind.severity.value, 0.1) for ind in indicators)
    normalized_score = min(total_weight / len(indicators), 1.0)
    
    if normalized_score >= 0.8:
        level = RiskLevel.CRITICAL
    elif normalized_score >= 0.5:
        level = RiskLevel.HIGH
    elif normalized_score >= 0.2:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
    
    return round(normalized_score, 2), level