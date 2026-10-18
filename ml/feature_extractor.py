import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "security", "update", "banking", "authenticate",
    "password", "confirm", "wallet", "paypal", "appleid", "support", "billing",
    "signin", "recover", "suspicious", "free-gift", "secure", "validate"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "tiny.cc"
}

HIGH_RISK_TLDS = {
    ".xyz": 0.8, ".top": 0.9, ".club": 0.7, ".work": 0.8, ".click": 0.9,
    ".buzz": 0.8, ".tk": 0.9, ".ml": 0.9, ".ga": 0.9, ".cf": 0.9,
    ".gq": 0.9, ".fit": 0.7, ".rest": 0.7, ".icu": 0.85
}

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect randomized/obfuscated tokens."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)

class URLFeatureExtractor:
    FEATURE_NAMES = [
        "url_length",
        "hostname_length",
        "path_length",
        "count_dots",
        "count_hyphens",
        "count_at",
        "count_question",
        "count_equal",
        "count_percent",
        "count_subdomains",
        "is_ip_address",
        "has_https",
        "shannon_entropy",
        "suspicious_keywords_count",
        "is_url_shortener",
        "digit_ratio",
        "has_port",
        "tld_risk_score"
    ]

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        """Extracts 18 lexical, domain, and structural features from a URL."""
        clean_url = url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "http://" + clean_url

        parsed = urlparse(clean_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        # 1. URL Length
        url_length = len(url)

        # 2. Hostname & Path Length
        hostname_len = len(hostname)
        path_len = len(path)

        # 3. Special Characters
        count_dots = url.count(".")
        count_hyphens = url.count("-")
        count_at = 1 if "@" in url else 0
        count_question = url.count("?")
        count_equal = url.count("=")
        count_percent = url.count("%")

        # 4. Subdomains
        host_parts = hostname.split(".")
        count_subdomains = max(0, len(host_parts) - 2)

        # 5. IP Address Check
        is_ip = 1 if IP_REGEX.match(hostname) else 0

        # 6. HTTPS
        has_https = 1 if parsed.scheme == "https" else 0

        # 7. Shannon Entropy
        entropy = calculate_shannon_entropy(url)

        # 8. Suspicious Keywords
        url_lower = url.lower()
        kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

        # 9. URL Shortener
        is_shortener = 1 if hostname in SHORTENER_DOMAINS else 0

        # 10. Digit Ratio
        digits_count = sum(c.isdigit() for c in url)
        digit_ratio = round(digits_count / max(len(url), 1), 4)

        # 11. Port Check
        has_port = 1 if parsed.port and parsed.port not in [80, 443] else 0

        # 12. TLD Risk
        tld_risk = 0.1
        for tld, risk in HIGH_RISK_TLDS.items():
            if hostname.endswith(tld):
                tld_risk = risk
                break
        if hostname.endswith(".gov") or hostname.endswith(".edu"):
            tld_risk = 0.0

        return {
            "url_length": url_length,
            "hostname_length": hostname_len,
            "path_length": path_len,
            "count_dots": count_dots,
            "count_hyphens": count_hyphens,
            "count_at": count_at,
            "count_question": count_question,
            "count_equal": count_equal,
            "count_percent": count_percent,
            "count_subdomains": count_subdomains,
            "is_ip_address": is_ip,
            "has_https": has_https,
            "shannon_entropy": entropy,
            "suspicious_keywords_count": kw_count,
            "is_url_shortener": is_shortener,
            "digit_ratio": digit_ratio,
            "has_port": has_port,
            "tld_risk_score": tld_risk
        }

    @classmethod
    def to_feature_vector(cls, features_dict: Dict[str, Any]) -> List[float]:
        return [float(features_dict[name]) for name in cls.FEATURE_NAMES]
