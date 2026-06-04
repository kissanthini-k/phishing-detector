import ipaddress
import re
from urllib.parse import urlparse

from virustotal import check_url as check_virustotal

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "bank",
    "paypal",
    "account",
    "confirm",
    "payment",
    "security",
    "ebay",
    "appleid",
    "signin",
]

SUSPICIOUS_TLDS = {"xyz", "tk", "ml", "cf", "ga", "gq", "cc", "pw"}

RISK_THRESHOLDS = {
    "Safe": range(0, 4),
    "Suspicious": range(4, 8),
    "Dangerous": range(8, 100),
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def parse_url(url: str):
    url = normalize_url(url)
    return urlparse(url)


def is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    if hostname.endswith("]") and hostname.startswith("["):
        hostname = hostname[1:-1]
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def length_check(url: str) -> tuple[int, str]:
    if len(url) > 100:
        return 3, "URL is very long, which is common for phishing URLs."
    if len(url) > 75:
        return 2, "URL length is above the typical threshold."
    if len(url) > 50:
        return 1, "URL is longer than average."
    return 0, "URL length is normal."


def ip_check(parsed) -> tuple[int, str]:
    host = parsed.hostname or ""
    if is_ip_address(host):
        return 3, "URL uses an IP address instead of a domain name."
    return 0, "URL hostname is not an IP address."


def https_check(parsed) -> tuple[int, str]:
    if parsed.scheme.lower() != "https":
        return 2, "URL does not use HTTPS. Secure sites should use HTTPS."
    return 0, "URL uses HTTPS."


def keyword_check(url: str) -> tuple[int, str]:
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if not hits:
        return 0, "No suspicious keywords found in the URL."

    score = min(len(hits), 3)
    reason = f"Found suspicious keyword(s): {', '.join(sorted(set(hits)))}."
    return score, reason


def subdomain_check(parsed) -> tuple[int, str]:
    host = parsed.hostname or ""
    if not host:
        return 0, "No hostname available to inspect for subdomains."
    parts = host.split(".")
    if len(parts) >= 4:
        return 2, "URL has many subdomains, which is often used by phishing scams."
    if len(parts) == 3:
        # Whitelist common www subdomain
        if parts[0].lower() == "www":
            return 0, "Subdomain count is normal."
        return 1, "URL has an extra subdomain component."
    return 0, "Subdomain count is normal."


def tld_check(parsed) -> tuple[int, str]:
    host = parsed.hostname or ""
    if not host or "." not in host:
        return 0, "No valid TLD found."
    tld = host.rsplit(".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        return 2, f"Top-level domain '.{tld}' is commonly abused by malicious actors."
    return 0, "Top-level domain looks normal."


def random_pattern_check(parsed) -> tuple[int, str]:
    host = parsed.hostname or ""
    path = parsed.path or ""
    hyphen_count = host.count("-")
    digits = sum(c.isdigit() for c in host + path)
    long_segment = max((len(segment) for segment in re.split(r"[./?_=-]", host + path) if segment), default=0)
    if hyphen_count > 3 or digits > 6 or long_segment > 18:
        details = []
        if hyphen_count > 3:
            details.append("many hyphens")
        if digits > 6:
            details.append("excessive digits")
        if long_segment > 18:
            details.append("long random-looking segment")
        return 2, f"Suspicious structure detected: {', '.join(details)}."
    return 0, "Hostname and path structure look normal."


def analyze_url(url: str, vt_api_key: str | None = None) -> dict:
    normalized = normalize_url(url)
    parsed = parse_url(normalized)

    checks = [
        length_check(normalized),
        ip_check(parsed),
        https_check(parsed),
        keyword_check(normalized),
        subdomain_check(parsed),
        tld_check(parsed),
        random_pattern_check(parsed),
    ]

    details = [
        {"name": name, "score": score, "reason": reason}
        for name, (score, reason) in zip(
            [
                "Length",
                "IP address",
                "HTTPS",
                "Keywords",
                "Subdomains",
                "TLD",
                "Random pattern",
            ],
            checks,
        )
    ]

    total_score = sum(item["score"] for item in details)
    level = next((level for level, rng in RISK_THRESHOLDS.items() if total_score in rng), "Dangerous")
    # Confidence should be high for Safe, medium for Suspicious, and high for Dangerous
    if level == "Safe":
        confidence = 95  # High confidence in safety
    elif level == "Dangerous":
        confidence = 90  # High confidence in danger
    else:  # Suspicious
        confidence = 60  # Medium confidence for uncertain cases

    result = {
        "url": url,
        "normalized_url": normalized,
        "score": total_score,
        "level": level,
        "confidence": confidence,
        "details": details,
    }

    if vt_api_key:
        vt = check_virustotal(normalized, vt_api_key)
        result["virustotal"] = vt
        
        if vt["success"] and vt["positives"] > 0:
            # Scoring based on number of positives
            if vt["positives"] >= 10:
                vt_score = 10
            elif vt["positives"] >= 4:
                vt_score = 5
            else:  # 1-3 positives
                vt_score = 2
            
            result["score"] += vt_score
            result["level"] = "Dangerous" if vt_score >= 5 else result["level"]
            result["details"].append(
                {
                    "name": "VirusTotal",
                    "score": vt_score,
                    "reason": vt["message"],
                }
            )
            # Boost confidence for dangerous detections
            if vt_score >= 5:
                result["confidence"] = min(100, result["confidence"] + 15)

    return result



