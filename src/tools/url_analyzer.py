from urllib.parse import urlparse
import ipaddress

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "signin",
    "bank"
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly"
}


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url):
    result = {
        "url": url,
        "domain": "",
        "risk_score": 0,
        "findings": []
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        result["domain"] = domain

        # HTTP instead of HTTPS
        if parsed.scheme == "http":
            result["risk_score"] += 20
            result["findings"].append("Uses HTTP instead of HTTPS.")

        # IP address
        if is_ip_address(domain):
            result["risk_score"] += 40
            result["findings"].append("URL uses an IP address.")

        # URL shortener
        if domain in URL_SHORTENERS:
            result["risk_score"] += 30
            result["findings"].append("Uses a URL shortening service.")

        # Suspicious keywords
        url_lower = url.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                result["risk_score"] += 10
                result["findings"].append(
                    f"Contains keyword '{keyword}'."
                )

    except Exception as e:
        result["findings"].append(str(e))

    return result