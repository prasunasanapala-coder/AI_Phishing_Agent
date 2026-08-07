import re
from urllib.parse import urlparse


def extract_iocs(email):
    """
    Extract Indicators of Compromise (IOCs) from a parsed email.

    Returns:
    {
        "emails": [],
        "urls": [],
        "domains": [],
        "ips": [],
        "attachments": []
    }
    """

    iocs = {
        "emails": [],
        "urls": [],
        "domains": [],
        "ips": [],
        "attachments": []
    }

    # -------------------------------------------------
    # Combine searchable text
    # -------------------------------------------------

    text = " ".join([
        email.get("sender", ""),
        email.get("recipient", ""),
        email.get("body", ""),
        email.get("html", "")
    ])

    # -------------------------------------------------
    # Email Addresses
    # -------------------------------------------------

    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

    emails = re.findall(email_pattern, text)

    iocs["emails"] = sorted(set(emails))

    # -------------------------------------------------
    # URLs
    # -------------------------------------------------

    urls = email.get("urls", [])

    iocs["urls"] = sorted(set(urls))

    # -------------------------------------------------
    # Domains
    # -------------------------------------------------

    domains = []

    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()

            if domain.startswith("www."):
                domain = domain[4:]

            domains.append(domain)

        except Exception:
            pass

    iocs["domains"] = sorted(set(domains))

    # -------------------------------------------------
    # IP Addresses
    # -------------------------------------------------

    ip_pattern = (
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"\b"
    )

    ips = re.findall(ip_pattern, text)

    iocs["ips"] = sorted(set(ips))

    # -------------------------------------------------
    # Attachments
    # -------------------------------------------------

    attachments = email.get("attachments", [])

    iocs["attachments"] = sorted(set(attachments))

    return iocs