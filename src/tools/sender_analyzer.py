import re

# Common free email providers
FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "icloud.com",
    "aol.com",
    "proton.me",
    "protonmail.com"
}

# Well-known brands that attackers often impersonate
KNOWN_BRANDS = [
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "adobe",
    "bank"
]


def analyze_sender(sender):
    """
    Analyze the sender email address for basic phishing indicators.
    """

    result = {
        "email": "",
        "domain": "",
        "is_free_provider": False,
        "lookalike_brand": False,
        "risk_score": 0,
        "findings": []
    }

    # Extract email address
    match = re.search(r'[\w\.-]+@[\w\.-]+', sender)

    if not match:
        result["findings"].append("Unable to extract sender email.")
        result["risk_score"] += 20
        return result

    email = match.group(0).lower()
    domain = email.split("@")[1]

    result["email"] = email
    result["domain"] = domain

    # Check free email provider
    if domain in FREE_EMAIL_PROVIDERS:
        result["is_free_provider"] = True
        result["risk_score"] += 10
        result["findings"].append(
            "Sender uses a free email provider."
        )

    # Very simple lookalike detection
    normalized = domain.replace("0", "o").replace("1", "l")

    for brand in KNOWN_BRANDS:
        if brand in normalized and brand not in domain:
            result["lookalike_brand"] = True
            result["risk_score"] += 40
            result["findings"].append(
                f"Possible lookalike domain for '{brand}'."
            )
            break

    return result