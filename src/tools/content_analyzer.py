import re

SUSPICIOUS_KEYWORDS = {
    "urgent": 15,
    "immediately": 15,
    "verify": 10,
    "password": 15,
    "login": 10,
    "account": 10,
    "suspended": 20,
    "click": 10,
    "confirm": 10,
    "payment": 15,
    "invoice": 10,
    "bank": 15,
    "security": 10,
    "reset": 15
}


def analyze_content(text):
    result = {
        "risk_score": 0,
        "findings": []
    }

    if not text:
        result["findings"].append("Email body is empty.")
        return result

    content = text.lower()

    for keyword, score in SUSPICIOUS_KEYWORDS.items():
        if re.search(rf"\b{re.escape(keyword)}\b", content):
            result["risk_score"] += score
            result["findings"].append(
                f"Contains suspicious keyword: '{keyword}'"
            )

    if "click the link" in content:
        result["risk_score"] += 20
        result["findings"].append(
            "Encourages the recipient to click a link."
        )

    if "verify your account" in content:
        result["risk_score"] += 25
        result["findings"].append(
            "Requests account verification."
        )

    if "unusual activity" in content:
        result["risk_score"] += 20
        result["findings"].append(
            "Claims unusual account activity."
        )

    return result