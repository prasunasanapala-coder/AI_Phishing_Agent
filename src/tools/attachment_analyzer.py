import os

HIGH_RISK = {
    ".exe",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".scr",
    ".ps1"
}

MEDIUM_RISK = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".docm",
    ".xlsm",
    ".pptm"
}


def analyze_attachments(attachments):
    result = {
        "risk_score": 0,
        "findings": []
    }

    if not attachments:
        result["findings"].append("No attachments found.")
        return result

    for attachment in attachments:

        filename = attachment.lower()
        _, ext = os.path.splitext(filename)

        # Double extension
        parts = filename.split(".")
        if len(parts) > 2:
            result["risk_score"] += 20
            result["findings"].append(
                f"Double extension detected: {attachment}"
            )

        # High-risk extension
        if ext in HIGH_RISK:
            result["risk_score"] += 50
            result["findings"].append(
                f"High-risk attachment: {attachment}"
            )

        # Medium-risk extension
        elif ext in MEDIUM_RISK:
            result["risk_score"] += 25
            result["findings"].append(
                f"Potentially risky attachment: {attachment}"
            )

    return result