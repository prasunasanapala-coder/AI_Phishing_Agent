import re


def analyze_headers(msg):
    """
    Analyze important email headers.
    """

    results = {
        "spf": "Not Found",
        "dkim": "Not Found",
        "dmarc": "Not Found",
        "reply_to": None,
        "from": None,
        "return_path": None,
        "message_id": None,
        "received_count": 0,
        "findings": [],
        "risk_score": 0,
    }

    # Basic headers
    results["from"] = msg.get("From")
    results["reply_to"] = msg.get("Reply-To")
    results["return_path"] = msg.get("Return-Path")
    results["message_id"] = msg.get("Message-ID")

    # SPF
    auth = msg.get("Authentication-Results", "")

    if "spf=pass" in auth.lower():
        results["spf"] = "PASS"

    elif "spf=fail" in auth.lower():
        results["spf"] = "FAIL"
        results["risk_score"] += 20
        results["findings"].append("SPF validation failed")

    # DKIM
    if "dkim=pass" in auth.lower():
        results["dkim"] = "PASS"

    elif "dkim=fail" in auth.lower():
        results["dkim"] = "FAIL"
        results["risk_score"] += 20
        results["findings"].append("DKIM validation failed")

    # DMARC
    if "dmarc=pass" in auth.lower():
        results["dmarc"] = "PASS"

    elif "dmarc=fail" in auth.lower():
        results["dmarc"] = "FAIL"
        results["risk_score"] += 20
        results["findings"].append("DMARC validation failed")

    # Reply-To mismatch
    if (
        results["reply_to"]
        and results["from"]
        and results["reply_to"] != results["from"]
    ):
        results["risk_score"] += 15
        results["findings"].append("Reply-To differs from From address")

    # Count Received headers
    received = msg.get_all("Received", [])

    results["received_count"] = len(received)

    return results