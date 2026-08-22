from email.message import EmailMessage

from src.tools.header_analyzer import analyze_headers


def test_clean_headers():
    msg = EmailMessage()

    msg["From"] = "sender@example.com"
    msg["Reply-To"] = "sender@example.com"
    msg["Return-Path"] = "<sender@example.com>"
    msg["Authentication-Results"] = (
        "example.com; spf=pass; dkim=pass; dmarc=pass"
    )

    result = analyze_headers(msg)

    assert result["spf"] == "PASS"
    assert result["dkim"] == "PASS"
    assert result["dmarc"] == "PASS"
    assert result["risk_score"] == 0
    assert result["findings"] == []


def test_authentication_failures():
    msg = EmailMessage()

    msg["From"] = "attacker@example.com"
    msg["Authentication-Results"] = (
        "example.com; spf=fail; dkim=fail; dmarc=fail"
    )

    result = analyze_headers(msg)

    assert result["spf"] == "FAIL"
    assert result["dkim"] == "FAIL"
    assert result["dmarc"] == "FAIL"

    assert result["risk_score"] == 60

    assert "SPF validation failed" in result["findings"]
    assert "DKIM validation failed" in result["findings"]
    assert "DMARC validation failed" in result["findings"]


def test_missing_authentication_is_not_failure():
    msg = EmailMessage()

    msg["From"] = "sender@example.com"

    result = analyze_headers(msg)

    assert result["spf"] == "Not Found"
    assert result["dkim"] == "Not Found"
    assert result["dmarc"] == "Not Found"

    assert result["risk_score"] == 0
    assert result["findings"] == []


def test_reply_to_mismatch():
    msg = EmailMessage()

    msg["From"] = "security@example.com"
    msg["Reply-To"] = "attacker@evil.com"

    result = analyze_headers(msg)

    assert result["risk_score"] == 15
    assert "Reply-To differs from From address" in result["findings"]


def test_received_header_count():
    msg = EmailMessage()

    msg["Received"] = "mail1.example.com"
    msg["Received"] = "mail2.example.com"
    msg["Received"] = "mail3.example.com"

    result = analyze_headers(msg)

    assert result["received_count"] == 3