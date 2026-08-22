from src.report.ioc_extractor import extract_iocs


def test_extract_email_addresses():
    email = {
        "sender": "attacker@example.com",
        "recipient": "victim@example.com",
        "body": "Contact security@evil.com for assistance.",
        "html": "",
        "urls": [],
        "attachments": [],
    }

    result = extract_iocs(email)

    assert result["emails"] == [
        "attacker@example.com",
        "security@evil.com",
        "victim@example.com",
    ]


def test_extract_urls():
    email = {
        "sender": "attacker@example.com",
        "recipient": "victim@example.com",
        "body": "Visit the link.",
        "html": "",
        "urls": [
            "https://example.com/login",
            "https://example.com/login",
        ],
        "attachments": [],
    }

    result = extract_iocs(email)

    assert result["urls"] == [
        "https://example.com/login"
    ]


def test_extract_domains():
    email = {
        "sender": "attacker@example.com",
        "recipient": "victim@example.com",
        "body": "",
        "html": "",
        "urls": [
            "https://www.example.com/login",
            "https://evil.com/verify",
        ],
        "attachments": [],
    }

    result = extract_iocs(email)

    assert result["domains"] == [
        "evil.com",
        "example.com",
    ]


def test_extract_ip_addresses():
    email = {
        "sender": "attacker@example.com",
        "recipient": "victim@example.com",
        "body": "Connect to 192.168.1.10 or 8.8.8.8.",
        "html": "",
        "urls": [],
        "attachments": [],
    }

    result = extract_iocs(email)

    assert result["ips"] == [
        "192.168.1.10",
        "8.8.8.8",
    ]


def test_extract_attachments():
    email = {
        "sender": "attacker@example.com",
        "recipient": "victim@example.com",
        "body": "",
        "html": "",
        "urls": [],
        "attachments": [
            "invoice.exe",
            "document.pdf",
            "invoice.exe",
        ],
    }

    result = extract_iocs(email)

    assert result["attachments"] == [
        "document.pdf",
        "invoice.exe",
    ]


def test_empty_email():
    email = {
        "sender": "",
        "recipient": "",
        "body": "",
        "html": "",
        "urls": [],
        "attachments": [],
    }

    result = extract_iocs(email)

    assert result["emails"] == []
    assert result["urls"] == []
    assert result["domains"] == []
    assert result["ips"] == []
    assert result["attachments"] == []