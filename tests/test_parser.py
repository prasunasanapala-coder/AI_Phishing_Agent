from io import BytesIO

from src.parser.parser import parse_email, extract_urls


def test_extract_urls():
    text = """
    Visit https://example.com/login
    or https://evil.com/verify.
    """

    result = extract_urls(text)

    assert result == [
        "https://example.com/login",
        "https://evil.com/verify"
    ]

def test_extract_urls_removes_trailing_punctuation():
    text = """
    Visit https://example.com/login.
    Then visit https://evil.com/verify,
    and finally https://test.com/account!
    """

    result = extract_urls(text)

    assert result == [
        "https://example.com/login",
        "https://evil.com/verify",
        "https://test.com/account",
    ]

def test_extract_urls_empty_text():
    result = extract_urls("")

    assert result == []


def test_parse_plain_text_email():
    eml = b"""\
From: sender@example.com
To: victim@example.com
Subject: Test Email
Date: Wed, 22 Jul 2026 09:30:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello,

Please visit https://example.com/login
for more information.
"""

    uploaded_file = BytesIO(eml)

    result = parse_email(uploaded_file)

    assert result["sender"] == "sender@example.com"
    assert result["recipient"] == "victim@example.com"
    assert result["subject"] == "Test Email"
    assert result["date"] == "Wed, 22 Jul 2026 09:30:00 +0000"

    assert "Hello" in result["body"]
    assert "https://example.com/login" in result["urls"]

    assert result["attachments"] == []


def test_parse_email_with_attachment():
    eml = b"""\
From: accounts@example.com
To: employee@example.com
Subject: Invoice
Date: Wed, 22 Jul 2026 09:30:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

Please review the attached invoice.

--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"

test attachment content

--BOUNDARY--
"""

    uploaded_file = BytesIO(eml)

    result = parse_email(uploaded_file)

    assert result["sender"] == "accounts@example.com"
    assert result["recipient"] == "employee@example.com"
    assert result["subject"] == "Invoice"

    assert "attached invoice" in result["body"]
    assert "invoice.exe" in result["attachments"]

    
def test_parse_html_email():
    eml = b"""\
From: security@example.com
To: employee@example.com
Subject: Security Notice
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Please <a href="https://example.com/verify">verify</a>
your account.</p>
</body>
</html>
"""

    uploaded_file = BytesIO(eml)

    result = parse_email(uploaded_file)

    assert result["sender"] == "security@example.com"
    assert result["recipient"] == "employee@example.com"
    assert result["subject"] == "Security Notice"

    assert result["html"] != ""
    assert "https://example.com/verify" in result["urls"]


def test_attachment_filename_is_sanitized():
    eml = b"""\
From: attacker@example.com
To: employee@example.com
Subject: Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset="utf-8"

Please see the attachment.

--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="../../invoice.exe"

test attachment

--BOUNDARY--
"""

    uploaded_file = BytesIO(eml)

    result = parse_email(uploaded_file)

    assert result["attachments"] == ["invoice.exe"]