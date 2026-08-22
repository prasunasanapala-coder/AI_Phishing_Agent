import re
from email import policy
from email.parser import BytesParser
import os


def sanitize_attachment_filename(filename):
    if not filename:
        return ""

    return os.path.basename(filename)


def extract_urls(text):
    """Extract all HTTP/HTTPS URLs from text."""
    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(pattern, text)

    # Remove common sentence punctuation from the end of URLs.
    urls = [
        url.rstrip(".,!?;:)]}")
        for url in urls
    ]

    return urls


def parse_email(uploaded_file):
    """
    Parse an uploaded .eml file and return structured email data.
    """

    msg = BytesParser(policy=policy.default).parse(uploaded_file)

    email_data = {
        "sender": msg.get("From", ""),
        "recipient": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "body": "",
        "html": "",
        "urls": [],
        "attachments": [],
        "message": msg
    }

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename:
                safe_filename = sanitize_attachment_filename(filename)
                email_data["attachments"].append(safe_filename)
                continue

            if content_type == "text/plain":
                try:
                    email_data["body"] += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":
                try:
                    email_data["html"] += part.get_content()
                except Exception:
                    pass

    else:

        if msg.get_content_type() == "text/plain":
            email_data["body"] = msg.get_content()

        elif msg.get_content_type() == "text/html":
            email_data["html"] = msg.get_content()

    email_data["urls"] = extract_urls(
        email_data["body"] + email_data["html"]
    )

    return email_data