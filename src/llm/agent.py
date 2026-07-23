import os

from dotenv import load_dotenv
from google import genai

from src.llm.prompts import SYSTEM_PROMPT

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=API_KEY)

# Models to try in order
MODELS = [
    "gemini-flash-latest",
    "gemini-3.1-flash-lite",
    "gemini-3.6-flash",
]


def investigate_email(
    sender_result,
    url_results,
    content_result,
    attachment_result,
    header_result,
    risk,
):
    prompt = f"""
{SYSTEM_PROMPT}

=========================
EMAIL INVESTIGATION DATA
=========================

Sender Analysis:
{sender_result}

Header Analysis:
{header_result}

URL Analysis:
{url_results}

Content Analysis:
{content_result}

Attachment Analysis:
{attachment_result}

Overall Risk Assessment:
{risk}

=========================
Generate a professional phishing investigation report containing:

1. Executive Summary

2. Phishing Verdict
   - Legitimate
   - Suspicious
   - Phishing
   - Highly Malicious

3. Risk Assessment

4. Indicators of Compromise (IOCs)
   - Suspicious sender
   - Suspicious URLs
   - Malicious attachments
   - Header anomalies
   - Social engineering indicators

5. Header Analysis Explanation
   Explain the impact of:
   - SPF
   - DKIM
   - DMARC
   - Reply-To
   - Return-Path
   - Received headers

6. MITRE ATT&CK Mapping
   Include relevant ATT&CK techniques where applicable.

7. Recommended Actions
   Provide practical remediation steps.

8. Final Conclusion
"""
    last_error = None

    for model in MODELS:
        try:
            print(f"Trying model: {model}")

            response = client.models.generate_content(
                model=model,
                contents=prompt,
            )

            print(f"Success with {model}")
            return response.text

        except Exception as e:
            print(f"{model} failed: {e}")
            last_error = e

    return f"Gemini Error:\n\n{last_error}"