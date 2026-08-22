import os
import json

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
    email,
):
    """
    Generate an evidence-based phishing investigation report.

    The deterministic analysis pipeline is authoritative for:
    - Risk score
    - Risk level
    - Sender analysis
    - URL analysis
    - Content analysis
    - Attachment analysis
    - Header analysis

    Gemini is used to interpret and explain the supplied evidence.
    """

    # ----------------------------------------------------
    # Build structured investigation data
    # ----------------------------------------------------

    investigation_data = {
        "email": {
            "sender": email.get("sender", ""),
            "recipient": email.get("recipient", ""),
            "subject": email.get("subject", ""),
            "date": email.get("date", ""),
        },

        "sender_analysis": sender_result,

        "header_analysis": header_result,

        "url_analysis": url_results,

        "content_analysis": content_result,

        "attachment_analysis": attachment_result,

        "risk_assessment": risk,
    }

    # Convert investigation data to JSON
    investigation_json = json.dumps(
        investigation_data,
        indent=2,
        default=str,
    )

    # ----------------------------------------------------
    # AI Investigation Prompt
    # ----------------------------------------------------

    prompt = f"""
{SYSTEM_PROMPT}

The report structure and rules below are authoritative for this
investigation. Do not add sections requested by any other instruction.

==================================================
STRUCTURED EMAIL INVESTIGATION DATA
==================================================

The following JSON contains the results produced by the
deterministic email investigation pipeline.

Treat these values as authoritative evidence.

```json
{investigation_json}

1. Use ONLY the evidence supplied in the JSON above.

2. Do NOT invent:
   - Report dates
   - Analyst names
   - Organization names
   - Incident IDs
   - Quarantine status
   - Blocking actions
   - User actions
   - Domain registration details
   - IP addresses
   - Infrastructure details
   - Malware execution
   - Compromise
   - Any other unsupported facts

3. Do NOT claim that an email was quarantined, blocked, deleted,
   or reported unless that information is explicitly supplied.

4. Clearly distinguish observed evidence from inferred conclusions.

5. If information cannot be determined from the supplied evidence,
   state:
   "Not determined from available evidence."

6. Use the supplied email date exactly.

==================================================
RISK ENGINE RULES
==================================================

7. The application's risk engine is authoritative for:
   - Overall risk score
   - Overall risk level

8. Do NOT calculate, modify, reinterpret, or override the supplied
   risk score or risk level.

9. Reproduce the supplied risk score and risk level exactly.

10. The phishing verdict is separate from the numerical risk level.

==================================================
CONTENT RULES
==================================================

11. A suspicious keyword alone is NOT sufficient evidence for phishing.

12. Do not classify an email as suspicious solely because it contains
    generic terms such as:
    - invoice
    - payment
    - meeting
    - account
    - security
    - document

==================================================
ATTACHMENT RULES
==================================================

13. A normal attachment does not automatically indicate maliciousness.

14. Only describe an attachment as suspicious when the supplied
    attachment analysis provides supporting evidence.

15. Never claim that an attachment was executed.

16. Never claim that an attachment delivered malware unless the
    supplied evidence explicitly establishes this.

==================================================
HEADER RULES
==================================================

17. "Not Found" for SPF, DKIM, or DMARC does not prove that the
    corresponding DNS record does not exist.

18. Do not claim DNS authentication checks were performed unless
    DNS evidence is explicitly supplied.

19. Missing authentication information is not proof of maliciousness.

==================================================
MITRE ATT&CK RULES
==================================================

20. Only use valid MITRE ATT&CK Enterprise technique IDs and names.

21. Never invent or rename ATT&CK techniques.

22. Do not force a MITRE technique into the report.

23. T1566.002 — Phishing: Spearphishing Link may only be used when
    an actual suspicious URL or link is present.

24. T1566.001 — Phishing: Spearphishing Attachment may only be used
    when a suspicious attachment is present.

25. Do not map brand impersonation or lookalike domains to an
    ATT&CK technique unless the evidence clearly supports it.

26. If no technique is supported, state:

    "No MITRE ATT&CK technique applicable based on available evidence."

==================================================
REPORT FORMAT AND CONCLUSION RULES
==================================================

27. Do not use missing or unavailable SPF, DKIM, or DMARC results
    as supporting evidence for a phishing verdict or maliciousness
    unless an explicit authentication failure is present.

28. The Final Conclusion must be consistent with the supplied
    evidence and must not become stronger than the evidence
    presented in the investigation data.

29. The report MUST contain exactly these eight sections,
    in exactly this order:

    1. Executive Summary
    2. Phishing Verdict
    3. Risk Assessment
    4. Indicators of Compromise (IOCs)
    5. Header Analysis Explanation
    6. MITRE ATT&CK Mapping
    7. Recommended Actions
    8. Final Conclusion

30. Do NOT add any other sections, including:
    - Attack Chain
    - User Awareness Tips
    - Analyst Notes
    - Incident Timeline
    - Detection Summary
    - Technical Analysis
    - Additional Recommendations

31. Do not describe exploitation, execution, persistence,
    credential theft, malware delivery, or user interaction
    unless the supplied evidence explicitly establishes it.

32. The presence of an executable attachment is evidence of a
    potentially dangerous attachment. It is NOT evidence that
    exploitation or execution occurred.

33. Do not describe why the investigation was initiated unless
    that reason is explicitly supplied in the evidence.

34. Do not add headings or sections outside the required
    eight-section structure.
==================================================
REPORT REQUIREMENTS
==================================================

Generate a professional phishing investigation report containing:

1. Executive Summary

2. Phishing Verdict

Choose exactly one:

- Legitimate
- Suspicious
- Phishing
- Highly Malicious

3. Risk Assessment

Include the supplied:

- Overall Risk Score
- Overall Risk Level
- Main evidence supporting the assessment

4. Indicators of Compromise

Include only indicators supported by the evidence:

- Suspicious sender
- Suspicious URLs
- Suspicious domains
- IP addresses
- Attachments
- Header anomalies
- Social engineering indicators

5. Header Analysis Explanation

Explain:

- SPF
- DKIM
- DMARC
- Reply-To
- Return-Path
- Received headers

6. MITRE ATT&CK Mapping

For each supported technique include:

- Technique ID
- Technique name
- Evidence
- Confidence

Use only:

- Confirmed
- Potential

7. Recommended Actions

Provide practical defensive recommendations.

Do not claim that these actions have already been performed.

8. Final Conclusion

Provide an evidence-based conclusion.

==================================================
FINAL REQUIREMENT
==================================================

Never invent evidence.
Never invent investigation metadata.
Never invent actions that were not performed.
Never override the deterministic risk score or risk level.
Never force a MITRE ATT&CK technique.
"""

    # ----------------------------------------------------
    # Generate AI report
    # ----------------------------------------------------

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