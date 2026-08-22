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
    email,
):
    """
    Generate an evidence-based phishing investigation report.

    The AI must use only the evidence supplied by the application
    and must not invent investigation metadata or actions.
    """

    prompt = f"""
{SYSTEM_PROMPT}

==================================================
IMPORTANT INVESTIGATION RULES
==================================================

1. Use ONLY the evidence provided below.

2. DO NOT invent:
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
   - Any other unsupported facts

3. Do NOT claim that the email was:
   - quarantined
   - blocked
   - deleted
   - reported
   - investigated by a specific team

   unless that information is explicitly present in the supplied evidence.

4. Clearly distinguish between:
   - OBSERVED EVIDENCE
   - INFERRED CONCLUSIONS

5. If something cannot be determined from the supplied evidence, state:
   "Not determined from available evidence."

6. Do not create fictional metadata such as:
   "Senior Cyber Threat Intelligence Analyst"

7. Do not create a fictional report date.

8. The email date provided below is the actual email date.
   Do not replace it with another date.

9. MITRE ATT&CK techniques must only be mapped when the supplied
   evidence reasonably supports the technique.

10. If a MITRE technique is uncertain, label it as:
    "Potential"
11. Do not invent MITRE ATT&CK technique IDs or technique names.
    Only use officially recognized ATT&CK techniques when the evidence
    supports them.

12. Do not map brand impersonation or typosquatting to an ATT&CK technique
    unless the evidence clearly supports a specific recognized technique.

13. Distinguish email-header observations from DNS authentication checks.
    "Not Found" in the supplied header analysis does NOT prove that an
    SPF, DKIM, or DMARC DNS record does not exist.

14. Do not claim that SPF, DKIM, or DMARC was checked against DNS unless
    DNS lookup evidence is explicitly supplied.

15. MITRE ATT&CK accuracy is mandatory.

16. Only use MITRE ATT&CK technique IDs and names that are valid
    in the official MITRE ATT&CK Enterprise framework.

17. Do not invent or rename ATT&CK techniques.

18. Do not map "brand impersonation", "lookalike domain",
    "typosquatting", or similar observations to an ATT&CK technique
    unless the supplied evidence clearly supports a specific official
    ATT&CK technique.

19. For this investigation, T1566.002 (Phishing: Spearphishing Link)
    may be used when the evidence supports phishing through a malicious
    link.

20. If no additional ATT&CK technique can be confidently supported,
    report only the supported technique rather than forcing another
    mapping.

21. Do not use "proves" or "confirms" for conclusions that are based
    only on indicators. Prefer "strongly indicates", "supports",
    or "is consistent with" unless the supplied evidence directly
    establishes the fact.

22. Do not describe missing SPF, DKIM, or DMARC results as evidence
    that legitimate authentication failed unless the supplied data
    explicitly contains a failed authentication result.

23. Do not describe the absence of authentication results as proof
    that the sender is malicious.

24. When authentication information is unavailable, state only:
    "Authentication results were not available in the supplied evidence."

25. Never map T1566.002 (Phishing: Spearphishing Link) unless
    an actual URL or link is present in the supplied email evidence.

26. A suspicious keyword alone is NOT sufficient evidence for
    a phishing verdict or MITRE ATT&CK technique.

27. Do not escalate a message to Suspicious solely because of
    generic business terms such as:
    "invoice", "payment", "meeting", "account", "security",
    or "document".

28. The presence of a normal attachment does not imply maliciousness.
    Only classify an attachment as suspicious when the supplied
    attachment analysis provides evidence supporting that conclusion.

29. When evidence is insufficient for a phishing classification,
    prefer "Legitimate" or "Low Risk / Needs Review" rather than
    inventing an attack technique.

30. The application's risk engine is authoritative for the overall
    risk score and risk level.

31. Do NOT calculate, modify, reinterpret, or override the supplied
    risk score or risk level.

32. In the Risk Assessment section, reproduce exactly:
    - Overall Risk Score
    - Overall Risk Level

    using the values supplied in OVERALL RISK ASSESSMENT.

33. The phishing verdict is separate from the numerical risk level.
    Do not use "High" or "Critical" as a substitute for the supplied
    risk level.

34. Do not label an email "Highly Malicious" solely because it contains
    an executable attachment. Describe the attachment as a high-risk
    indicator and base the final verdict on the complete supplied
    evidence.

35. Never state that an attachment was executed, delivered malware,
    or caused compromise unless that evidence is explicitly supplied.
==================================================
EMAIL METADATA
==================================================

Sender:
{email.get("sender", "")}

Recipient:
{email.get("recipient", "")}

Subject:
{email.get("subject", "")}

Email Date:
{email.get("date", "")}

==================================================
SENDER ANALYSIS
==================================================

{sender_result}

==================================================
HEADER ANALYSIS
==================================================

{header_result}

==================================================
URL ANALYSIS
==================================================

{url_results}

==================================================
CONTENT ANALYSIS
==================================================

{content_result}

==================================================
ATTACHMENT ANALYSIS
==================================================

{attachment_result}

==================================================
OVERALL RISK ASSESSMENT
==================================================

{risk}

==================================================
REQUIRED REPORT STRUCTURE
==================================================

Generate a professional phishing investigation report containing:

1. Executive Summary

   Summarize the observed evidence and explain why the email
   is legitimate, suspicious, phishing, or highly malicious.

2. Phishing Verdict

   Choose exactly one:

   - Legitimate
   - Suspicious
   - Phishing
   - Highly Malicious

3. Risk Assessment

   Include:
   - Overall risk level
   - Overall risk score
   - Main evidence supporting the assessment

4. Indicators of Compromise (IOCs)

   Include only indicators supported by the supplied evidence:

   - Suspicious sender
   - Suspicious URLs
   - Suspicious domains
   - IP addresses
   - Attachments
   - Header anomalies
   - Social engineering indicators

5. Header Analysis Explanation

   Explain the supplied results for:

   - SPF
   - DKIM
   - DMARC
   - Reply-To
   - Return-Path
   - Received headers

   Do not treat missing information as proof of malicious activity.

6. MITRE ATT&CK Mapping

   Include relevant techniques only when supported by the evidence.

   For each technique provide:
   - Technique ID
   - Technique name
   - Evidence
   - Confidence: Confirmed or Potential

7. Recommended Actions

   Provide practical defensive actions based on the observed
   evidence.

   Do not claim that an action has already been performed.

8. Final Conclusion

   Summarize the evidence-based conclusion.

==================================================
FINAL REQUIREMENT
==================================================

The report must be evidence-based.

Never present assumptions as confirmed facts.
Never invent investigation metadata.
Never invent actions that were not performed.
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