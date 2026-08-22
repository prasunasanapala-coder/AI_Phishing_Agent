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

    Gemini is used only to interpret and explain the supplied evidence.
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

==================================================
IMPORTANT INVESTIGATION RULES

    Use ONLY the evidence supplied in the JSON above.

    Do NOT invent:

        Report dates

        Analyst names

        Organization names

        Incident IDs

        Quarantine status

        Blocking actions

        User actions

        Domain registration details

        IP addresses

        Infrastructure details

        Malware execution

        Compromise

        Any other unsupported facts

    Do NOT claim that an email was:

        quarantined

        blocked

        deleted

        reported

    unless that information is explicitly supplied.

    Clearly distinguish observed evidence from inferred conclusions.

    If information cannot be determined from the supplied evidence,
    state:

    "Not determined from available evidence."

    Use the supplied email date exactly.

==================================================
RISK ENGINE RULES

    The application's risk engine is authoritative for:

        Overall risk score

        Overall risk level

    Do NOT calculate, modify, reinterpret, or override the supplied
    risk score or risk level.

    Reproduce the supplied risk score and risk level exactly.

    The phishing verdict is separate from the numerical risk level.

==================================================
CONTENT RULES

    A suspicious keyword alone is NOT sufficient evidence for phishing.

    Do not classify an email as suspicious solely because it contains
    generic terms such as:

        invoice

        payment

        meeting

        account

        security

        document

==================================================
ATTACHMENT RULES

    A normal attachment does not automatically indicate maliciousness.

    Only describe an attachment as suspicious when the supplied
    attachment analysis provides supporting evidence.

    Never claim that an attachment was executed.

    Never claim that an attachment delivered malware unless the
    supplied evidence explicitly establishes this.

==================================================
HEADER RULES

    "Not Found", "None", or unavailable SPF, DKIM, or DMARC
    information MUST NOT be interpreted as a failed authentication
    result.

    Do not claim that SPF, DKIM, or DMARC DNS records are:

        missing

        absent

        invalid

        failed

    unless explicit DNS or authentication evidence is supplied.

    Do not claim that DNS authentication checks were performed unless
    DNS lookup or authentication evidence is explicitly supplied.

    Missing or unavailable SPF, DKIM, or DMARC information MUST NOT
    be used as supporting evidence for:

        phishing

        maliciousness

        fraud

        impersonation

        the final conclusion

    When SPF, DKIM, or DMARC information is unavailable, state:

    "Authentication results were not available in the supplied
    header evidence."

    The phishing verdict must be supported by other supplied evidence
    when SPF, DKIM, or DMARC information is unavailable.

    Do not describe the absence of authentication information as
    evidence that legitimate authentication failed unless the
    supplied data explicitly contains a failed authentication result.

    Distinguish email-header observations from DNS authentication
    checks.

==================================================
MITRE ATT&CK RULES

    Only use valid MITRE ATT&CK Enterprise technique IDs and names.

    Never invent or rename ATT&CK techniques.

    Do not force a MITRE technique into the report.

    T1566.002 — Phishing: Spearphishing Link may only be used when
    an actual suspicious URL or link is present.

    T1566.001 — Phishing: Spearphishing Attachment may only be used
    when a suspicious attachment is present.

    Do not map brand impersonation or lookalike domains to an
    ATT&CK technique unless the evidence clearly supports it.

    If no technique is supported, state:

    "No MITRE ATT&CK technique applicable based on available evidence."

==================================================
REPORT FORMAT AND CONCLUSION RULES

    The Final Conclusion must be consistent with the supplied evidence
    and must not become stronger than the evidence presented in the
    investigation data.

    The report MUST contain exactly these eight sections,
    in exactly this order:

        Executive Summary

        Phishing Verdict

        Risk Assessment

        Indicators of Compromise (IOCs)

        Header Analysis Explanation

        MITRE ATT&CK Mapping

        Recommended Actions

        Final Conclusion

    Do NOT add any other sections, including:

        Attack Chain

        User Awareness Tips

        Analyst Notes

        Incident Timeline

        Detection Summary

        Technical Analysis

        Additional Recommendations

    Do not describe exploitation, execution, persistence,
    credential theft, malware delivery, or user interaction
    unless the supplied evidence explicitly establishes it.

    The presence of an executable attachment is evidence of a
    potentially dangerous attachment. It is NOT evidence that
    exploitation or execution occurred.

    Do not describe why the investigation was initiated unless
    that reason is explicitly supplied in the evidence.

    Do not add headings or sections outside the required
    eight-section structure.

    Do not claim credential harvesting occurred unless the supplied
    evidence explicitly establishes credential collection or theft.

    A login page or suspicious login URL alone does not establish
    that credentials were harvested.

==================================================
REPORT REQUIREMENTS

Generate a professional phishing investigation report containing:

    Executive Summary

    Summarize the observed evidence and explain why the email is
    legitimate, suspicious, phishing, or highly malicious.

    Phishing Verdict

    Choose exactly one:

        Legitimate

        Suspicious

        Phishing

        Highly Malicious

    Risk Assessment

    Include the supplied:

        Overall Risk Score

        Overall Risk Level

        Main evidence supporting the assessment

    Indicators of Compromise (IOCs)

    Include only indicators supported by the evidence:

        Suspicious sender

        Suspicious URLs

        Suspicious domains

        IP addresses

        Attachments

        Header anomalies

        Social engineering indicators

    Header Analysis Explanation

    Explain the supplied results for:

        SPF

        DKIM

        DMARC

        Reply-To

        Return-Path

        Received headers

    Do not treat missing information as proof of malicious activity.

    MITRE ATT&CK Mapping

    Include relevant techniques only when supported by the evidence.

    For each supported technique provide:

        Technique ID

        Technique name

        Evidence

        Confidence

    Use only:

        Confirmed

        Potential

    Recommended Actions

    Provide practical defensive recommendations.

    Do not claim that these actions have already been performed.

    Final Conclusion

    Provide an evidence-based conclusion.

==================================================
FINAL EVIDENCE PRIORITY RULE

The deterministic investigation data has higher authority than
general cybersecurity knowledge.

If the supplied evidence says "Not Found", do not transform that
into:

    failed

    missing

    absent

    invalid

unless explicit evidence supports that conclusion.

If a fact is not explicitly supported by the supplied evidence,
do not introduce it into the report.

Never present assumptions as confirmed facts.
Never invent investigation metadata.
Never invent actions that were not performed.
Never override the deterministic risk score or risk level.
Never force a MITRE ATT&CK technique.
"""

    # ----------------------------------------------------
    # Generate AI report using model fallback
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