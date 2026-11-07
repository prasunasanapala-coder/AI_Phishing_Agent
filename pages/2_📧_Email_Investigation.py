import streamlit as st  # pyright: ignore[reportMissingImports]

from src.parser.parser import parse_email
from src.tools.sender_analyzer import analyze_sender
from src.tools.url_analyzer import analyze_url
from src.tools.content_analyzer import analyze_content
from src.tools.attachment_analyzer import analyze_attachments
from src.tools.header_analyzer import analyze_headers
from src.scoring.risk_engine import calculate_risk
from src.llm.agent import investigate_email
from src.report.ioc_extractor import extract_iocs
from src.report.pdf_generator import generate_pdf


import hashlib
import re

from src.database import (
    initialize_database,
    save_investigation
)


def extract_verdict(report):
    if not report:
        return "Not determined"

    section_match = re.search(
        r"(?im)^#{1,6}\s*Phishing Verdict\s*$"
        r"(.*?)(?=^#{1,6}\s|\Z)",
        report,
        re.DOTALL
    )

    if not section_match:
        return "Not determined"

    section = section_match.group(1)

    verdict_match = re.search(
        r"(?im)^\s*Verdict\s*:\s*"
        r"(Highly Malicious|Phishing|Suspicious|Legitimate)\b",
        section
    )

    if verdict_match:
        return verdict_match.group(1)

    return "Not determined"



st.set_page_config(
    page_title="AI Phishing Investigation Agent",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>

/* Main application */
.stApp {
    background: #0b1120;
    color: #e2e8f0;
}

.block-container {
    padding-top: 2rem;
    max-width: 1400px;
}

/* Sidebar background */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #111827, #0f172a);
    border-right: 1px solid #263449;
}

/* Sidebar content */
section[data-testid="stSidebar"] > div {
    padding-top: 2rem;
}

/* Sidebar navigation links */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a {
    border-radius: 10px;
    padding: 12px 14px;
    margin: 5px 8px;
    transition: all 0.2s ease;
}

/* Navigation hover */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a:hover {
    background: #1e293b;
    color: #38bdf8;
}

/* Selected navigation item */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] a[aria-current="page"] {
    background: linear-gradient(90deg, #164e63, #1e3a5f);
    border-left: 3px solid #38bdf8;
    color: #ffffff;
}

/* Sidebar text */
section[data-testid="stSidebar"] [data-testid="stSidebarNav"] span {
    font-weight: 600;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: #172033;
    border: 1px solid #334155;
    padding: 18px;
    border-radius: 14px;
}

/* Buttons */
.stButton button,
.stLinkButton a {
    border-radius: 10px;
    font-weight: 600;
}

/* Dividers */
hr {
    border-color: #263449;
}

</style>
""", unsafe_allow_html=True)



initialize_database()

st.markdown("""
<div style="
    background: linear-gradient(120deg, #172554, #1e293b);
    padding: 28px;
    border-radius: 18px;
    border: 1px solid #334155;
    margin-bottom: 25px;
">
    <h1 style="color:#f8fafc;">
        🛡️ Email Threat Investigation
    </h1>
    <p style="color:#cbd5e1;">
        Analyze email headers, sender reputation, URLs,
        attachments and phishing indicators.
    </p>
</div>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Upload Email",
    type=["eml"]
)

if uploaded_file:

    # Parse email
    try:
        email = parse_email(uploaded_file)

        if not email:
            st.error("Unable to parse this email file.")
            st.stop()

    except Exception as e:
        st.error(f"Email parsing failed: {e}")
        st.stop()

    # Analyses
    header_result = analyze_headers(email["message"])
    sender_result = analyze_sender(email["sender"])

    url_results = [
        analyze_url(url)
        for url in email["urls"]
    ]

    content_result = analyze_content(email["body"])

    attachment_result = analyze_attachments(
        email["attachments"]
    )
    # Extract Indicators of Compromise
    iocs = extract_iocs(email)

    # Risk calculation
    risk = calculate_risk(
        sender_result,
        url_results,
        content_result,
        attachment_result
    )

    # ==========================
    # ON-DEMAND AI INVESTIGATION
    # ==========================

    file_hash = hashlib.sha256(
        uploaded_file.getvalue()
    ).hexdigest()

    # Clear the previous report when a different email is uploaded.
    if st.session_state.get("ai_report_file_id") != file_hash:
        st.session_state.pop("ai_report", None)
        st.session_state.ai_report_file_id = file_hash

    existing_report = st.session_state.get("ai_report", "")
    ai_failed = (
        "AI Investigation Temporarily Unavailable" in existing_report
    )

    st.subheader("🤖 AI Investigation")
    st.caption(
        "Gemini API usage occurs only when you request an AI investigation."
    )

    if st.button(
        "🔄 Retry AI Investigation" if ai_failed
        else "🚀 Generate AI Investigation",
        type="primary",
        use_container_width=True,
        disabled=bool(existing_report) and not ai_failed
    ):
        with st.spinner("Generating AI investigation..."):
            st.session_state.ai_report = investigate_email(
                sender_result,
                url_results,
                content_result,
                attachment_result,
                header_result,
                risk,
                email,
            )
            st.session_state.ai_report_file_id = file_hash

    report = st.session_state.get(
        "ai_report",
        "AI investigation has not been generated. "
        "Generate the AI report when required."
    )

    # Save deterministic results even when Gemini has not been called.
    # The database can update the verdict later when an AI verdict exists.
    verdict = extract_verdict(report)

    save_investigation(
        filename=uploaded_file.name,
        risk_score=risk["total_score"],
        risk_level=risk["risk_level"],
        verdict=verdict,
        iocs=iocs,
        file_hash=file_hash
    )

    # Generate PDF Investigation Report
    pdf_filename = "Phishing_Investigation_Report.pdf"

    generate_pdf(
        pdf_filename,
        email,
        sender_result,
        header_result,
        url_results,
        content_result,
        attachment_result,
        iocs,
        risk,
        report,
    )

    st.success("Email parsed successfully!")

    # ==========================
    # Overall Threat Assessment
    # ==========================

    st.markdown("## 🚨 Threat Assessment")

    score = risk["total_score"]
    risk_level = risk["risk_level"]

    # Determine display color from the risk level
    if "Critical" in risk_level:
        risk_color = "#ef4444"
        risk_label = "CRITICAL"
    elif "High" in risk_level:
        risk_color = "#f97316"
        risk_label = "HIGH"
    elif "Medium" in risk_level:
        risk_color = "#eab308"
        risk_label = "MEDIUM"
    else:
        risk_color = "#22c55e"
        risk_label = "LOW"

    # Threat assessment cards
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #172033, #1e293b);
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 24px;
            min-height: 155px;
        ">
            <div style="color:#94a3b8; font-size:14px;">
                THREAT SCORE
            </div>
            <div style="
                color:#38bdf8;
                font-size:42px;
                font-weight:700;
                margin-top:12px;
            ">
                {score}<span style="font-size:20px;color:#94a3b8;"> / 100</span>
            </div>
            <div style="color:#94a3b8;font-size:12px;">
                Heuristic risk assessment
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #172033, #1e293b);
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 24px;
            min-height: 155px;
        ">
            <div style="color:#94a3b8;font-size:14px;">
                CURRENT RISK LEVEL
            </div>
            <div style="
                color:{risk_color};
                font-size:36px;
                font-weight:700;
                margin-top:15px;
            ">
                ● {risk_label}
            </div>
            <div style="color:#94a3b8;font-size:12px;">
                Automated security assessment
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # Risk score progress
    st.markdown("**Risk Score Indicator**")

    st.progress(
        min(max(score, 0), 100) / 100
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.caption("🟢 Low: 0–29")
    col2.caption("🟡 Medium: 30–59")
    col3.caption("🟠 High: 60–79")
    col4.caption("🔴 Critical: 80–100")

    st.divider()

    # ==========================
    # Email Details
    # ==========================
    st.header("📧 Email Details")

    st.write("**Sender:**", email["sender"])
    st.write("**Recipient:**", email["recipient"])
    st.write("**Subject:**", email["subject"])
    st.write("**Date:**", email["date"])

    st.divider()

     # ==========================
    # Sender Analysis
    # ==========================

    st.markdown("## 🔍 Sender Intelligence")

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.caption("SENDER EMAIL")
            st.markdown(
                f"### {sender_result['email']}"
            )

        with st.container(border=True):
            st.caption("DOMAIN")
            st.markdown(
                f"### {sender_result['domain']}"
            )

    with col2:
        with st.container(border=True):
            st.caption("SENDER RISK SCORE")
            st.metric(
                "Risk Score",
                sender_result["risk_score"]
            )

        with st.container(border=True):
            st.caption("LOOKALIKE DOMAIN")
            if sender_result["lookalike_brand"]:
                st.error("⚠️ Yes — lookalike detected")
            else:
                st.success("✓ No lookalike detected")

    st.write("")

    # Sender findings
    with st.container(border=True):
        st.markdown("**🔎 Sender Investigation Findings**")

        if sender_result["findings"]:
            for finding in sender_result["findings"]:
                st.warning(finding)
        else:
            st.success(
                "No suspicious sender indicators found."
            )

    st.divider()

    # ==========================
    # Header Analysis
    # ==========================

    st.markdown("## 📧 Header Security Analysis")

    def get_auth_style(value):
        value = str(value).strip().lower()

        if value == "pass":
            return "🟢 PASS"

        elif value == "fail":
            return "🔴 FAIL"

        return "⚪ NOT FOUND"

    col1, col2, col3 = st.columns(3)

    with col1:
        with st.container(border=True):
            st.caption("SPF")
            st.subheader(
                get_auth_style(header_result["spf"])
            )

    with col2:
        with st.container(border=True):
            st.caption("DKIM")
            st.subheader(
                get_auth_style(header_result["dkim"])
            )

    with col3:
        with st.container(border=True):
            st.caption("DMARC")
            st.subheader(
                get_auth_style(header_result["dmarc"])
            )

    st.write("")

    # Additional header information
    with st.container(border=True):

        st.markdown("### 🔎 Additional Header Information")

        details = [
            ("Reply-To", header_result["reply_to"]),
            ("Return-Path", header_result["return_path"]),
            ("Received Headers", header_result["received_count"]),
            ("Header Risk Score", header_result["risk_score"])
        ]

        for label, value in details:
            col1, col2 = st.columns([1, 2])

            col1.caption(label)
            col2.write(str(value))

            st.divider()

    # Header findings
    with st.container(border=True):

        st.markdown("### 🛡️ Header Investigation Findings")

        if header_result["findings"]:

            for finding in header_result["findings"]:
                st.warning(finding)

        else:
            st.success(
                "No suspicious header findings detected."
            )

    st.divider()

    # ==========================
    # URL Analysis
    # ==========================
    st.header("🌐 URL Analysis")

    if url_results:

        for result in url_results:

            st.markdown(f"### {result['url']}")
            st.write(f"**Domain:** {result['domain']}")
            st.write(f"**Risk Score:** {result['risk_score']}")

            if result["findings"]:
                st.warning("Findings")
                for finding in result["findings"]:
                    st.write(f"• {finding}")

            st.divider()

    else:
        st.success("No URLs found.")

    # ==========================
    # Content Analysis
    # ==========================
    st.header("📝 Content Analysis")

    st.metric(
        "Risk Score",
        content_result["risk_score"]
    )

    if content_result["findings"]:
        st.warning("Findings")
        for finding in content_result["findings"]:
            st.write(f"• {finding}")
    else:
        st.success("No suspicious content detected.")

    st.divider()

    # ==========================
    # Attachment Analysis
    # ==========================
    st.header("📎 Attachment Analysis")

    st.metric(
        "Risk Score",
        attachment_result["risk_score"]
    )

    if attachment_result["findings"]:
        st.warning("Findings")
        for finding in attachment_result["findings"]:
            st.write(f"• {finding}")

    if email["attachments"]:
        st.write("### Attachments")
        for attachment in email["attachments"]:
            st.write(f"• {attachment}")
    else:
        st.success("No attachments present.")

    st.divider()

    # ==========================
    # Indicators of Compromise (IOCs)
    # ==========================
    st.header("🚨 Indicators of Compromise (IOCs)")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📧 Email Addresses")

        if iocs["emails"]:
            for item in iocs["emails"]:
                st.write(f"• {item}")
        else:
            st.write("None")

        st.subheader("🌐 Domains")

        if iocs["domains"]:
            for item in iocs["domains"]:
                st.write(f"• {item}")
        else:
            st.write("None")

        st.subheader("🖥️ IP Addresses")

        if iocs["ips"]:
            for item in iocs["ips"]:
                st.write(f"• {item}")
        else:
            st.write("None")

    with col2:
        st.subheader("🔗 URLs")

        if iocs["urls"]:
            for item in iocs["urls"]:
                st.write(f"• {item}")
        else:
            st.write("None")

        st.subheader("📎 Attachments")

        if iocs["attachments"]:
            for item in iocs["attachments"]:
                st.write(f"• {item}")
        else:
            st.write("None")       

    # ==========================
    # Email Body
    # ==========================
    st.header("📄 Email Body")

    st.text_area(
        "Body",
        email["body"],
        height=300
    )

    st.divider()

    # ==========================
    # AI Investigation Report
    # ==========================
    st.header("🤖 AI Investigation Report")

    if "ai_report" in st.session_state:
        st.markdown(st.session_state.ai_report)
    else:
        st.info(
            "AI report not generated. "
            "Click Generate AI Investigation when needed."
        )
    # ==========================
    # Investigation PDF Report
    # ==========================

    st.divider()

    st.header("📄 Investigation Report")

    with open(pdf_filename, "rb") as pdf_file:

        st.download_button(
            label="⬇ Download Investigation Report",
            data=pdf_file,
            file_name=pdf_filename,
            mime="application/pdf",
        )