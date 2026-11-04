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

st.set_page_config(
    page_title="AI Phishing Investigation Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Phishing Investigation Agent")

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
    # AI Investigation
    # ==========================

    # Create a unique identifier for the uploaded email.
    # This prevents unnecessary Gemini API calls when Streamlit
    # reruns the application for the same uploaded file.
    file_id = f"{uploaded_file.name}_{uploaded_file.size}"

    # Generate the AI report only when:
    # 1. No previous report exists, OR
    # 2. A different email has been uploaded.
    if (
        "ai_report" not in st.session_state
        or st.session_state.get("ai_report_file_id") != file_id
    ):

        with st.spinner("🤖 Generating AI investigation report..."):

            st.session_state.ai_report = investigate_email(
                sender_result,
                url_results,
                content_result,
                attachment_result,
                header_result,
                risk,
                email,
            )

            st.session_state.ai_report_file_id = file_id

    report = st.session_state.ai_report
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
    st.header("🚨 Overall Threat Assessment")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Threat Score",
            f"{risk['total_score']}/100"
        )

    with col2:
        st.metric(
            "Risk Level",
            risk["risk_level"]
        )

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
    st.header("🔍 Sender Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Sender Email", sender_result["email"])
        st.metric("Domain", sender_result["domain"])

    with col2:
        st.metric("Risk Score", sender_result["risk_score"])
        st.metric(
            "Lookalike Domain",
            "Yes" if sender_result["lookalike_brand"] else "No"
        )

    if sender_result["findings"]:
        st.warning("Findings")
        for finding in sender_result["findings"]:
            st.write(f"• {finding}")
    else:
        st.success("No suspicious sender indicators found.")

    st.divider()

    # ==========================
    # Header Analysis
    # ==========================
    st.header("📧 Header Analysis")

    st.write("**SPF:**", header_result["spf"])
    st.write("**DKIM:**", header_result["dkim"])
    st.write("**DMARC:**", header_result["dmarc"])
    st.write("**Reply-To:**", header_result["reply_to"])
    st.write("**Return-Path:**", header_result["return_path"])
    st.write("**Received Headers:**", header_result["received_count"])
    st.write("**Risk Score:**", header_result["risk_score"])

    if header_result["findings"]:
        st.warning("Findings")
        for finding in header_result["findings"]:
            st.write(f"• {finding}")
    else:
        st.success("No suspicious header findings detected.")

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

    st.markdown(report)
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