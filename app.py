import streamlit as st

from src.parser.parser import parse_email
from src.tools.sender_analyzer import analyze_sender
from src.tools.url_analyzer import analyze_url
from src.tools.content_analyzer import analyze_content
from src.tools.attachment_analyzer import analyze_attachments
from src.tools.header_analyzer import analyze_headers
from src.scoring.risk_engine import calculate_risk
from src.llm.agent import investigate_email

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
    email = parse_email(uploaded_file)

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

    # Risk calculation
    risk = calculate_risk(
        sender_result,
        url_results,
        content_result,
        attachment_result,
        header_result
    )

    # AI Investigation
    report = investigate_email(
        sender_result,
        url_results,
        content_result,
        attachment_result,
        header_result,
        risk
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