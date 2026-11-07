
import streamlit as st

from src.database import (
    initialize_database,
    get_all_investigations
)

st.set_page_config(
    page_title="Phishing Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

initialize_database()

# ==========================
# Custom Styling
# ==========================

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0b1120 0%, #111827 100%);
    color: #e5e7eb;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1400px;
}

.hero {
    background: linear-gradient(120deg, #172554, #1e293b);
    padding: 30px;
    border-radius: 18px;
    border: 1px solid #334155;
    margin-bottom: 25px;
}

.hero h1 {
    color: #f8fafc;
    font-size: 34px;
    margin-bottom: 8px;
}

.hero p {
    color: #cbd5e1;
    font-size: 15px;
}

div[data-testid="stMetric"] {
    background: #172033;
    border: 1px solid #334155;
    padding: 18px;
    border-radius: 14px;
}

div[data-testid="stMetricValue"] {
    color: #38bdf8;
}

div[data-testid="stMetricLabel"] {
    color: #cbd5e1;
}

.stButton button, 
.stLinkButton a {
    border-radius: 10px;
    font-weight: 600;
}

hr {
    border-color: #334155;
}
</style>
""", unsafe_allow_html=True)


# ==========================
# Dashboard Header
# ==========================

st.markdown("""
<div class="hero">
    <h1>🛡️ Phishing Security Dashboard</h1>
    <p>
        AI-powered email threat detection, investigation
        and security intelligence.
    </p>
</div>
""", unsafe_allow_html=True)


# ==========================
# Investigation Navigation
# ==========================

st.subheader("🚀 Investigation Center")

st.write(
    "Upload and investigate suspicious email files using "
    "automated security analysis and AI."
)

st.page_link(
    "pages/2_📧_Email_Investigation.py",
    label="📧 Open Email Investigation",
    icon="📧",
    use_container_width=True
)

st.divider()


# ==========================
# Fetch Records
# ==========================

records = get_all_investigations()

total = len(records)

phishing = sum(
    1 for r in records
    if r[5] in ["Phishing", "Highly Malicious"]
)

suspicious = sum(
    1 for r in records
    if r[5] == "Suspicious"
)

legitimate = sum(
    1 for r in records
    if r[5] == "Legitimate"
)

undetermined = sum(
    1 for r in records
    if r[5] == "Not determined"
)


# ==========================
# Metrics
# ==========================

st.subheader("📊 Security Overview")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Analyzed", total)
col2.metric("Phishing", phishing)
col3.metric("Suspicious", suspicious)
col4.metric("Legitimate", legitimate)
col5.metric("Not Determined", undetermined)

st.divider()


# ==========================
# Risk Distribution
# ==========================

st.subheader("📈 Risk Distribution")

risk_counts = {
    "Low": 0,
    "Medium": 0,
    "High": 0,
    "Critical": 0
}

for record in records:
    level = (
        record[4]
        .replace("🔴 ", "")
        .replace("🟠 ", "")
        .replace("🟡 ", "")
        .replace("🟢 ", "")
    )

    if level in risk_counts:
        risk_counts[level] += 1

if total:
    st.bar_chart(
        risk_counts,
        x_label="Risk Level",
        y_label="Investigations"
    )
else:
    st.info("No investigation data available yet.")


st.divider()


# ==========================
# Recent Investigations
# ==========================

st.subheader("🗂️ Recent Investigations")

if records:
    for record in records[:10]:

        with st.expander(
            f"📧 {record[1]} | Risk Score: {record[3]}/100"
        ):

            col1, col2, col3 = st.columns(3)

            col1.metric("Risk Score", f"{record[3]}/100")
            col2.metric("Risk Level", record[4])
            col3.metric("Verdict", record[5])

            st.caption(f"Investigation ID: {record[0]}")
            st.caption(f"Analyzed at: {record[2]}")

else:
    st.info("No investigations recorded yet.")


st.divider()

st.caption(
    "AI Phishing Email Detection & Investigation Agent | "
    "Security Analysis Dashboard"
)
