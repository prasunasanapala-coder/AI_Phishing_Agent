
import streamlit as st

# ==========================
# PAGE CONFIGURATION
# ==========================

st.set_page_config(
    page_title="Phishing Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ==========================
# CUSTOM STYLING
# ==========================

st.markdown("""
<style>

/* Application background */
.stApp {
    background: #0b1120;
    color: #e2e8f0;
}

.block-container {
    padding-top: 2rem;
    max-width: 1400px;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(
        180deg,
        #0b1426,
        #111c30
    );
    border-right: 1px solid #263449;
}

/* Sidebar branding */
.brand-title {
    font-size: 19px;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: 0.4px;
}

.brand-subtitle {
    font-size: 10px;
    color: #94a3b8;
    letter-spacing: 1.3px;
}

/* Custom navigation links */
section[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"] {
    background: transparent;
    border-radius: 10px;
    padding: 12px;
    margin: 5px 0;
    transition: 0.2s ease;
}

section[data-testid="stSidebar"] a[data-testid="stPageLink-NavLink"]:hover {
    background: #1e293b;
}

/* Active navigation link */
section[data-testid="stSidebar"] a[aria-current="page"] {
    background: #164e63;
    border-left: 3px solid #38bdf8;
}

/* Sidebar section label */
.sidebar-section {
    color: #94a3b8;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.2px;
    margin-top: 25px;
    margin-bottom: 12px;
}

/* Dividers */
hr {
    border-color: #263449;
}

/* Main metric cards */
div[data-testid="stMetric"] {
    background: #172033;
    border: 1px solid #334155;
    padding: 18px;
    border-radius: 14px;
}

</style>
""", unsafe_allow_html=True)


# ==========================
# PAGE DEFINITIONS
# ==========================

dashboard = st.Page(
    "pages/1_Dashboard.py",
    title="Dashboard",
    icon=":material/dashboard:",
    default=True
)

investigation = st.Page(
    "pages/2_📧_Email_Investigation.py",
    title="Email Investigation",
    icon=":material/mark_email_unread:"
)


# ==========================
# HIDE AUTOMATIC NAVIGATION
# ==========================

navigation = st.navigation(
    {
        "WORKSPACE": [
            dashboard,
            investigation
        ]
    },
    position="hidden"
)


# ==========================
# CUSTOM SIDEBAR
# ==========================

with st.sidebar:

    # Brand identity
    st.markdown(
        '<div style="font-size:36px;">🛡️</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="brand-title">PHISHING INTELLIGENCE</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="brand-subtitle">'
        'SECURITY OPERATIONS CENTER'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("")

    st.success("● ANALYSIS ENGINE READY")

    st.divider()

    # Navigation links
    st.markdown(
        '<div class="sidebar-section">WORKSPACE</div>',
        unsafe_allow_html=True
    )

    st.page_link(
        dashboard,
        label="Dashboard",
        icon=":material/dashboard:"
    )

    st.page_link(
        investigation,
        label="Email Investigation",
        icon=":material/mark_email_unread:"
    )

    st.divider()

    st.caption("AI PHISHING INVESTIGATION AGENT")


# ==========================
# RUN SELECTED PAGE
# ==========================

navigation.run()
