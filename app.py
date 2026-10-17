
import streamlit as st
import joblib
import os
import re
import html
import hashlib
from datetime import datetime

# =========================================================
# CONFIGURATION
# =========================================================
st.set_page_config(
    page_title="SULTAN AI | TrustShield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# SESSION STATE
# =========================================================
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "total_scans" not in st.session_state:
    st.session_state.total_scans = 1284

if "total_threats" not in st.session_state:
    st.session_state.total_threats = 96

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None

# =========================================================
# MODEL LOADING
# =========================================================
@st.cache_resource
def load_models():
    model_path = "models/sms_spam_model.joblib"
    vectorizer_path = "models/sms_vectorizer.joblib"

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        try:
            return (
                joblib.load(model_path),
                joblib.load(vectorizer_path)
            )
        except Exception:
            return None, None

    return None, None


sms_model, sms_vectorizer = load_models()

# =========================================================
# CUSTOM CSS
# =========================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --bg: #07111f;
    --panel: #101d2d;
    --border: #23344a;
    --cyan: #21d4fd;
    --gold: #f5c542;
    --text: #edf5ff;
    --muted: #91a4ba;
}

.stApp {
    background:
        radial-gradient(ellipse at 50% -15%,
        #183653 0%, #0a1728 40%, #07111f 75%);
    color: var(--text);
    font-family: 'Inter', sans-serif;
}

[data-testid="stHeader"] {
    background: rgba(7,17,31,0.85);
}

[data-testid="stSidebar"] {
    background: #091524;
    border-right: 1px solid #203148;
}

[data-testid="stSidebar"] * {
    color: #e6eef8;
}

.block-container {
    padding-top: 1.8rem;
    padding-bottom: 3rem;
    max-width: 1500px;
}

h1, h2, h3 {
    color: #f4f8ff !important;
    letter-spacing: -0.7px;
}

p, label {
    color: #c4d2e2;
}

.brand {
    font-size: 30px;
    font-weight: 800;
    letter-spacing: 1px;
    color: #f5c542;
    margin-bottom: 0;
}

.brand-sub {
    color: #91a4ba;
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 3px;
    margin-bottom: 25px;
}

.hero {
    padding: 26px 28px;
    border-radius: 18px;
    border: 1px solid #25415b;
    background: linear-gradient(120deg, #10263b, #102034 70%, #112b40);
    margin-bottom: 25px;
    box-shadow: 0 12px 40px rgba(0,0,0,.15);
}

.hero-title {
    font-size: 32px;
    font-weight: 800;
    color: #f5f8ff;
    margin: 0;
}

.hero-sub {
    font-size: 14px;
    color: #9db1c8;
    margin-top: 8px;
}

.panel {
    background: linear-gradient(145deg, #111f30, #0d1928);
    border: 1px solid #25364b;
    border-radius: 15px;
    padding: 21px;
    margin-bottom: 14px;
}

.metric-label {
    color: #9db0c6;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .6px;
    text-transform: uppercase;
}

.metric-value {
    color: #f4f8ff;
    font-size: 30px;
    font-weight: 800;
    margin-top: 9px;
}

.metric-note {
    font-size: 12px;
    color: #21d4a0;
    margin-top: 6px;
}

.section-title {
    font-size: 19px;
    font-weight: 700;
    color: #f2f7ff;
    margin-bottom: 4px;
}

.section-subtitle {
    color: #91a4ba;
    font-size: 12px;
    margin-bottom: 18px;
}

.status {
    display: inline-block;
    padding: 7px 12px;
    border: 1px solid #176a58;
    border-radius: 20px;
    color: #55e6b5;
    background: #0c302c;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .6px;
}

div.stButton > button {
    background: linear-gradient(100deg, #21d4fd, #46b7f4);
    color: #07111f !important;
    border: none;
    border-radius: 9px;
    font-weight: 800;
    min-height: 44px;
    transition: .2s ease;
}

div.stButton > button:hover {
    background: #6be3ff;
    border: none;
    box-shadow: 0 0 18px rgba(33,212,253,.20);
    transform: translateY(-1px);
}

div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea {
    background: #091524;
    color: #edf5ff;
    border: 1px solid #2a4159;
    border-radius: 9px;
}

div[data-testid="stTextInput"] input:focus,
div[data-testid="stTextArea"] textarea:focus {
    border-color: #21d4fd;
    box-shadow: 0 0 0 1px #21d4fd;
}

div[data-testid="stFileUploader"] {
    background: #0c1929;
    border: 1px dashed #34516b;
    border-radius: 12px;
    padding: 12px;
}

div[data-testid="stMetric"] {
    background: #101d2d;
    border: 1px solid #25364b;
    border-radius: 14px;
    padding: 18px;
}

div[data-testid="stMetricLabel"] {
    color: #9db0c6;
}

div[data-testid="stMetricValue"] {
    color: #f4f8ff;
}

hr {
    border-color: #25364b;
}

footer {
    visibility: hidden;
}

#MainMenu {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# =========================================================
# HELPERS
# =========================================================
def add_history(scan_type, content, result, risk, details):
    item = {
        "time": datetime.now().strftime("%d %b %Y, %H:%M"),
        "type": scan_type,
        "content": content[:120],
        "result": result,
        "risk": risk,
        "details": details
    }
    st.session_state.scan_history.insert(0, item)
    st.session_state.total_scans += 1

    if risk >= 60:
        st.session_state.total_threats += 1

    st.session_state.last_scan = item


def risk_label(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def show_result(result, risk, details):
    st.markdown("---")
    st.subheader("🔍 Scan Results")

    c1, c2 = st.columns([1, 2])

    with c1:
        st.metric("Risk Score", f"{risk}/100")
        st.progress(risk / 100)

        if risk >= 80:
            st.error(f"🚨 {risk_label(risk)} RISK")
        elif risk >= 60:
            st.warning(f"⚠️ {risk_label(risk)} RISK")
        elif risk >= 35:
            st.info(f"🟠 {risk_label(risk)} RISK")
        else:
            st.success(f"🛡️ {risk_label(risk)} RISK")

    with c2:
        st.markdown(f"### {result}")
        st.write(details)
        st.caption(
            "Risk score is an estimate from available checks, "
            "not proof that content is safe or fraudulent."
        )


# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.markdown('<div class="brand">🛡️ SULTAN AI</div>',
                unsafe_allow_html=True)
    st.markdown(
        '<div class="brand-sub">TRUSTSHIELD SECURITY</div>',
        unsafe_allow_html=True
    )

    st.markdown("### WORKSPACE")
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Link Scanner",
            "Message Scanner",
            "Image Scanner",
            "Login Scanner",
            "Scan History"
        ],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("### SYSTEM STATUS")

    if sms_model is not None:
        st.success("Message ML model loaded")
    else:
        st.warning("Message scanner in demo/fallback mode")

    st.markdown(
        '<span class="status">● APPLICATION ONLINE</span>',
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.caption("SULTAN AI • TrustShield")
    st.caption("Cybersecurity demonstration platform")


# =========================================================
# HEADER
# =========================================================
left, right = st.columns([4, 1])

with left:
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-title">
                {"Security Overview" if page == "Overview" else html.escape(page)}
            </div>
            <div class="hero-sub">
                Intelligent fraud detection • Analyze threats before they reach you
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with right:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        '<div style="text-align:right">'
        '<span class="status">● SYSTEM READY</span></div>',
        unsafe_allow_html=True
    )


# =========================================================
# OVERVIEW DASHBOARD
# =========================================================
if page == "Overview":

    st.markdown("### Security at a glance")

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric("Items Scanned", f"{st.session_state.total_scans:,}")

    with m2:
        st.metric("Threats Detected", f"{st.session_state.total_threats:,}")

    with m3:
        blocked = max(
            0,
            round(st.session_state.total_threats * 0.948)
        )
        st.metric("Threats Flagged", f"{blocked:,}")

    with m4:
        if st.session_state.last_scan:
            avg_risk = st.session_state.last_scan["risk"]
        else:
            avg_risk = 24

        st.metric("Latest Risk Score", f"{avg_risk}/100")

    st.markdown("")

    left, right = st.columns([1.35, 1])

    with left:
        st.markdown(
            '<div class="panel">'
            '<div class="section-title">⚡ Quick Scan</div>'
            '<div class="section-subtitle">'
            'Analyze a suspicious message or URL'
            '</div></div>',
            unsafe_allow_html=True
        )

        quick_input = st.text_area(
            "Suspicious content",
            placeholder=(
                "Paste a suspicious link, SMS, email, "
                "or message here..."
            ),
            height=130,
            key="quick_scan_input"
        )

        if st.button("🛡️ Analyze Threat", use_container_width=True):
            if not quick_input.strip():
                st.warning("Enter a link or message first.")
            else:
                # Choose a basic scan based on the input.
                if re.match(r"^https?://", quick_input.strip(), re.I):
                    suspicious = bool(re.search(
                        r"bit\.ly|tinyurl|t\.co|login-verify|"
                        r"secure-account|free-gift|claim-prize",
                        quick_input,
                        re.I
                    ))
                    risk = 72 if suspicious else 20
                    result = (
                        "Suspicious URL patterns found"
                        if suspicious else
                        "No basic URL red flags found"
                    )
                    details = (
                        "A URL pattern matched a basic suspicious-pattern "
                        "rule. Verify the real destination independently."
                        if suspicious else
                        "Basic checks did not flag this URL. This does not "
                        "establish that the destination is safe."
                    )
                    scan_type = "Quick URL"
                else:
                    if sms_model is not None and sms_vectorizer is not None:
                        try:
                            features = sms_vectorizer.transform([quick_input])
                            prediction = str(
                                sms_model.predict(features)[0]
                            ).lower()

                            suspicious = prediction in [
                                "spam", "fraud", "scam", "1", "phishing"
                            ]
                            risk = 85 if suspicious else 15
                            result = (
                                "Potential scam message"
                                if suspicious else
                                "Message not flagged by the model"
                            )
                            details = (
                                "The loaded ML model classified this "
                                "message as suspicious."
                                if suspicious else
                                "The loaded ML model did not flag this "
                                "message. False negatives are possible."
                            )
                        except Exception:
                            risk = 40
                            result = "Unable to classify message"
                            details = "Check your model and vectorizer files."
                    else:
                        suspicious = bool(re.search(
                            r"urgent|verify your account|password|"
                            r"send otp|one.time password|claim your prize|"
                            r"bank account|click here|wire transfer|"
                            r"you have won|free money",
                            quick_input,
                            re.I
                        ))
                        risk = 70 if suspicious else 20
                        result = (
                            "Suspicious wording detected"
                            if suspicious else
                            "No basic suspicious wording detected"
                        )
                        details = (
                            "A basic keyword rule matched this message. "
                            "Manual verification is recommended."
                            if suspicious else
                            "Basic keyword checks found no match. "
                            "This is not proof the message is legitimate."
                        )

                    scan_type = "Quick Message"

                add_history(
                    scan_type, quick_input, result, risk, details
                )
                show_result(result, risk, details)

    with right:
        st.markdown(
            '<div class="panel">'
            '<div class="section-title">📡 Detection Modules</div>'
            '<div class="section-subtitle">'
            'Available scanning capabilities'
            '</div></div>',
            unsafe_allow_html=True
        )

        modules = [
            ("🔗", "Link Scanner", "Basic URL pattern checks"),
            ("💬", "Message Scanner", "ML model or fallback rules"),
            ("🖼️", "Image Scanner", "Upload and inspect images"),
            ("🔐", "Login Scanner", "Basic login URL checks")
        ]

        for icon, name, description in modules:
            st.markdown(
                f"""
                <div class="panel" style="padding:15px 18px">
                    <div style="font-size:17px;font-weight:700">
                        {icon} {name}
                    </div>
                    <div style="font-size:12px;color:#91a4ba;
                                margin-top:5px">
                        {description}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.markdown("### 🕒 Recent Detections")

    if st.session_state.scan_history:
        for item in st.session_state.scan_history[:5]:
            a, b, c = st.columns([3, 1, 2])
            with a:
                st.write(f"**{item['type']}**")
                st.caption(item["content"])
            with b:
                if item["risk"] >= 60:
                    st.error(item["risk"] and item["risk"])
                else:
                    st.success(item["risk"])
            with c:
                st.caption(item["time"])
            st.divider()
    else:
        st.info(
            "No scans in this session yet. Run your first scan above."
        )


# =========================================================
# LINK SCANNER
# =========================================================
elif page == "Link Scanner":

    st.markdown("## 🔗 Phishing Link Scanner")
    st.write(
        "Check URL formatting and common suspicious patterns. "
        "This is a preliminary rule-based check, not a live reputation lookup."
    )

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com/login"
    )

    if st.button("🔍 Scan URL", use_container_width=True):
        if not url.strip():
            st.warning("Enter a URL first.")
        else:
            raw = url.strip()
            candidate = raw if "://" in raw else "https://" + raw

            from urllib.parse import urlparse

            parsed = urlparse(candidate)
            host = parsed.hostname or ""
            reasons = []
            score = 0

            if parsed.scheme != "https":
                reasons.append("Connection is not HTTPS.")
                score += 15

            if not host or "." not in host:
                reasons.append("The hostname format looks unusual.")
                score += 35

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                reasons.append("The URL uses an IP address as its host.")
                score += 25

            if "@" in raw:
                reasons.append("The URL contains an @ symbol.")
                score += 25

            if len(raw) > 100:
                reasons.append("The URL is unusually long.")
                score += 10

            if host.count("-") >= 3:
                reasons.append("The hostname contains many hyphens.")
                score += 15

            if host.startswith("xn--") or ".xn--" in host:
                reasons.append("The hostname uses an internationalized label.")
                score += 20

            suspicious_terms = [
                "login-verify", "secure-account", "account-verify",
                "free-gift", "claim-prize", "password-reset",
                "wallet-connect", "bank-verify"
            ]

            if any(term in raw.lower() for term in suspicious_terms):
                reasons.append("The URL contains a suspicious keyword pattern.")
                score += 30

            score = min(score, 100)

            if score >= 60:
                result = "Potentially dangerous URL"
            elif score >= 30:
                result = "URL requires further verification"
            else:
                result = "No basic URL red flags found"

            details = (
                " ".join(reasons)
                if reasons else
                "No configured suspicious patterns were detected."
            )

            add_history("Link Scanner", raw, result, score, details)
            show_result(result, score, details)


# =========================================================
# MESSAGE SCANNER
# =========================================================
elif page == "Message Scanner":

    st.markdown("## 💬 Message & Email Scanner")
    st.write("Analyze suspicious SMS, email text, or chat messages.")

    message = st.text_area(
        "Message content",
        height=220,
        placeholder=(
            "Example: Your account will be blocked. "
            "Click this link and verify your password..."
        )
    )

    if st.button("🛡️ Scan Message", use_container_width=True):
        if not message.strip():
            st.warning("Enter a message first.")
        else:
            if sms_model is not None and sms_vectorizer is not None:
                try:
                    X = sms_vectorizer.transform([message])
                    prediction = str(sms_model.predict(X)[0]).lower()

                    suspicious = prediction in [
                        "spam", "fraud", "scam", "1", "phishing"
                    ]

                    if hasattr(sms_model, "predict_proba"):
                        probs = sms_model.predict_proba(X)[0]
                        classes = [
                            str(c).lower()
                            for c in sms_model.classes_
                        ]
                        suspicious_indices = [
                            i for i, c in enumerate(classes)
                            if c in [
                                "spam", "fraud", "scam",
                                "1", "phishing"
                            ]
                        ]

                        if suspicious_indices:
                            risk = round(
                                max(probs[i] for i in suspicious_indices)
                                * 100
                            )
                        else:
                            risk = 75 if suspicious else 15
                    else:
                        risk = 80 if suspicious else 20

                    result = (
                        "Potential scam detected"
                        if suspicious else
                        "Message not flagged by the model"
                    )

                    details = (
                        f"Model prediction: {prediction}. "
                        "Review the sender and verify any request "
                        "for money, credentials, or OTPs."
                    )

                except Exception as e:
                    st.error(f"Model error: {e}")
                    st.stop()

            else:
                suspicious_words = [
                    "urgent", "verify your account", "password",
                    "send otp", "one-time password", "claim your prize",
                    "bank account", "click here", "free money",
                    "you have won", "limited time", "payment failed"
                ]

                matches = [
                    word for word in suspicious_words
                    if word in message.lower()
                ]

                risk = min(15 + len(matches) * 18, 90)
                suspicious = risk >= 50

                result = (
                    "Suspicious wording detected"
                    if suspicious else
                    "No strong keyword match found"
                )

                details = (
                    "Matched patterns: " + ", ".join(matches)
                    if matches else
                    "No configured suspicious keywords matched. "
                    "This does not prove the message is safe."
                )

            add_history("Message Scanner", message, result, risk, details)
            show_result(result, risk, details)


# =========================================================
# IMAGE SCANNER
# =========================================================
elif page == "Image Scanner":

    st.markdown("## 🖼️ Suspicious Screenshot Analyzer")
    st.write(
        "Upload a screenshot of a suspicious message, email, "
        "payment request, or website."
    )

    uploaded = st.file_uploader(
        "Upload screenshot",
        type=["png", "jpg", "jpeg", "webp"]
    )

    if uploaded:
        st.image(uploaded, caption="Uploaded screenshot", use_container_width=True)

        st.info(
            "Image uploaded. OCR is not configured in this version, "
            "so the image content has not been automatically analyzed."
        )

        if st.button("Record Image for Review", use_container_width=True):
            details = (
                f"File: {uploaded.name}. "
                "Manual review required; OCR is not enabled."
            )
            add_history(
                "Image Scanner",
                uploaded.name,
                "Image awaiting review",
                0,
                details
            )
            st.success("Image recorded in session history.")


# =========================================================
# LOGIN SCANNER
# =========================================================
elif page == "Login Scanner":

    st.markdown("## 🔐 Login Page Safety Check")
    st.write(
        "Perform basic URL checks before entering credentials. "
        "This does not inspect the actual website or verify its owner."
    )

    login_url = st.text_input(
        "Login page URL",
        placeholder="https://your-bank.example/login"
    )

    if st.button("🔐 Check Login URL", use_container_width=True):
        if not login_url.strip():
            st.warning("Enter a login page URL.")
        else:
            from urllib.parse import urlparse

            candidate = login_url.strip()
            if "://" not in candidate:
                candidate = "https://" + candidate

            parsed = urlparse(candidate)
            host = parsed.hostname or ""
            risk = 0
            reasons = []

            if parsed.scheme != "https":
                risk += 25
                reasons.append("HTTPS is not being used.")

            if not host or "." not in host:
                risk += 30
                reasons.append("Hostname appears invalid.")

            if "@" in login_url:
                risk += 30
                reasons.append("The URL includes an @ symbol.")

            if any(x in host.lower() for x in [
                "login-verify", "secure-account",
                "bank-verify", "password-reset"
            ]):
                risk += 35
                reasons.append("Suspicious login-related hostname pattern.")

            risk = min(risk, 100)

            result = (
                "Review this login page carefully"
                if risk >= 30 else
                "No configured red flags detected"
            )

            details = (
                " ".join(reasons)
                if reasons else
                "No basic red flags were detected. "
                "Check the domain through the official organization."
            )

            add_history("Login Scanner", login_url, result, risk, details)
            show_result(result, risk, details)


# =========================================================
# SCAN HISTORY
# =========================================================
elif page == "Scan History":

    st.markdown("## 📜 Scan History")
    st.write("Results from the current application session.")

    if st.session_state.scan_history:
        if st.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.rerun()

        for i, item in enumerate(st.session_state.scan_history):
            with st.expander(
                f"{item['type']} • {item['time']} • "
                f"Risk {item['risk']}/100"
            ):
                st.write("**Content:**", item["content"])
                st.write("**Result:**", item["result"])
                st.write("**Details:**", item["details"])
                st.write("**Risk level:**", risk_label(item["risk"]))
    else:
        st.info("No scans have been recorded in this session.")

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.markdown(
    """
    <div style="text-align:center;color:#71869e;font-size:12px">
        <b style="color:#f5c542">SULTAN AI</b> · TrustShield Fraud Defense
        <br><br>
        Security assistance, not a guarantee. Always verify suspicious
        requests through official channels.
    </div>
    """,
    unsafe_allow_html=True
)
