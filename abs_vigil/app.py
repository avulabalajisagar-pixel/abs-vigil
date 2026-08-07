import streamlit as st
import numpy as np
import datetime
import time
import random
from PIL import Image
from pyzbar.pyzbar import decode

from core import db
from core.url_analysis import analyze_url_structure, valid_url, get_root_domain
from core.domain_analysis import analyze_domain
from core.threat_intel import run_threat_intel
from core.scoring import compute_final_score
from core.sms_analysis import analyze_sms

# ---------------------------------
# ABS VIGIL Configuration
# ---------------------------------

st.set_page_config(
    page_title="ABS VIGIL | Advanced Behavioral Shield",
    page_icon="🛡️",
    layout="centered"
)

# ---------------------------------
# Terminal / Hacker Theme
# ---------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, sans-serif !important;
}

.stApp {
    background: linear-gradient(180deg, #0b0f14 0%, #0e1420 100%);
}

h1 { color: #e6edf3 !important; font-weight: 700 !important; letter-spacing: -0.5px; }
h2, h3 { color: #7dd3c0 !important; font-weight: 600 !important; }
p, li, span, label, .stMarkdown { color: #c9d1d9; }

.stButton > button {
    background-color: #12181f; color: #5eead4; border: 1px solid #22303c;
    border-radius: 6px; font-family: 'Inter', sans-serif; font-weight: 500;
    padding: 0.5rem 1.1rem; transition: all 0.15s ease-in-out;
}
.stButton > button:hover { background-color: #14b8a6; color: #0b0f14; border-color: #14b8a6; }

.stTextInput > div > div > input, .stTextArea > div > div > textarea {
    background-color: #0d1117; color: #e6edf3; border: 1px solid #22303c;
    border-radius: 6px; font-family: 'JetBrains Mono', monospace;
}
.stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {
    border: 1px solid #14b8a6; box-shadow: 0 0 0 1px #14b8a6;
}

div[data-testid="stExpander"] { background-color: #0d1117; border: 1px solid #21262d; border-radius: 8px; }
div[data-testid="stExpander"] summary { color: #e6edf3; font-weight: 600; }

code { color: #7dd3c0 !important; background-color: #131a22 !important; }

button[data-baseweb="tab"] { font-family: 'Inter', sans-serif; font-weight: 500; color: #8b949e; }
button[data-baseweb="tab"][aria-selected="true"] { color: #5eead4; border-bottom: 2px solid #14b8a6 !important; }

.stProgress > div > div > div > div { background-color: #14b8a6; }

.status-line { font-family: 'JetBrains Mono', monospace; color: #5eead4; font-size: 0.9rem; opacity: 0.85; margin-top: -8px; }
.status-line .cursor::after { content: "▌"; animation: blink 1.1s step-start infinite; }
@keyframes blink { 50% { opacity: 0; } }

.abs-metric-row { display: flex; gap: 14px; margin-bottom: 6px; }
.abs-metric-card { flex: 1; background-color: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 14px 16px; }
.abs-metric-label { font-family: 'Inter', sans-serif; font-size: 0.78rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 4px; }
.abs-metric-value { font-family: 'JetBrains Mono', monospace; font-size: 1.5rem; font-weight: 600; white-space: nowrap; }

.abs-badge {
    display: inline-block; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
    padding: 2px 8px; border-radius: 10px; margin-right: 6px; margin-bottom: 4px;
    background-color: #131a22; border: 1px solid #22303c; color: #5eead4;
}
.abs-roadmap {
    font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #8b949e;
    border-left: 2px solid #22303c; padding-left: 10px; margin: 6px 0;
}
</style>
""", unsafe_allow_html=True)

db.init_db()

SCAN_FLAVOR_MESSAGES = [
    "🛰️  Establishing secure uplink to threat intelligence grid...",
    "🌐  Cross-referencing global malware signature databases...",
    "🧬  Fingerprinting domain infrastructure...",
    "📡  Querying WHOIS registries across regional nodes...",
    "🔐  Validating SSL/TLS certificate chain of trust...",
    "🕵️  Scanning for homograph and lookalike domain patterns...",
    "📊  Aggregating multi-engine reputation scores...",
    "🧠  Running behavioral risk heuristics...",
    "🔗  Cross-referencing entity risk graph...",
]

SMS_FLAVOR_MESSAGES = [
    "📨  Parsing message structure...",
    "🧠  Scoring social-engineering intent (urgency / fear / authority)...",
    "🔗  Extracting and resolving embedded links...",
    "🏷️  Fingerprinting brand impersonation patterns...",
    "📞  Evaluating sender ID spoofing risk...",
    "🕸️  Cross-referencing entity risk graph...",
]


def run_scan_animation(label="TARGET", messages=None):
    placeholder = st.empty()
    progress = st.progress(0)
    pool = messages or SCAN_FLAVOR_MESSAGES
    steps = random.sample(pool, k=min(5, len(pool)))

    for i, msg in enumerate(steps):
        pct = int(((i + 1) / len(steps)) * 100)
        placeholder.markdown(
            f"<span style='font-family:JetBrains Mono, monospace; color:#14b8a6; font-weight:600;'>[{pct:3d}%]</span> "
            f"<span style='font-family:JetBrains Mono, monospace; color:#8b949e;'>{msg}</span>",
            unsafe_allow_html=True
        )
        progress.progress(pct)
        time.sleep(0.18)

    placeholder.markdown(
        f"<span style='font-family:JetBrains Mono, monospace; color:#14b8a6; font-weight:600;'>[100%]</span> "
        f"<span style='font-family:JetBrains Mono, monospace; color:#8b949e;'>Scan sequence complete for {label}. Compiling report...</span>",
        unsafe_allow_html=True
    )
    time.sleep(0.25)
    placeholder.empty()
    progress.empty()


def risk_metric_row(final_score, risk_level, confidence):
    risk_colors = {"High Risk 🔴": "#f85149", "Medium Risk 🟡": "#e3b341", "Low Risk 🟢": "#3fb950"}
    score_color = risk_colors.get(risk_level, "#5eead4")
    st.markdown(f"""
    <div class="abs-metric-row">
        <div class="abs-metric-card">
            <div class="abs-metric-label">Risk Score</div>
            <div class="abs-metric-value" style="color:{score_color};">{final_score}/100</div>
        </div>
        <div class="abs-metric-card">
            <div class="abs-metric-label">Threat Level</div>
            <div class="abs-metric-value" style="color:{score_color};">{risk_level}</div>
        </div>
        <div class="abs-metric-card">
            <div class="abs-metric-label">Confidence</div>
            <div class="abs-metric-value" style="color:#5eead4;">{confidence}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------
# URL / QR pipeline (shared)
# ---------------------------------

def render_full_report(url, source="manual"):
    run_scan_animation(label=url[:40])

    with st.spinner("Parsing URL structure, encoding patterns and brand-impersonation signals..."):
        structure_result = analyze_url_structure(url)

    with st.spinner("Resolving domain fingerprint (WHOIS / SSL / DNS)..."):
        domain_result = analyze_domain(url)

    final_score, risk_level, confidence = compute_final_score(structure_result, domain_result)

    scan_id = db.save_scan(
        url, final_score, risk_level, confidence,
        {"structure": structure_result, "domain": domain_result, "threat_intel": None},
        channel=source if source == "qr" else "url"
    )

    root = structure_result.get("root_domain") or get_root_domain(url)
    db.upsert_entity("domain", root, final_score, risk_level, channel=(source if source == "qr" else "url"))

    st.session_state["last_url"] = url
    st.session_state["last_source"] = source
    st.session_state["structure_result"] = structure_result
    st.session_state["domain_result"] = domain_result
    st.session_state["threat_intel_result"] = None
    st.session_state["final_score"] = final_score
    st.session_state["risk_level"] = risk_level
    st.session_state["confidence"] = confidence
    st.session_state["current_scan_id"] = scan_id


def display_report(source="manual"):
    if st.session_state.get("last_source") != source:
        return
    if "last_url" not in st.session_state:
        return

    url = st.session_state["last_url"]
    structure_result = st.session_state["structure_result"]
    domain_result = st.session_state["domain_result"]
    threat_intel_result = st.session_state.get("threat_intel_result")
    final_score = st.session_state["final_score"]
    risk_level = st.session_state["risk_level"]
    confidence = st.session_state["confidence"]

    st.subheader("🛡️ ABS THREAT REPORT")
    risk_metric_row(final_score, risk_level, confidence)

    with st.expander("🧩 URL Structure Analysis", expanded=True):
        st.write(f"Sub-score: {structure_result['score']}/100")
        for r in structure_result["reasons"]:
            st.write(f"- {r}")
        if structure_result.get("redirect_chain") and len(structure_result["redirect_chain"]) > 1:
            st.write("Redirect chain:")
            for hop in structure_result["redirect_chain"]:
                st.code(hop)

    brand = structure_result.get("brand_impersonation")
    with st.expander("🏷️ Brand Impersonation Engine", expanded=bool(brand and brand["score"] > 0)):
        if brand:
            st.write(f"Sub-score: {brand['score']}/100")
            if brand.get("matched_brand"):
                st.write(f"Closest brand match: **{brand['matched_brand']}**")
            for r in brand["reasons"]:
                st.write(f"- {r}")

    with st.expander("🌐 Domain Analysis", expanded=True):
        st.write(f"Sub-score: {domain_result['score']}/100")
        for r in domain_result["reasons"]:
            st.write(f"- {r}")

    with st.expander("🕸️ Entity Risk Graph", expanded=False):
        root = structure_result.get("root_domain")
        prior = db.lookup_entity(root) if root else None
        if prior and prior["times_seen"] > 1:
            st.write(f"This domain has been seen **{prior['times_seen']}** time(s) across channels: "
                     f"{', '.join(f'`{c}`' for c in prior['channels'])}")
            st.write(f"Highest score on record: {prior['max_score']}/100 ({prior['worst_risk_level']})")
        else:
            st.info("First time this domain has been seen across any channel.")

    with st.expander("🔎 Threat Intelligence", expanded=True):
        if threat_intel_result is None:
            st.info("Not yet run — click below to query VirusTotal + Google Safe Browsing.")
            if st.button("🔍 Run Threat Intelligence Scan", key=f"ti_btn_{source}"):
                with st.spinner("Dispatching payload to VirusTotal + Google Safe Browsing networks..."):
                    ti_result = run_threat_intel(url)
                st.session_state["threat_intel_result"] = ti_result
                final_score, risk_level, confidence = compute_final_score(
                    structure_result, domain_result, ti_result
                )
                st.session_state["final_score"] = final_score
                st.session_state["risk_level"] = risk_level
                st.session_state["confidence"] = confidence

                scan_id = st.session_state.get("current_scan_id")
                if scan_id is not None:
                    db.update_scan(
                        scan_id, final_score, risk_level, confidence,
                        {"structure": structure_result, "domain": domain_result, "threat_intel": ti_result}
                    )
                root = structure_result.get("root_domain")
                if root:
                    db.upsert_entity("domain", root, final_score, risk_level, channel=(source if source == "qr" else "url"))
                st.rerun()
        else:
            vt = threat_intel_result["vt"]
            gsb = threat_intel_result["gsb"]

            st.write("**VirusTotal**")
            if vt.get("available") and "stats" in vt:
                mal_count = threat_intel_result.get("vt_malicious_count", 0)
                if mal_count == 0:
                    st.write("✅ 0 engines flagged this URL as malicious")
                elif mal_count < 3:
                    st.write(f"⚠️ {mal_count} engine(s) flagged this URL — below the 3-engine "
                             "consensus threshold, treated as noise rather than a confirmed threat")
                else:
                    st.write(f"🔴 {mal_count} engines flagged this URL — confirmed threat")
                st.json(vt["stats"])
            else:
                st.write(f"- {vt.get('reason', 'Unavailable')}")

            st.write("**Google Safe Browsing**")
            if gsb.get("available"):
                st.write("⚠️ Flagged as threat" if gsb["flagged"] else "✅ No threats found")
            else:
                st.write(f"- {gsb.get('reason', 'Unavailable')}")


# ---------------------------------
# SMS pipeline
# ---------------------------------

def render_sms_report(text, sender_id):
    run_scan_animation(label="SMS", messages=SMS_FLAVOR_MESSAGES)

    with st.spinner("Scoring message and cross-referencing entity graph..."):
        result = analyze_sms(text, sender_id)

    scan_id = db.save_scan(
        (sender_id or "unknown sender") + " — " + text[:80],
        result["final_score"], result["risk_level"], "High" if result["urls"] else "Medium",
        result,
        channel="sms"
    )
    st.session_state["sms_result"] = result
    st.session_state["sms_scan_id"] = scan_id
    st.session_state["sms_text"] = text
    st.session_state["sms_sender"] = sender_id


def display_sms_report():
    if "sms_result" not in st.session_state:
        return
    result = st.session_state["sms_result"]

    st.subheader("📱 SMS THREAT REPORT")
    risk_metric_row(result["final_score"], result["risk_level"],
                     "High" if result["urls"] else "Medium")

    with st.expander("🧠 Social Engineering Intent Score", expanded=True):
        intent = result["intent"]
        st.write(f"Sub-score: {intent['score']}/100 — **{intent['label']}**")
        st.markdown(f"<span class='abs-badge'>engine: {intent['engine']}</span>", unsafe_allow_html=True)
        if intent.get("explanation"):
            st.write(f"_{intent['explanation']}_")
        if intent.get("category_hits"):
            st.write("Manipulation categories detected:")
            for cat, count in intent["category_hits"].items():
                st.write(f"- {cat.replace('_', ' ').title()}: {count} pattern match(es)")
        else:
            st.write("No manipulation-language patterns matched.")

    with st.expander("📞 Sender ID Analysis", expanded=True):
        sender = result["sender"]
        st.write(f"Sub-score: {sender['score']}/100 — type: **{sender['sender_type']}**")
        for r in sender["reasons"]:
            st.write(f"- {r}")
        st.markdown(
            "<div class='abs-roadmap'>🔧 Roadmap: carrier-level sender verification "
            "(confirming a message genuinely originated from the claimed shortcode/operator) "
            "requires a telecom API partnership — not simulated here.</div>",
            unsafe_allow_html=True
        )

    with st.expander("🔗 Embedded Link Analysis", expanded=bool(result["urls"])):
        if not result["urls"]:
            st.info("No URLs detected in this message.")
        for u in result["urls"]:
            st.write(f"**{u['url']}** — combined score: {u['combined_score']}/100")
            for r in u["structure"]["reasons"]:
                st.write(f"- {r}")
            brand = u["structure"].get("brand_impersonation")
            if brand and brand["score"] > 0:
                st.write(f"- ⚠️ Brand impersonation: {', '.join(brand['reasons'])}")
            st.divider()

    if result["reinforcement_notes"]:
        with st.expander("🕸️ Cross-Channel Entity Risk Graph", expanded=True):
            st.write(f"Reinforcement bonus applied: **+{result['reinforcement_bonus']}**")
            for note in result["reinforcement_notes"]:
                st.write(f"- {note}")


# ---------------------------------
# Page Layout
# ---------------------------------

st.title("🛡️ ABS VIGIL")
st.markdown(
    "<p class='status-line'>root@abs-vigil:~$ system armed and monitoring <span class='cursor'></span></p>",
    unsafe_allow_html=True
)
st.subheader("Advanced Behavioral Shield")
st.write(
    """
    A unified, multi-channel cybersecurity platform: URL, QR, and SMS scanning
    feeding into one cross-channel **Entity Risk Graph** — so a phishing domain
    caught in one channel is instantly recognized when it resurfaces in another.
    """
)

tab_scan, tab_qr, tab_sms, tab_history, tab_about = st.tabs(
    ["🌐 URL Scanner", "📱 QR Scanner", "💬 SMS Scanner", "🗂️ Scan History", "ℹ️ About / Roadmap"]
)

with tab_scan:
    st.write("Enter a URL to run it through the full ABS VIGIL pipeline: "
             "URL Structure → Brand Impersonation → Domain Analysis → Threat Intel → Risk Scoring.")

    url_input = st.text_input("Enter website URL", key="manual_url")

    if st.button("Analyze Threat", key="analyze_btn"):
        if not url_input:
            st.error("Please enter a URL")
        elif not valid_url(url_input):
            st.error("Invalid URL format")
        else:
            render_full_report(url_input, source="manual")

    display_report(source="manual")

with tab_qr:
    st.write("Upload a QR code image to extract and analyze its embedded URL.")

    uploaded_file = st.file_uploader(
        "Upload QR Code Image", type=["png", "jpg", "jpeg"], key="qr_upload"
    )

    if uploaded_file:
        image = Image.open(uploaded_file)
        img_array = np.array(image.convert("L"))
        result = decode(img_array)

        if result:
            qr_data = result[0].data.decode("utf-8")
            st.success("QR Code successfully decoded")
            st.write("Extracted Data:")
            st.code(qr_data)

            if valid_url(qr_data):
                if st.button("Analyze QR URL", key="qr_analyze_btn"):
                    render_full_report(qr_data, source="qr")
                display_report(source="qr")
            else:
                st.warning("QR code does not contain a valid URL")
        else:
            st.warning("No QR code detected")

with tab_sms:
    st.write(
        "Paste a suspicious SMS/text message to check for smishing patterns — "
        "social-engineering language, embedded links, and sender ID spoofing."
    )

    sender_input = st.text_input(
        "Sender ID / phone number (optional)", key="sms_sender_input",
        placeholder="e.g. +1-202-555-0181 or 'AMAZON'"
    )
    sms_text = st.text_area(
        "Message text", key="sms_text_input", height=140,
        placeholder="Paste the SMS content here..."
    )

    if st.button("Analyze Message", key="sms_analyze_btn"):
        if not sms_text.strip():
            st.error("Please paste a message to analyze")
        else:
            render_sms_report(sms_text, sender_input)

    display_sms_report()

with tab_history:
    st.write("Past scans stored locally in SQLite, across all channels.")

    channel_filter = st.selectbox(
        "Filter by channel", ["All", "url", "qr", "sms"], key="history_filter"
    )
    rows = db.load_history(channel=None if channel_filter == "All" else channel_filter)

    if rows:
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🗑️ Clear History"):
                db.clear_history()
                st.rerun()

        st.table(
            [
                {
                    "Time": r[0],
                    "Channel": r[1],
                    "Target": (r[2][:50] + "...") if len(r[2]) > 50 else r[2],
                    "Score": r[3],
                    "Risk Level": r[4],
                    "Confidence": r[5]
                }
                for r in rows
            ]
        )
    else:
        st.info("No scans recorded yet. Run a scan to see history here.")

with tab_about:
    st.write("### Why ABS VIGIL is architected this way")
    st.write(
        "Most phishing tools score a single artifact in isolation. Real attacks today are "
        "multi-channel — a domain surfaces in an SMS, then an email, then a QR code — and "
        "ABS VIGIL's Entity Risk Graph correlates those sightings instead of treating each "
        "scan as a blank slate."
    )
    st.write("### Roadmap (scoped out for this build, not faked)")
    st.markdown(
        "- **Cloaking Detector** — diff server responses across different user-agents/geos "
        "to catch pages that serve a clean version to scanners and a malicious one to real victims.\n"
        "- **Email Scanner** — header forensics (SPF/DKIM/DMARC alignment), attachment scanning, "
        "and nested-QR (quishing) extraction from PDFs.\n"
        "- **Carrier-level sender verification** for SMS — requires a telecom API partnership.\n"
        "- **Favicon/visual similarity hashing** for brand impersonation at the pixel level.\n"
        "- **Browser extension** for real-time protection at click-time, not just on-demand scanning.\n"
        "- **Public API** for enterprise integration (Slack/Teams bots, SOC pipelines)."
    )

st.divider()
st.caption("🛡️ ABS VIGIL | Advanced Behavioral Shield | Cyber Threat Intelligence Platform")
