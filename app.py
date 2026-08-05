import streamlit as st
import numpy as np
import requests
import re
import base64
import sqlite3
import json
import socket
import ssl
import math
import datetime
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import urlparse

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import tldextract
except ImportError:
    tldextract = None


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

/* Titles */
h1 {
    color: #e6edf3 !important;
    font-weight: 700 !important;
    letter-spacing: -0.5px;
}
h1::before {
    content: none;
}
h2, h3 {
    color: #7dd3c0 !important;
    font-weight: 600 !important;
}

/* Body text */
p, li, span, label, .stMarkdown {
    color: #c9d1d9;
}

/* Buttons */
.stButton > button {
    background-color: #12181f;
    color: #5eead4;
    border: 1px solid #22303c;
    border-radius: 6px;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    padding: 0.5rem 1.1rem;
    transition: all 0.15s ease-in-out;
}
.stButton > button:hover {
    background-color: #14b8a6;
    color: #0b0f14;
    border-color: #14b8a6;
}

/* Text input */
.stTextInput > div > div > input {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #22303c;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
}
.stTextInput > div > div > input:focus {
    border: 1px solid #14b8a6;
    box-shadow: 0 0 0 1px #14b8a6;
}

/* Expanders as clean panel cards */
div[data-testid="stExpander"] {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
}
div[data-testid="stExpander"] summary {
    color: #e6edf3;
    font-weight: 600;
}

/* Code blocks */
code {
    color: #7dd3c0 !important;
    background-color: #131a22 !important;
}

/* Tabs */
button[data-baseweb="tab"] {
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    color: #8b949e;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #5eead4;
    border-bottom: 2px solid #14b8a6 !important;
}

/* Progress bar */
.stProgress > div > div > div > div {
    background-color: #14b8a6;
}

/* Terminal-style status line under the title */
.status-line {
    font-family: 'JetBrains Mono', monospace;
    color: #5eead4;
    font-size: 0.9rem;
    opacity: 0.85;
    margin-top: -8px;
}
.status-line .cursor::after {
    content: "▌";
    animation: blink 1.1s step-start infinite;
}
@keyframes blink { 50% { opacity: 0; } }

/* Custom risk badges (replace default st.metric where used) */
.abs-metric-row {
    display: flex;
    gap: 14px;
    margin-bottom: 6px;
}
.abs-metric-card {
    flex: 1;
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px 16px;
}
.abs-metric-label {
    font-family: 'Inter', sans-serif;
    font-size: 0.78rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 4px;
}
.abs-metric-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 600;
    white-space: nowrap;
}
</style>
""", unsafe_allow_html=True)

DB_PATH = "abs_vigil_history.db"

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "tiny.cc", "rebrand.ly", "shorte.st", "cutt.ly",
    "rb.gy", "shorturl.at", "v.gd", "s.id"
}

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "bank",
    "password", "free", "gift", "confirm", "signin", "payment",
    "wallet", "crypto"
]


# ---------------------------------
# Database Layer
# ---------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            url TEXT,
            final_score INTEGER,
            risk_level TEXT,
            confidence TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(url, final_score, risk_level, confidence, details):
    """Insert a new scan row and return its id, so a later update (e.g.
    once Threat Intel finishes) can revise this same row instead of
    creating a duplicate entry."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (timestamp, url, final_score, risk_level, confidence, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            final_score,
            risk_level,
            confidence,
            json.dumps(details)
        )
    )
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def update_scan(scan_id, final_score, risk_level, confidence, details):
    """Revise an existing scan row in place, used when Threat Intel
    completes after the initial structure/domain result was already
    saved — avoids a duplicate 'incomplete' entry in Scan History."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE scans SET final_score = ?, risk_level = ?, confidence = ?, details = ? "
        "WHERE id = ?",
        (final_score, risk_level, confidence, json.dumps(details), scan_id)
    )
    conn.commit()
    conn.close()


def load_history(limit=100):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, url, final_score, risk_level, confidence FROM scans "
        "ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return rows


def clear_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


init_db()


# ---------------------------------
# URL Validation
# ---------------------------------

def valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except Exception:
        return False


# ---------------------------------
# Branch 1: URL Structure Analysis
# ---------------------------------

def shannon_entropy(s):
    if not s:
        return 0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def resolve_redirect_chain(url, max_hops=5):
    chain = [url]
    current = url
    try:
        for _ in range(max_hops):
            resp = requests.head(current, allow_redirects=False, timeout=5)
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                next_url = resp.headers["Location"]
                chain.append(next_url)
                current = next_url
            else:
                break
    except requests.exceptions.RequestException:
        pass
    return chain


def analyze_url_structure(url):
    score = 0
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            score += 8
            reasons.append(f"Suspicious keyword detected: '{word}'")

    if len(url) > 100:
        score += 12
        reasons.append("Unusually long URL")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("Direct IP address used instead of domain")

    if "@" in url:
        score += 20
        reasons.append("Possible spoofing using '@' symbol")

    if url.count("-") > 3:
        score += 8
        reasons.append("Excessive hyphens in URL")

    # Punycode / homograph detection
    if "xn--" in domain:
        score += 25
        reasons.append("Punycode domain detected (possible homograph/lookalike attack)")

    # Subdomain depth
    subdomain_depth = domain.count(".")
    if subdomain_depth > 3:
        score += 10
        reasons.append(f"Unusually deep subdomain structure ({subdomain_depth} levels)")

    # Shortener detection
    root_domain = domain.split(":")[0]
    if root_domain in KNOWN_SHORTENERS:
        score += 15
        reasons.append(f"Known URL shortener detected: {root_domain}")

    # Entropy (randomness of domain name — DGA-style domains score high)
    domain_label = root_domain.split(".")[0]
    entropy = shannon_entropy(domain_label)
    if entropy > 3.8 and len(domain_label) > 8:
        score += 15
        reasons.append(f"High domain entropy ({entropy:.2f}) — possibly auto-generated")

    # Redirect chain
    redirect_chain = []
    if root_domain in KNOWN_SHORTENERS:
        redirect_chain = resolve_redirect_chain(url)
        if len(redirect_chain) > 1:
            reasons.append(f"URL redirects {len(redirect_chain) - 1} time(s) before final destination")
            score += 5 * (len(redirect_chain) - 1)

    score = min(score, 100)

    if not reasons:
        reasons.append("No structural red flags detected")

    return {
        "score": score,
        "reasons": reasons,
        "redirect_chain": redirect_chain
    }


# ---------------------------------
# Branch 2: Domain Analysis
# ---------------------------------

def check_domain_age(domain):
    if whois_lib is None:
        return None, "python-whois not installed"
    try:
        w = whois_lib.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None, "Creation date unavailable"
        if isinstance(creation, str):
            return None, "Could not parse creation date"

        # Some WHOIS servers return timezone-aware datetimes, others
        # naive ones. Normalize both to naive UTC before subtracting,
        # otherwise Python raises "can't subtract offset-naive and
        # offset-aware datetimes".
        if creation.tzinfo is not None:
            creation = creation.astimezone(datetime.timezone.utc).replace(tzinfo=None)

        age_days = (datetime.datetime.utcnow() - creation).days
        return age_days, w.registrar
    except Exception as e:
        return None, f"WHOIS lookup failed: {e}"


def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.now()).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "valid": True,
                    "days_until_expiry": days_left,
                    "issuer": issuer.get("organizationName", "Unknown")
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_dns_resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def analyze_domain(url):
    score = 0
    reasons = []
    details = {}

    parsed = urlparse(url)
    netloc = parsed.netloc.split(":")[0]

    if tldextract:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
    else:
        domain = netloc

    # Run DNS, WHOIS, and SSL checks concurrently — all three are
    # independent network calls, so there's no reason to wait on them
    # one after another. SSL will simply fail gracefully if DNS can't
    # resolve, so it's safe to fire alongside the DNS check.
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(check_dns_resolves, netloc): "dns",
            executor.submit(check_domain_age, domain): "whois",
            executor.submit(check_ssl_certificate, netloc): "ssl",
        }
        results = {}
        for future in as_completed(futures):
            label = futures[future]
            try:
                results[label] = future.result()
            except Exception as e:
                results[label] = e

    # DNS resolution
    resolves = results.get("dns")
    if isinstance(resolves, Exception):
        resolves = False
    details["dns_resolves"] = resolves
    if not resolves:
        score += 30
        reasons.append("Domain does not resolve via DNS")

    # WHOIS domain age
    whois_result = results.get("whois")
    if isinstance(whois_result, Exception):
        age_days, registrar_or_error = None, f"WHOIS lookup failed: {whois_result}"
    else:
        age_days, registrar_or_error = whois_result
    details["domain_age_days"] = age_days
    details["registrar_info"] = registrar_or_error
    if age_days is not None:
        if age_days < 30:
            score += 30
            reasons.append(f"Domain registered very recently ({age_days} days ago)")
        elif age_days < 180:
            score += 15
            reasons.append(f"Domain is relatively new ({age_days} days old)")
        else:
            reasons.append(f"Domain age: {age_days} days (established)")
    else:
        reasons.append(f"Domain age unknown ({registrar_or_error})")

    # SSL certificate
    ssl_info = results.get("ssl")
    if isinstance(ssl_info, Exception):
        ssl_info = {"valid": False, "error": str(ssl_info)}
    details["ssl"] = ssl_info
    if resolves:
        if not ssl_info.get("valid"):
            score += 20
            reasons.append("No valid SSL certificate found")
        elif ssl_info.get("days_until_expiry", 0) < 0:
            score += 15
            reasons.append("SSL certificate has expired")
        else:
            reasons.append(f"Valid SSL certificate (issuer: {ssl_info.get('issuer')})")

    score = min(score, 100)

    return {
        "score": score,
        "reasons": reasons,
        "details": details
    }


# ---------------------------------
# Branch 3: Threat Intelligence
# ---------------------------------

@st.cache_data(ttl=600, show_spinner=False)
def check_virustotal(url):
    try:
        api_key = st.secrets["VT_API_KEY"]
    except Exception:
        return {"available": False, "reason": "VirusTotal API key not configured"}

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"available": False, "reason": f"Network error: {e}"}

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        vt_score = min(100, int(((malicious * 2 + suspicious) / total) * 100))
        return {"available": True, "stats": stats, "score": vt_score}
    elif response.status_code == 404:
        return {"available": False, "reason": "URL not found in VirusTotal database", "score": 0}
    else:
        return {"available": False, "reason": f"Request failed (status {response.status_code})"}


@st.cache_data(ttl=600, show_spinner=False)
def check_google_safe_browsing(url):
    try:
        api_key = st.secrets["GSB_API_KEY"]
    except Exception:
        return {"available": False, "reason": "Google Safe Browsing API key not configured"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "abs-vigil", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"available": False, "reason": f"Network error: {e}"}

    if response.status_code == 200:
        data = response.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "flagged": len(matches) > 0,
            "matches": matches,
            "score": 100 if matches else 0
        }
    else:
        return {"available": False, "reason": f"Request failed (status {response.status_code})"}


def run_threat_intel(url):
    # VT and GSB are independent HTTP calls to different services —
    # run them concurrently instead of waiting on VT before starting GSB.
    with ThreadPoolExecutor(max_workers=2) as executor:
        vt_future = executor.submit(check_virustotal, url)
        gsb_future = executor.submit(check_google_safe_browsing, url)
        vt = vt_future.result()
        gsb = gsb_future.result()

    scores = []
    if "score" in vt:
        scores.append(vt["score"])
    if gsb.get("available"):
        scores.append(gsb["score"])

    # Use the HIGHEST score among sources, not the average. If even one
    # reputable source (VT or GSB) flags a URL as malicious, that's a
    # strong signal on its own — averaging it against a source that found
    # nothing wrongly dilutes a confirmed threat down to "looks fine".
    combined_score = max(scores) if scores else None

    # Hard override flag: only trip this for sources with genuinely low
    # false-positive rates. VirusTotal aggregates ~70-90 antivirus engines,
    # and it's common for 1-2 low-quality/noisy engines to flag even
    # completely legitimate, high-traffic domains — that's not a real
    # verdict, it's engine noise. Require a real multi-engine consensus
    # before trusting VT as "confirmed malicious". Google Safe Browsing
    # is a hand-curated list rather than a multi-vendor vote, so a single
    # GSB match is trustworthy enough to trigger on its own.
    MIN_VT_CONSENSUS = 3
    vt_malicious_count = vt.get("stats", {}).get("malicious", 0) if vt.get("available") else 0

    explicitly_flagged = (
        gsb.get("available") and gsb.get("flagged")
    ) or (
        vt_malicious_count >= MIN_VT_CONSENSUS
    )

    return {
        "vt": vt,
        "gsb": gsb,
        "score": combined_score,
        "explicitly_flagged": explicitly_flagged,
        "vt_malicious_count": vt_malicious_count
    }


# ---------------------------------
# Risk Scoring Engine (weighted, adaptive)
# ---------------------------------

def compute_final_score(structure_result, domain_result, threat_intel_result=None):
    components = {
        "url_structure": (structure_result["score"], 0.25),
        "domain": (domain_result["score"], 0.35),
    }

    if threat_intel_result and threat_intel_result.get("score") is not None:
        components["threat_intel"] = (threat_intel_result["score"], 0.40)

    total_weight = sum(w for _, w in components.values())
    weighted_sum = sum(s * w for s, w in components.values())
    final_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
    final_score = min(final_score, 100)

    # Hard override: a confirmed hit from VirusTotal or Google Safe
    # Browsing is direct evidence, not a heuristic guess like the other
    # two branches. Don't let a clean domain/URL-structure score water
    # down a confirmed malicious verdict.
    if threat_intel_result and threat_intel_result.get("explicitly_flagged"):
        final_score = max(final_score, 85)

    confidence = "High" if "threat_intel" in components else "Medium"

    if final_score >= 70:
        risk_level = "High Risk 🔴"
    elif final_score >= 40:
        risk_level = "Medium Risk 🟡"
    else:
        risk_level = "Low Risk 🟢"

    return final_score, risk_level, confidence


# ---------------------------------
# UI Rendering Helpers
# ---------------------------------

SCAN_FLAVOR_MESSAGES = [
    "🛰️  Establishing secure uplink to threat intelligence grid...",
    "🌐  Cross-referencing global malware signature databases...",
    "🧬  Fingerprinting domain infrastructure...",
    "📡  Querying WHOIS registries across regional nodes...",
    "🔐  Validating SSL/TLS certificate chain of trust...",
    "🕵️  Scanning for homograph and lookalike domain patterns...",
    "📊  Aggregating multi-engine reputation scores...",
    "🧠  Running behavioral risk heuristics...",
]


def run_scan_animation(label="TARGET"):
    """
    Cosmetic scan sequence — purely visual flavor to match the tool's
    theme. The REAL analysis (WHOIS/DNS/SSL/URL-structure) runs
    separately, right after this. This just makes the wait feel like
    a proper security-terminal scan instead of a bare spinner.
    """
    placeholder = st.empty()
    progress = st.progress(0)
    steps = random.sample(SCAN_FLAVOR_MESSAGES, k=5)

    for i, msg in enumerate(steps):
        pct = int(((i + 1) / len(steps)) * 100)
        placeholder.markdown(
            f"<span style='font-family:JetBrains Mono, monospace; color:#14b8a6; font-weight:600;'>[{pct:3d}%]</span> "
            f"<span style='font-family:JetBrains Mono, monospace; color:#8b949e;'>{msg}</span>",
            unsafe_allow_html=True
        )
        progress.progress(pct)
        time.sleep(0.22)

    placeholder.markdown(
        f"<span style='font-family:JetBrains Mono, monospace; color:#14b8a6; font-weight:600;'>[100%]</span> "
        f"<span style='font-family:JetBrains Mono, monospace; color:#8b949e;'>Scan sequence complete for {label}. Compiling report...</span>",
        unsafe_allow_html=True
    )
    time.sleep(0.3)
    placeholder.empty()
    progress.empty()


def render_full_report(url, source="manual"):
    run_scan_animation(label=url[:40])

    with st.spinner("Parsing URL structure and encoding patterns..."):
        structure_result = analyze_url_structure(url)

    with st.spinner("Resolving domain fingerprint (WHOIS / SSL / DNS)..."):
        domain_result = analyze_domain(url)

    final_score, risk_level, confidence = compute_final_score(structure_result, domain_result)

    # Save immediately so a scan is never lost even if the user never
    # clicks "Run Threat Intelligence Scan" — this row gets revised in
    # place (not duplicated) if they do run it afterward.
    scan_id = save_scan(
        url, final_score, risk_level, confidence,
        {"structure": structure_result, "domain": domain_result, "threat_intel": None}
    )

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
    # Streamlit executes the code inside every tab on every rerun, not
    # just the visible one. If both tabs called this unconditionally,
    # they'd both try to create a button with the same key in the same
    # run and crash with StreamlitDuplicateElementKey. Only render in
    # the tab that actually produced the current result.
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

    c1, c2, c3 = st.columns(3)
    risk_colors = {
        "High Risk 🔴": "#f85149",
        "Medium Risk 🟡": "#e3b341",
        "Low Risk 🟢": "#3fb950",
    }
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

    with st.expander("🧩 URL Structure Analysis", expanded=True):
        st.write(f"Sub-score: {structure_result['score']}/100")
        for r in structure_result["reasons"]:
            st.write(f"- {r}")
        if structure_result.get("redirect_chain") and len(structure_result["redirect_chain"]) > 1:
            st.write("Redirect chain:")
            for hop in structure_result["redirect_chain"]:
                st.code(hop)

    with st.expander("🌐 Domain Analysis", expanded=True):
        st.write(f"Sub-score: {domain_result['score']}/100")
        for r in domain_result["reasons"]:
            st.write(f"- {r}")

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

                # Revise the existing history row in place instead of
                # inserting a second row for the same scan.
                scan_id = st.session_state.get("current_scan_id")
                if scan_id is not None:
                    update_scan(
                        scan_id, final_score, risk_level, confidence,
                        {
                            "structure": structure_result,
                            "domain": domain_result,
                            "threat_intel": ti_result
                        }
                    )
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
                    st.write(
                        f"⚠️ {mal_count} engine(s) flagged this URL — below the 3-engine "
                        "consensus threshold, treated as noise rather than a confirmed threat"
                    )
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

    # Note: this scan was already saved to history when it was first
    # computed in render_full_report(), and revised in place above if
    # Threat Intel was run — no additional save needed here.


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
    An intelligent cybersecurity platform to analyze QR codes,
    URLs, and suspicious links for phishing threats, malicious
    indicators, and threat intelligence insights.
    """
)

tab_scan, tab_qr, tab_history = st.tabs(["🌐 URL Scanner", "📱 QR Scanner", "🗂️ Scan History"])

with tab_scan:
    st.write("Enter a URL to run it through the full ABS VIGIL pipeline: "
             "URL Structure → Domain Analysis → Threat Intel → Risk Scoring.")

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

with tab_history:
    st.write("Past scans stored locally in SQLite.")

    rows = load_history()

    if rows:
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.button("🗑️ Clear History"):
                clear_history()
                st.rerun()

        st.table(
            [
                {
                    "Time": r[0],
                    "URL": (r[1][:50] + "...") if len(r[1]) > 50 else r[1],
                    "Score": r[2],
                    "Risk Level": r[3],
                    "Confidence": r[4]
                }
                for r in rows
            ]
        )
    else:
        st.info("No scans recorded yet. Run a scan to see history here.")

st.divider()
st.caption("🛡️ ABS VIGIL | Advanced Behavioral Shield | Cyber Threat Intelligence Platform")
