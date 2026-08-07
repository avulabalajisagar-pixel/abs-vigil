"""
ABS VIGIL - SMS / Text (Smishing) Scanner

Pipeline for a raw text message:
  1. Extract embedded URLs and run them through the existing URL +
     domain + brand-impersonation branches (full reuse, not a rewrite).
  2. Extract a claimed sender ID / phone number and apply format-based
     spoofing heuristics (alphanumeric sender IDs, VOIP-range patterns,
     shortcode mismatches).
  3. Score the raw text for social-engineering intent (urgency, fear,
     authority, reward/scarcity, credential bait).
  4. Cross-reference every extracted domain/phone against the entity
     risk graph — a number or domain that already showed up in a prior
     phishing email or URL scan reinforces this score.

Note: true carrier-level sender verification (confirming a text
genuinely originated from a given shortcode/operator) requires a
telecom/carrier API partnership and is out of scope for this build —
flagged clearly in the UI as a roadmap item rather than faked.
"""

import re
from urllib.parse import urlparse

from core.url_analysis import analyze_url_structure, valid_url, get_root_domain
from core.domain_analysis import analyze_domain
from core.intent_scoring import analyze_intent
from core import db

URL_RE = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)
# Loosely catches embedded URLs without a scheme too, e.g. "bit.ly/xyz123"
BARE_URL_RE = re.compile(
    r"\b((?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?)\b", re.IGNORECASE
)
PHONE_RE = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")

# Alphanumeric sender IDs (e.g. "AMAZON", "BANK-XY") are easy to spoof —
# there's no cryptographic binding between the displayed name and the
# actual originating network the way SPF/DKIM works for email.
SUSPICIOUS_SENDER_PATTERNS = [
    r"^(alert|notice|verify|secure|update|support)$",
]


def extract_urls(text):
    urls = URL_RE.findall(text)
    if not urls:
        # fall back to bare-domain detection and add a scheme so the
        # existing URL analysis pipeline can run on it
        bare = BARE_URL_RE.findall(text)
        urls = [f"http://{b}" for b in bare if "." in b]
    # de-dupe, preserve order
    seen = set()
    unique = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def extract_phone_like(sender_id):
    if not sender_id:
        return None
    digits = re.sub(r"[^\d+]", "", sender_id)
    return digits if len(re.sub(r"\D", "", digits)) >= 7 else None


def analyze_sender_id(sender_id):
    score = 0
    reasons = []
    if not sender_id:
        return {"score": 0, "reasons": ["No sender ID provided"], "sender_type": "unknown"}

    sender_id = sender_id.strip()
    is_numeric = bool(re.fullmatch(r"\+?\d+", sender_id))
    is_shortcode = bool(re.fullmatch(r"\d{4,6}", sender_id))

    if is_shortcode:
        sender_type = "shortcode"
        reasons.append("Numeric shortcode sender — common for legitimate bulk senders, "
                        "but shortcodes are frequently spoofed/leased by scam operations too")
        score += 5
    elif is_numeric:
        sender_type = "phone_number"
        reasons.append("Standard phone number sender")
    else:
        sender_type = "alphanumeric"
        score += 15
        reasons.append(
            "Alphanumeric sender ID (e.g. a brand name) — these have no cryptographic "
            "verification and are trivially spoofable, unlike email's SPF/DKIM/DMARC"
        )
        for pattern in SUSPICIOUS_SENDER_PATTERNS:
            if re.match(pattern, sender_id.lower()):
                score += 10
                reasons.append(f"Generic/suspicious sender label: '{sender_id}'")

    return {"score": min(score, 100), "reasons": reasons, "sender_type": sender_type}


def analyze_sms(text, sender_id=None):
    reasons_summary = []

    # --- 1. Embedded URL analysis (full reuse of URL/domain/brand engines) ---
    urls_found = extract_urls(text)
    url_results = []
    worst_url_score = 0
    for u in urls_found:
        if not valid_url(u):
            continue
        structure = analyze_url_structure(u)
        domain_info = analyze_domain(u)
        combined = int(0.5 * structure["score"] + 0.5 * domain_info["score"])
        url_results.append({
            "url": u,
            "structure": structure,
            "domain": domain_info,
            "combined_score": combined,
        })
        worst_url_score = max(worst_url_score, combined)

        # Feed into entity graph
        root = structure.get("root_domain") or urlparse(u).netloc
        db.upsert_entity("domain", root, combined,
                          "High Risk 🔴" if combined >= 70 else "Medium Risk 🟡" if combined >= 40 else "Low Risk 🟢",
                          channel="sms")

    # --- 2. Sender ID heuristics ---
    sender_result = analyze_sender_id(sender_id)

    phone_prior = None
    phone_value = extract_phone_like(sender_id)
    if phone_value:
        phone_prior = db.upsert_entity("phone", phone_value, sender_result["score"],
                                        "Medium Risk 🟡" if sender_result["score"] >= 15 else "Low Risk 🟢",
                                        channel="sms")

    # --- 3. Social engineering intent scoring on the raw text ---
    intent_result = analyze_intent(text)

    # --- 4. Cross-channel reinforcement check ---
    reinforcement_bonus = 0
    reinforcement_notes = []
    for r in url_results:
        root = r["structure"].get("root_domain")
        prior = db.lookup_entity(root) if root else None
        if prior and prior["times_seen"] >= 1:
            channels_before = [c for c in prior["channels"]]
            if channels_before and channels_before != ["sms"]:
                reinforcement_bonus = max(reinforcement_bonus, 15)
                reinforcement_notes.append(
                    f"Domain '{root}' was previously seen in another channel "
                    f"({', '.join(channels_before)}) with risk score {prior['max_score']}"
                )

    if phone_prior and phone_prior["times_seen"] >= 1:
        reinforcement_bonus = max(reinforcement_bonus, 10)
        reinforcement_notes.append(
            f"Sender previously seen {phone_prior['times_seen']} time(s), "
            f"last flagged at score {phone_prior['max_score']}"
        )

    # --- Weighted composite score ---
    components = {
        "intent": (intent_result["score"], 0.40),
        "sender": (sender_result["score"], 0.15),
    }
    if url_results:
        components["embedded_url"] = (worst_url_score, 0.45)
    else:
        # no link at all - re-weight so intent/sender carry the full signal
        components = {
            "intent": (intent_result["score"], 0.75),
            "sender": (sender_result["score"], 0.25),
        }

    total_weight = sum(w for _, w in components.values())
    weighted = sum(s * w for s, w in components.values())
    final_score = int(weighted / total_weight) if total_weight else 0
    final_score = min(100, final_score + reinforcement_bonus)

    if final_score >= 70:
        risk_level = "High Risk 🔴"
    elif final_score >= 40:
        risk_level = "Medium Risk 🟡"
    else:
        risk_level = "Low Risk 🟢"

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "intent": intent_result,
        "sender": sender_result,
        "urls": url_results,
        "reinforcement_bonus": reinforcement_bonus,
        "reinforcement_notes": reinforcement_notes,
    }
