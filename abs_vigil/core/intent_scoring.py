"""
ABS VIGIL - Social Engineering Intent Scoring

Why this exists: modern phishing/smishing text is often LLM-written and
contains none of the classic misspellings or keyword tells. What DOESN'T
change is the underlying manipulation structure - urgency, authority,
fear, and reward/scarcity are the four levers every social-engineering
message pulls, because they're what work on humans, not on spam filters.

This module scores text on those four levers.

Two modes, same output shape, graceful degrade (same pattern as the
VirusTotal / Google Safe Browsing integrations elsewhere in this app):

  - Heuristic engine (always available, zero cost, deterministic):
    weighted phrase-pattern matching across the four manipulation
    categories.

  - LLM-enhanced mode (optional): if an Anthropic API key is configured
    in st.secrets, the raw text is additionally sent to Claude for a
    structured social-engineering assessment, which tends to catch
    paraphrased/novel manipulation the fixed phrase list can't.
"""

import re
import json
import requests

try:
    import streamlit as st
except ImportError:
    st = None


PATTERNS = {
    "urgency": {
        "weight": 22,
        "phrases": [
            r"\bact now\b", r"\bimmediately\b", r"\burgent\b", r"\bright away\b",
            r"\bwithin (24|12|2|4)\s*hours\b", r"\bexpires? (today|soon|shortly|in \d+\s*(hour|day)s?)\b",
            r"\blast (chance|warning|notice)\b", r"\btime[- ]sensitive\b",
            r"\bfinal (notice|reminder)\b", r"\bdo not delay\b", r"\bhurry\b",
            r"\brespond (within|by)\b",
        ]
    },
    "authority": {
        "weight": 20,
        "phrases": [
            r"\b(irs|hmrc|income tax dept)\b", r"\bpolice\b", r"\bgovernment\b",
            r"\bbank (security|fraud) (team|department)\b", r"\bcourt\b",
            r"\blegal action\b", r"\bofficial notice\b", r"\bcompliance department\b",
            r"\byour employer\b", r"\bmicrosoft support\b", r"\bapple support\b",
        ]
    },
    "fear": {
        "weight": 26,
        "phrases": [
            r"\bsuspended\b", r"\blocked\b", r"\bunauthorized (access|activity|login)\b",
            r"\baccount (compromised|closed|terminated|will be closed)\b",
            r"\bsuspicious activity\b", r"\bverify your identity\b",
            r"\bunusual (sign[- ]?in|login|activity)\b", r"\bpenalty\b", r"\bfine of\b",
            r"\barrest\b", r"\blegal consequences\b", r"\boverdue\b",
        ]
    },
    "reward_scarcity": {
        "weight": 18,
        "phrases": [
            r"\byou('ve| have) won\b", r"\bwinner\b", r"\bclaim (your|now|it)\b", r"\bfree gift\b",
            r"\blimited time\b", r"\bcongratulations\b", r"\bcashback\b", r"\bprize\b",
            r"\bexclusive offer\b", r"\bonly \d+ (left|spots|remaining)\b",
            r"\brefund (pending|available)\b", r"\bgift card\b", r"\byou (have been|are) selected\b",
        ]
    },
    "credential_bait": {
        "weight": 14,
        "phrases": [
            r"\bclick (here|below|the link)\b", r"\bverify (now|your account|your details)\b",
            r"\bconfirm your (password|otp|pin|card|details)\b", r"\bupdate (your )?payment\b",
            r"\bre-?enter your\b", r"\blogin to (confirm|verify)\b",
        ]
    },
}


def heuristic_intent_score(text):
    text_l = (text or "").lower()
    score = 0
    hits = {}

    for category, cfg in PATTERNS.items():
        matched = [p for p in cfg["phrases"] if re.search(p, text_l)]
        if matched:
            # diminishing returns within a category so one category can't
            # single-handedly blow the score to 100 on repetition
            category_score = min(cfg["weight"], cfg["weight"] * (0.6 + 0.15 * len(matched)))
            score += category_score
            hits[category] = len(matched)

    # Combo bonus: a message stacking 2+ distinct manipulation categories
    # (e.g. fake reward + artificial urgency) is a materially stronger
    # signal of a deliberate social-engineering script than any single
    # category alone, so it earns a bonus rather than a flat sum.
    if len(hits) >= 3:
        score += 15
    elif len(hits) == 2:
        score += 8

    score = min(int(round(score)), 100)

    label = (
        "High manipulation pressure" if score >= 55 else
        "Moderate manipulation pressure" if score >= 28 else
        "Low / no manipulation pressure"
    )

    return {
        "engine": "heuristic",
        "score": score,
        "label": label,
        "category_hits": hits,
    }


def _get_anthropic_key():
    if st is None:
        return None
    try:
        return st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        return None


def llm_intent_score(text):
    """
    Optional enhancement. Sends the message to Claude for a structured
    social-engineering assessment. Requires ANTHROPIC_API_KEY in
    st.secrets. Returns None on any failure so callers can silently fall
    back to the heuristic score - never let an unavailable API key break
    the scan.
    """
    api_key = _get_anthropic_key()
    if not api_key:
        return None

    system_prompt = (
        "You are a social-engineering / phishing text analyst. Given a raw "
        "SMS or email message, respond ONLY with JSON (no prose, no markdown "
        "fences) in this exact shape: "
        '{"score": <0-100 integer risk of manipulative/phishing intent>, '
        '"label": "<one short phrase>", "explanation": "<one sentence>"}'
    )

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 200,
                "system": system_prompt,
                "messages": [{"role": "user", "content": text[:2000]}],
            },
            timeout=10,
        )
        if response.status_code != 200:
            return None
        data = response.json()
        raw_text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        ).strip()
        raw_text = re.sub(r"^```(json)?|```$", "", raw_text.strip()).strip()
        parsed = json.loads(raw_text)
        return {
            "engine": "llm",
            "score": int(parsed.get("score", 0)),
            "label": parsed.get("label", ""),
            "explanation": parsed.get("explanation", ""),
        }
    except Exception:
        return None


def analyze_intent(text):
    """
    Public entry point. Always returns a heuristic result; augments with
    an LLM result when a key is configured and the call succeeds.
    """
    heuristic = heuristic_intent_score(text)
    llm = llm_intent_score(text)

    if llm is not None:
        # Blend: trust the LLM's contextual read more, but don't let the
        # heuristic signal vanish entirely - it catches boilerplate scam
        # templates the LLM occasionally under-scores as "just marketing".
        combined_score = int(round(0.65 * llm["score"] + 0.35 * heuristic["score"]))
        return {
            "score": combined_score,
            "engine": "llm+heuristic",
            "label": llm["label"] or heuristic["label"],
            "explanation": llm.get("explanation"),
            "category_hits": heuristic["category_hits"],
        }

    return {
        "score": heuristic["score"],
        "engine": "heuristic (LLM key not configured)",
        "label": heuristic["label"],
        "explanation": None,
        "category_hits": heuristic["category_hits"],
    }
