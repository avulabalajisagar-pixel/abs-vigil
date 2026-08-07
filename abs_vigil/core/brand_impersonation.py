"""
ABS VIGIL - Brand Impersonation Engine

Catches lookalike-brand attacks that pure keyword/entropy checks miss:
  - Typosquats:        paypa1.com, micros0ft.com, netfl1x-billing.com
  - Character swaps:   payapl.com, gooogle.com
  - Subdomain abuse:   paypal.com.verify-secure-login.io
                        (root domain is NOT paypal.com, but the brand
                        name is stuffed into the subdomain/path to look
                        legitimate at a glance)

No external API or paid data source required - runs entirely offline
against a curated brand list, so it's demo-safe and cost-free.
"""

import json
import os
import difflib
import re

_BRANDS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "brands.json")

with open(_BRANDS_PATH, "r") as f:
    _BRAND_DATA = json.load(f)["brands"]

# Flat lookup: legit domain -> brand name
_LEGIT_DOMAINS = {}
for b in _BRAND_DATA:
    for d in b["domains"]:
        _LEGIT_DOMAINS[d.lower()] = b["name"]

_BRAND_NAMES = [(b["name"], b["name"].lower().replace(" ", "")) for b in _BRAND_DATA]

SIMILARITY_THRESHOLD = 0.78  # tuned to catch 1-2 char edits without false-flagging unrelated domains


def _similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()


def analyze_brand_impersonation(root_domain, full_url):
    """
    root_domain: the eTLD+1 (e.g. 'paypa1.com')
    full_url:    the complete URL, used to check subdomain/path stuffing
    """
    score = 0
    reasons = []
    matched_brand = None

    root_domain = (root_domain or "").lower()
    label = root_domain.split(".")[0] if root_domain else ""

    # 1. Exact match against a known-legit brand domain -> trusted, skip
    if root_domain in _LEGIT_DOMAINS:
        return {"score": 0, "reasons": ["Domain matches an official brand domain on record"],
                "matched_brand": _LEGIT_DOMAINS[root_domain], "impersonation_type": None}

    # 2. Typosquat / character-swap detection via similarity ratio
    best_ratio = 0.0
    best_brand = None
    for brand_name, brand_key in _BRAND_NAMES:
        ratio = _similarity(label, brand_key)
        if ratio > best_ratio:
            best_ratio = ratio
            best_brand = brand_name

    if best_brand and SIMILARITY_THRESHOLD <= best_ratio < 1.0:
        score += 35
        matched_brand = best_brand
        reasons.append(
            f"Domain closely resembles '{best_brand}' ({best_ratio:.0%} similarity) "
            "but does not match its official domain — likely typosquat"
        )

    # 3. Subdomain / path stuffing: brand name appears in the URL but the
    #    actual root domain is unrelated and unofficial.
    for brand_name, brand_key in _BRAND_NAMES:
        if len(brand_key) < 4:
            continue  # skip very short names to avoid noisy false positives
        if brand_key in full_url.lower().replace(" ", "") and root_domain not in _LEGIT_DOMAINS:
            # only fire if the brand name is NOT simply the actual root domain itself
            if brand_key not in root_domain.replace("-", "").replace(".", ""):
                score += 30
                matched_brand = matched_brand or brand_name
                reasons.append(
                    f"'{brand_name}' brand name found stuffed into subdomain/path while the "
                    f"actual registered domain ('{root_domain}') is unrelated — classic disguise tactic"
                )
                break

    # 4. Digit-for-letter substitution heuristic (paypa1, micr0soft, g00gle)
    de_leeted = (
        label.replace("0", "o").replace("1", "l")
        .replace("3", "e").replace("5", "s").replace("@", "a")
    )
    has_digit = any(c.isdigit() for c in label)
    if has_digit:
        for brand_name, brand_key in _BRAND_NAMES:
            if de_leeted == brand_key and label != brand_key:
                score += 30
                matched_brand = matched_brand or brand_name
                reasons.append(
                    f"Digit/letter substitution matches '{brand_name}' when normalized "
                    f"('{label}' -> '{de_leeted}') — leetspeak typosquat pattern"
                )
                break

    # 5. Brand name embedded as a SUBSTRING inside a compound/hyphenated
    #    domain label (e.g. 'amaz0n-delivery-verify.tk'). This is extremely
    #    common in phishing kits: keep the recognizable brand name so the
    #    victim's eye catches it, pad the rest with plausible-sounding
    #    words. Whole-label similarity (#2) misses this because the extra
    #    words drag the overall similarity ratio down.
    if not matched_brand:
        label_clean = de_leeted.replace("-", "").replace("_", "")
        for brand_name, brand_key in _BRAND_NAMES:
            if len(brand_key) < 4:
                continue
            if brand_key in label_clean and label_clean != brand_key and root_domain not in _LEGIT_DOMAINS:
                score += 28
                matched_brand = brand_name
                leet_note = " (after normalizing leetspeak digits)" if has_digit else ""
                reasons.append(
                    f"'{brand_name}' brand name embedded inside a longer compound domain "
                    f"('{root_domain}'){leet_note} — mimics the brand while padding with "
                    "plausible extra words, a common phishing-kit pattern"
                )
                break

    score = min(score, 100)
    if not reasons:
        reasons.append("No brand impersonation patterns detected")

    return {
        "score": score,
        "reasons": reasons,
        "matched_brand": matched_brand,
        "impersonation_type": "typosquat/impersonation" if score > 0 else None
    }
