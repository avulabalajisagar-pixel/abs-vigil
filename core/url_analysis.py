import re
import math
import requests
from urllib.parse import urlparse

try:
    import tldextract
    # Force the bundled offline snapshot of the public-suffix list instead
    # of fetching it live on every cold start. Keeps the tool fast and
    # fully functional even with no internet access (e.g. during a live
    # demo on restricted wifi) and avoids noisy fetch-failure logging.
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    tldextract = None
    _TLD_EXTRACTOR = None

from core.brand_impersonation import analyze_brand_impersonation

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


def valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ["http", "https"], result.netloc])
    except Exception:
        return False


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


def get_root_domain(url):
    parsed = urlparse(url)
    netloc = parsed.netloc.split(":")[0]
    if _TLD_EXTRACTOR:
        ext = _TLD_EXTRACTOR(url)
        return f"{ext.domain}.{ext.suffix}" if ext.suffix else netloc
    return netloc


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

    if "xn--" in domain:
        score += 25
        reasons.append("Punycode domain detected (possible homograph/lookalike attack)")

    subdomain_depth = domain.count(".")
    if subdomain_depth > 3:
        score += 10
        reasons.append(f"Unusually deep subdomain structure ({subdomain_depth} levels)")

    root_domain = domain.split(":")[0]
    if root_domain in KNOWN_SHORTENERS:
        score += 15
        reasons.append(f"Known URL shortener detected: {root_domain}")

    domain_label = root_domain.split(".")[0]
    entropy = shannon_entropy(domain_label)
    if entropy > 3.8 and len(domain_label) > 8:
        score += 15
        reasons.append(f"High domain entropy ({entropy:.2f}) — possibly auto-generated")

    redirect_chain = []
    if root_domain in KNOWN_SHORTENERS:
        redirect_chain = resolve_redirect_chain(url)
        if len(redirect_chain) > 1:
            reasons.append(f"URL redirects {len(redirect_chain) - 1} time(s) before final destination")
            score += 5 * (len(redirect_chain) - 1)

    # Brand impersonation engine
    eff_root = get_root_domain(url)
    brand_result = analyze_brand_impersonation(eff_root, url)
    if brand_result["score"] > 0:
        score += brand_result["score"]
        reasons.extend(brand_result["reasons"])

    score = min(score, 100)
    if not reasons:
        reasons.append("No structural red flags detected")

    return {
        "score": score,
        "reasons": reasons,
        "redirect_chain": redirect_chain,
        "root_domain": eff_root,
        "brand_impersonation": brand_result,
    }
