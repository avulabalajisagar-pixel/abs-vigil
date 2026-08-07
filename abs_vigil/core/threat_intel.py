import base64
import requests
from concurrent.futures import ThreadPoolExecutor

try:
    import streamlit as st
except ImportError:
    st = None


def _secret(key):
    if st is None:
        return None
    try:
        return st.secrets[key]
    except Exception:
        return None


def check_virustotal(url):
    api_key = _secret("VT_API_KEY")
    if not api_key:
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


def check_google_safe_browsing(url):
    api_key = _secret("GSB_API_KEY")
    if not api_key:
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

    combined_score = max(scores) if scores else None

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
