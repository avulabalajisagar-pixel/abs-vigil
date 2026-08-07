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
