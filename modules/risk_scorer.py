# ─────────────────────────────────────────────
# MODULE 3: Risk Scoring Engine
# Assigns Low / Medium / High risk level
# ─────────────────────────────────────────────

def calculate_risk(anomalies):
    """
    Calculate total risk score from anomalies.
    Returns: score (int), level (str), color (str)
    """
    score = sum(a["weight"] for a in anomalies)

    if score == 0:
        return {"score": 0, "level": "Safe",   "color": "#14B8A6", "badge": "success"}
    elif score <= 30:
        return {"score": score, "level": "Low",    "color": "#EF9F27", "badge": "warning"}
    elif score <= 60:
        return {"score": score, "level": "Medium", "color": "#F97316", "badge": "orange"}
    else:
        return {"score": score, "level": "High",   "color": "#E24B4A", "badge": "danger"}
