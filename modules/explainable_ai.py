# ─────────────────────────────────────────────
# MODULE 4: Explainable AI
# Generates plain-English alert explanations
# ─────────────────────────────────────────────

TEMPLATES = {
    "unknown_location": "⚠️ User '{user}' logged in from an unrecognized location ({location}). "
                        "This IP has not been seen before for this account.",
    "unknown_device"  : "🖥️ A new or unrecognized device ({device}) was used to access '{user}'s account. "
                        "This could indicate a compromised credential.",
    "brute_force"     : "🔐 Account '{user}' experienced {attempts} failed login attempts before this event. "
                        "This pattern matches a brute-force or credential-stuffing attack.",
    "odd_timing"      : "🕐 '{user}' logged in at an unusual time ({time}). "
                        "This deviates from the account's normal activity window.",
    "failed_login"    : "❌ The login attempt for '{user}' was unsuccessful. "
                        "If repeated, this may indicate an unauthorized access attempt.",
}

def generate_explanation(event, anomalies, risk):
    """Build a structured explanation for why this event was flagged."""
    if not anomalies:
        return {
            "summary"   : f"✅ Login for '{event['username']}' appears normal. No anomalies detected.",
            "details"   : [],
            "advice"    : "No action required.",
        }

    details = []
    for a in anomalies:
        tmpl = TEMPLATES.get(a["type"], a["description"])
        msg  = tmpl.format(
            user    = event.get("username", "?"),
            location= event.get("location", "?"),
            device  = event.get("device", "?"),
            attempts= event.get("failed_attempts", 0),
            time    = event.get("timestamp", "?")[-8:-3],
        )
        details.append({"type": a["type"], "message": msg, "weight": a["weight"]})

    level   = risk["level"]
    summary = (
        f"🚨 HIGH RISK: Immediate review required for '{event['username']}'." if level == "High" else
        f"⚠️ MEDIUM RISK: Suspicious activity detected for '{event['username']}'." if level == "Medium" else
        f"🟡 LOW RISK: Minor anomaly flagged for '{event['username']}'."
    )

    advice = (
        "Block account and notify user immediately." if level == "High" else
        "Monitor account closely and verify with user." if level == "Medium" else
        "Log and observe — no immediate action needed."
    )

    return {"summary": summary, "details": details, "advice": advice}
