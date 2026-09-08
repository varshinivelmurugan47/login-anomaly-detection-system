# ─────────────────────────────────────────────
# MODULE 2: Anomaly Detection Engine
# Detects suspicious login behavior
# ─────────────────────────────────────────────

KNOWN_LOCATIONS = {"Chennai", "Mumbai", "Delhi", "Bangalore"}
KNOWN_DEVICES   = {"Chrome/Windows", "Safari/Mac", "Firefox/Linux", "Mobile/Android", "Mobile/iOS"}

def detect_anomalies(event):
    """Analyze a login event and return list of detected anomalies."""
    anomalies = []

    if event.get("location") not in KNOWN_LOCATIONS:
        anomalies.append({
            "type"       : "unknown_location",
            "description": f"Login from unrecognized location: {event['location']}",
            "weight"     : 35,
        })

    if event.get("device") not in KNOWN_DEVICES:
        anomalies.append({
            "type"       : "unknown_device",
            "description": f"Login from unrecognized device: {event['device']}",
            "weight"     : 30,
        })

    if event.get("failed_attempts", 0) >= 3:
        anomalies.append({
            "type"       : "brute_force",
            "description": f"Multiple failed attempts detected: {event['failed_attempts']} tries",
            "weight"     : 40,
        })

    if event.get("odd_hour"):
        anomalies.append({
            "type"       : "odd_timing",
            "description": f"Login at unusual hour: {event['timestamp'][-8:-3]}",
            "weight"     : 20,
        })

    if not event.get("login_success") and event.get("failed_attempts", 0) >= 1:
        anomalies.append({
            "type"       : "failed_login",
            "description": "Login attempt was unsuccessful",
            "weight"     : 15,
        })

    return anomalies
