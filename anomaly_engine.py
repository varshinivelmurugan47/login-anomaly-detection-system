# ============================================================
# anomaly_engine.py — Anomaly Detection Engine
# ============================================================

from datetime import datetime, timezone


# ============================================================
# KNOWN SAFE VALUES
# ============================================================

KNOWN_LOCATIONS = {
    "Chennai",
    "Mumbai",
    "Delhi",
    "Bangalore",
    "Hyderabad",
    "localhost",
    "local"
}


KNOWN_DEVICES = {
    "Chrome/Windows",
    "Safari/Mac",
    "Firefox/Linux",
    "Mobile/Android",
    "Mobile/iOS"
}


# ============================================================
# SAFE IP RANGES
# ============================================================

SAFE_IP_PREFIXES = (
    "127.",
    "192.168.",
    "10.",
    "172."
)


# ============================================================
# SAFE IP CHECK
# ============================================================

def is_safe_ip(ip):

    if not ip:
        return False

    ip = str(ip).strip()

    for prefix in SAFE_IP_PREFIXES:

        if ip.startswith(prefix):
            return True

    return False


# ============================================================
# MAIN ANOMALY DETECTION
# ============================================================

def detect_anomalies(
    username,
    ip_address,
    location,
    device,
    login_success,
    failed_attempts,
    timestamp=None
):

    """
    Existing rule-based anomaly detection.

    Checks:

    1. Unknown location
    2. Unknown device
    3. Brute-force pattern
    4. Odd login timing
    5. Failed login
    6. Suspicious external IP

    Returns:

    anomalies
    score
    risk_score
    risk_level
    is_anomalous
    explanation
    """

    if timestamp is None:

        timestamp = datetime.now(
            timezone.utc
        )


    anomalies = []

    score = 0


    # ========================================================
    # CHECK 1 — UNKNOWN LOCATION
    # ========================================================

    if location not in KNOWN_LOCATIONS:

        anomalies.append(
            "unknown_location"
        )

        score += 35


    # ========================================================
    # CHECK 2 — UNKNOWN DEVICE
    # ========================================================

    if device not in KNOWN_DEVICES:

        anomalies.append(
            "unknown_device"
        )

        score += 30


    # ========================================================
    # CHECK 3 — BRUTE FORCE
    # ========================================================

    if failed_attempts >= 3:

        anomalies.append(
            "brute_force"
        )

        score += 40


    # ========================================================
    # CHECK 4 — ODD LOGIN HOUR
    # ========================================================

    if hasattr(timestamp, "hour"):

        hour = timestamp.hour

    else:

        hour = datetime.now(
            timezone.utc
        ).hour


    if hour < 5 or hour >= 23:

        anomalies.append(
            "odd_timing"
        )

        score += 20


    # ========================================================
    # CHECK 5 — FAILED LOGIN
    # ========================================================

    if (
        not login_success
        and
        failed_attempts >= 1
    ):

        anomalies.append(
            "failed_login"
        )

        score += 15


    # ========================================================
    # CHECK 6 — SUSPICIOUS EXTERNAL IP
    # ========================================================

    if not is_safe_ip(ip_address):

        anomalies.append(
            "suspicious_ip"
        )

        score += 25


    # ========================================================
    # LIMIT SCORE
    # ========================================================

    score = min(
        score,
        100
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score == 0:

        risk_level = "Safe"

    elif score <= 30:

        risk_level = "Low"

    elif score <= 60:

        risk_level = "Medium"

    elif score <= 80:

        risk_level = "High"

    else:

        risk_level = "Critical"


    # ========================================================
    # EXPLANATION
    # ========================================================

    explanation = build_explanation(

        username,
        ip_address,
        location,
        device,
        failed_attempts,
        anomalies,
        risk_level,
        timestamp
    )


    return {

        "anomalies": anomalies,

        "score": score,

        # Compatibility with app.py
        "risk_score": score,

        "risk_level": risk_level,

        "is_anomalous": (
            len(anomalies) > 0
        ),

        "explanation": explanation
    }


# ============================================================
# EXPLANATION BUILDER
# ============================================================

def build_explanation(
    username,
    ip,
    location,
    device,
    failed_attempts,
    anomalies,
    risk_level,
    timestamp
):

    # ========================================================
    # NORMAL LOGIN
    # ========================================================

    if not anomalies:

        return (
            f"Login for '{username}' is normal. "
            f"No suspicious activity detected."
        )


    parts = []


    # ========================================================
    # UNKNOWN LOCATION
    # ========================================================

    if "unknown_location" in anomalies:

        parts.append(
            f"Login from unrecognized "
            f"location '{location}'"
        )


    # ========================================================
    # UNKNOWN DEVICE
    # ========================================================

    if "unknown_device" in anomalies:

        parts.append(
            f"Unknown device '{device}' used"
        )


    # ========================================================
    # BRUTE FORCE
    # ========================================================

    if "brute_force" in anomalies:

        parts.append(
            f"{failed_attempts} failed login "
            f"attempts detected "
            f"(brute force pattern)"
        )


    # ========================================================
    # ODD TIMING
    # ========================================================

    if "odd_timing" in anomalies:

        if hasattr(
            timestamp,
            "strftime"
        ):

            time_text = timestamp.strftime(
                "%H:%M"
            )

        else:

            time_text = str(timestamp)


        parts.append(
            f"Login at unusual hour "
            f"({time_text})"
        )


    # ========================================================
    # FAILED LOGIN
    # ========================================================

    if "failed_login" in anomalies:

        parts.append(
            "Login attempt was unsuccessful"
        )


    # ========================================================
    # SUSPICIOUS IP
    # ========================================================

    if "suspicious_ip" in anomalies:

        parts.append(
            f"Suspicious external IP address "
            f"({ip})"
        )


    summary = ". ".join(
        parts
    )

    if summary:

        summary += "."


    # ========================================================
    # ADVICE
    # ========================================================

    if risk_level == "Critical":

        advice = (
            "IMMEDIATE ACTION: Block account, "
            "verify identity and notify user."
        )

    elif risk_level == "High":

        advice = (
            "IMMEDIATE ACTION: Block or challenge "
            "the suspicious session and notify user."
        )

    elif risk_level == "Medium":

        advice = (
            "Monitor closely and verify user identity."
        )

    else:

        advice = (
            "Log and observe — no immediate action needed."
        )


    return (
        f"{summary} | {advice}"
    )
