# ============================================================
# anomaly_engine.py — Anomaly Detection Engine
# ============================================================
from datetime import datetime

# Known safe values
KNOWN_LOCATIONS = {'Chennai','Mumbai','Delhi','Bangalore','Hyderabad','localhost','local'}
KNOWN_DEVICES   = {'Chrome/Windows','Safari/Mac','Firefox/Linux','Mobile/Android','Mobile/iOS'}

# IP ranges considered internal/safe
SAFE_IP_PREFIXES = ('127.','192.168.','10.','172.')

def is_safe_ip(ip):
    for prefix in SAFE_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

def detect_anomalies(username, ip_address, location,
                     device, login_success, failed_attempts,
                     timestamp=None):
    """
    Analyze login event and return anomaly results.
    Returns dict with: anomalies list, risk score, risk level, explanation
    """
    if timestamp is None:
        timestamp = datetime.utcnow()

    anomalies  = []
    score      = 0

    # CHECK 1 — Unknown location
    if location not in KNOWN_LOCATIONS:
        anomalies.append('unknown_location')
        score += 35

    # CHECK 2 — Unknown device
    if device not in KNOWN_DEVICES:
        anomalies.append('unknown_device')
        score += 30

    # CHECK 3 — Brute force (3+ failed attempts)
    if failed_attempts >= 3:
        anomalies.append('brute_force')
        score += 40

    # CHECK 4 — Odd login hour (before 5am or after 11pm)
    hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.utcnow().hour
    if hour < 5 or hour >= 23:
        anomalies.append('odd_timing')
        score += 20

    # CHECK 5 — Failed login
    if not login_success and failed_attempts >= 1:
        anomalies.append('failed_login')
        score += 15

    # CHECK 6 — Suspicious external IP
    if not is_safe_ip(ip_address):
        anomalies.append('suspicious_ip')
        score += 25

    # Calculate risk level
    if score == 0:
        risk_level = 'Safe'
    elif score <= 30:
        risk_level = 'Low'
    elif score <= 60:
        risk_level = 'Medium'
    else:
        risk_level = 'High'

    # Generate explanation
    explanation = build_explanation(
        username, ip_address, location, device,
        failed_attempts, anomalies, risk_level, timestamp
    )

    return {
        'anomalies'  : anomalies,
        'score'      : score,
        'risk_level' : risk_level,
        'is_anomalous': len(anomalies) > 0,
        'explanation': explanation,
    }

def build_explanation(username, ip, location, device,
                      failed_attempts, anomalies, risk_level, timestamp):
    """Build plain-English explanation for the alert."""
    if not anomalies:
        return f"Login for '{username}' is normal. No suspicious activity detected."

    parts = []
    if 'unknown_location' in anomalies:
        parts.append(f"Login from unrecognized location '{location}'")
    if 'unknown_device' in anomalies:
        parts.append(f"Unknown device '{device}' used")
    if 'brute_force' in anomalies:
        parts.append(f"{failed_attempts} failed login attempts detected (brute force pattern)")
    if 'odd_timing' in anomalies:
        t = timestamp.strftime('%H:%M') if hasattr(timestamp,'strftime') else str(timestamp)
        parts.append(f"Login at unusual hour ({t})")
    if 'failed_login' in anomalies:
        parts.append("Login attempt was unsuccessful")
    if 'suspicious_ip' in anomalies:
        parts.append(f"Suspicious external IP address ({ip})")

    summary = '. '.join(parts) + '.'

    if risk_level == 'High':
        advice = 'IMMEDIATE ACTION: Block account and notify user.'
    elif risk_level == 'Medium':
        advice = 'Monitor closely and verify user identity.'
    else:
        advice = 'Log and observe — no immediate action needed.'

    return f"{summary} | {advice}"
