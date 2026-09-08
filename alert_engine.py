# ============================================================
# alert_engine.py
# Email Alert + Simulated SMS Alert
# Login Anomaly Detection System
# ============================================================

import os
import smtplib
from email.message import EmailMessage
from datetime import datetime


# ============================================================
# EMAIL CONFIGURATION
# ============================================================

# Email address that will RECEIVE the security alert
ALERT_EMAIL = os.getenv("ALERT_EMAIL")

# Gmail address used to SEND the alert
SMTP_USER = os.getenv("SMTP_USER")

# Gmail App Password
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")


# Gmail SMTP configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587


# ============================================================
# SMS CONFIGURATION
# ============================================================

# This is a DEMO SMS.
# No real SMS is sent by this version.

ALERT_PHONE = os.getenv(
    "ALERT_PHONE",
    "Demo Phone"
)


# ============================================================
# EMAIL CONFIGURATION CHECK
# ============================================================

def email_configured():
    """
    Check whether all required email settings
    are configured.
    """

    if not ALERT_EMAIL:
        return False

    if not SMTP_USER:
        return False

    if not EMAIL_APP_PASSWORD:
        return False

    return True


# ============================================================
# SEND EMAIL ALERT
# ============================================================

def send_email_alert(
    username,
    ip_address,
    location,
    risk_level,
    risk_score,
    explanation=""
):
    """
    Send a security alert through Gmail SMTP.

    Returns:
        True  -> email sent successfully
        False -> email failed
    """

    # --------------------------------------------------------
    # Check configuration
    # --------------------------------------------------------

    if not ALERT_EMAIL:
        print("ERROR: ALERT_EMAIL is not configured.")
        return False

    if not SMTP_USER:
        print("ERROR: SMTP_USER is not configured.")
        return False

    if not EMAIL_APP_PASSWORD:
        print("ERROR: EMAIL_APP_PASSWORD is not configured.")
        return False

    # --------------------------------------------------------
    # Create email
    # --------------------------------------------------------

    message = EmailMessage()

    message["Subject"] = (
        f"[SECURITY ALERT] "
        f"{risk_level.upper()} Login Detected"
    )

    message["From"] = SMTP_USER
    message["To"] = ALERT_EMAIL

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    email_body = f"""
LOGIN ANOMALY DETECTION SYSTEM
========================================

SECURITY ALERT

Risk Level : {risk_level}
Risk Score : {risk_score}

LOGIN DETAILS
----------------------------------------
Username   : {username}
IP Address : {ip_address}
Location   : {location}
Time       : {timestamp}

EXPLANATION
----------------------------------------
{
    explanation
    if explanation
    else
    "Suspicious login activity detected."
}

ACTION REQUIRED
----------------------------------------
Please verify this login activity.

If this login was not performed by you,
take appropriate security action.

This alert was generated automatically
by the Login Anomaly Detection System.

========================================
"""

    message.set_content(email_body)

    # --------------------------------------------------------
    # Connect to Gmail SMTP
    # --------------------------------------------------------

    try:

        print("\nSending email alert...")

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=15
        ) as server:

            # Start TLS encryption
            server.starttls()

            # Login to Gmail
            server.login(
                SMTP_USER,
                EMAIL_APP_PASSWORD
            )

            # Send email
            server.send_message(message)

        print("EMAIL ALERT: SENT SUCCESSFULLY")

        return True

    # --------------------------------------------------------
    # Authentication error
    # --------------------------------------------------------

    except smtplib.SMTPAuthenticationError:

        print(
            "ERROR: Gmail authentication failed."
        )

        print(
            "Check SMTP_USER and EMAIL_APP_PASSWORD."
        )

        return False

    # --------------------------------------------------------
    # Connection error
    # --------------------------------------------------------

    except smtplib.SMTPConnectError:

        print(
            "ERROR: Could not connect to Gmail SMTP server."
        )

        return False

    # --------------------------------------------------------
    # Timeout
    # --------------------------------------------------------

    except TimeoutError:

        print(
            "ERROR: Gmail SMTP connection timed out."
        )

        return False

    # --------------------------------------------------------
    # Other error
    # --------------------------------------------------------

    except Exception as e:

        print(
            f"ERROR: Email sending failed: {e}"
        )

        return False


# ============================================================
# SIMULATED SMS ALERT
# ============================================================

def send_sms_alert(
    username,
    ip_address,
    location,
    risk_level,
    risk_score
):
    """
    Simulated SMS alert for project demonstration.

    IMPORTANT:
    This function DOES NOT send a real SMS.

    It displays the SMS notification in the
    terminal to demonstrate the alert workflow.

    Returns:
        True -> simulation completed
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # --------------------------------------------------------
    # SMS Header
    # --------------------------------------------------------

    print("\n")

    print("=" * 60)

    print(
        "             SIMULATED SMS ALERT"
    )

    print("=" * 60)

    # --------------------------------------------------------
    # SMS information
    # --------------------------------------------------------

    print(
        "SMS STATUS : SENT (DEMO)"
    )

    print(
        f"Recipient  : {ALERT_PHONE}"
    )

    print(
        f"Time       : {timestamp}"
    )

    print("-" * 60)

    # --------------------------------------------------------
    # Login information
    # --------------------------------------------------------

    print(
        f"User       : {username}"
    )

    print(
        f"IP Address : {ip_address}"
    )

    print(
        f"Location   : {location}"
    )

    print(
        f"Risk Level : {risk_level}"
    )

    print(
        f"Risk Score : {risk_score}"
    )

    print("-" * 60)

    # --------------------------------------------------------
    # SMS message
    # --------------------------------------------------------

    print(
        "SMS MESSAGE"
    )

    print("-" * 60)

    print(
        "HIGH RISK LOGIN DETECTED!"
    )

    print(
        f"User: {username}"
    )

    print(
        f"Location: {location}"
    )

    print(
        f"Risk Level: {risk_level}"
    )

    print(
        "Please verify your account."
    )

    # --------------------------------------------------------
    # Finish
    # --------------------------------------------------------

    print("=" * 60)

    print(
        "SMS SIMULATION COMPLETED"
    )

    print("=" * 60)

    print()

    return True


# ============================================================
# MAIN SECURITY ALERT FUNCTION
# ============================================================

def send_security_alert(
    username,
    ip_address,
    location,
    risk_level,
    risk_score,
    explanation=""
):
    """
    Main security alert function.

    HIGH and CRITICAL:
        -> Email alert
        -> Simulated SMS alert

    LOW and MEDIUM:
        -> No alert

    SAFE:
        -> No alert
    """

    # --------------------------------------------------------
    # Normalize risk level
    # --------------------------------------------------------

    risk_level = str(
        risk_level
    ).strip().capitalize()

    # --------------------------------------------------------
    # Only HIGH and CRITICAL trigger alerts
    # --------------------------------------------------------

    if risk_level not in [
        "High",
        "Critical"
    ]:

        print(
            f"Risk level is {risk_level}. "
            "No security alert required."
        )

        return {
            "alert_triggered": False,
            "email_sent": False,
            "sms_sent": False
        }

    # ========================================================
    # HIGH / CRITICAL RISK
    # ========================================================

    print("\n" + "=" * 60)

    print(
        f"{risk_level.upper()} RISK DETECTED "
        "- SENDING EMAIL AND SMS ALERT."
    )

    print("=" * 60)

    # ========================================================
    # EMAIL ALERT
    # ========================================================

    email_sent = send_email_alert(
        username=username,
        ip_address=ip_address,
        location=location,
        risk_level=risk_level,
        risk_score=risk_score,
        explanation=explanation
    )

    # ========================================================
    # SMS ALERT
    # ========================================================

    sms_sent = send_sms_alert(
        username=username,
        ip_address=ip_address,
        location=location,
        risk_level=risk_level,
        risk_score=risk_score
    )

    # ========================================================
    # ALERT SUMMARY
    # ========================================================

    print("\n" + "=" * 60)

    print(
        "SECURITY ALERT SUMMARY"
    )

    print("=" * 60)

    print(
        f"Email Alert : "
        f"{'SENT' if email_sent else 'FAILED'}"
    )

    print(
        f"SMS Alert   : "
        f"{'SENT (DEMO)' if sms_sent else 'FAILED'}"
    )

    print("=" * 60)

    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {
        "alert_triggered": True,
        "email_sent": email_sent,
        "sms_sent": sms_sent
    }


# ============================================================
# TEST ALERT ENGINE
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "LOGIN ANOMALY DETECTION"
    )

    print(
        "ALERT ENGINE TEST"
    )

    print("=" * 60)

    # --------------------------------------------------------
    # Test HIGH risk event
    # --------------------------------------------------------

    result = send_security_alert(

        username="admin",

        ip_address="8.8.8.8",

        location="Unknown",

        risk_level="High",

        risk_score=85,

        explanation=(
            "Multiple failed login attempts detected "
            "from an unusual location."
        )

    )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print("\nFinal Result:")

    print(result)
