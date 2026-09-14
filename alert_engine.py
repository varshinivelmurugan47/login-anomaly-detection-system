# ============================================================
# alert_engine.py — Email + Simulated SMS Alerts
# ============================================================

import os
import logging
from datetime import datetime

import resend


logging.basicConfig(
    level=logging.INFO
)


# ============================================================
# EMAIL ALERT
# ============================================================

def send_email_alert(
    username,
    ip_address,
    location,
    device,
    risk_level,
    risk_score,
    explanation,
    timestamp
):

    api_key = os.getenv(
        "RESEND_API_KEY"
    )

    alert_email = os.getenv(
        "ALERT_EMAIL"
    )

    email_from = os.getenv(
        "EMAIL_FROM",
        "Login Security System <onboarding@resend.dev>"
    )


    if not api_key or not alert_email:

        logging.error(
            "Email configuration is missing."
        )

        return False


    resend.api_key = api_key


    subject = (
        f"Security Alert: "
        f"{risk_level} Login Detected"
    )


    html_body = f"""
    <html>
    <body style="font-family:Arial,sans-serif;">

        <h2>🚨 Login Security Alert</h2>

        <p>
            A suspicious login was detected by the
            <b>Real-Time Login Anomaly Detection System</b>.
        </p>

        <table
            border="1"
            cellpadding="8"
            cellspacing="0"
            style="border-collapse:collapse;"
        >

            <tr>
                <td><b>Username</b></td>
                <td>{username}</td>
            </tr>

            <tr>
                <td><b>IP Address</b></td>
                <td>{ip_address}</td>
            </tr>

            <tr>
                <td><b>Location</b></td>
                <td>{location}</td>
            </tr>

            <tr>
                <td><b>Device</b></td>
                <td>{device}</td>
            </tr>

            <tr>
                <td><b>Timestamp</b></td>
                <td>{timestamp}</td>
            </tr>

            <tr>
                <td><b>Risk Level</b></td>
                <td>{risk_level}</td>
            </tr>

            <tr>
                <td><b>Risk Score</b></td>
                <td>{risk_score}</td>
            </tr>

        </table>

        <h3>Explanation</h3>

        <p>
            {explanation}
        </p>

        <p>
            If you did not perform this login,
            secure your account immediately.
        </p>

        <hr>

        <p>
            This alert was generated automatically by the
            Login Anomaly Detection System.
        </p>

    </body>
    </html>
    """


    try:

        response = resend.Emails.send({

            "from": email_from,

            "to": [alert_email],

            "subject": subject,

            "html": html_body
        })


        logging.info(
            "EMAIL ALERT SENT SUCCESSFULLY"
        )

        logging.info(
            "Resend response: %s",
            response
        )

        return True


    except Exception as error:

        logging.exception(
            "EMAIL ALERT FAILED: %s",
            error
        )

        return False


# ============================================================
# SIMULATED SMS
# ============================================================

def send_sms_alert(
    username,
    risk_level,
    risk_score
):

    """
    SMS demonstration mode.

    No paid SMS gateway is used.

    The notification is:
    1. Displayed in terminal
    2. Saved to sms_demo.log
    """


    alert_phone = os.getenv(
        "ALERT_PHONE",
        "+91-XXXXXXXXXX"
    )


    message = (

        f"SECURITY ALERT: "
        f"{risk_level} login detected. "

        f"User: {username}. "

        f"Risk Score: {risk_score}. "

        f"Check your security dashboard."
    )


    print()

    print("=" * 60)

    print(
        "SMS ALERT - DEMO MODE"
    )

    print("=" * 60)

    print(
        f"To      : {alert_phone}"
    )

    print(
        f"Message : {message}"
    )

    print(
        "Status  : SIMULATED - "
        "No paid SMS service used"
    )

    print("=" * 60)

    print()


    try:

        with open(
            "sms_demo.log",
            "a"
        ) as file:

            file.write(

                f"\n[{datetime.now()}]\n"

                f"To: {alert_phone}\n"

                f"Message: {message}\n"

                f"Status: SIMULATED SMS\n"

                f"{'-' * 50}\n"
            )


        logging.info(
            "SMS demo notification recorded."
        )


    except Exception as error:

        logging.warning(
            "Could not write SMS demo log: %s",
            error
        )


    return True


# ============================================================
# MAIN SECURITY ALERT
# ============================================================

def send_security_alert(event):

    if event is None:

        logging.error(
            "Security alert received an empty event."
        )

        return {

            "email_sent": False,

            "sms_sent": False
        }


    username = getattr(
        event,
        "username",
        "Unknown"
    )

    ip_address = getattr(
        event,
        "ip_address",
        "Unknown"
    )

    location = getattr(
        event,
        "location",
        "Unknown"
    )

    device = getattr(
        event,
        "device",
        "Unknown"
    )

    risk_level = getattr(
        event,
        "risk_level",
        "LOW"
    )

    risk_score = getattr(
        event,
        "risk_score",
        0
    )

    explanation = getattr(
        event,
        "explanation",
        "Suspicious login activity detected."
    )

    timestamp = getattr(
        event,
        "timestamp",
        datetime.now()
    )


    risk_level = str(
        risk_level
    ).strip().upper()


    # ========================================================
    # ONLY HIGH / CRITICAL
    # ========================================================

    if risk_level not in [
        "HIGH",
        "CRITICAL"
    ]:

        logging.info(
            "No security alert required. "
            "Risk level: %s",
            risk_level
        )

        return {

            "email_sent": False,

            "sms_sent": False
        }


    # ========================================================
    # DISPLAY ALERT
    # ========================================================

    print()

    print("=" * 60)

    print(
        "SECURITY ALERT TRIGGERED"
    )

    print("=" * 60)

    print(
        f"Risk Level : {risk_level}"
    )

    print(
        f"Risk Score : {risk_score}"
    )

    print(
        f"Username   : {username}"
    )

    print(
        f"IP Address : {ip_address}"
    )

    print(
        f"Location   : {location}"
    )

    print(
        f"Device     : {device}"
    )

    print(
        f"Explanation: {explanation}"
    )

    print("=" * 60)


    # ========================================================
    # EMAIL
    # ========================================================

    print()

    print(
        "[EMAIL] Sending security alert..."
    )


    email_sent = send_email_alert(

        username,

        ip_address,

        location,

        device,

        risk_level,

        risk_score,

        explanation,

        timestamp
    )


    if email_sent:

        print(
            "[EMAIL] SUCCESS"
        )

    else:

        print(
            "[EMAIL] FAILED"
        )


    # ========================================================
    # SIMULATED SMS
    # ========================================================

    print()

    print(
        "[SMS] Starting demo SMS notification..."
    )


    sms_sent = send_sms_alert(

        username,

        risk_level,

        risk_score
    )


    if sms_sent:

        print(
            "[SMS] DEMO SUCCESS"
        )

    else:

        print(
            "[SMS] DEMO FAILED"
        )


    print()

    print("=" * 60)

    print(
        "ALERT PROCESS COMPLETED"
    )

    print("=" * 60)

    print()


    return {

        "email_sent": email_sent,

        "sms_sent": sms_sent
    }
