from alert_engine import send_email_alert


send_email_alert(

    username="admin",

    ip_address="192.168.1.50",

    location="Moscow",

    risk_level="High",

    risk_score=85,

    explanation=(
        "Login detected from an unfamiliar "
        "location and device."
    )
)
