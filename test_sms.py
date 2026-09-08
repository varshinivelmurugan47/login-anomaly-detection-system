from alert_engine import send_sms_alert


result = send_sms_alert(
    username="admin",
    ip_address="192.168.43.7",
    location="Chennai",
    risk_level="High",
    risk_score=85
)

if result:
    print("\nDemo SMS notification completed.")
else:
    print("\nDemo SMS notification failed.")
