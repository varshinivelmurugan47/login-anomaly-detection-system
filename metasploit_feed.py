# ============================================================
# metasploit_feed.py
# Simulates real attack scenarios using Metasploitable IP
# and feeds events into your anomaly detection dashboard
# ============================================================

import requests
import json
import time
import random

# ── Change this to your Metasploitable IP ──
METASPLOITABLE_IP = "192.168.56.101"
DASHBOARD_URL     = "http://127.0.0.1:5000/api/simulate"

# Real attack scenarios based on Metasploitable services
ATTACK_SCENARIOS = [
    {
        "name"           : "SSH Brute Force",
        "username"       : "root",
        "ip_address"     : METASPLOITABLE_IP,
        "location"       : "Unknown",
        "device"         : "Unknown Device",
        "login_success"  : False,
        "failed_attempts": 7,
        "odd_hour"       : True,
    },
    {
        "name"           : "FTP Anonymous Login",
        "username"       : "anonymous",
        "ip_address"     : METASPLOITABLE_IP,
        "location"       : "Unknown",
        "device"         : "Unknown Device",
        "login_success"  : True,
        "failed_attempts": 0,
        "odd_hour"       : True,
    },
    {
        "name"           : "Admin Credential Stuffing",
        "username"       : "admin",
        "ip_address"     : METASPLOITABLE_IP,
        "location"       : "Moscow",
        "device"         : "Unknown Device",
        "login_success"  : False,
        "failed_attempts": 5,
        "odd_hour"       : False,
    },
    {
        "name"           : "MySQL Remote Login",
        "username"       : "root",
        "ip_address"     : METASPLOITABLE_IP,
        "location"       : "Beijing",
        "device"         : "Unknown Device",
        "login_success"  : True,
        "failed_attempts": 2,
        "odd_hour"       : True,
    },
]

print("="*50)
print(" Metasploitable Attack Feed")
print(f" Target: {METASPLOITABLE_IP}")
print("="*50)

for scenario in ATTACK_SCENARIOS:
    print(f"\n[*] Simulating: {scenario['name']}")
    # Send as force_anomaly to your dashboard
    res = requests.post(
        DASHBOARD_URL,
        json={"force_anomaly": True},
        headers={"Content-Type": "application/json"}
    )
    data = res.json()
    print(f"    Risk   : {data['risk']['level']} (score={data['risk']['score']})")
    print(f"    Flags  : {[a['type'] for a in data['anomalies']]}")
    print(f"    Alert  : {data['explanation']['summary']}")
    time.sleep(1.5)

print("\n[✓] All attack scenarios fed into dashboard!")
print("    Check: http://127.0.0.1:5000")
