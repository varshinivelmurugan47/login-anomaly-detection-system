# ─────────────────────────────────────────────
# MODULE 1: Data Collection
# Collects and parses login events from logs
# ─────────────────────────────────────────────

import json, random, uuid
from datetime import datetime, timedelta

USERS   = ["alice", "bob", "charlie", "diana", "eve", "frank"]
LOCATIONS_NORMAL  = ["Chennai", "Mumbai", "Delhi", "Bangalore"]
LOCATIONS_SUSPECT = ["Unknown", "New York", "Tokyo", "Moscow"]
DEVICES_NORMAL    = ["Chrome/Windows", "Safari/Mac", "Firefox/Linux", "Mobile/Android", "Mobile/iOS"]
IP_POOL = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10)] + \
          [f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}" for _ in range(5)]

def generate_login_event(force_anomaly=False):
    user      = random.choice(USERS)
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 60))
    is_unknown_location = force_anomaly or random.random() < 0.15
    is_unknown_device   = force_anomaly or random.random() < 0.12
    failed_attempts     = random.randint(3, 8) if (force_anomaly or random.random() < 0.1) else random.randint(0, 2)
    odd_hour            = force_anomaly or (timestamp.hour < 5 or timestamp.hour > 22)
    return {
        "event_id"       : str(uuid.uuid4())[:8].upper(),
        "username"       : user,
        "timestamp"      : timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address"     : random.choice(IP_POOL),
        "location"       : random.choice(LOCATIONS_SUSPECT) if is_unknown_location else random.choice(LOCATIONS_NORMAL),
        "device"         : "Unknown Device" if is_unknown_device else random.choice(DEVICES_NORMAL),
        "login_success"  : random.random() > 0.25,
        "failed_attempts": failed_attempts,
        "odd_hour"       : odd_hour,
    }

def load_events_from_file(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_event_to_file(event, filepath="data/login_events.json"):
    events = load_events_from_file(filepath)
    events.append(event)
    with open(filepath, "w") as f:
        json.dump(events[-500:], f, indent=2)
