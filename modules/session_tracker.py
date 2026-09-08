# ─────────────────────────────────────────────
# MODULE 5: Session Tracker
# Tracks and correlates user login sessions
# ─────────────────────────────────────────────

import json
from datetime import datetime

_sessions = {}   # in-memory store: username -> list of events

def track_session(event):
    """Add event to user's session history."""
    user = event["username"]
    if user not in _sessions:
        _sessions[user] = []
    _sessions[user].append(event)
    # Keep only last 50 events per user
    _sessions[user] = _sessions[user][-50:]

def get_user_timeline(username):
    """Return all events for a user sorted by time."""
    events = _sessions.get(username, [])
    return sorted(events, key=lambda e: e["timestamp"], reverse=True)

def get_all_sessions():
    """Return summary of all tracked sessions."""
    summary = {}
    for user, events in _sessions.items():
        summary[user] = {
            "total_events"  : len(events),
            "last_seen"     : events[-1]["timestamp"] if events else "N/A",
            "locations"     : list({e["location"] for e in events}),
            "devices"       : list({e["device"] for e in events}),
        }
    return summary
