# ============================================================
# models.py — Database Models
# ============================================================

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone


db = SQLAlchemy()


# ============================================================
# UTC TIME HELPER
# ============================================================

def utc_now():
    return datetime.now(timezone.utc)


# ============================================================
# LOGIN EVENT MODEL
# ============================================================

class LoginEvent(db.Model):

    __tablename__ = "login_events"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False
    )

    ip_address = db.Column(
        db.String(50),
        nullable=False
    )

    location = db.Column(
        db.String(100),
        default="Unknown"
    )

    device = db.Column(
        db.String(200),
        default="Unknown"
    )

    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=utc_now
    )

    login_success = db.Column(
        db.Boolean,
        default=False
    )

    failed_attempts = db.Column(
        db.Integer,
        default=0
    )

    is_anomalous = db.Column(
        db.Boolean,
        default=False
    )

    risk_level = db.Column(
        db.String(20),
        default="Safe"
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    anomaly_types = db.Column(
        db.String(500),
        default=""
    )

    explanation = db.Column(
        db.Text,
        default=""
    )

    # ========================================================
    # Convert database object to dictionary
    # ========================================================

    def to_dict(self):

        return {

            "id": self.id,

            "username": self.username,

            "ip_address": self.ip_address,

            "location": self.location,

            "device": self.device,

            "timestamp": (
                self.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if self.timestamp
                else ""
            ),

            "login_success": bool(
                self.login_success
            ),

            "failed_attempts": (
                self.failed_attempts or 0
            ),

            "is_anomalous": bool(
                self.is_anomalous
            ),

            "risk_level": (
                self.risk_level or "Safe"
            ),

            "risk_score": (
                self.risk_score or 0
            ),

            "anomaly_types": (
                self.anomaly_types.split(",")
                if self.anomaly_types
                else []
            ),

            "explanation": (
                self.explanation or ""
            )
        }


# ============================================================
# TRUSTED DEVICE MODEL
# ============================================================

class TrustedDevice(db.Model):

    __tablename__ = "trusted_devices"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    # Device classification
    device = db.Column(
        db.String(200),
        default="Unknown"
    )

    # Complete browser fingerprint information
    user_agent = db.Column(
        db.Text,
        default=""
    )

    # Network information
    ip_address = db.Column(
        db.String(50),
        default="Unknown"
    )

    location = db.Column(
        db.String(100),
        default="Unknown"
    )

    # Behaviour history
    first_seen = db.Column(
        db.DateTime(timezone=True),
        default=utc_now
    )

    last_seen = db.Column(
        db.DateTime(timezone=True),
        default=utc_now
    )

    login_count = db.Column(
        db.Integer,
        default=1
    )

    # ========================================================
    # Convert trusted device to dictionary
    # ========================================================

    def to_dict(self):

        return {

            "id": self.id,

            "username": self.username,

            "device": self.device,

            "user_agent": self.user_agent,

            "ip_address": self.ip_address,

            "location": self.location,

            "first_seen": (
                self.first_seen.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if self.first_seen
                else ""
            ),

            "last_seen": (
                self.last_seen.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if self.last_seen
                else ""
            ),

            "login_count": (
                self.login_count or 0
            )
        }
