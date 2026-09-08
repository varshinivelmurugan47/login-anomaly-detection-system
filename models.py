# ============================================================
# models.py — Database Models
# ============================================================

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone


db = SQLAlchemy()


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
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
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

            "login_success": self.login_success,

            "failed_attempts": self.failed_attempts,

            "is_anomalous": self.is_anomalous,

            "risk_level": self.risk_level,

            "risk_score": self.risk_score,

            "anomaly_types": (
                self.anomaly_types.split(",")
                if self.anomaly_types
                else []
            ),

            "explanation": self.explanation

        }
