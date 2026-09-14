# ============================================================
# app.py — Real-Time Login Anomaly Detection System
# ============================================================

import os
import logging

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()


from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    render_template,
    send_file
)


from models import (
    db,
    LoginEvent,
    TrustedDevice
)


from anomaly_engine import (
    detect_anomalies
)


# ============================================================
# ALERT ENGINE
# ============================================================

try:

    from alert_engine import (
        send_security_alert
    )

    ALERT_ENGINE_AVAILABLE = True


except ImportError as error:

    ALERT_ENGINE_AVAILABLE = False

    print("=" * 60)

    print(
        "ALERT ENGINE NOT AVAILABLE"
    )

    print(
        f"Reason: {error}"
    )

    print("=" * 60)


    def send_security_alert(event):

        return {

            "email_sent": False,

            "sms_sent": False
        }


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO
)


logger = logging.getLogger(
    __name__
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__
)


app.secret_key = os.getenv(
    "SECRET_KEY",
    "change-this-secret-key-for-production"
)


app.config[
    "SQLALCHEMY_TRACK_MODIFICATIONS"
] = False


database_url = os.getenv(
    "DATABASE_URL",
    "sqlite:///database.db"
)


if database_url.startswith(
    "postgres://"
):

    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )


app.config[
    "SQLALCHEMY_DATABASE_URI"
] = database_url


db.init_app(
    app
)


# ============================================================
# DEMO USERS
# ============================================================

VALID_USERS = {

    "admin": "admin123",

    "alice": "alice123",

    "bob": "bob123",

    "varshini": "varshini123"
}


# ============================================================
# FAILED LOGIN TRACKER
# ============================================================

failed_tracker = {}


# ============================================================
# NORMAL LOGIN HOURS
# ============================================================

NORMAL_LOGIN_START = 8

NORMAL_LOGIN_END = 22


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

with app.app_context():

    db.create_all()

    logger.info(
        "Database ready."
    )


# ============================================================
# UTC TIME
# ============================================================

def utc_now():

    return datetime.now(
        timezone.utc
    )


# ============================================================
# CLIENT IP
# ============================================================

def get_client_ip():

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )


    if forwarded_for:

        return (
            forwarded_for
            .split(",")[0]
            .strip()
        )


    return (
        request.remote_addr
        or
        "Unknown"
    )


# ============================================================
# USER AGENT
# ============================================================

def get_user_agent():

    return request.headers.get(
        "User-Agent",
        "Unknown"
    )


# ============================================================
# DEVICE TYPE
# ============================================================

def get_device_type(
    user_agent
):

    ua = (
        user_agent
        or ""
    ).lower()


    # --------------------------------------------------------
    # Android
    # --------------------------------------------------------

    if "android" in ua:

        return "Mobile/Android"


    # --------------------------------------------------------
    # iPhone / iPad
    # --------------------------------------------------------

    if (
        "iphone" in ua
        or
        "ipad" in ua
    ):

        return "Mobile/iOS"


    # --------------------------------------------------------
    # Windows
    # --------------------------------------------------------

    if "windows" in ua:

        return "Chrome/Windows"


    # --------------------------------------------------------
    # Mac
    # --------------------------------------------------------

    if (
        "macintosh" in ua
        or
        "mac os" in ua
    ):

        return "Safari/Mac"


    # --------------------------------------------------------
    # Linux
    # --------------------------------------------------------

    if "linux" in ua:

        return "Firefox/Linux"


    return "Unknown"


# ============================================================
# DEVICE DETAILS
# ============================================================

def get_device_details():

    user_agent = get_user_agent()

    return get_device_type(
        user_agent
    )


# ============================================================
# LOCATION
# ============================================================

def get_location():

    location = request.form.get(
        "location",
        ""
    ).strip()


    if not location:

        location = request.args.get(
            "location",
            ""
        ).strip()


    if not location:

        location = "Unknown"


    return location


# ============================================================
# TRUSTED PROFILE
# ============================================================

def get_trusted_profile(
    username
):

    return TrustedDevice.query.filter_by(
        username=username
    ).all()


# ============================================================
# TRUSTED DEVICE CHECK
# ============================================================

def check_trusted_device(
    username,
    device,
    user_agent,
    ip_address,
    location
):

    exact_match = TrustedDevice.query.filter_by(

        username=username,

        device=device,

        ip_address=ip_address

    ).first()


    known_device = TrustedDevice.query.filter_by(

        username=username,

        device=device

    ).first()


    known_ip = TrustedDevice.query.filter_by(

        username=username,

        ip_address=ip_address

    ).first()


    known_location = TrustedDevice.query.filter_by(

        username=username,

        location=location

    ).first()


    known_user_agent = TrustedDevice.query.filter_by(

        username=username,

        user_agent=user_agent

    ).first()


    return {

        "trusted_exact_match":
            exact_match is not None,

        "known_device":
            known_device is not None,

        "known_ip":
            known_ip is not None,

        "known_location":
            known_location is not None,

        "known_user_agent":
            known_user_agent is not None
    }


# ============================================================
# BEHAVIORAL RISK
# ============================================================

def calculate_behavioral_risk(
    username,
    device,
    user_agent,
    ip_address,
    location,
    login_time=None
):

    if login_time is None:

        login_time = datetime.now()


    profile = check_trusted_device(

        username=username,

        device=device,

        user_agent=user_agent,

        ip_address=ip_address,

        location=location
    )


    # ========================================================
    # FIRST LOGIN / NO PROFILE
    # ========================================================

    existing_profile = TrustedDevice.query.filter_by(
        username=username
    ).first()


    if existing_profile is None:

        return {

            "score": 0,

            "risk_level": "Safe",

            "explanation": (
                "First successful login for this user. "
                "Device and login behaviour will be "
                "registered as the initial trusted profile."
            ),

            "known_device": False,

            "known_ip": False,

            "known_location": False,

            "trusted_exact_match": False,

            "first_login": True
        }


    score = 0

    reasons = []


    # ========================================================
    # EXACT TRUSTED DEVICE
    # ========================================================

    if profile[
        "trusted_exact_match"
    ]:

        reasons.append(
            "Known trusted device and IP"
        )


    # ========================================================
    # NEW DEVICE
    # ========================================================

    if not profile[
        "known_device"
    ]:

        score += 35

        reasons.append(
            "New device detected"
        )


    else:

        reasons.append(
            "Known device detected"
        )


    # ========================================================
    # NEW USER AGENT
    # ========================================================

    if not profile[
        "known_user_agent"
    ]:

        score += 10

        reasons.append(
            "New browser/device fingerprint detected"
        )


    # ========================================================
    # NEW IP
    # ========================================================

    if not profile[
        "known_ip"
    ]:

        score += 25

        reasons.append(
            "New IP address detected"
        )


    else:

        reasons.append(
            "Known IP address detected"
        )


    # ========================================================
    # NEW LOCATION
    # ========================================================

    if not profile[
        "known_location"
    ]:

        score += 25

        reasons.append(
            "New location detected"
        )


    else:

        reasons.append(
            "Known location detected"
        )


    # ========================================================
    # UNUSUAL LOGIN TIME
    # ========================================================

    hour = login_time.hour


    if (
        hour < NORMAL_LOGIN_START
        or
        hour >= NORMAL_LOGIN_END
    ):

        score += 20

        reasons.append(
            "Login outside normal hours"
        )

    else:

        reasons.append(
            "Login time is within normal hours"
        )


    score = min(
        score,
        100
    )


    # ========================================================
    # BEHAVIORAL RISK LEVEL
    # ========================================================

    if score == 0:

        risk_level = "Safe"

    elif score <= 20:

        risk_level = "Low"

    elif score <= 45:

        risk_level = "Medium"

    elif score <= 70:

        risk_level = "High"

    else:

        risk_level = "Critical"


    explanation = "; ".join(
        reasons
    )


    return {

        "score": score,

        "risk_level": risk_level,

        "explanation": explanation,

        "known_device":
            profile["known_device"],

        "known_ip":
            profile["known_ip"],

        "known_location":
            profile["known_location"],

        "trusted_exact_match":
            profile["trusted_exact_match"],

        "first_login": False
    }


# ============================================================
# REGISTER TRUSTED DEVICE
# ============================================================

def register_trusted_device(
    username,
    device,
    user_agent,
    ip_address,
    location
):

    existing = TrustedDevice.query.filter_by(

        username=username,

        device=device,

        ip_address=ip_address

    ).first()


    now = utc_now()


    if existing:

        existing.last_seen = now

        existing.login_count = (
            existing.login_count or 0
        ) + 1

        existing.location = location

        existing.user_agent = user_agent


    else:

        trusted = TrustedDevice(

            username=username,

            device=device,

            user_agent=user_agent,

            ip_address=ip_address,

            location=location,

            first_seen=now,

            last_seen=now,

            login_count=1
        )


        db.session.add(
            trusted
        )


    db.session.commit()


    logger.info(
        "Trusted device updated for user: %s",
        username
    )


# ============================================================
# CREATE LOGIN EVENT
# ============================================================

def create_event(
    username,
    ip_address,
    location,
    device,
    timestamp,
    login_success,
    failed_attempts,
    is_anomalous,
    risk_level,
    risk_score,
    explanation,
    anomaly_types=None
):

    if anomaly_types is None:

        anomaly_types = []


    if isinstance(
        anomaly_types,
        list
    ):

        anomaly_types_string = ",".join(
            anomaly_types
        )

    else:

        anomaly_types_string = str(
            anomaly_types
        )


    event = LoginEvent(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        timestamp=timestamp,

        login_success=login_success,

        failed_attempts=failed_attempts,

        is_anomalous=is_anomalous,

        risk_level=risk_level,

        risk_score=risk_score,

        anomaly_types=anomaly_types_string,

        explanation=explanation
    )


    db.session.add(
        event
    )

    db.session.commit()


    return event


# ============================================================
# SEND ALERT
# ============================================================

def send_alert_if_required(
    event
):

    if not ALERT_ENGINE_AVAILABLE:

        logger.warning(
            "Alert engine unavailable."
        )

        return {

            "email_sent": False,

            "sms_sent": False
        }


    risk_level = str(
        getattr(
            event,
            "risk_level",
            "LOW"
        )
    ).strip().upper()


    if risk_level not in [
        "HIGH",
        "CRITICAL"
    ]:

        logger.info(
            "No security alert required. "
            "Risk level: %s",
            risk_level
        )

        return {

            "email_sent": False,

            "sms_sent": False
        }


    try:

        result = send_security_alert(
            event
        )


        logger.info(
            "Security alert result: %s",
            result
        )


        return result


    except Exception as error:

        logger.exception(
            "Security alert failed: %s",
            error
        )


        return {

            "email_sent": False,

            "sms_sent": False
        }


# ============================================================
# EVENT → DICTIONARY
# ============================================================

def event_to_dict(
    event
):

    anomaly_types = []

    if getattr(
        event,
        "anomaly_types",
        ""
    ):

        anomaly_types = [

            x.strip()

            for x in event.anomaly_types.split(",")

            if x.strip()
        ]


    return {

        "id":
            getattr(
                event,
                "id",
                None
            ),

        "username":
            getattr(
                event,
                "username",
                None
            ),

        "ip_address":
            getattr(
                event,
                "ip_address",
                None
            ),

        "location":
            getattr(
                event,
                "location",
                None
            ),

        "device":
            getattr(
                event,
                "device",
                None
            ),

        "timestamp":
            (
                event.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if getattr(
                    event,
                    "timestamp",
                    None
                )
                else ""
            ),

        "login_success":
            bool(
                getattr(
                    event,
                    "login_success",
                    False
                )
            ),

        "failed_attempts":
            getattr(
                event,
                "failed_attempts",
                0
            ) or 0,

        "is_anomalous":
            bool(
                getattr(
                    event,
                    "is_anomalous",
                    False
                )
            ),

        "risk_level":
            getattr(
                event,
                "risk_level",
                "Unknown"
            ),

        "risk_score":
            getattr(
                event,
                "risk_score",
                0
            ) or 0,

        "anomaly_types":
            anomaly_types,

        "explanation":
            getattr(
                event,
                "explanation",
                ""
            ) or ""
    }


# ============================================================
# LOGIN ROUTE
# ============================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )


    username = request.form.get(
        "username",
        ""
    ).strip()


    password = request.form.get(
        "password",
        ""
    )


    ip_address = get_client_ip()

    location = get_location()

    device = get_device_details()

    user_agent = get_user_agent()

    timestamp = datetime.now()


    # ========================================================
    # FAILED LOGIN TRACKING
    # ========================================================

    tracker_key = (
        f"{username}:{ip_address}"
    )


    failed_attempts = failed_tracker.get(
        tracker_key,
        0
    )


    credentials_valid = (

        username in VALID_USERS

        and

        VALID_USERS[username] == password
    )


    # ========================================================
    # INVALID CREDENTIALS
    # ========================================================

    if not credentials_valid:

        failed_attempts += 1


        failed_tracker[
            tracker_key
        ] = failed_attempts


        anomaly_result = detect_anomalies(

            username=username,

            ip_address=ip_address,

            location=location,

            device=device,

            login_success=False,

            failed_attempts=failed_attempts,

            timestamp=timestamp
        )


        risk_score = anomaly_result.get(
            "risk_score",
            anomaly_result.get(
                "score",
                0
            )
        )


        risk_level = anomaly_result.get(
            "risk_level",
            "Medium"
        )


        explanation = anomaly_result.get(
            "explanation",
            "Invalid credentials detected."
        )


        anomaly_types = anomaly_result.get(
            "anomalies",
            []
        )


        # Force escalating risk
        if failed_attempts >= 5:

            risk_level = "Critical"

        elif failed_attempts >= 3:

            risk_level = "High"


        is_anomalous = True


        event = create_event(

            username=username,

            ip_address=ip_address,

            location=location,

            device=device,

            timestamp=timestamp,

            login_success=False,

            failed_attempts=failed_attempts,

            is_anomalous=is_anomalous,

            risk_level=risk_level,

            risk_score=risk_score,

            explanation=explanation,

            anomaly_types=anomaly_types
        )


        alert_result = send_alert_if_required(
            event
        )


        return render_template(

            "login.html",

            error=(
                "Invalid username or password."
            ),

            risk_level=risk_level,

            risk_score=risk_score,

            explanation=explanation,

            alert_result=alert_result
        )


    # ========================================================
    # VALID CREDENTIALS
    # ========================================================

    failed_tracker[
        tracker_key
    ] = 0


    # ========================================================
    # BEHAVIORAL ANALYSIS
    # ========================================================

    behavioral_result = calculate_behavioral_risk(

        username=username,

        device=device,

        user_agent=user_agent,

        ip_address=ip_address,

        location=location,

        login_time=timestamp
    )


    behavioral_score = behavioral_result[
        "score"
    ]


    behavioral_risk = behavioral_result[
        "risk_level"
    ]


    behavioral_explanation = behavioral_result[
        "explanation"
    ]


    # ========================================================
    # EXISTING ANOMALY ENGINE
    # ========================================================

    anomaly_result = detect_anomalies(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        login_success=True,

        failed_attempts=0,

        timestamp=timestamp
    )


    anomaly_score = anomaly_result.get(
        "risk_score",
        anomaly_result.get(
            "score",
            0
        )
    )


    anomaly_level = anomaly_result.get(
        "risk_level",
        "Safe"
    )


    anomaly_explanation = anomaly_result.get(
        "explanation",
        ""
    )


    anomaly_types = anomaly_result.get(
        "anomalies",
        []
    )


    # ========================================================
    # COMBINE SCORES
    # ========================================================

    final_score = max(
        behavioral_score,
        anomaly_score
    )


    # ========================================================
    # RISK PRIORITY
    # ========================================================

    risk_priority = {

        "SAFE": 0,

        "LOW": 1,

        "MEDIUM": 2,

        "HIGH": 3,

        "CRITICAL": 4
    }


    behavioral_rank = risk_priority.get(

        str(
            behavioral_risk
        ).upper(),

        0
    )


    anomaly_rank = risk_priority.get(

        str(
            anomaly_level
        ).upper(),

        0
    )


    if behavioral_rank >= anomaly_rank:

        final_risk_level = behavioral_risk

    else:

        final_risk_level = anomaly_level


    # ========================================================
    # COMBINE EXPLANATIONS
    # ========================================================

    explanations = []


    if behavioral_explanation:

        explanations.append(
            behavioral_explanation
        )


    if anomaly_explanation:

        if anomaly_explanation not in explanations:

            explanations.append(
                anomaly_explanation
            )


    final_explanation = "; ".join(
        explanations
    )


    # ========================================================
    # FIRST LOGIN ENROLLMENT
    # ========================================================

    first_login = behavioral_result.get(
        "first_login",
        False
    )


    if first_login and not anomaly_types:

        final_score = 0

        final_risk_level = "Safe"

        final_explanation = (

            "First successful login detected. "
            "The device, IP address, location and "
            "browser fingerprint have been registered "
            "as the initial trusted profile."
        )

        anomaly_types = []


    # ========================================================
    # SAFE / LOW
    # ========================================================

    if final_risk_level.upper() in [
        "SAFE",
        "LOW"
    ]:

        is_anomalous = False


        event = create_event(

            username=username,

            ip_address=ip_address,

            location=location,

            device=device,

            timestamp=timestamp,

            login_success=True,

            failed_attempts=0,

            is_anomalous=is_anomalous,

            risk_level=final_risk_level,

            risk_score=final_score,

            explanation=final_explanation,

            anomaly_types=anomaly_types
        )


        # ====================================================
        # REGISTER TRUSTED DEVICE
        # ====================================================

        register_trusted_device(

            username=username,

            device=device,

            user_agent=user_agent,

            ip_address=ip_address,

            location=location
        )


        session[
            "logged_in"
        ] = True


        session[
            "username"
        ] = username


        session[
            "suspicious_login"
        ] = False


        logger.info(
            "Successful trusted login: %s",
            username
        )


        return redirect(
            url_for(
                "dashboard"
            )
        )


    # ========================================================
    # MEDIUM / HIGH / CRITICAL
    # ========================================================

    is_anomalous = True


    event = create_event(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        timestamp=timestamp,

        login_success=True,

        failed_attempts=0,

        is_anomalous=is_anomalous,

        risk_level=final_risk_level,

        risk_score=final_score,

        explanation=final_explanation,

        anomaly_types=anomaly_types
    )


    # ========================================================
    # HIGH / CRITICAL ALERT
    # ========================================================

    alert_result = send_alert_if_required(
        event
    )


    # ========================================================
    # DEMO SESSION
    # ========================================================

    session[
        "logged_in"
    ] = True


    session[
        "username"
    ] = username


    session[
        "suspicious_login"
    ] = True


    logger.warning(
        "Valid credentials but suspicious "
        "behavior detected for user: %s",
        username
    )


    return render_template(

        "login.html",

        error=(
            "Valid credentials detected, "
            "but suspicious login behavior was found."
        ),

        risk_level=final_risk_level,

        risk_score=final_score,

        explanation=final_explanation,

        alert_result=alert_result
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
def dashboard():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            url_for(
                "login"
            )
        )


    username = session.get(
        "username"
    )


    return render_template(

        "dashboard.html",

        username=username
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout"
)
def logout():

    session.clear()

    return redirect(
        url_for(
            "login"
        )
    )


# ============================================================
# API — EVENTS
# ============================================================

@app.route(
    "/api/events",
    methods=["GET"]
)
def api_events():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    limit = request.args.get(
        "limit",
        100,
        type=int
    )


    events = LoginEvent.query.order_by(

        LoginEvent.timestamp.desc()

    ).limit(
        limit
    ).all()


    return jsonify(
        [
            event_to_dict(event)
            for event in events
        ]
    )


# ============================================================
# API — STATS
# ============================================================

@app.route(
    "/api/stats",
    methods=["GET"]
)
def api_stats():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    total = LoginEvent.query.count()


    successful = LoginEvent.query.filter_by(
        login_success=True
    ).count()


    failed = LoginEvent.query.filter_by(
        login_success=False
    ).count()


    anomalous = LoginEvent.query.filter_by(
        is_anomalous=True
    ).count()


    safe = LoginEvent.query.filter_by(
        risk_level="Safe"
    ).count()


    low = LoginEvent.query.filter_by(
        risk_level="Low"
    ).count()


    medium = LoginEvent.query.filter_by(
        risk_level="Medium"
    ).count()


    high = LoginEvent.query.filter_by(
        risk_level="High"
    ).count()


    critical = LoginEvent.query.filter_by(
        risk_level="Critical"
    ).count()


    by_risk = {

        "Safe": safe,

        "Low": low,

        "Medium": medium,

        "High": high,

        "Critical": critical
    }


    return jsonify({

        "total": total,

        "successful": successful,

        "failed": failed,

        "anomalous": anomalous,

        "flagged": anomalous,

        "safe": safe,

        "low": low,

        "medium": medium,

        "high": high,

        "critical": critical,

        "by_risk": by_risk
    })


# ============================================================
# API — LIVE EVENT
# ============================================================

@app.route(
    "/api/live",
    methods=["GET"]
)
def api_live():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    event = LoginEvent.query.order_by(

        LoginEvent.timestamp.desc()

    ).first()


    if not event:

        return jsonify(
            {
                "event": None
            }
        )


    return jsonify(
        event_to_dict(event)
    )


# ============================================================
# API — TRUSTED DEVICES
# ============================================================

@app.route(
    "/api/trusted-devices",
    methods=["GET"]
)
def api_trusted_devices():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    username = request.args.get(
        "username"
    )


    if not username:

        username = session.get(
            "username"
        )


    devices = TrustedDevice.query.filter_by(

        username=username

    ).order_by(

        TrustedDevice.last_seen.desc()

    ).all()


    return jsonify(
        [
            device.to_dict()
            for device in devices
        ]
    )


# ============================================================
# API — INJECT DEMO EVENT
# ============================================================

@app.route(
    "/api/inject",
    methods=["POST"]
)
def api_inject():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    data = request.get_json(
        silent=True
    ) or {}


    username = data.get(
        "username",
        "attacker"
    )


    ip_address = data.get(
        "ip_address",
        "8.8.8.8"
    )


    location = data.get(
        "location",
        "Unknown City"
    )


    device = data.get(
        "device",
        "Unknown Device"
    )


    login_success = data.get(
        "login_success",
        False
    )


    failed_attempts = int(
        data.get(
            "failed_attempts",
            10
        )
    )


    timestamp = datetime.now()


    user_agent = data.get(
        "user_agent",
        "Demo User Agent"
    )


    # ========================================================
    # EXISTING ANOMALY ENGINE
    # ========================================================

    anomaly_result = detect_anomalies(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        login_success=login_success,

        failed_attempts=failed_attempts,

        timestamp=timestamp
    )


    # ========================================================
    # BEHAVIORAL ANALYSIS
    # ========================================================

    behavioral_result = calculate_behavioral_risk(

        username=username,

        device=device,

        user_agent=user_agent,

        ip_address=ip_address,

        location=location,

        login_time=timestamp
    )


    anomaly_score = anomaly_result.get(
        "risk_score",
        anomaly_result.get(
            "score",
            0
        )
    )


    behavioral_score = behavioral_result.get(
        "score",
        0
    )


    risk_score = max(
        anomaly_score,
        behavioral_score
    )


    # Failed attempts additional risk
    if failed_attempts >= 5:

        risk_score = min(
            risk_score + 20,
            100
        )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    if risk_score >= 81:

        risk_level = "Critical"

    elif risk_score >= 61:

        risk_level = "High"

    elif risk_score >= 31:

        risk_level = "Medium"

    elif risk_score >= 1:

        risk_level = "Low"

    else:

        risk_level = "Safe"


    # ========================================================
    # COMBINE ANOMALIES
    # ========================================================

    anomaly_types = list(
        anomaly_result.get(
            "anomalies",
            []
        )
    )


    behavioral_reasons = []


    if not behavioral_result.get(
        "known_device",
        True
    ):

        behavioral_reasons.append(
            "new_trusted_device"
        )


    if not behavioral_result.get(
        "known_ip",
        True
    ):

        behavioral_reasons.append(
            "new_ip"
        )


    if not behavioral_result.get(
        "known_location",
        True
    ):

        behavioral_reasons.append(
            "new_location"
        )


    for item in behavioral_reasons:

        if item not in anomaly_types:

            anomaly_types.append(
                item
            )


    # ========================================================
    # EXPLANATION
    # ========================================================

    explanations = []


    anomaly_explanation = anomaly_result.get(
        "explanation",
        ""
    )


    behavioral_explanation = behavioral_result.get(
        "explanation",
        ""
    )


    if anomaly_explanation:

        explanations.append(
            anomaly_explanation
        )


    if behavioral_explanation:

        explanations.append(
            behavioral_explanation
        )


    final_explanation = "; ".join(
        explanations
    )


    is_anomalous = (
        risk_level.upper()
        not in [
            "SAFE",
            "LOW"
        ]
    )


    event = create_event(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        timestamp=timestamp,

        login_success=login_success,

        failed_attempts=failed_attempts,

        is_anomalous=is_anomalous,

        risk_level=risk_level,

        risk_score=risk_score,

        explanation=final_explanation,

        anomaly_types=anomaly_types
    )


    alert_result = send_alert_if_required(
        event
    )


    return jsonify({

        "success": True,

        "event": event_to_dict(
            event
        ),

        "risk_level": risk_level,

        "risk_score": risk_score,

        "explanation": final_explanation,

        "alert": alert_result
    })


# ============================================================
# API — CLEAR EVENTS
# ============================================================

@app.route(
    "/api/clear",
    methods=["POST"]
)
def api_clear():

    if not session.get(
        "logged_in"
    ):

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


    LoginEvent.query.delete()

    db.session.commit()


    return jsonify({

        "success": True,

        "message":
            "All login events cleared."
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/health"
)
def health():

    return jsonify({

        "status":
            "running",

        "database":
            "available",

        "alert_engine":
            (
                "available"
                if ALERT_ENGINE_AVAILABLE
                else "unavailable"
            ),

        "trusted_device":
            "enabled",

        "behavioral_analysis":
            "enabled"
    })


# ============================================================
# GENERATE 10-DAY REPORT
# ============================================================

@app.route(
    "/generate-10-day-report"
)
def generate_10_day_report():

    if not session.get(
        "logged_in"
    ):

        return redirect(
            url_for(
                "login"
            )
        )


    try:

        from report_generator import (
            generate_report
        )


        end_date = datetime.now()


        start_date = (

            end_date

            -

            timedelta(
                days=10
            )
        )


        events = LoginEvent.query.filter(

            LoginEvent.timestamp >= start_date,

            LoginEvent.timestamp <= end_date

        ).order_by(

            LoginEvent.timestamp.asc()

        ).all()


        report_path = generate_report(

            events,

            start_date,

            end_date
        )


        return send_file(

            report_path,

            as_attachment=True
        )


    except Exception as error:

        logger.exception(
            "Report generation failed: %s",
            error
        )


        return jsonify({

            "error":
                "Report generation failed",

            "details":
                str(error)

        }), 500


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "REAL-TIME LOGIN ANOMALY DETECTION SYSTEM"
    )

    print("=" * 60)

    print(
        "Existing Anomaly Engine  : ENABLED"
    )

    print(
        "Explanation Engine       : ENABLED"
    )

    print(
        "Trusted Device Detection : ENABLED"
    )

    print(
        "Behavioral Analysis      : ENABLED"
    )

    print(
        "Device Fingerprinting    : ENABLED"
    )

    print(
        "IP Recognition           : ENABLED"
    )

    print(
        "Time Analysis            : ENABLED"
    )

    print(
        "Email Alerts             : ENABLED"
    )

    print(
        "SMS Demo Alerts          : ENABLED"
    )

    print(

        "Alert Engine             :",

        (
            "AVAILABLE"
            if ALERT_ENGINE_AVAILABLE
            else "UNAVAILABLE"
        )
    )

    print("=" * 60)


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=True
    )
