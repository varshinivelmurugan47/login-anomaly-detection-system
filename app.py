import os
from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    send_file
)

from models import db, LoginEvent
from anomaly_engine import detect_anomalies
from alert_engine import send_security_alert
from report_generator import generate_10_day_report


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "FLASK_SECRET_KEY",
    "demo-secret-key-change-this"
)

# =========================================================
# DATABASE CONFIGURATION
# =========================================================

database_url = os.getenv(
    "DATABASE_URL",
    "sqlite:///database.db"
)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url

# Render/PostgreSQL sometimes gives postgres://
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# =========================================================
# DEMO USERS
# =========================================================

VALID_USERS = {
    "admin": "admin123",
    "alice": "alice123",
    "bob": "bob123"
}


# =========================================================
# FAILED LOGIN TRACKER
# =========================================================

failed_tracker = {}


# =========================================================
# KNOWN LOCATIONS
# =========================================================

KNOWN_LOCATIONS = {
    "Chennai",
    "Mumbai",
    "Delhi",
    "Bangalore",
    "Hyderabad",
    "localhost",
    "local"
}


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():
    db.create_all()


# =========================================================
# DEVICE DETECTION
# =========================================================

def detect_device(user_agent):

    user_agent = user_agent.lower()

    if "android" in user_agent:
        return "Mobile/Android"

    if "iphone" in user_agent or "ipad" in user_agent:
        return "Mobile/iOS"

    if "windows" in user_agent:
        return "Chrome/Windows"

    if "macintosh" in user_agent:
        return "Safari/Mac"

    if "linux" in user_agent:
        return "Firefox/Linux"

    return "Unknown"


# =========================================================
# LOGIN PAGE
# =========================================================

@app.route("/")
def index():

    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    # -----------------------------------------------------
    # GET LOGIN DATA
    # -----------------------------------------------------

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    ip_address = request.remote_addr or "127.0.0.1"

    user_agent = request.headers.get(
        "User-Agent",
        ""
    )

    device = detect_device(
        user_agent
    )

    # -----------------------------------------------------
    # DEMO LOCATION
    # -----------------------------------------------------

    # If your login page sends location,
    # this value will be used.
    #
    # Otherwise Chennai is used for demo.

    location = request.form.get(
        "location",
        "Chennai"
    ).strip()

    if not location:
        location = "Chennai"

    # -----------------------------------------------------
    # CHECK CREDENTIALS
    # -----------------------------------------------------

    credentials_correct = (
        VALID_USERS.get(username) == password
    )

    # -----------------------------------------------------
    # FAILED ATTEMPT COUNT
    # -----------------------------------------------------

    if username not in failed_tracker:
        failed_tracker[username] = 0

    if not credentials_correct:

        failed_tracker[username] += 1

    else:

        # Successful login resets failed attempts
        failed_tracker[username] = 0

    failed_attempts = failed_tracker[username]

    # -----------------------------------------------------
    # CURRENT TIME
    # -----------------------------------------------------

    timestamp = datetime.utcnow()

    # =====================================================
    # SAFE LOGIN RULE
    # =====================================================

    # Correct credentials + known location
    # will normally be considered Safe.
    #
    # Other events go through anomaly detection.

    location_safe = (
        location in KNOWN_LOCATIONS
    )

    if credentials_correct and location_safe:

        risk_level = "Safe"
        risk_score = 0
        is_anomalous = False
        anomalies = []

        explanation = (
            f"Login for '{username}' is normal. "
            "Valid credentials and recognized location."
        )

    else:

        # =================================================
        # ANOMALY DETECTION
        # =================================================

        result = detect_anomalies(
            username=username,
            ip_address=ip_address,
            location=location,
            device=device,
            login_success=credentials_correct,
            failed_attempts=failed_attempts,
            timestamp=timestamp
        )

        anomalies = result.get(
            "anomalies",
            []
        )

        risk_score = result.get(
            "score",
            0
        )

        risk_level = result.get(
            "risk_level",
            "Safe"
        )

        is_anomalous = result.get(
            "is_anomalous",
            False
        )

        explanation = result.get(
            "explanation",
            ""
        )

    # =====================================================
    # DATABASE EVENT
    # =====================================================

    event = LoginEvent(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        timestamp=timestamp,

        login_success=credentials_correct,

        failed_attempts=failed_attempts,

        is_anomalous=is_anomalous,

        risk_level=risk_level,

        risk_score=risk_score,

        anomaly_types=",".join(anomalies),

        explanation=explanation
    )

    db.session.add(event)

    db.session.commit()

    # =====================================================
    # SECURITY ALERT
    # =====================================================

    alert_result = {

        "alert_triggered": False,

        "email_sent": False,

        "sms_sent": False

    }

    # -----------------------------------------------------
    # HIGH / CRITICAL ALERT
    # -----------------------------------------------------

    if risk_level in [
        "High",
        "Critical"
    ]:

        print("\n")
        print("=" * 70)
        print("🚨 HIGH RISK LOGIN DETECTED")
        print("=" * 70)

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
            f"Risk Level : {risk_level}"
        )

        print(
            f"Risk Score : {risk_score}"
        )

        print(
            f"Explanation: {explanation}"
        )

        print("=" * 70)

        # -------------------------------------------------
        # SEND EMAIL + SMS
        # -------------------------------------------------

        try:

            alert_result = send_security_alert(

                username=username,

                ip_address=ip_address,

                location=location,

                risk_level=risk_level,

                risk_score=risk_score,

                explanation=explanation
            )

        except Exception as e:

            print(
                f"Alert engine error: {e}"
            )

            alert_result = {

                "alert_triggered": True,

                "email_sent": False,

                "sms_sent": False,

                "error": str(e)

            }

    # =====================================================
    # LOGIN SUCCESS
    # =====================================================

    if credentials_correct:

        session["logged_in"] = True

        session["username"] = username

        session["login_time"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # -----------------------------------------------
        # SUCCESSFUL LOGIN
        # -----------------------------------------------

        return redirect(
            url_for("dashboard")
        )

    # =====================================================
    # LOGIN FAILURE
    # =====================================================

    return render_template(

        "login.html",

        error="Invalid username or password",

        risk_level=risk_level,

        risk_score=risk_score,

        explanation=explanation,

        alert_result=alert_result
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    return render_template(
        "dashboard.html",
        username=session.get("username")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# API - LOGIN EVENTS
# =========================================================

@app.route("/api/events")
def api_events():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    events = LoginEvent.query.order_by(
        LoginEvent.timestamp.desc()
    ).limit(100).all()

    return jsonify([
        event.to_dict()
        for event in events
    ])


# =========================================================
# API - STATISTICS
# =========================================================

@app.route("/api/stats")
def api_stats():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    total = LoginEvent.query.count()

    flagged = LoginEvent.query.filter_by(
        is_anomalous=True
    ).count()

    high = LoginEvent.query.filter_by(
        risk_level="High"
    ).count()

    critical = LoginEvent.query.filter_by(
        risk_level="Critical"
    ).count()

    medium = LoginEvent.query.filter_by(
        risk_level="Medium"
    ).count()

    low = LoginEvent.query.filter_by(
        risk_level="Low"
    ).count()

    safe = LoginEvent.query.filter_by(
        risk_level="Safe"
    ).count()

    successful = LoginEvent.query.filter_by(
        login_success=True
    ).count()

    failed = LoginEvent.query.filter_by(
        login_success=False
    ).count()

    return jsonify({

        "total": total,

        "flagged": flagged,

        "successful": successful,

        "failed": failed,

        "high": high,

        "critical": critical,

        "medium": medium,

        "low": low,

        "safe": safe,

        "by_risk": {

            "Safe": safe,

            "Low": low,

            "Medium": medium,

            "High": high,

            "Critical": critical

        }

    })


# =========================================================
# API - LIVE EVENTS
# =========================================================

@app.route("/api/live")
def api_live():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    current_time = datetime.utcnow()

    one_minute_ago = (
        current_time -
        timedelta(seconds=60)
    )

    events = LoginEvent.query.filter(
        LoginEvent.timestamp >= one_minute_ago
    ).order_by(
        LoginEvent.timestamp.desc()
    ).all()

    return jsonify([
        event.to_dict()
        for event in events
    ])


# =========================================================
# API - CLEAR EVENTS
# =========================================================

@app.route("/api/clear", methods=["POST"])
def api_clear():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    LoginEvent.query.delete()

    db.session.commit()

    failed_tracker.clear()

    return jsonify({

        "success": True,

        "message": "All login events cleared."

    })


# =========================================================
# API - TEST EVENT INJECTION
# =========================================================

@app.route("/api/inject", methods=["POST"])
def api_inject():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        "test_user"
    )

    ip_address = data.get(
        "ip_address",
        "8.8.8.8"
    )

    location = data.get(
        "location",
        "Unknown"
    )

    device = data.get(
        "device",
        "Unknown"
    )

    login_success = data.get(
        "login_success",
        False
    )

    failed_attempts = int(
        data.get(
            "failed_attempts",
            3
        )
    )

    timestamp = datetime.utcnow()

    # -----------------------------------------------------
    # RUN ANOMALY ENGINE
    # -----------------------------------------------------

    result = detect_anomalies(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        login_success=login_success,

        failed_attempts=failed_attempts,

        timestamp=timestamp
    )

    # -----------------------------------------------------
    # CREATE EVENT
    # -----------------------------------------------------

    event = LoginEvent(

        username=username,

        ip_address=ip_address,

        location=location,

        device=device,

        timestamp=timestamp,

        login_success=login_success,

        failed_attempts=failed_attempts,

        is_anomalous=result["is_anomalous"],

        risk_level=result["risk_level"],

        risk_score=result["score"],

        anomaly_types=",".join(
            result["anomalies"]
        ),

        explanation=result["explanation"]

    )

    db.session.add(event)

    db.session.commit()

    # -----------------------------------------------------
    # ALERT
    # -----------------------------------------------------

    alert_result = {

        "alert_triggered": False,

        "email_sent": False,

        "sms_sent": False

    }

    if result["risk_level"] in [
        "High",
        "Critical"
    ]:

        try:

            alert_result = send_security_alert(

                username=username,

                ip_address=ip_address,

                location=location,

                risk_level=result["risk_level"],

                risk_score=result["score"],

                explanation=result["explanation"]

            )

        except Exception as e:

            alert_result = {

                "alert_triggered": True,

                "email_sent": False,

                "sms_sent": False,

                "error": str(e)

            }

    return jsonify({

        "success": True,

        "event": event.to_dict(),

        "alert": alert_result

    })


# =========================================================
# 10-DAY PDF REPORT
# =========================================================

@app.route("/generate-10-day-report")
def generate_10_day_report_route():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    # -----------------------------------------------------
    # LAST 10 DAYS
    # -----------------------------------------------------

    end_date = datetime.utcnow()

    start_date = (
        end_date -
        timedelta(days=10)
    )

    events = LoginEvent.query.filter(

        LoginEvent.timestamp >= start_date,

        LoginEvent.timestamp <= end_date

    ).order_by(

        LoginEvent.timestamp.desc()

    ).all()

    # -----------------------------------------------------
    # REPORT FOLDER
    # -----------------------------------------------------

    reports_folder = os.path.join(

        app.root_path,

        "reports"

    )

    os.makedirs(

        reports_folder,

        exist_ok=True

    )

    # -----------------------------------------------------
    # FILE NAME
    # -----------------------------------------------------

    filename = (

        "login_security_report_"

        + datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        + ".pdf"

    )

    filepath = os.path.join(

        reports_folder,

        filename

    )

    # -----------------------------------------------------
    # GENERATE PDF
    # -----------------------------------------------------

    generate_10_day_report(

        events,

        filepath

    )

    # -----------------------------------------------------
    # DOWNLOAD PDF
    # -----------------------------------------------------

    return send_file(

        filepath,

        as_attachment=True,

        download_name=filename,

        mimetype="application/pdf"

    )


# =========================================================
# REPORT INFORMATION API
# =========================================================

@app.route("/api/report-info")
def report_info():

    if not session.get("logged_in"):

        return jsonify({
            "error": "Unauthorized"
        }), 401

    end_date = datetime.utcnow()

    start_date = (
        end_date -
        timedelta(days=10)
    )

    events = LoginEvent.query.filter(

        LoginEvent.timestamp >= start_date,

        LoginEvent.timestamp <= end_date

    ).all()

    total = len(events)

    successful = sum(

        1
        for event in events
        if event.login_success

    )

    failed = total - successful

    safe = sum(

        1
        for event in events
        if event.risk_level == "Safe"

    )

    low = sum(

        1
        for event in events
        if event.risk_level == "Low"

    )

    medium = sum(

        1
        for event in events
        if event.risk_level == "Medium"

    )

    high = sum(

        1
        for event in events
        if event.risk_level == "High"

    )

    critical = sum(

        1
        for event in events
        if event.risk_level == "Critical"

    )

    return jsonify({

        "report_period_days": 10,

        "start_date": start_date.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "end_date": end_date.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "total": total,

        "successful": successful,

        "failed": failed,

        "safe": safe,

        "low": low,

        "medium": medium,

        "high": high,

        "critical": critical

    })


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return jsonify({

        "status": "running",

        "service": "Login Anomaly Detection System",

        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    })


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    port = int(
        os.getenv(
            "PORT",
            5000
        )
    )

    app.run(

        host="0.0.0.0",

        port=port,

        debug=True

    )
