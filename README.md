# 🛡️ Real-Time Login Anomaly Detection System

A Python + Flask web application that monitors login events,
detects suspicious behavior, scores risk, and explains alerts
using an Explainable AI component.

---

## 📁 Project Structure

```
login_anomaly_detection/
│
├── app.py                    ← Main Flask application (entry point)
├── requirements.txt          ← Python dependencies
├── run.sh / run.bat          ← One-click start scripts
│
├── modules/
│   ├── data_collector.py     ← MODULE 1: Collects & parses login events
│   ├── anomaly_detector.py   ← MODULE 2: Detects anomalies
│   ├── risk_scorer.py        ← MODULE 3: Scores risk (Low/Medium/High)
│   ├── explainable_ai.py     ← MODULE 4: Generates alert explanations
│   └── session_tracker.py    ← MODULE 5: Tracks user sessions
│
├── templates/
│   └── dashboard.html        ← Frontend dashboard (HTML)
│
├── static/
│   ├── css/style.css         ← Dashboard styles
│   └── js/main.js            ← Dashboard logic (JS)
│
└── data/
    └── login_events.json     ← Stored login events (auto-created)
```

---

## 🚀 How to Run

### Step 1 — Install Python (3.8+)
Download from https://python.org

### Step 2 — Install Flask
```bash
pip install flask
```

### Step 3 — Run the app
```bash
python app.py
```
Or double-click `run.bat` (Windows) / `./run.sh` (Mac/Linux)

### Step 4 — Open browser
```
http://127.0.0.1:5000
```

---

## 🧩 Module Guide

| Module | File | What it does |
|--------|------|-------------|
| 1 | data_collector.py   | Generates/parses login events |
| 2 | anomaly_detector.py | Flags unknown location, device, brute force, odd timing |
| 3 | risk_scorer.py      | Assigns Low / Medium / High risk score |
| 4 | explainable_ai.py   | Writes plain-English alert reason |
| 5 | session_tracker.py  | Tracks per-user session history |

---

## 🖥️ Dashboard Features

- ▶ **Simulate Login** — generate a normal login event
- ⚡ **Force Anomaly** — generate a suspicious login
- 🔄 **Auto Mode** — simulate events every 2.5 seconds
- 🔍 **Click any alert** — see full detail + AI explanation
- 📊 **Risk chart** — live doughnut chart by risk level
- 📈 **Timeline chart** — event count over time
- 👥 **Sessions panel** — active users and login count

---

## ⚙️ API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/simulate | Generate a login event |
| GET  | /api/alerts   | Fetch all alerts |
| GET  | /api/stats    | Dashboard statistics |
| GET  | /api/timeline/<user> | User event history |

---

Made with ❤️ for cybersecurity education.
