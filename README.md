# Real-Time Login Anomaly Detection System

A rule-based Flask security application that monitors login activity,
calculates risk scores, detects suspicious behavior, and generates
explainable security alerts.

## Features

- Login monitoring
- Failed-login tracking
- Brute-force detection
- New device detection
- New IP and location detection
- Unusual-time detection
- Rule-based risk scoring
- Safe, Low, Medium, High, and Critical risk levels
- Explainable security alerts
- SQLite database storage
- Dashboard with charts
- PDF security reports
- Resend email alerts
- Simulated SMS notifications
- Trusted-device profiling

## Technology Stack

- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- HTML
- CSS
- JavaScript
- ReportLab
- Resend API

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
Open:

http://127.0.0.1:5000
Security Note

This project is intended for educational and authorized testing purposes. Never upload API keys, passwords, private database files, or personal data.


Push the README:

```bash
git add README.md
git commit -m "Add project documentation"
git push
