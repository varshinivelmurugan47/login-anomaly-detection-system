@echo off
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting Login Anomaly Detection System...
echo Open browser: http://127.0.0.1:5000
python app.py
pause
