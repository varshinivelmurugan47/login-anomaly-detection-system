import socket
import smtplib

host = "smtp.gmail.com"
port = 587

print("Testing DNS...")

try:
    ip = socket.gethostbyname(host)
    print("Gmail SMTP IP:", ip)
except Exception as e:
    print("DNS ERROR:", e)
    exit()

print("Testing SMTP connection...")

try:
    server = smtplib.SMTP(
        host,
        port,
        timeout=15
    )

    print("SMTP connection successful")

    server.ehlo()

    print("EHLO successful")

    server.starttls()

    print("STARTTLS successful")

    server.ehlo()

    server.quit()

    print("SMTP test completed successfully")

except Exception as e:
    print("SMTP ERROR:", repr(e))
