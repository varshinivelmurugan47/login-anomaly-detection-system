import socket

host = "smtp.gmail.com"
port = 587

print("Testing IPv4 connection...")

try:
    ipv4 = socket.gethostbyname(host)
    print("IPv4 address:", ipv4)

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(15)

    sock.connect((ipv4, port))

    print("IPv4 connection SUCCESS")

    sock.close()

except Exception as e:
    print("IPv4 connection FAILED:")
    print(repr(e))
