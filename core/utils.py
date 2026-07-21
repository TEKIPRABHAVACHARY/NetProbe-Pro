import socket

def resolve_hostname(ip: str) -> str:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"
