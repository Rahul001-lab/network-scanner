
import socket


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8000: "HTTP-alt",
    8080: "HTTP-proxy",
}


def identify_service(port):
    """Return a common service name for a port."""
    return COMMON_SERVICES.get(port, "Unknown")


def grab_banner(ip, port, timeout=2):
    """Collect a basic response banner from a TCP service."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # HTTP services usually wait for a request.
            if port in (80, 8000, 8080):
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    "Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode("ascii"))

            data = sock.recv(1024)

            if data:
                return data.decode("utf-8", errors="replace").strip()

            return "No banner returned"

    except (OSError, socket.timeout) as error:
        return f"Banner unavailable: {error}"


def detect_service(ip, port):
    """Identify a likely service and retrieve its response."""
    service = identify_service(port)
    banner = grab_banner(ip, port)

    return {
        "ip": ip,
        "port": port,
        "service": service,
        "banner": banner,
    }


if __name__ == "__main__":
    result = detect_service("127.0.0.1", 8000)

    print(f"Host:    {result['ip']}")
    print(f"Port:    {result['port']}")
    print(f"Service: {result['service']}")
    print(f"Banner:  {result['banner']}")
