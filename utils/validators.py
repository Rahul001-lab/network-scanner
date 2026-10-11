
import ipaddress


def validate_ip(target):
    """Validate a single IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def validate_network(network):
    """Validate a network in CIDR notation."""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port):
    """Validate a TCP/UDP port number."""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    print("IP valid:", validate_ip("192.168.1.10"))
    print("Network valid:", validate_network("192.168.1.0/24"))
    print("Port valid:", validate_port(443))
