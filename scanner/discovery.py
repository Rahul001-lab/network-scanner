
import socket
import ipaddress


def check_host(ip, port=80, timeout=1):
    """Check whether a host responds on a TCP port."""
    try:
        with socket.create_connection(
            (str(ip), port),
            timeout=timeout
        ):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def discover_hosts(network, port=80, timeout=1):
    """Discover hosts responding on the selected TCP port."""
    try:
        subnet = ipaddress.ip_network(network, strict=False)
    except ValueError:
        raise ValueError("Invalid network range")

    if subnet.version != 4:
        raise ValueError("This discovery module currently supports IPv4 only")

    if subnet.num_addresses > 256:
        raise ValueError("For now, scan networks containing at most 256 addresses")

    alive_hosts = []

    for ip in subnet.hosts():
        if check_host(ip, port, timeout):
            alive_hosts.append(str(ip))
            print(f"[+] Host responding: {ip}")

    return alive_hosts


if __name__ == "__main__":
    results = discover_hosts("127.0.0.1/32", port=8000)

    print("\nDiscovery complete.")
    print(f"Responsive hosts: {len(results)}")
    print(results)
