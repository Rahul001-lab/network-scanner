
import socket


def forward_dns(hostname):
    """Resolve a hostname into its IP addresses."""
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_INET
        )

        addresses = sorted({
            result[4][0] for result in results
        })

        return addresses

    except socket.gaierror:
        return []


def reverse_dns(ip):
    """Resolve an IP address into its hostname."""
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "aliases": aliases
        }

    except (socket.herror, socket.gaierror, OSError):
        return {
            "ip": ip,
            "hostname": None,
            "aliases": []
        }


if __name__ == "__main__":

    target = "google.com"

    print("[*] Forward DNS Lookup")
    print(f"Hostname: {target}")

    addresses = forward_dns(target)

    for address in addresses:
        print(f"[+] IP Address: {address}")

    print("\n[*] Reverse DNS Lookup")

    if addresses:
        result = reverse_dns(addresses[0])

        print(f"IP: {result['ip']}")
        print(f"Hostname: {result['hostname']}")
        print(f"Aliases: {result['aliases']}")
