
import argparse
import ipaddress
import sys

from scanner.discovery import discover_hosts
from scanner.ports import scan_ports
from utils.validators import validate_ip, validate_network


def parse_ports(value):
    """Parse comma-separated ports and ranges."""
    ports = set()

    try:
        for part in value.split(","):
            part = part.strip()

            if "-" in part:
                start, end = map(int, part.split("-", 1))

                if start < 1 or end > 65535 or start > end:
                    raise ValueError

                ports.update(range(start, end + 1))
            else:
                port = int(part)

                if not 1 <= port <= 65535:
                    raise ValueError

                ports.add(port)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use valid ports, e.g. 22,80,443 or 1-100"
        )

    if len(ports) > 1000:
        raise argparse.ArgumentTypeError("Maximum 1000 ports per scan")

    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="NetScout - Python Network Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IPv4 address or CIDR network"
    )

    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=[22, 80, 443, 8000, 8080],
        help="Ports, e.g. 22,80,443 or 1-100"
    )

    args = parser.parse_args()
    target = args.target

    print("=" * 45)
    print("             NetScout")
    print("         Network Scanner")
    print("=" * 45)

    if validate_ip(target):
        targets = [target]
    elif validate_network(target):
        network = ipaddress.ip_network(target, strict=False)

        if network.version != 4:
            sys.exit("Currently, only IPv4 is supported.")

        if network.num_addresses > 256:
            sys.exit("For now, use a network with at most 256 addresses.")

        targets = [str(ip) for ip in network.hosts()]

        if network.num_addresses == 1:
            targets = [str(network.network_address)]
    else:
        sys.exit("Invalid IP address or network range.")

    for host in targets:
        print(f"\n[*] Checking host: {host}")

        responsive = discover_hosts(
            f"{host}/32",
            port=args.ports[0],
            timeout=1
        )

        if not responsive:
            print("[-] No response on the discovery port.")
            print("[*] Skipping this host in this basic version.")
            continue

        print(f"[*] Scanning {len(args.ports)} TCP ports...")

        open_ports = scan_ports(host, args.ports)

        print(f"[*] Open ports on {host}: {open_ports}")

    print("\n[+] NetScout scan completed.")


if __name__ == "__main__":
    main()
