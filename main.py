
import argparse

from scanner.discovery import discover_hosts
from scanner.ports import scan_ports
from scanner.services import detect_service
from utils.validators import validate_ip, validate_network
from utils.output import save_json_report
from scanner.fingerprint import fingerprint_os

def main():
    parser = argparse.ArgumentParser(description="NetScout - Network Scanner")

    parser.add_argument("target", help="Target IP or network CIDR")
    parser.add_argument(
        "--ports",
        default="22,80,443,8000,8080",
        help="Ports to scan, e.g. 22,80,443"
    )

    args = parser.parse_args()
    target = args.target

    if not validate_ip(target) and not validate_network(target):
        print("[-] Invalid IP address or network")
        return

    ports = []

    try:
        for part in args.ports.split(","):
            part = part.strip()

            if "-" in part:
                start, end = map(int, part.split("-", 1))
                if not 1 <= start <= end <= 65535:
                    raise ValueError
                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.append(port)

        ports = sorted(set(ports))

    except ValueError:
        print("[-] Invalid port list")
        return

    if not ports:
        print("[-] No ports specified")
        return

    print("\n=== NetScout ===")
    print(f"Target: {target}")
    print(f"Ports: {ports}")

    # Build target list
    import ipaddress

    if validate_ip(target):
        targets = [target]
    else:
        network = ipaddress.ip_network(target, strict=False)

        if network.version != 4:
            print("[-] Only IPv4 is supported")
            return

        if network.num_addresses > 256:
            print("[-] Maximum supported network size is 256 addresses")
            return

        targets = (
            [str(ip) for ip in network]
            if network.prefixlen >= 31
            else [str(ip) for ip in network.hosts()]
        )

    all_results = []

    for host in targets:
        print(f"\n[*] Scanning {host}")

        # Host discovery
        try:
            alive = discover_hosts(
                f"{host}/32",
                port=ports[0]
            )

            if alive:
                print(f"[+] Host responded: {host}")
                os_info = fingerprint_os(host)

                print(f"[+] TTL: {os_info['ttl']}")
                print(f"[+] OS Guess: {os_info['os_guess']}")
           
            else:
                print("[*] No response on discovery port; checking ports anyway")

        except (OSError, ValueError) as error:
            print(f"[!] Discovery error: {error}")

        # Port scanning
        open_ports = scan_ports(host, ports)
        services = []

        # Service detection
        for port in open_ports:
            details = detect_service(host, port)
            services.append(details)

            print(f"[+] {host}:{port} - {details['service']}")

        all_results.append({
            "ip": host,
            "open_ports": open_ports,
            "services": services
        })

    # JSON report
    try:
        report_path = save_json_report(target, all_results)
        print(f"\n[+] Report saved: {report_path}")
    except (OSError, ValueError) as error:
        print(f"[!] Report error: {error}")

    print("\n[+] NetScout scan completed")
    "os_guess": os_info["os_guess"],
    "ttl": os_info["ttl"],

if __name__ == "__main__":
    main()
