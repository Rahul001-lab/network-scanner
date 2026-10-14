
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(ip, port, timeout=1):
    """Check whether a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return port if result == 0 else None

    except (socket.timeout, OSError, ValueError):
        return None


def scan_ports(ip, ports, timeout=1, workers=100):
    """Scan TCP ports concurrently on an authorized target."""
    open_ports = []

    # Limit concurrency to avoid excessive resource usage.
    workers = max(1, min(workers, 100))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
            if isinstance(port, int) and 1 <= port <= 65535
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                result = future.result()

                if result is not None:
                    open_ports.append(result)
                    print(f"[+] {ip}:{result} OPEN")

            except Exception as error:
                print(f"[-] Port {port}: {error}")

    return sorted(open_ports)


if __name__ == "__main__":
    target = "127.0.0.1"
    ports_to_scan = [22, 80, 443, 8000, 8080]

    results = scan_ports(target, ports_to_scan)

    print("\nScan complete.")
    print("Open ports:", results)
