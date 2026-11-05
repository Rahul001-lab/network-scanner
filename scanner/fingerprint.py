
import subprocess
import platform
import re


def get_ttl(ip):
    """Retrieve TTL value using the system ping command."""

    system = platform.system()

    if system == "Windows":
        command = ["ping", "-n", "1", "-w", "2000", ip]
    else:
        command = ["ping", "-c", "1", "-W", "2", ip]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=4
        )

        output = result.stdout + result.stderr

        match = re.search(
            r"ttl\s*[=:]\s*(\d+)",
            output,
            re.IGNORECASE
        )

        if match:
            return int(match.group(1))

        return None

    except (subprocess.TimeoutExpired, OSError):
        return None


def identify_os(ttl):
    """Estimate operating system using the received TTL."""

    if ttl is None:
        return "Unknown"

    if 1 <= ttl <= 64:
        return "Linux / Unix (Possible)"

    elif 65 <= ttl <= 128:
        return "Windows (Possible)"

    elif 129 <= ttl <= 255:
        return "Network Device / Other (Possible)"

    return "Unknown"


def fingerprint_os(ip):
    """Perform basic OS fingerprinting."""

    ttl = get_ttl(ip)
    operating_system = identify_os(ttl)

    return {
        "ip": ip,
        "ttl": ttl,
        "os_guess": operating_system
    }


if __name__ == "__main__":

    target = "127.0.0.1"

    print("\n=== NetScout OS Fingerprinting ===\n")

    result = fingerprint_os(target)

    print(f"Target IP: {result['ip']}")
    print(f"TTL: {result['ttl']}")
    print(f"OS Guess: {result['os_guess']}")
