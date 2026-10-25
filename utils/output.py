
import json
from pathlib import Path
from datetime import datetime, timezone


REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"


def save_json_report(target, results, filename=None):
    """Save scan results as a JSON report."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.json"

    # Keep report names inside the reports directory.
    if Path(filename).name != filename:
        raise ValueError("Filename must not contain directory paths")

    if not filename.endswith(".json"):
        raise ValueError("Report filename must end in .json")

    report = {
        "tool": "NetScout",
        "target": target,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }

    report_path = REPORT_DIR / filename

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return report_path


if __name__ == "__main__":
    example_results = [
        {
            "ip": "127.0.0.1",
            "open_ports": [8000],
            "services": [
                {
                    "port": 8000,
                    "service": "HTTP-alt",
                    "banner": "HTTP/1.0 200 OK",
                }
            ],
        }
    ]

    path = save_json_report(
        "127.0.0.1",
        example_results,
    )

    print(f"[+] Report saved to: {path}")
