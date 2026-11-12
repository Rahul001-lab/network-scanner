
import json
from pathlib import Path


CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


DEFAULT_CONFIG = {
    "scanner": {
        "timeout": 1.0,
        "workers": 100,
        "max_hosts": 256,
        "max_ports": 1000
    },
    "discovery": {
        "enabled": True,
        "port": 80
    },
    "services": {
        "enabled": True,
        "banner_grab": True
    },
    "dns": {
        "enabled": True,
        "reverse_lookup": True
    },
    "fingerprinting": {
        "enabled": True
    },
    "reporting": {
        "json": True,
        "csv": False
    }
}


def load_config():
    """Load and validate scanner configuration."""

    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as file:
            config = json.load(file)

        for section, settings in DEFAULT_CONFIG.items():
            if section not in config or not isinstance(config[section], dict):
                config[section] = {}

            for key, default_value in settings.items():
                config[section].setdefault(key, default_value)

        scanner = config["scanner"]
        discovery = config["discovery"]

        if not isinstance(scanner["timeout"], (int, float)) or isinstance(scanner["timeout"], bool) or scanner["timeout"] <= 0:
            raise ValueError("Timeout must be a positive number")

        if not isinstance(scanner["workers"], int) or isinstance(scanner["workers"], bool) or not 1 <= scanner["workers"] <= 100:
            raise ValueError("Workers must be between 1 and 100")

        if not isinstance(scanner["max_hosts"], int) or not 1 <= scanner["max_hosts"] <= 256:
            raise ValueError("max_hosts must be between 1 and 256")

        if not isinstance(scanner["max_ports"], int) or not 1 <= scanner["max_ports"] <= 1000:
            raise ValueError("max_ports must be between 1 and 1000")

        if not isinstance(discovery["port"], int) or not 1 <= discovery["port"] <= 65535:
            raise ValueError("Invalid discovery port")

        return config

    except (json.JSONDecodeError, OSError, ValueError) as error:
        raise ValueError(f"Configuration error: {error}") from error


if __name__ == "__main__":
    settings = load_config()
    print(json.dumps(settings, indent=4))
