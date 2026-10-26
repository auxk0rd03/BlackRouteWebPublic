import os
import sys
import tempfile
from pathlib import Path

def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller. Enforces base directory confinement."""
    if "\x00" in str(relative_path):
        raise ValueError("Null byte detected in resource path.")
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = Path(sys._MEIPASS).resolve()
    except Exception:
        base_path = Path(__file__).resolve().parent.parent.parent
    rel_clean = str(relative_path).strip()
    if rel_clean in ("", "."):
        return str(base_path)
    candidate = (base_path / rel_clean).resolve()
    if not candidate.is_relative_to(base_path):
        raise ValueError(f"Security Violation: Resource path '{relative_path}' escapes application root.")
    return str(candidate)


class Settings:
    # Resolve base resource directory
    BASE_DIR = Path(resource_path("."))
    STATIC_DIR = Path(os.environ.get("BLACKROUTE_STATIC_DIR", str(BASE_DIR / "app" / "static")))
    TEMPLATES_DIR = BASE_DIR / "app" / "templates"

    # Persistent Data (Next to Executable, or overridden via environment for custom VM/Docker mounts)
    if getattr(sys, 'frozen', False):
        EXEC_DIR = Path(sys.executable).parent
    else:
        EXEC_DIR = Path(__file__).resolve().parent.parent.parent

    DB_NAME = "blackroute_web.db"
    DB_PATH = Path(os.environ.get("BLACKROUTE_DB_PATH", str(EXEC_DIR / DB_NAME)))

    # Compiled Polyglot Engine Binaries (Rust / Go)
    ENGINE_BIN_DIR = EXEC_DIR / "bin"

    # Multi-Target Batch Output Directory Architecture
    OUTPUT_DIR = Path(os.environ.get("BLACKROUTE_OUTPUT_DIR", str(EXEC_DIR / "Output")))

    # Default Crawling & Analysis Limits
    CRAWL_MAX_PAGES = 35
    CRAWL_MAX_DEPTH = 3
    CRAWL_TIMEOUT = 15.0
    REQUEST_TIMEOUT = 10.0
    # Realistic Modern Browser Persona (Chrome 124 on Linux) to prevent WAF bot-blocking
    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    MAX_JS_ASSET_SIZE = 5 * 1024 * 1024  # 5MB

    # SOC Stealth & Rate-Pacing Controls
    PROBE_CONCURRENCY_LIMIT = 2
    PROBE_JITTER_MIN = 0.25  # seconds
    PROBE_JITTER_MAX = 0.75  # seconds
    WAF_COOLDOWN_SECONDS = 5.0

    @classmethod
    def get_stealth_headers(cls, engagement_id: str = None) -> dict:
        """
        Generate modern browser L7 Client Hints and realistic navigation headers.
        Optionally injects authorized engagement tags for SOC de-escalation.
        """
        headers = {
            "User-Agent": cls.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1"
        }
        if engagement_id:
            clean_id = str(engagement_id).replace("\r", "").replace("\n", "").replace("\x00", "").strip()
            if clean_id:
                headers["X-Security-Engagement"] = clean_id
                headers["X-Authorized-Audit"] = "true"
                # Targeted Akamai Edge Cache Bypass & True Origin Verification headers
                headers["Pragma"] = "akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, no-cache"
                headers["Cache-Control"] = "no-cache, no-store, max-age=0"
                if ":" in clean_id:
                    prefix, token_val = clean_id.split(":", 1)
                    prefix_clean = prefix.lower().strip()
                    token_clean = token_val.strip()
                    if prefix_clean in ("staging", "akamai", "token", "edge") and token_clean:
                        headers["X-Akamai-Staging"] = "true"
                        headers["X-Akamai-Edge-Token"] = token_clean
                    else:
                        headers["X-Akamai-Staging"] = "true"
                else:
                    headers["X-Akamai-Staging"] = "true"
        return headers

settings = Settings()

