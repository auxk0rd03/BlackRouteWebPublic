import os
import sys
import tempfile
from pathlib import Path

def resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = Path(__file__).resolve().parent.parent.parent
    return os.path.join(str(base_path), relative_path)


class Settings:
    # Resolve base resource directory
    BASE_DIR = Path(resource_path("."))
    STATIC_DIR = BASE_DIR / "app" / "static"
    TEMPLATES_DIR = BASE_DIR / "app" / "templates"

    # Persistent Data (Next to Executable)
    if getattr(sys, 'frozen', False):
        EXEC_DIR = Path(sys.executable).parent
    else:
        EXEC_DIR = Path(__file__).resolve().parent.parent.parent

    DB_NAME = "blackroute_web.db"
    DB_PATH = EXEC_DIR / DB_NAME

    # Compiled Polyglot Engine Binaries (Rust / Go)
    ENGINE_BIN_DIR = EXEC_DIR / "bin"

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
            clean_id = str(engagement_id).strip()
            if clean_id:
                headers["X-Security-Engagement"] = clean_id
                headers["X-Authorized-Audit"] = "true"
        return headers

settings = Settings()

