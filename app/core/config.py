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
    USER_AGENT = "BlackRoute-Web/1.0 (CyberNest Labs Security Auditor; +https://cybernest.labs)"
    MAX_JS_ASSET_SIZE = 5 * 1024 * 1024  # 5MB

settings = Settings()
