import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.core.config import settings

logger = logging.getLogger("blackroute_web.engine_bridge")

def _validate_path(path: str) -> str:
    """Resolve and validate a filesystem path before passing to an engine."""
    if "\0" in path:
        raise ValueError("Null byte detected in path argument")
    return os.path.realpath(path)

def _find_engine(name: str) -> Optional[str]:
    """Locate a compiled engine binary in the configured bin/ directory."""
    bin_path = settings.ENGINE_BIN_DIR / name
    if bin_path.is_file() and os.access(str(bin_path), os.X_OK):
        return str(bin_path)
    return None

def engine_available(name: str) -> bool:
    """Check if a specific compiled engine binary exists and is executable."""
    return _find_engine(name) is not None

def _run_engine(binary_path: str, args: List[str], timeout: int = 60) -> Optional[Dict[str, Any]]:
    """Execute compiled engine binary via subprocess without shell=True and parse JSON."""
    cmd = [binary_path] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        stdout = result.stdout.strip()
        if not stdout:
            logger.warning("Engine %s returned empty stdout (exit %d)", binary_path, result.returncode)
            return None
        return json.loads(stdout)
    except subprocess.TimeoutExpired:
        logger.error("Engine %s timed out after %ds", binary_path, timeout)
    except json.JSONDecodeError as exc:
        logger.error("Engine %s produced invalid JSON: %s", binary_path, exc)
    except Exception as exc:
        logger.error("Error executing engine %s: %s", binary_path, exc)
    return None


# ---------------------------------------------------------------------------
# Rust Engine: web_spider
# High-speed web asset parser & endpoint extractor with Python fallback
# ---------------------------------------------------------------------------

def run_spider_extractor(target_path: str) -> Dict[str, Any]:
    """
    Extract endpoints, links, and forms from a file or directory using Rust web_spider.
    Falls back to Python parser if the Rust engine binary is not compiled.
    """
    engine = _find_engine("web_spider")
    safe_path = _validate_path(target_path)

    if engine is not None:
        args = ["dir", safe_path] if os.path.isdir(safe_path) else [safe_path]
        result = _run_engine(engine, args, timeout=45)
        if result is not None:
            return result

    # Python Fallback
    return _python_fallback_spider(safe_path)

def _python_fallback_spider(path: str) -> Dict[str, Any]:
    """Pure Python fallback for asset parsing and endpoint extraction."""
    endpoints = []
    links = []
    scripts = []
    forms = []

    junk_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.css', '.mp4')
    re_pattern = re.compile(r'[\'"]((?:/|https?://|wss?://)[a-zA-Z0-9_?&=/\-\.:%]+)[\'"]')

    files_to_read = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                files_to_read.append(os.path.join(root, f))
    elif os.path.isfile(path):
        files_to_read.append(path)

    for fpath in files_to_read:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if fpath.endswith((".html", ".htm")) or "<html" in content:
                soup = BeautifulSoup(content, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href and not href.startswith(("javascript:", "mailto:")):
                        links.append(href)
                for s in soup.find_all("script", src=True):
                    scripts.append(s["src"].strip())
                for form in soup.find_all("form"):
                    forms.append({
                        "action": form.get("action", "/"),
                        "method": form.get("method", "GET").upper()
                    })

            for match in re_pattern.finditer(content):
                p = match.group(1)
                if len(p) < 3 or p.lower().endswith(junk_extensions):
                    continue
                endpoints.append({
                    "file_path": fpath,
                    "line_number": 1,
                    "content": p,
                    "confidence": 0.85 if any(kw in p.lower() for kw in ["/api/", "admin", "token", "graphql"]) else 0.5,
                    "type": "endpoint",
                    "method": "DISCOVERED",
                    "path": p
                })
        except Exception:
            pass

    # Deduplicate endpoints by path
    unique_endpoints = {v["path"]: v for v in endpoints}.values()
    return {
        "target_path": path,
        "total_endpoints": len(unique_endpoints),
        "endpoints": list(unique_endpoints),
        "links": list(set(links)),
        "scripts": list(set(scripts)),
        "forms": forms
    }


# ---------------------------------------------------------------------------
# Go Engine: surface_graph
# Attack surface topology analyzer & tech fingerprinter with Python fallback
# ---------------------------------------------------------------------------

def run_surface_graph(endpoints: List[str], headers: Dict[str, str], content: str) -> Dict[str, Any]:
    """
    Build attack surface hierarchy, fingerprint tech stacks, and score surface risk.
    Falls back to Python implementation if Go engine binary is not compiled.
    """
    engine = _find_engine("surface_graph")
    payload = {
        "endpoints": endpoints,
        "headers": headers,
        "content": content[:100000] # cap sample size for IPC
    }

    if engine is not None:
        try:
            cmd = [engine, json.dumps(payload)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout.strip())
        except Exception as exc:
            logger.warning("surface_graph engine execution failed, falling back to Python: %s", exc)

    return _python_fallback_surface_graph(endpoints, headers, content)

def _python_fallback_surface_graph(endpoints: List[str], headers: Dict[str, str], content: str) -> Dict[str, Any]:
    """Pure Python fallback for attack surface and topology analysis."""
    nodes = set()
    edges = []
    sensitive_routes = []
    ext_domains = set()
    sensitive_keywords = ["admin", "login", "auth", "oauth", "token", "secret", "config", "actuator", "metrics", "upload"]

    for ep in endpoints:
        ep = ep.strip()
        if not ep:
            continue
        if ep.startswith(("http://", "https://")):
            parsed = urlparse(ep)
            if parsed.netloc:
                ext_domains.add(parsed.netloc)
            path = parsed.path or "/"
        else:
            path = ep.split("?")[0].split("#")[0]
            if not path.startswith("/"):
                path = "/" + path

        nodes.add(path)
        if any(kw in path.lower() for kw in sensitive_keywords):
            sensitive_routes.append(path)

    # Simple tech fingerprinting
    techs = []
    c_lower = content.lower()
    if "_next/static" in c_lower:
        techs.append({"name": "Next.js", "category": "Frontend Framework", "evidence": "Next.js static assets"})
    if "react-dom" in c_lower or "data-reactroot" in c_lower:
        techs.append({"name": "React", "category": "UI Library", "evidence": "React DOM signature"})
    if "vue" in c_lower or "data-v-" in c_lower:
        techs.append({"name": "Vue.js", "category": "Frontend Framework", "evidence": "Vue.js signature"})

    for k, v in headers.items():
        if k.lower() == "server":
            techs.append({"name": v, "category": "Web Server", "evidence": f"Server: {v}"})
        if k.lower() == "x-powered-by":
            techs.append({"name": v, "category": "Backend", "evidence": f"X-Powered-By: {v}"})

    risk_score = 15 + (len(sensitive_routes) * 5)
    if risk_score > 95:
        risk_score = 95

    return {
        "total_routes": len(nodes),
        "nodes": list(nodes),
        "edges": edges,
        "technologies": techs,
        "sensitive_routes": list(set(sensitive_routes)),
        "external_domains": list(ext_domains),
        "risk_score": risk_score
    }
