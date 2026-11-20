import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.core.config import settings

logger = logging.getLogger("blackroute_web.engine_bridge")

_ALLOWED_ENGINES = {"web_spider", "surface_graph"}


def _get_sandbox_env() -> Dict[str, str]:
    """Return a minimal, scrubbed environment for child engine processes to prevent secret/host env leakage."""
    tmp_dir = tempfile.gettempdir()
    env: Dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": tmp_dir,
        "TMPDIR": tmp_dir,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GOFIPS": "1",
        "GODEBUG": "fips140=on",
    }
    if os.name == "nt":
        for win_var in ("SYSTEMROOT", "COMSPEC", "LOCALAPPDATA", "USERPROFILE", "TEMP", "TMP", "WINDIR", "PATH"):
            val = os.environ.get(win_var)
            if val:
                env[win_var] = val
    return env


def _validate_path(path: str) -> str:
    """Resolve and validate a filesystem path before passing to an engine, enforcing sandbox boundaries."""
    if not path or not isinstance(path, str):
        raise ValueError("Target path must be a non-empty string")
    if "\0" in path or "\r" in path or "\n" in path:
        raise ValueError("Null byte or control character detected in path argument")
    if path.strip().startswith("-"):
        raise ValueError("Security Violation: Hyphen-prefixed path rejected (argument injection defense)")
    if os.path.islink(path):
        raise ValueError("Security Violation: Symlink target path is not permitted for engine execution")

    real_path = Path(os.path.realpath(path)).resolve()
    allowed_roots = [
        Path(tempfile.gettempdir()).resolve(),
        Path(settings.OUTPUT_DIR).resolve(),
        Path(settings.STATIC_DIR).resolve(),
        Path(settings.EXEC_DIR).resolve(),
        Path(settings.BASE_DIR).resolve(),
    ]
    if not any(real_path.is_relative_to(root) for root in allowed_roots):
        raise ValueError(
            f"Security Violation: Path '{real_path}' is outside allowed sandbox directories"
        )
    return str(real_path)

def _is_valid_route(path: str) -> bool:
    """Validate that an extracted candidate path is a genuine URI route and not JS code."""
    if not path or len(path) > 256:
        return False
    if not path.startswith(("/", "http://", "https://", "ws://", "wss://")):
        return False

    invalid_tokens = [
        "&&", "||", "return", "function", "var ", "let ", "const ",
        "test(", "match(", "replace(", "typeof ", "undefined", "null",
        ";", "{", "}", "[", "]", "(", ")", "=>", "<", ">", "$", "\\",
        ",", " ", "\t", "\n", "\r", '"', "'", "`",
    ]
    for token in invalid_tokens:
        if token in path:
            return False

    if "d{" in path or "w{" in path or path.endswith(("/i", "/g")):
        return False

    return True

def _find_engine(name: str) -> Optional[str]:
    """Locate a compiled engine binary in the configured bin/ directory with strict allowlist & boundary checks."""
    if not name or name not in _ALLOWED_ENGINES or os.path.basename(name) != name:
        return None
    bin_dir = settings.ENGINE_BIN_DIR.resolve()
    candidates = [settings.ENGINE_BIN_DIR / f"{name}.exe", settings.ENGINE_BIN_DIR / name] if os.name == "nt" else [settings.ENGINE_BIN_DIR / name]
    for candidate in candidates:
        if candidate.is_symlink():
            continue
        bin_path = candidate.resolve()
        if not bin_path.is_relative_to(bin_dir):
            continue
        if bin_path.is_file() and os.access(str(bin_path), os.X_OK):
            return str(bin_path)
    return None

def engine_available(name: str) -> bool:
    """Check if a specific compiled engine binary exists and is executable."""
    return _find_engine(name) is not None

def _extract_json_payload(raw: str) -> Optional[Any]:
    """
    Resilient boundary-aware JSON payload extractor.
    Locates and parses the outermost valid JSON structure, ignoring
    any preceding/trailing diagnostic messages, compiler warnings, or panics.
    """
    if not raw:
        return None
    raw_clean = raw.strip()

    # 1. Fast path: direct parse
    try:
        return json.loads(raw_clean)
    except json.JSONDecodeError:
        pass

    # 2. Boundary search: find first { or [ and last matching } or ]
    start_obj = raw_clean.find('{')
    start_arr = raw_clean.find('[')

    start_idx = -1
    end_char = '}'
    if start_obj != -1 and (start_arr == -1 or start_obj < start_arr):
        start_idx = start_obj
        end_char = '}'
    elif start_arr != -1:
        start_idx = start_arr
        end_char = ']'

    if start_idx != -1:
        end_idx = raw_clean.rfind(end_char)
        if end_idx != -1 and end_idx > start_idx:
            candidate = raw_clean[start_idx:end_idx + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    # 3. Incremental decoder: scan forward from first bracket
    decoder = json.JSONDecoder()
    for idx in range(len(raw_clean)):
        if raw_clean[idx] in ('{', '['):
            try:
                obj, _ = decoder.raw_decode(raw_clean[idx:])
                if isinstance(obj, (dict, list)):
                    return obj
            except json.JSONDecodeError:
                continue

    return None

def _run_engine(binary_path: str, args: List[str], timeout: int = 60) -> Optional[Dict[str, Any]]:
    """Execute compiled engine binary via subprocess without shell=True in a scrubbed environment and parse JSON safely."""
    cmd = [binary_path] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_get_sandbox_env(),
            cwd=tempfile.gettempdir(),
            close_fds=(os.name != "nt"),
        )

        stdout = result.stdout.strip()
        parsed = _extract_json_payload(stdout)

        if parsed is not None and isinstance(parsed, dict):
            return parsed

        if result.returncode != 0:
            logger.warning(
                "Engine %s failed (exit %d). stderr: %s",
                binary_path, result.returncode, result.stderr[:500]
            )
        elif not stdout:
            logger.warning("Engine %s returned empty stdout (exit %d)", binary_path, result.returncode)
        else:
            logger.warning("Engine %s produced unparseable output: %s", binary_path, stdout[:300])

    except subprocess.TimeoutExpired:
        logger.error("Engine %s timed out after %ds", binary_path, timeout)
    except Exception as exc:
        logger.error("Error executing engine %s: %s", binary_path, exc)

    return None


# ---------------------------------------------------------------------------
# Rust Engine: web_spider
# High-speed web asset parser & endpoint extractor with Python fallback
# ---------------------------------------------------------------------------

def run_spider_extractor(target_path: str, depth: int = 2, target_domain: str = "") -> Dict[str, Any]:
    """
    Extract endpoints, links, and forms from a file or directory using Rust web_spider.
    Validates output schema and falls back to Python parser if engine fails or crashes.
    """
    engine = _find_engine("web_spider")
    safe_path = _validate_path(target_path)

    if engine is not None:
        args = ["dir", safe_path, "--depth", str(depth)] if os.path.isdir(safe_path) else [safe_path]
        if target_domain:
            args.extend(["--domain", target_domain])
        result = _run_engine(engine, args, timeout=45)
        # Schema validation
        if result is not None and "endpoints" in result and isinstance(result["endpoints"], list):
            result["engine_mode"] = "NATIVE_RUST"
            return result
        logger.info("web_spider engine unavailable or schema mismatch; falling back to Python.")

    # Python Fallback
    fallback_res = _python_fallback_spider(safe_path, depth=depth, target_domain=target_domain)
    fallback_res["engine_mode"] = "PYTHON_FALLBACK"
    return fallback_res

def _is_allowed_domain(url: str, target_domain: str) -> bool:
    if not target_domain:
        return True
    t_lower = target_domain.lower()
    if url.startswith("/") and not url.startswith("//"):
        return True
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").split(":")[0].lower()
        return host == t_lower or host.endswith("." + t_lower)
    except Exception:
        return True

def _resolve_webpack_chunks_python(content: str) -> List[str]:
    """Extract Webpack, Vite, and Rollup dynamic code chunks from JS content."""
    discovered = []
    # 1. Webpack dynamic chunk maps: __webpack_require__.u or jsonpScriptSrc
    for needle in ["__webpack_require__.u", "jsonpScriptSrc"]:
        start_idx = 0
        while True:
            found_idx = content.find(needle, start_idx)
            if found_idx == -1:
                break
            chunk_slice = content[found_idx:found_idx + 1500]
            suffix = ".chunk.js" if ".chunk.js" in chunk_slice else (".bundle.js" if ".bundle.js" in chunk_slice else ".js")
            prefix_match = re.search(r'[\'"]((?:static/|assets/)?js/?)[\'"]', chunk_slice)
            prefix = prefix_match.group(1) if prefix_match else ""

            entries = re.findall(r'(?:"?([a-zA-Z0-9_\-]+)"?\s*:\s*["\']([a-zA-Z0-9_\-]+)["\'])', chunk_slice)
            for cid, hash_val in entries:
                resolved = f"{prefix}{cid}.{hash_val}{suffix}"
                if resolved not in discovered:
                    discovered.append(resolved)
                if len(hash_val) > 6:
                    alt = f"{prefix}{hash_val}{suffix}"
                    if alt not in discovered:
                        discovered.append(alt)
            start_idx = found_idx + len(needle)

    # 2. Vite / Rollup dynamic imports: import("./views/AdminDashboard.js")
    for m in re.finditer(r'import\s*\(\s*[\'"]([^\'"]+\.js)[\'"]\s*\)', content):
        p = m.group(1)
        if p not in discovered:
            discovered.append(p)
        clean = p.lstrip("./")
        if clean and clean not in discovered:
            discovered.append(clean)

    # 3. Standard chunk patterns
    for m in re.finditer(r'[\'"]((?:/|https?://)?[^\'"]*chunk-[^\'"]*\.js)[\'"]', content):
        p = m.group(1)
        if p not in discovered:
            discovered.append(p)

    return discovered

def _python_fallback_spider(path: str, depth: int = 2, target_domain: str = "") -> Dict[str, Any]:
    """Pure Python fallback for asset parsing and endpoint extraction."""
    endpoints = []
    links = []
    scripts = []
    forms = []

    junk_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.css', '.mp4')
    re_pattern = re.compile(r'[\'"]((?:/|https?://|wss?://)[a-zA-Z0-9_?&=/\-\.:%]+)[\'"]')

    files_to_read = []
    html_count = 0
    js_count = 0
    max_html = 25
    max_js = 50

    safe_root = Path(_validate_path(path)).resolve()

    if safe_root.is_dir():
        for root, dirs, files in os.walk(str(safe_root), followlinks=False):
            # Prune symlinked directories in-place
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for f in sorted(files):
                fpath = os.path.join(root, f)
                if os.path.islink(fpath):
                    continue
                resolved_f = Path(os.path.realpath(fpath)).resolve()
                if not resolved_f.is_relative_to(safe_root):
                    continue
                is_html = f.endswith((".html", ".htm"))
                is_js = f.endswith(".js")
                if is_html and html_count >= max_html:
                    continue
                if is_js and js_count >= max_js:
                    continue
                if is_html:
                    html_count += 1
                elif is_js:
                    js_count += 1
                files_to_read.append(str(resolved_f))
    elif safe_root.is_file() and not os.path.islink(path):
        files_to_read.append(str(safe_root))

    for fpath in files_to_read:
        try:
            if os.path.islink(fpath):
                continue
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(settings.MAX_JS_ASSET_SIZE)

            if fpath.endswith((".html", ".htm")) or "<html" in content:
                soup = BeautifulSoup(content, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href and not href.startswith(("javascript:", "mailto:")) and _is_allowed_domain(href, target_domain):
                        links.append(href)
                for s in soup.find_all("script", src=True):
                    scripts.append(s["src"].strip())
                for form in soup.find_all("form"):
                    forms.append({
                        "action": form.get("action", "/"),
                        "method": form.get("method", "GET").upper()
                    })

            # Webpack chunk resolver fallback
            chunk_scripts = _resolve_webpack_chunks_python(content)
            scripts.extend(chunk_scripts)

            for match in re_pattern.finditer(content):
                p = match.group(1)
                if len(p) < 3 or p.lower().endswith(junk_extensions) or not _is_valid_route(p):
                    continue
                if not _is_allowed_domain(p, target_domain):
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

    unique_endpoints = {v["path"]: v for v in endpoints}.values()
    return {
        "target_path": path,
        "total_endpoints": len(unique_endpoints),
        "endpoints": list(unique_endpoints),
        "links": list(set(links)),
        "scripts": list(set(scripts)),
        "forms": forms,
        "engine_mode": "PYTHON_FALLBACK",
    }


# ---------------------------------------------------------------------------
# Go Engine: surface_graph
# Attack surface topology analyzer & tech fingerprinter with Python fallback
# ---------------------------------------------------------------------------

def run_surface_graph(
    endpoints: List[str],
    headers: Dict[str, Any],
    content: str,
    findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Build attack surface hierarchy, fingerprint tech stacks, and score surface risk.
    Validates output schema and falls back to Python if engine fails or crashes.
    """
    engine = _find_engine("surface_graph")
    payload = {
        "endpoints": endpoints,
        "headers": headers,
        "content": content[:100000]
    }
    if findings:
        payload["findings"] = [
            {
                "severity": str(f.get("severity", "INFO")).upper(),
                "category": str(f.get("category", "")),
                "title": str(f.get("title", "")),
                "vendor_context": str(f.get("vendor_context", "")),
                "tags": [str(t) for t in f.get("tags", [])]
            }
            for f in findings
        ]

    # Debug logging to verify IPC data flow
    logger.debug("surface_graph payload - endpoints count: %d, headers count: %d, content length: %d", 
                 len(endpoints), len(headers), len(payload["content"]))
    logger.debug("surface_graph payload - headers keys: %s", list(headers.keys()))

    # Dump temporary debug payload to disk for IPC audit (guarded against symlink/FIFO attacks in /tmp)
    tmp_root = Path(tempfile.gettempdir()).resolve()
    debug_payload_path = str(tmp_root / "surface_graph_payload_debug.json")
    payload_file_ready = False
    try:
        if os.path.lexists(debug_payload_path):
            st = os.lstat(debug_payload_path)
            import stat as _stat
            if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISREG(st.st_mode):
                os.unlink(debug_payload_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(debug_payload_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        payload_file_ready = True
        logger.debug("Dumped surface_graph IPC payload to %s", debug_payload_path)
    except Exception as dump_err:
        logger.warning("Failed to dump surface_graph debug payload to disk: %s", dump_err)
    
    if engine is not None:
        try:
            # Pass file path if written, otherwise fallback to raw JSON string argument
            cmd = [engine, debug_payload_path] if payload_file_ready else [engine, json.dumps(payload)]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
                env=_get_sandbox_env(),
                cwd=tempfile.gettempdir(),
                close_fds=(os.name != "nt"),
            )
            parsed = _extract_json_payload(res.stdout)
            
            # Debug logging for Go engine response
            if parsed is not None and isinstance(parsed, dict):
                techs = parsed.get("technologies") or []
                logger.debug("surface_graph engine returned %d technologies", len(techs))
                for tech in techs:
                    logger.debug("Detected tech: %s (%s)", tech.get("name"), tech.get("category"))
            
            # Schema validation
            if parsed is not None and isinstance(parsed, dict) and ("nodes" in parsed or "total_routes" in parsed):
                parsed["engine_mode"] = "NATIVE_GO"
                return parsed
            logger.info("surface_graph engine output failed schema check; falling back to Python.")
        except Exception as exc:
            logger.warning("surface_graph engine execution failed, falling back to Python: %s", exc)

    fallback_graph = _python_fallback_surface_graph(endpoints, headers, content, findings=findings)
    fallback_graph["engine_mode"] = "PYTHON_FALLBACK"
    return fallback_graph

def _is_vendor_endpoint(ep: str) -> bool:
    ep_lower = ep.lower()
    vendor_indicators = (
        "akamai", "tiqcdn", "tealium", "adobe", "demdex", "omtrdc",
        "google-analytics", "googletagmanager", "hotjar", "segment"
    )
    return any(ind in ep_lower for ind in vendor_indicators)

_EDITORIAL_IGNORED_DIRS = (
    "/news/", "/media/", "/blog/", "/press/", "/articles/",
    "/events/", "/stories/", "/publications/",
)

_IGNORED_STATIC_SUFFIXES = (
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg",
    ".css", ".ico", ".woff", ".woff2",
)

_SENSITIVE_STRUCTURAL_MARKERS = (
    "api-docs", "/.git", "/.env", "/graphql", "/swagger", "/openapi", "/actuator",
)

_SENSITIVE_ROUTE_TOKENS = frozenset({
    "admin", "login", "signin", "auth", "oauth", "token", "secret", "config",
    "actuator", "metrics", "upload", "debug", "internal", "graphql", "swagger",
    "openapi", "backup", "dump",
})


def _is_sensitive_route(path: str) -> bool:
    """Return True when path matches a genuine sensitive route token (ignoring vendor, editorial, and static assets)."""
    if not path or _is_vendor_endpoint(path):
        return False
    path_lower = path.lower()
    if any(ignored in path_lower for ignored in _EDITORIAL_IGNORED_DIRS):
        return False
    if path_lower.endswith(_IGNORED_STATIC_SUFFIXES):
        return False
    if any(marker in path_lower for marker in _SENSITIVE_STRUCTURAL_MARKERS):
        return True
    tokens = [t for t in re.split(r"[/\-_.]", path_lower) if t]
    return any(tok in _SENSITIVE_ROUTE_TOKENS for tok in tokens)


def _python_fallback_surface_graph(
    endpoints: List[str],
    headers: Dict[str, Any],
    content: str,
    findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Pure Python fallback for attack surface and topology analysis with normalized scoring."""
    nodes = set()
    edges = []
    sensitive_routes = []
    ext_domains = set()

    for ep in endpoints:
        ep = ep.strip()
        if not ep or not _is_valid_route(ep):
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

        if not _is_valid_route(path):
            continue

        nodes.add(path)
        if _is_sensitive_route(path):
            sensitive_routes.append(path)

    techs = []
    c_lower = content.lower()
    if "_next/static" in c_lower:
        techs.append({"name": "Next.js", "category": "Frontend Framework", "evidence": "Next.js static assets"})
    if "react-dom" in c_lower or "data-reactroot" in c_lower:
        techs.append({"name": "React", "category": "UI Library", "evidence": "React DOM signature"})
    if "vue" in c_lower or "data-v-" in c_lower:
        techs.append({"name": "Vue.js", "category": "Frontend Framework", "evidence": "Vue.js signature"})

    # Enterprise Vendor & Server Checks (mirroring Go engine)
    for k, v in headers.items():
        k_lower = k.lower()
        v_list = v if isinstance(v, list) else [str(v)]
        for val in v_list:
            val_str = str(val)
            val_lower = val_str.lower()
            if k_lower == "server":
                if "cloudflare" in val_lower:
                    techs.append({"name": "Cloudflare", "category": "CDN / Reverse Proxy", "evidence": f"Server: {val_str}"})
                elif "nginx" in val_lower:
                    techs.append({"name": "Nginx", "category": "Web Server", "evidence": f"Server: {val_str}"})
                elif "apache" in val_lower:
                    techs.append({"name": "Apache", "category": "Web Server", "evidence": f"Server: {val_str}"})
                elif "akamai" in val_lower:
                    techs.append({"name": "Akamai", "category": "CDN / Edge Platform", "evidence": f"Server: {val_str}"})
                else:
                    techs.append({"name": val_str, "category": "Web Server", "evidence": f"Server: {val_str}"})
            if k_lower == "x-powered-by":
                techs.append({"name": val_str, "category": "Backend Platform", "evidence": f"X-Powered-By: {val_str}"})
            if k_lower == "set-cookie":
                if any(sig in val_lower for sig in ["_abck", "bm_mi", "bm_so", "bm_sz", "akamai_session"]):
                    techs.append({"name": "Akamai Bot Manager", "category": "Bot Protection / WAF", "evidence": "Akamai Bot Manager cookies detected"})
                if any(sig in val_lower for sig in ["mbox", "amcv"]):
                    techs.append({"name": "Adobe Experience Cloud", "category": "Marketing / Analytics", "evidence": "Adobe Experience Cloud cookies detected"})

    if any(sig in c_lower for sig in ["utag.sync", "utag.js", "tealium"]):
        techs.append({"name": "Tealium iQ", "category": "Tag Management", "evidence": "Tealium iQ Tag Management detected"})

    # Category-capped & diminishing-returns Risk Score Calculation
    risk_score = 10
    dedup_sensitive = list(set(sensitive_routes))
    if dedup_sensitive:
        risk_score += min(15, len(dedup_sensitive) * 3)

    if len(endpoints) > 30:
        risk_score += 10
    elif len(endpoints) > 10:
        risk_score += 5

    if findings:
        severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 6, "LOW": 2}
        category_caps = {"COOKIES": 15, "HEADERS": 15}
        cat_weights: Dict[str, List[int]] = {}
        cat_crits: Dict[str, int] = {}
        crit_count = 0
        vendor_info_count = 0

        for f in findings:
            tags = f.get("tags", [])
            is_vendor = (
                bool(f.get("vendor_context"))
                or str(f.get("title", "")).lower().startswith("[third-party]")
                or any(t in ("third_party", "vendor_integration", "vendor_script") for t in tags)
            )
            sev = str(f.get("severity", "INFO")).upper().strip()
            if is_vendor or sev == "INFO":
                vendor_info_count += 1
                continue
            if sev not in severity_weights:
                continue
            cat = str(f.get("category", "")).upper().strip()
            if not cat:
                t_low = str(f.get("title", "")).lower()
                if "cookie" in t_low:
                    cat = "COOKIES"
                elif any(k in t_low for k in ("csp", "cors", "hsts", "referrer", "permissions", "frame", "nosniff", "server", "powered")):
                    cat = "HEADERS"
                elif any(k in t_low for k in ("secret", "key", "token")):
                    cat = "SECRETS"
                elif any(k in t_low for k in ("dom", "xss", "postmessage")):
                    cat = "DOM_XSS"
                elif any(k in t_low for k in ("graphql", "swagger", "openapi", "actuator", ".git", ".env")):
                    cat = "API_EXPOSURE"
                else:
                    cat = "GENERAL"
            if sev == "CRITICAL":
                crit_count += 1
                cat_crits[cat] = cat_crits.get(cat, 0) + 1
            cat_weights.setdefault(cat, []).append(severity_weights[sev])

        total_category_impact = 0
        active_cat_impact = 0
        for cat, weights in cat_weights.items():
            weights.sort(reverse=True)
            cat_sum = 0
            for idx, w in enumerate(weights):
                if idx == 0:
                    contrib = w
                elif idx == 1:
                    contrib = max(1, w // 2)
                else:
                    contrib = max(1, w // 4)
                cat_sum += contrib
            cap_val = category_caps.get(cat, 60)
            if cat in category_caps and cat_crits.get(cat, 0) > 0:
                cap_val = min(60, max(cap_val, cat_crits[cat] * 25))
            cat_sum = min(cap_val, cat_sum)
            total_category_impact += cat_sum
            if cat not in ("COOKIES", "HEADERS"):
                active_cat_impact += cat_sum

        vendor_impact = 1 if 0 < vendor_info_count < 5 else (2 if vendor_info_count >= 5 else 0)
        composite = (risk_score // 2) + total_category_impact + vendor_impact
        if composite > risk_score:
            risk_score = composite

        has_active_or_critical = (crit_count > 0) or (active_cat_impact > 0)
        if not has_active_or_critical and len(dedup_sensitive) == 0 and risk_score > 40:
            risk_score = 40

    risk_score = min(100, max(0, risk_score))

    return {
        "total_routes": len(nodes),
        "nodes": list(nodes),
        "edges": edges,
        "technologies": techs,
        "sensitive_routes": list(set(sensitive_routes)),
        "external_domains": list(ext_domains),
        "risk_score": risk_score,
        "engine_mode": "PYTHON_FALLBACK",
    }
