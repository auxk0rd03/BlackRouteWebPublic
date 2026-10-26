# CyberNest Labs: BlackRoute-Web Developer Handoff Manual

## Document Purpose & Scope

This document serves as the primary technical handover, architecture specification, and developer onboarding reference for **BlackRoute-Web** (`Active_Dev/BlackRoute-Web-Linux_VersionPopOS`). It details the end-to-end architecture, explains the role of every file in the codebase, describes how each component interacts within the broader system, and provides actionable guides for extending rules, modifying engines, and maintaining the platform.

---

## 1. Complete Codebase Directory Tree

```text
BlackRoute-Web-Linux_VersionPopOS/
├── .dockerignore                       # Docker build context exclusion rules
├── .gitignore                          # Git ignore rules (binaries, venvs, databases, cache)
├── CyberNestLabsLogo.png               # Root brand logo asset
├── Dockerfile                          # Multi-stage production container build (Rust/Go -> Python 3.12)
├── docker-compose.yml                  # Container deployment specification with persistent volumes
├── LICENSE                             # CyberNest Labs Authorized Security Research & Dual-Use License
├── Handoff.md                          # Technical architecture & maintenance handover manual
├── README.md                           # Operational manual, setup instructions, disclaimer
├── requirements.txt                    # Python library dependency definitions
├── blackroute_web.py                   # Master entrypoint, port scanner & server bootloader
├── launcher.sh                         # Unified Linux CLI launcher, venv manager & compiler
├── launcher.bat                        # Unified Windows CLI launcher
├── app/
│   ├── __init__.py                     # App package marker
│   ├── core/
│   │   ├── __init__.py                 # Core package marker
│   │   ├── config.py                   # Global settings, paths, timeouts & PyInstaller resolution
│   │   ├── database.py                 # SQLite schema, connection lifecycles, migrations & cURL storage
│   │   ├── security.py                 # SSRF firewall, IP filtering, target normalization & hashing
│   │   ├── auditor_headers.py          # CSP, HSTS, CORS, Clickjacking & Cookie hygiene engine
│   │   ├── auditor_secrets.py          # Shannon entropy & high-confidence token/credential leak detector
│   │   ├── auditor_api_routes.py       # OpenAPI/Swagger, GraphQL, Actuators & Git metadata probes
│   │   ├── auditor_dom.py              # Client-side DOM XSS sinks & unvalidated postMessage audits
│   │   ├── engine_bridge.py            # Resilient boundary-aware IPC adapter for Rust/Go binaries
│   │   └── scanner.py                  # Master audit orchestrator, cURL generator & SSE log broadcaster
│   ├── routes/
│   │   ├── __init__.py                 # Routes package marker
│   │   ├── home.py                     # HTML dashboard & favicon router (Starlette 0.36+ compatible)
│   │   └── api.py                      # REST endpoints: scan trigger, SSE streaming, STIX/TAXII export
│   ├── static/
│   │   ├── CyberNestLabsLogo.png       # Web asset brand logo
│   │   ├── brand.css                   # CyberNest Labs corporate header styles
│   │   └── terminal.css                # Dark military-industrial cyberpunk theme & tables
│   └── templates/
│       ├── layout.html                 # Jinja2 master HTML layout with HTMX loader
│       └── index.html                  # Jinja2 dashboard with EventSource SSE & 1-click cURL PoC copy
├── bin/
│   ├── web_spider                      # [Compiled Rust binary] High-performance crawler/regex extractor
│   └── surface_graph                   # [Compiled Go binary] Attack surface topology & tech fingerprinter
├── engines/
│   ├── web_spider/
│   │   ├── Cargo.toml                  # Rust package definition & compiler optimizations (LTO, strip)
│   │   ├── Cargo.lock                  # Pinned offline crate dependencies
│   │   └── src/
│   │       └── main.rs                 # Rust source: Thompson NFA regex crawler & endpoint harvester
│   └── surface_graph/
│       ├── go.mod                      # Go module definition (Go 1.21+, zero external dependencies)
│       └── main.go                     # Go source: concurrent topology tree & tech fingerprinter
├── Sources/
│   ├── __init__.py                     # Sources package marker
│   └── Utilities/
│       ├── __init__.py                 # Utilities package marker
│       └── vids_pdf_gen.py             # CyberNest VIDS PDF Web Audit report generator (with cURL PoCs)
├── Output/                             # Per-target isolated report artifacts (Output/Targ001 .. Output/Targ00N)
└── tests/
    ├── test_audit.py                   # Unit tests (entropy, cURL generation, resilient IPC, sandbox confinement)
    └── test_pipeline_e2e.py            # End-to-end integration test (single & batch pipeline, isolated temp sandbox)
```

---

## 2. Deep File-by-File Breakdown

### Root Control & Containerization Files

#### `Dockerfile`
- **Role**: Multi-stage hardened production container specification.
- **What It Does**:
  - **Stage 1 (`builder`)**: Uses `golang:1.22-bookworm`, installs the Rust toolchain, and compiles `engines/web_spider` (Rust with LTO/strip) and `engines/surface_graph` (Go with `-s -w`). Outputs static binaries to `/build/bin/`.
  - **Stage 2 (`runtime`)**: Uses lightweight `python:3.12-slim`. Copies compiled binaries into `/app/bin/` with read/execute-only permissions (`chmod 550`), installs Python requirements, creates an unprivileged non-root system user (`cybernest` with `/usr/sbin/nologin` shell), pre-provisions `/app/Output`, configures Docker healthchecks (`/api/status`), and launches the application via Uvicorn on port `8000`.
- **How to Modify**: Adjust base images or add system packages (e.g. `ca-certificates`, `curl`).

#### `docker-compose.yml`
- **Role**: Single-command hardened container deployment orchestration.
- **What It Does**: Builds the Dockerfile, exposes port `8000:8000`, attaches persistent Docker volumes for the SQLite threat database and generated VIDS PDF audit reports, and enforces runtime container isolation (`security_opt: ["no-new-privileges:true"]`, `cap_drop: ["ALL"]`, and a `noexec,nosuid,nodev` memory-backed `/tmp` tmpfs mount).
- **How to Modify**: Change port mappings or attach custom persistent volume storage.

#### `.dockerignore`
- **Role**: Build context filter preventing unneeded local files (`.venv`, `target/`, `.git`, `*.db`) from polluting the Docker build daemon context.

#### `blackroute_web.py`
- **Role**: Primary application server entrypoint and dynamic port binder.
- **What It Does**:
  1. Dynamically scans local ports in range `8000–8100` (`find_available_port`).
  2. Spawns an asynchronous background thread (`open_browser`) that opens the operating system's default browser after 1.5 seconds.
  3. Defines the FastAPI `lifespan` context manager, printing the boot sequence banner and initializing SQLite tables via `init_db()`.
  4. Mounts `/static` files and registers `home.router` and `api.router` (prefixed with `/api`).
  5. Boots Uvicorn without auto-reload (`reload=False`) to ensure compatibility with PyInstaller standalone compilation.
- **How to Modify**: Adjust port scan ranges or change host binding to `0.0.0.0` for remote container access.

#### `launcher.sh`
- **Role**: Unified Linux CLI runner, environment manager, engine compiler, and test runner.
- **What It Does**:
  - `setup_venv`: Detects system Python 3, initializes `.venv` if absent, and installs dependencies from `requirements.txt`.
  - `run_application`: Invokes `setup_venv` and boots `blackroute_web.py`.
  - `build_engines`: Compiles Rust `web_spider` (`cargo build --release --offline`) and Go `surface_graph` (`go build -ldflags="-s -w"`), moving binaries to `bin/`.
  - `build_release`: Bundles the application into a single Linux binary (`dist/BlackRoute_Web_v1.0`) via PyInstaller.
  - `run_tests` (`./launcher.sh test`): Verifies `.venv` and executes the unit and E2E test suites through `.venv/bin/python -m unittest`.
  - Interactive menu: Provides a numbered selection menu if invoked without arguments.
- **How to Modify**: Add new compiler flags or additional pre-flight diagnostic checks.

#### `launcher.bat`
- **Role**: Unified Windows CLI runner and setup script for Windows 10/11 environments.

#### `requirements.txt`
- **Role**: Python dependency definitions.
- **Packages**: `fastapi`, `uvicorn`, `jinja2`, `aiofiles`, `fpdf2`, `pydantic`, `python-multipart`, `beautifulsoup4`, `httpx`, `sse-starlette`.

---

### Core Security & Auditing Layer (`app/core/`)

#### `app/core/config.py`
- **Role**: Global application configuration, sandboxed path resolution, browser personas, and SOC stealth settings.
- **What It Does**:
  - `resource_path()`: Dynamically resolves file paths relative to `sys._MEIPASS` when compiled into a PyInstaller binary, or relative to the source tree in development mode. Strictly enforces `candidate.is_relative_to(base_path)` and rejects null bytes (`\x00`) to prevent directory traversal (`..`) or absolute path escapes.
  - `Settings`: Defines runtime parameters, database paths (`DB_PATH`, configurable via `BLACKROUTE_DB_PATH`), compiled binary directories (`ENGINE_BIN_DIR`), static directory (`STATIC_DIR`, configurable via `BLACKROUTE_STATIC_DIR`), batch/report output root (`OUTPUT_DIR`, configurable via `BLACKROUTE_OUTPUT_DIR`), and crawling limits.
  - `USER_AGENT`: Realistic modern Chrome 124 on Linux browser persona to prevent WAF bot-blocking.
  - `get_stealth_headers(engagement_id=None)`: Generates authentic modern browser L7 Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Sec-Fetch-*`, `Accept-Language`, `Accept-Encoding`, `Upgrade-Insecure-Requests`). Strips CR/LF/NUL characters from `engagement_id` to prevent HTTP header injection. When an authorized `engagement_id` is supplied:
    - Injects authorized audit de-escalation headers: `X-Security-Engagement` and `X-Authorized-Audit: true`.
    - **Targeted Akamai Cache Bypass**: Appends `Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, no-cache` and `Cache-Control: no-cache, no-store, max-age=0` to force edge cache bypass.
    - **Staging Origin Verification**: Supports dedicated staging tokens (`staging:<token>` or `akamai:<token>`), automatically injecting `X-Akamai-Staging: true` and `X-Akamai-Edge-Token: <token>` to audit true origin infrastructure.
  - Pacing constants: `PROBE_CONCURRENCY_LIMIT = 2`, `PROBE_JITTER_MIN = 0.25s`, `PROBE_JITTER_MAX = 0.75s`, `WAF_COOLDOWN_SECONDS = 5.0s`.
- **How to Modify**: Tune jitter ranges, concurrency limits, or add new browser personas.

#### `app/core/database.py`
- **Role**: SQLite persistence layer with automated schema migrations.
- **What It Does**:
  - `init_db()`: Initializes relational tables: `scans`, `findings`, and `endpoints`. Automatically runs backwards-compatible schema migrations (`ALTER TABLE findings ADD COLUMN curl_command TEXT` and `ALTER TABLE findings ADD COLUMN html_poc TEXT`) if older database versions are detected.
  - `save_scan_record()`: Persists target URL, status, pages crawled, findings list (including severity, category, evidence, reproducible `curl_command`, and `html_poc`), and endpoints into SQLite.
  - `get_latest_scan_findings()`: Retrieves the most recent scan metadata and associated findings/endpoints for STIX/TAXII exports and HTML PoC retrieval.
- **How to Modify**: Add columns to table schemas and bind new finding metadata attributes.

#### `app/core/security.py`
- **Role**: SSRF prevention, URL validation, batch `src_list` sanitization, and filesystem sandbox confinement.
- **What It Does**:
  - `normalize_target_url(raw)`: Strips quotes/whitespace, ensures lowercase scheme, prepends `https://` if absent, and drops fragments.
  - `validate_target_url(url, allow_local_staging)`: Resolves host IP addresses via `socket.getaddrinfo`. Blocks loopback (`127.0.0.1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
  - If `allow_local_staging=True`, allows local dev targets while strictly retaining the cloud metadata block.
  - `sanitize_target_input(raw_target)` & `parse_src_list(raw_content)`: Validates and deduplicates multi-target batch inputs (from `.csv` uploads or comma-separated strings), rejecting shell metacharacters, CLI flag injection (`-`), path traversal tokens (`..`, `\`), and non-HTTP schemes.
  - `sanitize_filename(filename, default)` & `resolve_sandboxed_path(base_dir, *parts)`: Enforces strict filesystem boundary confinement. Strips directory components, control characters, and traversal sequences, and verifies `resolved.is_relative_to(base_resolved)` while rejecting symlinks along the path.
  - `sanitize_text(text)`: HTML-escapes content before terminal log injection.
  - `calculate_sha256(filepath)`: Computes cryptographic file checksums while rejecting symlinks and null bytes.
- **How to Modify**: Add blocked hostnames or subnets to the SSRF blocklist.

#### `app/core/auditor_secrets.py`
- **Role**: Shannon entropy and regex-based token/credential leakage scanner.
- **What It Does**:
  - `calculate_shannon_entropy(data: str) -> float`: Calculates average information entropy $H(X) = -\sum p(x) \log_2 p(x)$ in bits per character.
  - Maintains `SECRET_RULES` with specific `min_entropy` thresholds:
    - `AWS_KEY`: `AKIA[0-9A-Z]{16}` (`min_entropy: 3.0`)
    - `GOOGLE_API_KEY`: `AIza[0-9A-Za-z\-_]{35}` (`min_entropy: 3.2`)
    - `STRIPE_SECRET_KEY`: `sk_live_[0-9a-zA-Z]{24,}` (`min_entropy: 3.4`)
    - `GITHUB_TOKEN` / `GITLAB_TOKEN`: (`min_entropy: 3.2`)
    - `OPENAI_KEY`: (`min_entropy: 3.2`)
    - `JWT_TOKEN`: (`min_entropy: 3.4`)
  - **False-Positive Suppression**: Repetitive dummy strings (e.g. `AKIAAAAAAAAAAAAAAAAA`) falling below the entropy threshold are suppressed in normal mode, or flagged as low-confidence `INFO` in Shadow Mode.
  - Obfuscates secret tokens (e.g. `AKIA****MPLE`) and appends exact entropy scores to finding evidence.
- **How to Modify**: Add new regex rules or tune `min_entropy` values to adjust sensitivity.

#### `app/core/auditor_headers.py`
- **Role**: HTTP response header, cookie security, and transport layer auditor.
- **What It Does**:
  - `audit_response_headers(url, headers, status)`:
    - Evaluates Content-Security-Policy (flags missing CSP, `'unsafe-inline'`, `'unsafe-eval'`, and wildcard origins).
    - Evaluates Strict-Transport-Security (HSTS) on HTTPS, minimum `max-age` (recommended >= 31536000), and `includeSubDomains`.
    - Evaluates Anti-Clickjacking: `X-Frame-Options` and CSP `frame-ancestors`.
    - Evaluates MIME Sniffing: `X-Content-Type-Options: nosniff`.
    - Evaluates Referrer and Permissions policies.
    - Detects server banners (`Server: Apache/2.4.41`, `X-Powered-By: PHP/7.4`).
  - `audit_cookies(url, cookies_headers)`: Audits `Set-Cookie` directives for `Secure`, `HttpOnly`, `SameSite` compliance, and flags `SameSite=None` without `Secure`.
    - **Vendor Cookie Exclusions**: Automatically downgrades WAF/analytics cookies (Akamai Bot Manager, Adobe Experience Cloud, Tealium, Google Analytics) to INFO severity for missing HttpOnly/Secure flags, as these are expected vendor behaviors.
    - **Deduplication**: Prevents duplicate cookie findings from redirect chains using `seen_cookies` set tracking `(cookie_name.lower(), check_type)` tuples.
  - `audit_cors(url, acao, acac, tested_origin)`: Flags wildcard origins with credentials (`Access-Control-Allow-Origin: *` + `Credentials: true`) and dynamic untrusted origin reflection.
- **How to Modify**: Add checks inside `audit_response_headers()` returning standardized finding dictionaries. Extend `VENDOR_COOKIE_EXCLUSIONS` regex patterns for new vendor cookies.

#### `app/core/auditor_api_routes.py`
- **Role**: Active non-destructive probe for exposed API schemas, actuators, and debug files with WAF circuit breaker.
- **What It Does**:
  - Probes `PROBE_TARGETS`: `/.git/HEAD`, `/.env`, `/openapi.json`, `/swagger.json`, `/actuator/env`, `/actuator/health`, `/phpinfo.php`, `/server-status`.
  - Probes GraphQL endpoints (`/graphql`, `/api/graphql`) with safe introspection query:
    `{"query": "{ __schema { queryType { name } } }"}`. Flags exposed introspection schemas.
  - **Pacing & Concurrency**: Restricts probe concurrency with `asyncio.Semaphore(settings.PROBE_CONCURRENCY_LIMIT)` and injects randomized jitter (250ms–750ms) before each request to break deterministic burst patterns.
  - **WAF & Rate-Limit Circuit Breaker**: `is_waf_block(resp)` evaluates HTTP 429 status codes and WAF block signatures (`cf-ray`, `x-amzn-waf-action`, `Server: cloudflare`, `AkamaiGHost`). Automatically halts active probes upon detection to prevent escalating SOC alarm severity.
- **How to Modify**: Append new diagnostic route paths and response validation checks to `PROBE_TARGETS`, or add signatures to `WAF_SIGNATURE_HEADERS`.

#### `app/core/auditor_dom.py`
- **Role**: Client-side JavaScript auditor looking for DOM XSS sinks, insecure postMessage listeners, and reproduction harness synthesis.
- **What It Does**:
  - Analyzes downloaded JavaScript bundles for dangerous sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`) taking input from DOM sources (`location.search`, `location.hash`) on the same execution line.
  - Flags `window.addEventListener('message', ...)` listeners lacking `event.origin` validation.
  - `build_postmessage_poc(target_url, script_url, body)`: Synthesizes an offline, self-contained HTML reproduction harness (`poc_postmessage_<hash>.html`) embedding the target via `<iframe>`, inspecting message contract structures (`json.parse`, `e.data.action`), dispatching test messages with wildcard origin (`'*'`), and rendering clear testing instructions.
  - Enriches unvalidated postMessage findings with `html_poc` (filename) and `html_poc_content` (full HTML source) for 1-click clipboard copy and downloading.
- **How to Modify**: Append new sink or source regex patterns to `DOM_SINKS` or `DOM_SOURCES`.

#### `app/core/engine_bridge.py`
- **Role**: Resilient, boundary-aware IPC adapter for compiled Rust and Go engine binaries with pure Python fallbacks and subprocess sandboxing.
- **What It Does**:
  - `_find_engine(name)` & `_validate_path(target_path)`: Enforces a strict binary allowlist (`_ALLOWED_ENGINES = {"web_spider", "surface_graph"}`), ensures resolved binaries reside within `settings.ENGINE_BIN_DIR`, and dynamically verifies target paths are non-symlink paths confined to `tempfile.gettempdir()`, `settings.OUTPUT_DIR`, `settings.STATIC_DIR`, `settings.EXEC_DIR`, or `settings.BASE_DIR` (allowing custom Docker volume mounts or external VM directories configured via `Settings`).
  - `_get_sandbox_env()`: Scrubs host environment variables before spawning Rust/Go subprocesses, passing only minimal safe runtime variables (`PATH`, `HOME=/tmp`, `TMPDIR`, `LANG`, `LC_ALL`, `SystemRoot`) so host secrets or `LD_PRELOAD` cannot leak into child processes.
  - `_extract_json_payload(raw)`: Scans stdout for the outermost valid JSON structure `{...}` or `[...]`, ignoring preceding or trailing compiler warnings, debug output, or panic messages.
  - `_run_engine(binary_path, args, timeout)`: Invokes binaries via argument lists (never `shell=True`) inside a temporary working directory (`cwd=tempfile.gettempdir()`) with scrubbed environment variables, validates return codes, separates stderr, and parses JSON output.
  - `run_spider_extractor(target_path, depth=2, domain="")`: Executes Rust `web_spider` with `--depth` and `--domain` flags. Automatically falls back to `_python_fallback_spider()` on binary failure or panic (which also skips symbolic links during directory walks).
  - `_resolve_webpack_chunks_python(content)`: Robust chunk map resolver parsing Webpack `__webpack_require__.u`, `jsonpScriptSrc`, Vite dynamic imports (`import("./...")`), and Rollup chunk preloads.
  - `_is_allowed_domain(url, target_domain)`: Restricts crawling scope strictly to target domain and subdomains.
  - `run_surface_graph(endpoints, headers, content, findings=None)`: Runs Go `surface_graph` with findings payload (protecting the `/tmp/surface_graph_payload_debug.json` IPC file against symlink attacks via `O_NOFOLLOW` and `0o600` permissions). Falls back to `_python_fallback_surface_graph()` with normalized composite threat scoring (capping vendor noise at +2).
- **How to Modify**: Add new engine connectors following the `_run_engine()` pattern.

#### `app/core/scanner.py`
- **Role**: Master single-target and multi-target batch audit pipeline orchestrator, cURL PoC generator, HTML reproduction harness manager, isolated `Output/Targ00N` artifact generator, and real-time SSE broadcaster.
- **What It Does**:
  - `generate_curl_poc(finding)`: Synthesizes reproducible, functional `curl` commands for every finding using benign origins (`https://origin-verify.<domain>`), cookie checks, grep-filtered asset downloads, and GraphQL introspection requests.
  - `generate_html_poc(finding)`: Manages HTML reproduction harnesses for DOM XSS and postMessage vulnerabilities, writing PoC files strictly inside `settings.STATIC_DIR` via `resolve_sandboxed_path()`.
  - `deduplicate_findings(findings)`: Removes duplicate findings based on `(category, title, endpoint)` tuples before persistence.
  - `broadcast_log(entry)`: Broadcasts real-time terminal log entries to all connected SSE subscriber queues (`LOG_SUBSCRIBERS`).
  - `generate_target_output_artifacts(...)`: Writes isolated per-target deliverables (`blackroute_triage_scan_<scan_id>.md` and `BlackRoute_Web_Report_<timestamp>.pdf`) into `Output/Targ001`, `Output/Targ002`, ..., `Output/Targ00N` with strict path confinement.
  - `run_batch_scan_pipeline(targets, ...)`: Sequentially orchestrates multi-target batch audits across validated `src_list` domains, isolating each target's state, temporary directory, SQLite record, and `Output/Targ{index:03d}` report folder while streaming unified progress and batch summary metrics over SSE.
  - `WebScanner.run_pipeline()`:
    1. Validates target and SSRF boundaries. Injects `Settings.get_stealth_headers(self.engagement_id)` with Akamai cache bypass and staging tokens. Creates an isolated `0o700` temporary harvest directory (`blackroute_web_...`) with sandbox-verified deterministic file names (`index.html`, `page_<hash>.html`, `asset_<hash>.js`, `chunk_<hash>.js`).
    2. Phase 1: Header, cookie, CORS (using benign origin test), and transport audit. Detects initial WAF response blocks.
    3. Phase 2: Bounded BFS spidering of web assets and client routes via Rust `web_spider` (depth=2, strict target domain filter, capped at 25 HTML / 50 JS assets, <45s runtime). Harvests and analyzes Webpack dynamic chunks.
    4. Phase 3: Secret and credential leak detection with Shannon entropy evaluation.
    5. Phase 4: DOM XSS and postMessage risk analysis; synthesizes offline HTML PoC reproduction harnesses.
    6. Phase 5: API surface and sensitive path probing (conditionally executed based on `self.stealth_mode`; suppressed in Stealth Mode to protect client SOC telemetry). Active verification verifies GraphQL introspection and accessible login endpoints.
    7. Phase 6: Attack surface topology and stack fingerprinting via Go `surface_graph` with normalized composite scoring.
    8. Phase 7: Deduplicates findings, generates cURL PoCs and HTML harnesses, saves scan to SQLite, compiles VIDS PDF report, populates `Output/Targ001/` (for single-target scans) or `Output/Targ00N/` (for batch scans), and broadcasts dynamic results grid with `[COPY cURL PoC]`, `[COPY HTML PoC]`, and `[DOWNLOAD BATCH ZIP]` buttons.
    9. Zero-Footprint Protocol: Removes temporary asset directories upon completion.
- **How to Modify**: Add new scan phases or adjust confidence suppression thresholds.

---

### Polyglot Compiled Engines (`engines/`)

#### `engines/web_spider/` (Rust Engine)
- **Files**: `Cargo.toml`, `Cargo.lock`, `src/main.rs`.
- **Role**: High-throughput web asset crawler, BFS directory traverser, and dynamic chunk resolver.
- **What It Does**:
  - Accepts CLI commands: `web_spider <file_path>` or `web_spider dir <directory_path> [--depth <N>] [--domain <target_domain>]`.
  - Parses HTML structures: extracts `<a href>`, `<script src>`, `<form action method>`.
  - **Bounded Recursive Spidering (BFS Queue)**: Implements queue-based breadth-first traversal up to configurable depth (default: 2, max: 3). Enforces strict domain filtering (`is_allowed_domain`) so crawling never escapes to external CDNs or untrusted hosts. Enforces per-domain asset caps (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`) keeping runtime under 45 seconds.
  - **Webpack / Vite / Rollup Chunk Resolver**: Automatically scans JavaScript bundles for dynamic chunk mappings (`__webpack_require__.u`, `jsonpScriptSrc`), Vite dynamic imports (`import("./...")`), and Rollup preloads (`preload([...])`, `__vitePreload(...)`). Reconstructs split code chunk paths so hidden client routes are harvested before DOM execution.
  - **Route Sanitization & Regex ReDoS Protection**: Enforces `is_valid_endpoint` filtering, rejecting JavaScript control words (`return `, `function`, `test(`, `const `) and balanced regex literals (`/regex/`, `\d{5}`). Uses linear-time Thompson NFA regexes.
  - Outputs structured JSON conforming to `engine_bridge.py`.
- **How to Modify**: Add keywords to `HIGH_VALUE_KEYWORDS` or chunk patterns in `src/main.rs`. Recompile via `./launcher.sh build_engines`.

#### `engines/surface_graph/` (Go Engine)
- **Files**: `go.mod`, `main.go`.
- **Role**: Concurrent attack surface topology analyzer, enterprise vendor fingerprinter, and normalized threat scorer.
- **What It Does**:
  - Accepts CLI commands: `surface_graph <json_path | dir <directory>>`. Ingests scan findings payload alongside routes and headers.
  - Normalizes route paths, decomposes segments, and builds parent-child topology edges.
  - **Vendor Route Segregation**: Filters out third-party vendor tracking/telemetry scripts (`akamai`, `tiqcdn`, `tealium`, `adobe`, `demdex`, `google-analytics`) so third-party URLs are not misidentified as first-party sensitive administrative routes.
  - **Enterprise Technology Fingerprinting**: Detects Next.js, React, Vue, Angular, Apache, Nginx, Cloudflare, Akamai Bot Manager (`_abck`, `bm_sz`, `akamai_session`), Adobe Experience Cloud (`mbox`, `amcv`), and Tealium iQ (`utag.sync`, `utag.js`).
  - **Normalized Composite Threat Scoring**: Refactored scoring formula that caps third-party vendor and `INFO` items to a maximum contribution of +2 points (preventing the 95–100 score inflation bug), while appropriately weighting first-party CRITICAL (+25) and HIGH (+15) vulnerabilities.
  - Outputs structured JSON conforming to `engine_bridge.py`.
- **How to Modify**: Add new technology signatures in `fingerprintTechnologies()` or adjust scoring weights in `calculateRiskScore()` in `main.go`. Recompile via `./launcher.sh build_engines`.

---

### Presentation & Threat Intelligence (`app/routes/`, `app/templates/`, `app/static/`, `Sources/`)

#### `app/routes/home.py`
- **Role**: Dashboard view router.
- **What It Does**: Serves `index.html` with Starlette 0.36+ keyword syntax (`request=request, name="index.html", context={...}`) and handles `/favicon.ico`.

#### `app/routes/api.py`
- **Role**: REST API endpoints for single and batch scanning, HTMX mode switching, log streaming, and threat intelligence export.
- **What It Does**:
  - `POST /api/scan`: Accepts target URL, `shadow_mode`, `local_staging`, `auth_header`, `stealth_mode` (default `True`), and `engagement_id`. Launches `WebScanner.run_pipeline` in background tasks and returns SSE activation script.
  - `POST /api/scan/batch`: Accepts either an uploaded `.csv` file (`src_list_file`, capped at 2 MB with sanitized filename) or inline comma-separated domains (`batch_targets`). Parses and sanitizes targets via `parse_src_list()`, enforces SSRF/staging checks, and launches `run_batch_scan_pipeline` in background tasks.
  - `GET /api/input-mode`: HTMX fragment switcher (`?mode=single` or `?mode=batch`) that dynamically swaps the dashboard submission form between Single Target Domain mode (`POST /api/scan`) and Batch Domain Import mode (`POST /api/scan/batch`) without page reloads.
  - `GET /POST /api/export/batch-zip`: Compiles all generated `Output/Targ001 .. Output/Targ00N` directories into an in-memory ZIP archive (`compile_batch_zip_archive()`, rejecting symlinks and enforcing `Output/` path boundaries) and streams `BlackRoute_Batch_Audit_<timestamp>.zip`.
  - `GET /api/poc/{filename}` & `GET /api/export/report-latest`: Serves generated HTML PoC harnesses and latest VIDS PDF reports using strict `sanitize_filename()` and `resolve_sandboxed_path()` confinement inside `settings.STATIC_DIR`.
  - `GET /api/stream-logs-sse`: Server-Sent Events endpoint streaming log events over a persistent connection (`text/event-stream`) with automatic keepalive heartbeats.
  - `GET /api/stream-logs`: Legacy HTTP polling fallback.
  - `GET /api/engines-status`: HTMX fragment displaying live badges for Rust Web Spider, Go Surface Graph, and Python DAST pipeline.
  - `GET /api/export/stix`: Builds an authentic STIX 2.1 JSON bundle (`bundle--<uuid>`) containing `vulnerability`, `report`, and `indicator` objects with embedded cURL PoC steps.
  - `GET /api/export/taxii`: Builds a TAXII 2.1 collection envelope containing threat indicators.

#### `app/templates/index.html`
- **Role**: Real-time mission control dashboard.
- **What It Does**:
  - **Left Column**: Live engine status badges, **HTMX Input Mode Toggle (`SINGLE TARGET` vs. `BATCH IMPORT (.CSV / LIST)`)**, target submission form, **Stealth Protocol toggle** (enabled by default for low SOC footprint), Shadow Mode toggle, Local Staging Mode toggle, **Authorized Engagement ID input** (`X-Security-Engagement`), Advanced Auth drawer, `[DOWNLOAD BATCH ZIP]` export trigger, and real-time scrolling console log container with live `SSE CONNECTED` indicator.
  - **Right Column**: Interactive results grid with severity badges, confidence scores, 1-click `[COPY cURL PoC]` and `[COPY HTML PoC]` buttons for instant HackerOne triage, expandable command drawers, and one-click report export actions (including Batch ZIP download when `Output/Targ*` artifacts are present).
  - **Client Script**: Implements native JavaScript `EventSource('/api/stream-logs-sse')` with automatic reconnection and clipboard copy handlers.

#### `app/templates/layout.html`
- **Role**: Master base template with Google Fonts (`Inter`), HTMX script tag, brand banner, and stylesheets.

#### `app/static/brand.css` & `app/static/terminal.css`
- **Role**: Corporate branding and dark military-industrial cyberpunk interface themes. Defines typography, severity badge colors (`.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`, `.sev-info`), grids, tables, and scrollbars.

#### `Sources/Utilities/vids_pdf_gen.py`
- **Role**: CyberNest VIDS (Vulnerability Identification & Defense Specification) PDF & Bug Bounty Markdown report formatting engine.
- **What It Does**:
  - `STEALTH_CURL_HEADERS_BLOCK` & `ensure_stealth_curl_poc(curl_cmd, endpoint)`: Guarantees every generated or persisted `curl` command embeds the complete L7 client hint and modern Chrome 124 browser persona headers (`User-Agent`, `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Accept`, `Accept-Language`) so security engineers and bug bounty triagers never trigger edge WAF `403 Forbidden` blocks during reproduction.
  - `classify_bug_bounty_metadata(finding, default_target)`: Deterministically maps every finding category and vulnerability type to its exact CWE classification (`CWE-693`, `CWE-1021`, `CWE-319`, `CWE-942`, `CWE-614`, `CWE-1004`, `CWE-1275`, `CWE-798`, `CWE-79`, `CWE-346`, `CWE-200`, `CWE-538`), CVSS v3.1 Base Vector & Score (`CVSS:3.1/...`), and a numbered 3-step reproduction guide.
  - `build_chained_impact_statement(target_url, actionable_findings, risk_score)`: Synthesizes an **Executive Summary & Chained Triage Impact Statement** explaining how discovered vulnerabilities chain together across the target origin.
  - `build_bug_bounty_markdown_triage(scan, findings, endpoints)` & `generate_web_report(data, output_dir)`: Generates standardized Bug Bounty Submission Markdown (`.md`) and VIDS PDF (`.pdf`) reports containing Executive Summaries, Chained Triage Impact Statements, CWE/CVSS v3.1 vectors, Step-by-Step Reproduction Guides, Actionable Remediation Guidance, and Stealth Browser Persona cURL PoCs.

---

### Test Suites (`tests/`)

#### `tests/test_audit.py`
- **Role**: Comprehensive unit test suite (running inside an isolated temporary sandbox via `setUpClass`/`tearDownClass` so production `blackroute_web.db`, `Output/`, and `app/static/` are never touched by test data) covering:
  - URL normalization, SSRF validation rules, and batch `src_list` sanitization (`sanitize_target_input`, `parse_src_list`).
  - Filesystem sandbox confinement and path traversal prevention (`sanitize_filename`, `resolve_sandboxed_path`, `resource_path`, `engine_bridge._validate_path`, `_get_sandbox_env`).
  - Header, cookie, and CORS auditor logic.
  - Shannon entropy calculation and false-positive suppression.
  - Automated cURL PoC generation across finding categories.
  - Resilient boundary-aware JSON extraction in `engine_bridge.py`.
  - DOM XSS sink detection and postMessage origin checks.
  - Engine bridge Python fallback execution.
  - Clean VIDS PDF report generation.
- **Execution**: `.venv/bin/python -m unittest tests/test_audit.py`

#### `tests/test_pipeline_e2e.py`
- **Role**: Full end-to-end integration test running against an in-process mock vulnerable HTTP server inside an isolated temporary directory (`DB_PATH`, `OUTPUT_DIR`, `STATIC_DIR`).
- **What It Verifies**: Verifies that all 5 vulnerability categories are discovered, data is persisted to SQLite with functional `curl_command` attributes, VIDS PDF reports are generated, STIX 2.1 / TAXII 2.1 exports succeed, and multi-target batch scanning (`run_batch_scan_pipeline`) creates isolated `Output/Targ001` and `Output/Targ002` folders and compiles them into a valid Batch ZIP archive (`compile_batch_zip_archive`).
- **Execution**: `.venv/bin/python -m unittest tests/test_pipeline_e2e.py`

---

## 3. Data Flow & Lifecycle of an Audit

```text
                       [User Form in Browser (HTMX Toggle)]
                                        │
            ┌───────────────────────────┴───────────────────────────┐
            │ (Single Target Mode)                                  │ (Batch Import Mode: .csv / comma list)
            │ POST /api/scan                                        │ POST /api/scan/batch
            ▼                                                       ▼
  [api.py: start_scan()]                                 [api.py: start_batch_scan()]
  (Dispatches WebScanner.run_pipeline)                   (Parses & sanitizes src_list via parse_src_list())
            │                                            (Dispatches run_batch_scan_pipeline() as Background Task)
            │                                                       │
            │                                                       ▼
            │                                            [scanner.py: run_batch_scan_pipeline()]
            │                                            (Iterates sequentially [1/N .. N/N] with isolated state)
            └───────────────────────────┬───────────────────────────┘
                                        │ (Signals browser to open SSE stream /api/stream-logs-sse)
                                        ▼
                      [scanner.py: Security & SSRF Validation]
                       │ (Rejects loopback, private IPs & cloud metadata unless Local Staging Mode)
                       ▼
                      [scanner.py: Phase 1 - HTTP Header / Cookie / CORS Audit]
                       │ (HeaderAuditor analyzes response headers)
                       ▼
                      [scanner.py: Phase 2 - Asset Crawl & JS Harvest]
                       │ (Downloads HTML & scripts into isolated 0o700 temp dir)
                       │ (Invokes bin/web_spider [Rust] via engine_bridge.py)
                       ▼
                      [scanner.py: Phase 3 - Secret & Credential Scan with Shannon Entropy]
                       │ (SecretAuditor calculates H(X); suppresses low-entropy false positives)
                       ▼
                      [scanner.py: Phase 4 - Client-Side DOM & postMessage Audit]
                       │ (DomAuditor checks execution sinks and event origin validation)
                       ▼
                      [scanner.py: Phase 5 - API Surface & Sensitive Route Probing]
                       │ (ApiRouteAuditor probes /.git, /.env, /openapi.json, GraphQL introspection)
                       ▼
                      [scanner.py: Phase 6 - Attack Surface & Stack Fingerprinting]
                       │ (Invokes bin/surface_graph [Go] via engine_bridge.py)
                       ▼
                      [scanner.py: Phase 7 - cURL Generation, Reporting & Persistence]
                       ├─► Generate reproducible cURL PoC & HTML harness for each finding
                       ├─► Filter low confidence (< 0.75 unless Shadow Mode)
                       ├─► Save scan, findings & cURL commands to SQLite (database.py)
                       ├─► Write isolated per-target Markdown & VIDS PDF to Output/Targ001..Targ00N
                       ├─► Zero-Footprint Protocol: Clean temporary harvest directory
                       └─► Stream dynamic Results Panel HTML (with 1-click cURL/HTML PoC & Batch ZIP export) via SSE
```

---

## 4. Developer Extension How-To Guides

### How to Add a New Secret Detection Rule with Entropy Threshold
1. Open `app/core/auditor_secrets.py`.
2. Append a new dictionary to `SECRET_RULES`:
   ```python
   {
       "id": "CUSTOM_TOKEN",
       "title": "Exposed Custom Service API Key",
       "regex": re.compile(r'(custom_key_[0-9a-zA-Z]{32})'),
       "severity": "CRITICAL",
       "min_entropy": 3.2,  # Enforce minimum Shannon randomness
       "description": "Hardcoded API key for Custom Service exposed in client assets.",
       "remediation": "Revoke the key immediately and route calls through a backend proxy."
   }
   ```
3. Run `./launcher.sh test` (or `.venv/bin/python -m unittest tests/test_audit.py`) to verify.

### How to Add a New Active Probe Path
1. Open `app/core/auditor_api_routes.py`.
2. Append a new entry to `PROBE_TARGETS`:
   ```python
   {
       "path": "/api/debug/vars",
       "title": "Exposed Debug Variables (/api/debug/vars)",
       "severity": "HIGH",
       "category": "API_EXPOSURE",
       "check": lambda resp: resp.status_code == 200 and "memstats" in resp.text,
       "description": "Go runtime debug metrics and environment variables exposed.",
       "remediation": "Disable expvar or restrict /debug/vars to internal localhost."
   }
   ```

### How to Add a New Framework Fingerprint to the Go Engine
1. Open `engines/surface_graph/main.go`.
2. In `fingerprintTechnologies()`, add your signature matching rule:
   ```go
   if strings.Contains(contentLower, "gatsby") {
       addTech("Gatsby", "Static Site Generator", "Gatsby runtime signature detected")
   }
   ```
3. Recompile the Go engine:
   ```bash
   ./launcher.sh build_engines
   ```

---

## 5. SOC-Friendly Architecture & Telemetry Evasion Protocol

A critical design requirement for BlackRoute-Web is preventing alert storms, false positive alarms, and IP bans on client perimeters. Security testing that trips client SOC tripwires wastes defensive analyst hours on triage tickets and creates unnecessary operational friction.

BlackRoute-Web implements a comprehensive, 6-pillar stealth defense architecture:

### 5.1 Modern Browser Persona & L7 Client Hints
- **The Problem**: Standard scanners use explicit User-Agents (e.g. `User-Agent: Nikto`, `User-Agent: BlackRoute-Web/1.0 (CyberNest Labs Security Auditor)`). WAF rules (such as ModSecurity CRS rule 913100) maintain regex blacklists for these strings and immediately return 403 blocks.
- **Implementation**: `Settings.get_stealth_headers()` generates realistic Chromium/Chrome 124 browser headers on Linux with full L7 Client Hints:
  ```python
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  "Sec-Ch-Ua-Mobile": "?0",
  "Sec-Ch-Ua-Platform": '"Linux"',
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "none",
  "Sec-Fetch-User": "?1",
  "Upgrade-Insecure-Requests": "1"
  ```
  This matches standard browser traffic profiles and prevents automated bot-classification by Cloudflare Bot Management or Akamai Bot Manager.

### 5.2 Randomized Dynamic CORS Origin Probing
- **The Problem**: Probing cross-origin reflection with `Origin: https://evil.cybernest.labs` immediately trips SIEM detection rules looking for keywords like `evil`, `attacker`, or unauthorized TLDs. Conversely, static origin checks risk false positives if a server has an unverified, static test rule configured.
- **Implementation**: In `scanner.py`, origin reflection is actively tested using an ephemeral, dynamically randomized subdomain probe with a cryptographic nonce matching the target's root domain:
  ```python
  parsed_host = urllib.parse.urlparse(validated_url).netloc
  probe_nonce = secrets.token_hex(4)
  benign_origin = f"https://probe-{probe_nonce}.{parsed_host}"
  cors_resp = await client.get(validated_url, headers={"Origin": benign_origin})
  ```
  This proves the backend dynamically reflects untrusted incoming origins in real time rather than matching a static whitelist. The resulting cURL PoC is generated with the exact tested origin for authentic reproducibility:
  ```bash
  curl -s -i "https://target.domain/api" -H "Origin: https://probe-a1b2c3d4.target.domain"
  ```

### 5.3 Semaphore Concurrency & Randomized Jitter Pacing
- **The Problem**: Firing multiple sensitive path probes simultaneously (`asyncio.gather(*tasks)`) creates microsecond burst spikes that trigger WAF volumetric anomaly rate limits.
- **Implementation**: In `auditor_api_routes.py`, requests are bounded by `asyncio.Semaphore(2)` and injected with randomized jitter between `0.25s` and `0.75s`. This breaks statistical burst detection and mimics human navigation latency.

### 5.4 Dual Scan Profiles: Stealth Protocol vs. Active Verification
- **Stealth Protocol (`stealth_mode=True`, Default)**:
  - Executes transport evaluation, header audits, cookie hygiene checks, JS asset harvesting, offline Rust Thompson NFA spidering, Shannon entropy credential auditing, and client-side DOM XSS sink analysis.
  - **Suppresses Phase 5 active path probes** (`/.env`, `/.git/HEAD`, `/actuator/*`, `/phpinfo.php`). This achieves zero 404 alert noise on the client backend during passive posture assessments.
- **Active Verification Mode (`stealth_mode=False`)**:
  - Explicitly chosen by the analyst when deep endpoint probing is authorized. Executes paced and jittered probes against sensitive paths.

### 5.5 WAF & Rate-Limit Circuit Breaker
- **Implementation**: `is_waf_block(resp)` evaluates responses for:
  - HTTP `429 Too Many Requests` or `503 Service Unavailable`.
  - HTTP `403 Forbidden` carrying WAF headers (`cf-ray`, `cf-mitigated`, `x-amzn-waf-action`, `Server: cloudflare`, `AkamaiGHost`) or challenge page signatures.
- **Action**: When detected, the circuit breaker halts further active probes, logs a warning to the SSE stream, and attaches an informative finding rather than continuing to hammer the perimeter and escalating incident severity.

### 5.6 Authorized Engagement Tagging (`X-Security-Engagement`)
- When assessing client infrastructure with an active SOC, analysts can specify an **Authorized Engagement ID** (e.g., `CN-AUDIT-2026-X`).
- Outbound requests automatically inject:
  ```http
  X-Security-Engagement: CN-AUDIT-2026-X
  X-Authorized-Audit: true
  ```
### 5.7 Decoupled Reporting Engine & Asynchronous Architecture
- **Non-Blocking Thread Pool Offloading**:
  - The core audit pipeline runs within Python's asynchronous event loop (`asyncio`).
  - Generating comprehensive VIDS PDF audit reports involves compute-intensive layout formatting (coordinate checks, string sanitization to Latin-1, multi-cell auto-wrapping, and disk I/O).
  - Rather than blocking the event loop or stalling SSE telemetry streaming, `scanner.py` offloads PDF generation to a separate OS worker thread:
    ```python
    loop = asyncio.get_running_loop()
    report_file = await loop.run_in_executor(
        None,
        generate_web_report,
        report_data,
        str(settings.STATIC_DIR)
    )
    ```
- **Optional Headless / Decoupled Execution**:
  - `WebScanner(generate_pdf=False)` allows automated CI/CD sweeps or large-target scans to persist findings directly to SQLite and return immediately without generating PDF artifacts.
- **On-Demand Report Compilation**:
  - Any historical or completed scan can have its VIDS PDF report compiled on-demand via the dedicated endpoint `POST /api/scans/{scan_id}/report`, decoupling reporting latency entirely from high-throughput network auditing.

---

## 6. Recent Pipeline Enhancements & Critical Bug Fixes

### 6.1 Findings Deduplication System
**Problem**: Cookie findings were duplicated across redirect chains (e.g., `akamai_session` appearing 3 times in reports), inflating severity counts and saturating the Surface Risk Score at 100/100.

**Solution**:
- **Auditor-Level Deduplication** (`auditor_headers.py`): Added `seen_cookies` set tracking `(cookie_name.lower(), check_type)` tuples to prevent duplicate cookie evaluations across multiple HTTP transactions.
- **Scanner-Level Deduplication** (`scanner.py`): Implemented `deduplicate_findings()` function that removes duplicate findings based on `(category, title, endpoint)` tuples before SQLite insertion.

**Impact**: Eliminates duplicate findings spam, normalizes Surface Risk Score calculation, and provides accurate severity counts for genuine vulnerabilities.

### 6.2 Enhanced Vendor Cookie Recognition
**Problem**: `akamai_session` cookie was not recognized as a vendor cookie, incorrectly flagged as HIGH severity for missing HttpOnly.

**Solution**: Updated Akamai Bot Manager regex pattern from `r"^(?:_abck|bm_(?:mi|so|sz|sv|lso)|ak_bmsc)$"` to `r"^(?:_abck|bm_(?:mi|so|sz|sv|lso)|ak_bmsc|akamai_.*)$"` to match all `akamai_*` cookies.

**Impact**: All Akamai cookies (including `akamai_session`, `akamai_edge_token`) are now correctly categorized as INFO severity with vendor_integration tags, reducing false positive HIGH findings.

### 6.3 Rust Spider Enhancements
**Problem**: Modern SPAs rely on code-splitting and dynamic routing, which the original depth-1 spider couldn't fully capture.

**Solution**:
- **Chunk Manifest Hydration**: Added regex patterns to detect and extract Vue.js/React chunk manifests (`chunk-`, `runtime~`, `vendors~`, `main.`, `app.`, `commons.`, `polyfills.`) for complete client-side routing tree discovery.
- **Dynamic Route Extraction**: Enhanced regex patterns to detect GraphQL query/mutation definitions and REST path parameters (`:id`, `{id}`) for dynamic API endpoint discovery.
- **Recursive Depth Traversal**: Added `MAX_RECURSION_DEPTH` constant (default: 3) for bounded BFS queue traversal while maintaining strict origin constraints.

**Impact**: Significantly increases endpoint yield from single-page crawls (demonstrated 837 endpoints from one page), captures dynamic API structures, and provides more comprehensive attack surface mapping.

### 6.4 Go Engine Enterprise Vendor Fingerprinting
**Problem**: Enterprise infrastructure detection was incomplete, missing critical WAF and marketing analytics platforms.

**Solution**: Expanded `fingerprintTechnologies()` in `main.go` with enterprise vendor detection:
- **Akamai Bot Manager**: Cookie-based detection (`_abck`, `bm_mi`, `bm_so`, `bm_sz`, `akamai_session`) and Server header analysis.
- **Adobe Experience Cloud**: Cookie detection (`mbox`, `amcv`) for enterprise marketing/analytics suites.
- **Tealium iQ Tag Management**: Script source detection (`utag.sync`, `utag.js`, `tealium`) for tag management platforms.

**Impact**: Provides accurate infrastructure mapping, enables targeted risk assessment based on vendor technologies, and improves contextual threat intelligence.

### 6.5 Validated Client Posture & Target Remediation
With noise filtering and deduplication active, the actual attack surface is now defined by core issues rather than false positives:

**Content Security Policy (Medium)**: Targets relying on `unsafe-inline` and `unsafe-eval` require architectural refactoring to cryptographic nonces or strict hashes to neutralize XSS vectors.

**EdgeLocation Cookie (Medium)**: First-party cookies transmitting geographic coordinates (e.g., `41.4088,-75.6626`) without the Secure flag are vulnerable to plaintext interception on HTTP downgrades.

**Header Hygiene (Low)**: Missing Referrer-Policy could leak session IDs or internal paths to external analytics platforms.

### 6.6 Bounded Recursive Spidering (BFS Queue & Origin Boundaries)
**Problem**: Single-page static crawling lacked visibility into multi-page applications, while naive recursive crawlers suffered from scope creep into external CDNs and infinite crawling loops.

**Solution**:
- **BFS Queue Traversal**: Implemented breadth-first search queue in `engines/web_spider/src/main.rs` with configurable crawl depth (`--depth 2`, max 3) and Python fallback in `app/core/engine_bridge.py`.
- **Strict Host & Subdomain Boundary Filtering**: Enforced `is_allowed_domain()` / `_is_allowed_domain()` ensuring the spider strictly follows links belonging to the target host and permitted subdomains (`host == target || host.endsWith("." + target)`).
- **Per-Domain Asset Caps**: Enforced strict per-crawl limits (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`), ensuring complete SPA harvests while guaranteeing execution completes well under 45 seconds.

### 6.7 Webpack, Vite & Rollup Dynamic Chunk Resolver
**Problem**: Modern frontend SPAs split application code across dozens of lazy-loaded chunks (`React.lazy()`, `import()`). A crawler parsing only initial HTML files misses hidden administrative routes and internal API contracts stored in deferred chunks.

**Solution**:
- **Dynamic Chunk Map Extraction**: Implemented chunk map resolution in both Rust (`resolve_webpack_chunks`) and Python (`_resolve_webpack_chunks_python`).
- **Runtime Support**:
  - Automatically identifies Webpack 4 & 5 dynamic chunk functions (`__webpack_require__.u`, `jsonpScriptSrc`) and extracts mapping dictionaries `{ [chunkId]: hash }`.
  - Parses Vite dynamic imports (`import("./views/...")`) and Rollup preload arrays (`preload([...])`, `__vitePreload(...)`).
- **Asset Queue Ingestion**: Reconstructed chunk URLs (`<prefix><chunkId>.<hash>.chunk.js`) are ingested into the spider pipeline and harvested for internal routes before DOM and secret scanning phases begin.

### 6.8 Active postMessage PoC Synthesizer & Dashboard Harness
**Problem**: Previous postMessage audit findings only generated generic `curl` commands searching JavaScript text, leaving security engineers without an actionable, reproducible verification harness.

**Solution**:
- **Automated Harness Synthesis**: `DomAuditor.build_postmessage_poc()` creates standalone, offline HTML reproduction harnesses (`poc_postmessage_<hash>.html`) embedding the target application in an `<iframe>`.
- **Payload & Origin Analysis**: Identifies target message format expectations (`json.parse`, `e.data.action`) and generates test payloads dispatched via wildcard `window.postMessage(payload, '*')`.
- **1-Click Dashboard Clipboard Copy**: Findings in `app/templates/index.html` feature a dedicated `[COPY HTML PoC]` button powered by `copyHtmlPoC()`, allowing instantaneous reproduction and verification.
- **Audit Logging & Persistence**: PoC file references and source content are stored in SQLite (`html_poc` column) and exposed for download via `GET /api/poc/{filename}`.

### 6.9 Targeted Akamai Edge Cache Bypass & Staging Origin Verification
**Problem**: CDN edge caches frequently serve cached responses that mask origin-level header misconfigurations and prevent accurate security posture evaluation during permitted engagements.

**Solution**:
- **Edge Cache Bypass**: When an authorized `engagement_id` is supplied, `Settings.get_stealth_headers()` automatically appends Akamai cache bypass and debugging headers:
  - `Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, no-cache`
  - `Cache-Control: no-cache, no-store, max-age=0`
- **Staging Token Support**: When clients provide a staging engagement format (`staging:<token>` or `akamai:<token>`), the engine injects:
  - `X-Akamai-Staging: true`
  - `X-Akamai-Edge-Token: <token>`
- **Safety**: Headers are only activated when an engagement ID is explicitly provided, ensuring default scans maintain a clean stealth profile.

### 6.10 Surface Risk Score Normalization Formula
**Problem**: Pure `INFO` observations and third-party vendor integrations (Akamai bot protection cookies, Adobe Experience Cloud tags, Tealium iQ scripts) were previously contributing linear risk points, artificially saturating aggregate Surface Risk Scores at 95–100 even on highly secure applications.

**Solution**:
- **Vendor Route Exclusion**: Excluded known vendor telemetry patterns (`akamai`, `tiqcdn`, `tealium`, `adobe`, `demdex`, `google-analytics`) from being classified as first-party sensitive administrative routes.
- **Bounded Vendor/INFO Contribution**: In both `engines/surface_graph/main.go` and `app/core/engine_bridge.py`, pure `INFO` items and vendor integration findings are capped at a maximum composite impact of +2 points.
- **Calibrated Severity Weighting**: Risk score calculation now prioritizes genuine exploitable vulnerabilities:
  - Base Score: +10
  - Sensitive Routes: +3 per unique route (capped at +15)
  - Critical Severity Findings: +25 each
  - High Severity Findings: +15 each
  - Medium Severity Findings: +8 each
  - Low Severity Findings: +3 each
  - Vendor / INFO Noise: Bounded to max +2
- **Result**: Eliminates score saturation and accurately portrays true security risk.

### 6.11 Multi-Target Batch Scanning & Isolated Output Architecture (`Output/Targ00N`)
**Problem**: Security engineers conducting multi-domain client engagements needed a way to ingest a list of target domains (`src_list`) via CSV upload or inline comma-separated input, audit each target sequentially without cross-target state pollution, and export neatly segregated per-target report packages.

**Solution**:
1. **Input Ingestion & Strict `src_list` Sanitization (`app/core/security.py`)**:
   - `parse_src_list(raw_content: str) -> List[str]` parses both multi-line `.csv` files (automatically skipping header rows like `domain`, `url`, `target`, `host` and extracting the first column) and inline comma/newline-separated domain lists.
   - `sanitize_target_input(raw_target: str) -> str` validates each entry prior to normalization:
     - Rejects command/shell injection characters (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, `\n`, `\r`, `\x00`) and whitespace injection.
     - Rejects CLI argument/flag injection (inputs starting with `-`).
     - Rejects path traversal sequences (`..`, `\`).
     - Enforces valid `http://` or `https://` URL structure and hostname format while deduplicating normalized URLs in order.
2. **HTMX Dynamic Input Mode Switcher (`app/routes/api.py`, `app/templates/index.html`)**:
   - Added `GET /api/input-mode?mode=single|batch`, allowing the operator to toggle seamlessly between **Single Target Domain** mode (`POST /api/scan`) and **Batch Domain Import** mode (`POST /api/scan/batch` with `enctype="multipart/form-data"`) via HTMX without reloading the dashboard.
   - In Batch Import mode, operators can upload a `.csv` file (`src_list_file`, capped at 2 MB) and/or paste comma-separated domains (`batch_targets`) while preserving all operational toggles (`stealth_mode`, `shadow_mode`, `local_staging`, `engagement_id`, `auth_header`, `auth_cookies`).
3. **Sequential Asynchronous Batch Orchestrator & Isolated `Output/Targ00N` Directories (`app/core/scanner.py`)**:
   - `run_batch_scan_pipeline()` iterates sequentially through validated targets (`[1/N] .. [N/N]`), instantiating a fresh `WebScanner` with `batch_index=idx` (`1..N`) for each target so findings, endpoints, cookies, and temporary asset directories never bleed across targets.
   - At the start of a new scan run (both single-target and batch), stale `Output/Targ*` directories from prior runs are cleaned out of `settings.OUTPUT_DIR` (`Output/`).
   - `generate_target_output_artifacts()` creates an isolated directory `Output/Targ001`, `Output/Targ002`, ..., `Output/Targ00N` for each scanned target (single-target scans automatically populate `Output/Targ001/`) containing:
     - `blackroute_triage_scan_<scan_id>.md`: Full HackerOne/Bugcrowd-ready Markdown triage report with target metadata, severity distribution, findings, evidence, and reproducible `curl` PoC blocks.
     - `BlackRoute_Web_Report_<timestamp>.pdf`: Compiled CyberNest VIDS PDF Executive & Technical Audit Report for that target.
4. **In-Memory Batch ZIP Archive Export (`app/routes/api.py`)**:
   - `compile_batch_zip_archive()` packages all `Output/Targ*` directories into an in-memory `io.BytesIO` ZIP stream (`ZIP_DEFLATED`) without writing temporary archives to disk.
   - Exposed via `GET /api/export/batch-zip` and `POST /api/export/batch-zip`, and wired to the `[DOWNLOAD BATCH ZIP]` action button in both the left control panel and the completed scan results banner.

### 6.12 Infrastructure Security Audit, Filesystem Confinement & Sandbox Isolation
**Problem**: Because BlackRoute-Web fetches untrusted external HTML/JS content, synthesizes HTML/PDF/Markdown artifacts, and invokes compiled Rust/Go binaries over local IPC, any unvalidated path construction, symlink following, or environment leakage could expose the host or container to path traversal or arbitrary file write risks.

**Solution (Zero Impact on Scan Heuristics or Output Schemas)**:
1. **Strict Filesystem Confinement (`app/core/security.py`, `app/core/config.py`)**:
   - Added `sanitize_filename(filename, default)` to strip directory separators, drive letters, null bytes, control characters, and leading dots from any untrusted filename.
   - Added `resolve_sandboxed_path(base_dir, *parts)` to verify that every resolved path satisfies `resolved.is_relative_to(base_resolved)` and that no intermediate or leaf component is a symbolic link.
   - Hardened `resource_path()` in `app/core/config.py` with `is_relative_to(base_path)` verification and stripped CR/LF/NUL characters from `engagement_id` in `Settings.get_stealth_headers()`.
2. **Sandboxed Temp & Artifact Writes (`app/core/scanner.py`, `Sources/Utilities/vids_pdf_gen.py`, `app/routes/api.py`)**:
   - `WebScanner.run_pipeline()` sets `0o700` permissions on its per-scan temporary directory (`self.temp_dir`) and confines all downloaded asset writes (`index.html`, `page_<hash>.html`, `asset_<hash>.js`, `chunk_<hash>.js`) via `resolve_sandboxed_path(Path(self.temp_dir), ...)`.
   - `validate_target_url()` is enforced on `auth_macro_url` before executing pre-scan authentication macros.
   - `generate_web_report()` in `Sources/Utilities/vids_pdf_gen.py` validates that output PDF paths are non-symlink paths confined to `STATIC_DIR`, `OUTPUT_DIR`, or `/tmp`.
   - `/api/poc/{filename}` and `/api/export/report-latest` validate requested filenames with `sanitize_filename()` and `resolve_sandboxed_path(settings.STATIC_DIR, ...)`, and `compile_batch_zip_archive()` skips symlinks and verifies `is_relative_to(out_root)` before archiving.
3. **Polyglot Subprocess & Binary Sandboxing (`app/core/engine_bridge.py`, `engines/`)**:
   - `_find_engine()` enforces `_ALLOWED_ENGINES = {"web_spider", "surface_graph"}` and verifies binaries reside inside `settings.ENGINE_BIN_DIR`.
   - `_validate_path()` rejects symlinks, null bytes, and CLI flag injection (`-`), dynamically resolving allowed sandbox roots against `tempfile.gettempdir()`, `settings.OUTPUT_DIR`, `settings.STATIC_DIR`, `settings.EXEC_DIR`, and `settings.BASE_DIR` so custom Docker volume mounts or external VM directories (`BLACKROUTE_OUTPUT_DIR`, `BLACKROUTE_STATIC_DIR`) work seamlessly without static directory name heuristics.
   - `_get_sandbox_env()` scrubs the subprocess environment (`env=_get_sandbox_env()`, `cwd=tempfile.gettempdir()`) so host credentials and environment variables are never inherited by Rust/Go child processes.
   - `run_surface_graph()` protects `/tmp/surface_graph_payload_debug.json` with `os.O_NOFOLLOW` and `0o600` permissions.
   - Both `engines/web_spider/src/main.rs` and `engines/surface_graph/main.go` (as well as `_python_fallback_spider`) explicitly reject symbolic links and verify canonical directory boundaries (`canonicalize` / `filepath.EvalSymlinks`) during directory walks.
4. **Container & Test Suite Isolation (`Dockerfile`, `docker-compose.yml`, `tests/`)**:
   - Hardened `Dockerfile` (`cybernest` user with `/usr/sbin/nologin`, `chmod 550 /app/bin/*`) and `docker-compose.yml` (`no-new-privileges:true`, `cap_drop: [ALL]`, `tmpfs: /tmp:rw,noexec,nosuid,nodev,size=64m`).
   - Isolated `settings.DB_PATH`, `settings.OUTPUT_DIR`, and `settings.STATIC_DIR` inside `tempfile.TemporaryDirectory` in `tests/test_audit.py` and `tests/test_pipeline_e2e.py` so running test suites never pollutes production `blackroute_web.db` or `Output/Targ*`.

### 6.13 Standardized Bug Bounty Report Formatting Engine & Stealth cURL PoC Synthesis
**Problem**: Standard automated scanner exports often lack the structured fields required by professional bug bounty platforms (HackerOne, Bugcrowd, Intigriti) and enterprise triage teams, and bare `curl -s -I` commands in PoC blocks are frequently blocked with `403 Forbidden` by edge WAFs (Akamai Bot Manager, Cloudflare) due to missing L7 browser client hints.

**Solution (`Sources/Utilities/vids_pdf_gen.py`, `app/core/scanner.py`, `app/routes/api.py`)**:
1. **Standardized Bug Bounty Report Structure (`.md` & `.pdf`)**:
   - Both `build_bug_bounty_markdown_triage()` (used by `/api/export/markdown`, `/api/scans/{scan_id}/export/markdown`, and `Output/Targ00N/blackroute_triage_scan_<id>.md`) and `generate_web_report()` (used for `BlackRoute_Web_Report_<timestamp>.pdf`) now output a unified bug bounty submission structure:
     - **Executive Summary & Chained Triage Impact Statement** (`build_chained_impact_statement()`): Synthesizes multi-finding attack chains across CSP, cookie security flags, DOM sinks, CORS, API exposure, and credential leaks.
     - **Precise CWE Classifications & CVSS v3.1 Base Vectors** (`classify_bug_bounty_metadata()`): Maps every finding to its exact CWE identifier (e.g., `CWE-693`, `CWE-1021`, `CWE-614`, `CWE-1004`, `CWE-798`, `CWE-79`, `CWE-346`, `CWE-942`) and calibrated CVSS v3.1 Base Vector string (`CVSS:3.1/AV:N/...`) and base score.
     - **Step-by-Step Reproduction Guides**: Provides numbered verification steps tailored to the target endpoint and evidence indicator.
     - **Actionable Remediation Guidance**: Provides concrete engineering remediation instructions alongsideSection B vendor telemetry segregation.
2. **Stealth Browser Persona cURL PoCs (`generate_curl_poc()` & `ensure_stealth_curl_poc()`)**:
   - Every generated and exported `curl` PoC command automatically embeds the verified Chrome 124 on Linux stealth browser persona and L7 Client Hints (`STEALTH_CURL_HEADERS_BLOCK`) before any pipe or post-processing filter:
     ```bash
     curl -s -I "https://<target-domain>/" \
       -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
       -H "Sec-Ch-Ua: \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"" \
       -H "Sec-Ch-Ua-Mobile: ?0" \
       -H "Sec-Ch-Ua-Platform: \"Linux\"" \
       -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
       -H "Accept-Language: en-US,en;q=0.5"
     ```
   - `ensure_stealth_curl_poc()` also upgrades any historical or pre-persisted `curl_command` strings on-the-fly during Markdown and PDF report compilation.

---

## 7. Maintenance & Operational Commands

```bash
# Launch development server locally
./launcher.sh launch

# Recompile Rust and Go engines into bin/
./launcher.sh build_engines

# Run all unit and integration tests via virtual environment
./launcher.sh test
# (or directly via .venv)
.venv/bin/python -m unittest discover -s tests -v

# Run end-to-end integration test specifically
./launcher.sh test tests/test_pipeline_e2e.py
# (or directly via .venv)
.venv/bin/python -m unittest tests/test_pipeline_e2e.py

# Package single-file standalone release binary
./launcher.sh build_release

# Build and run multi-stage Docker container
docker-compose up --build -d

# Check Docker container status and logs
docker-compose logs -f
```

---
*CyberNest Labs Internal Application — Authorized Security Engineering Standard.*
