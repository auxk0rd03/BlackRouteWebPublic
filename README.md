# BlackRoute-Web

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Engine](https://img.shields.io/badge/polyglot-Rust%20%7C%20Go%20%7C%20Python-orange.svg)](https://cybernest.labs)

**BlackRoute-Web** is an automated dynamic application security testing (DAST), web attack surface mapping, and security posture auditing engine designed for web applications, REST/GraphQL APIs, and distributed cloud services.

As the sister application to **BlackRoute** (which audits source code repositories, AST data flows, and compiled binary P-Code), BlackRoute-Web targets live web application environments, evaluating transport security, HTTP security header hygiene, cookie protections, credential/secret leaks in client-side bundles, exposed administrative/debug surfaces, client-side DOM XSS sinks, and full attack surface topology.

---

## Legal and Ethical Disclaimer

This software tool is provided strictly for educational purposes and authorized security auditing only. Any unauthorized testing, scanning, or target reconnaissance without explicit, prior written permission from the asset owner is strictly prohibited and illegal. CyberNest Labs and the maintainers assume no liability for misuse or damage. Users are solely responsible for ensuring compliance with all local, national, and international cyber laws.

---

## Codebase Architecture

```
BlackRoute-Web-Linux_VersionPopOS/
├── app/
│   ├── core/
│   │   ├── auditor_api_routes.py # Probes for OpenAPI/Swagger, actuators, debug, and Git metadata
│   │   ├── auditor_dom.py        # Client-side DOM XSS sink and postMessage origin analyzer
│   │   ├── auditor_headers.py    # CSP, HSTS, CORS, Clickjacking, and Cookie hygiene analyzer
│   │   ├── auditor_secrets.py    # High-confidence regex engine for tokens/secrets in assets
│   │   ├── config.py             # Global application settings and path resolution
│   │   ├── database.py           # SQLite persistence layer
│   │   ├── engine_bridge.py      # Secure IPC adapter for Rust and Go compiled engines
│   │   ├── scanner.py            # Master orchestrator: crawling, audits, scoring, and VIDS trigger
│   │   └── security.py           # SSRF protection, target validation, and string sanitization
│   ├── routes/
│   │   ├── api.py                # Async REST endpoints: scanning, logs, STIX/TAXII export
│   │   └── home.py               # Mission control dashboard view router
│   ├── static/                   # Brand styling, dark military-industrial terminal CSS, logo
│   └── templates/                # HTMX-powered Jinja2 dashboard templates
├── engines/
│   ├── web_spider/               # [Rust] High-performance crawler & route regex extractor
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── surface_graph/            # [Go] Concurrent attack surface topology & tech fingerprinter
│       ├── go.mod
│       └── main.go
├── bin/                          # Compiled engine binaries (web_spider, surface_graph)
├── Sources/
│   └── Utilities/
│       └── vids_pdf_gen.py       # CyberNest VIDS Web Security Audit PDF report generator
├── tests/
│   └── test_audit.py             # Automated unit and module validation tests
├── blackroute_web.py             # Server entrypoint, CLI diagnostic & simulation engine
├── dev.sh                        # Dual-Native Linux orchestrator (CN-DIR-2026-004)
├── dev.bat                       # Dual-Native Windows 10/11 orchestrator (CN-DIR-2026-004)
├── launcher.sh                   # Unified Linux launcher, venv manager, engine compiler
├── launcher.bat                  # Unified Windows CLI launcher
└── requirements.txt              # Python library dependencies
```

---

## Dual-Native Orchestration (`CN-DIR-2026-004` Bi-Launcher Compliance)

BlackRoute-Web complies with **CyberNest Labs Architecture Specification // Standard 004 (`CN-DIR-2026-004`)**, providing full command parity across Linux (`dev.sh` / `launcher.sh`) and Windows 10/11 (`dev.bat` / `launcher.bat`), including native `.exe` compilation (`bin\web_spider.exe`, `bin\surface_graph.exe`), `GOFIPS=1` FIPS 140-3 enforcement, `CWE-377` symlink/ACL protection (`~/.cache/blackroute_web/session.log` / `%LOCALAPPDATA%\blackroute_web\session.log`), and `CWE-114` explicit PID tracking.

### Universal Command Parity Contract

| Subcommand | Linux (`./dev.sh <cmd>`) | Windows (`dev.bat <cmd>`) | Operational Function |
| :--- | :--- | :--- | :--- |
| **`setup`** | `./dev.sh setup` | `dev.bat setup` | Verifies `go`, `cargo`, `python3`, initializes `.venv`, and installs `requirements.txt`. |
| **`build`** | `./dev.sh build` | `dev.bat build` | Compiles `bin/web_spider[.exe]` (Rust) and `bin/surface_graph[.exe]` (Go `GOFIPS=1`) + regenerates SBOMs. |
| **`run` / `serve`** | `./dev.sh run` | `dev.bat run` | Launches the FastAPI/HTMX Mission Control server on `127.0.0.1` (`8000–8100`). |
| **`cli`** | `./dev.sh cli` | `dev.bat cli` | Executes a deterministic single-sweep CLI diagnostic, engine health, and CMMC 2.0 L2 compliance audit. |
| **`simulate`** | `./dev.sh simulate` | `dev.bat simulate` | Runs fault-injection / degraded enterprise attack-surface simulation and writes `Output/simulated_fault_audit.json`. |
| **`test`** | `./dev.sh test` | `dev.bat test` | Executes Go (`go test`), Rust (`cargo test`), and Python (`unittest`) verification suites. |
| **`fmt`** | `./dev.sh fmt` | `dev.bat fmt` | Formats Go (`go fmt ./...`) and Rust (`cargo fmt`) polyglot engines. |

---

## Features and Capabilities

* **Polyglot Compiled Performance (Rust & Go)**: Critical asset parsing and route extraction routines are executed via a compiled Rust engine using linear-time Thompson NFA regexes. Surface topology graph construction and tech fingerprinting run in Go goroutines. Both feature seamless Python fallbacks.
* **Bounded Recursive Spidering (BFS Queue)**: Queue-based breadth-first crawling with configurable crawl depth (`depth=2`, max 3). Restricts ingestion strictly to target host and legitimate subdomains, enforcing per-domain asset caps (max 25 HTML / 50 JS files) to guarantee execution under 45 seconds.
* **Webpack, Vite & Rollup Dynamic Chunk Resolver**: Automatically resolves Webpack 4/5 dynamic chunk maps (`__webpack_require__.u`, `jsonpScriptSrc`), Vite dynamic imports (`import()`), and Rollup preloads (`__vitePreload`), uncovering hidden administrative client routes and internal API contracts in split bundles.
* **Active postMessage PoC Synthesizer**: Offline HTML reproduction harness synthesis for unvalidated `postMessage` listeners, featuring iframe target embedding, message contract matching, and 1-click clipboard copy directly from the dashboard.
* **Targeted Akamai Bypass for Permitted Scans**: Injects Akamai edge cache bypass headers (`Pragma`, `Cache-Control: no-cache, no-store, max-age=0`) and staging tokens (`X-Akamai-Staging`, `X-Akamai-Edge-Token`) when an engagement ID is provided, allowing true origin posture verification.
* **Surface Risk Score Normalization**: Calibrated threat scoring formula that segregates vendor telemetry from first-party sensitive routes and caps third-party vendor and `INFO` items at a maximum of +2 points, preventing artificial 95–100 score saturation.
* **SOC-Friendly Stealth Protocol & Evasion**: Uses realistic modern Chrome 124 browser personas with full L7 Client Hints (`Sec-Ch-Ua`, `Sec-Fetch-*`), benign dynamic CORS origin reflection tests (no `evil` tags), Semaphore concurrency limits, and randomized request jitter (250ms–750ms).
* **Dual Scan Profiles (Stealth vs. Active)**: Defaults to low-noise Stealth Mode (suppressing noisy `/.env` and `/.git` probes) during passive posture audits, with an explicit toggle for Active Verification when intrusive probing is authorized.
* **WAF & Rate-Limit Circuit Breaker**: Detects HTTP 429 rate-limiting and WAF block signatures (Cloudflare, AWS WAF, Akamai), automatically halting active probes and backing off to avoid escalating SOC incident severity.
* **Deep Transport & Header Posture Auditing**: Evaluates Content Security Policy (CSP), Strict-Transport-Security (HSTS), CORS origin reflection, X-Frame-Options (Clickjacking), X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
* **Session & Cookie Hygiene**: Audits all `Set-Cookie` directives for `Secure`, `HttpOnly`, and `SameSite` compliance, recognizing enterprise vendor cookies to eliminate noise.
* **Client-Side Secret & Token Leakage**: Inspects HTML markup and linked JavaScript bundles with **Shannon Entropy** filtering ($H(X) = -\sum p \log_2 p$) to eliminate false positives on dummy credentials while capturing authentic API keys and secrets.
* **API Surface & Debug Exposure Detection**: Probes for exposed OpenAPI/Swagger documentation, active GraphQL introspection verification, Spring Boot actuators, environment files (`.env`), and Git metadata (`.git/HEAD`).
* **DOM Security Analysis**: Analyzes client JavaScript for DOM XSS sinks (`innerHTML`, `eval`, `document.write`) paired with unvalidated sources, as well as unvalidated `postMessage` event listeners.
* **SSRF Protection & Local Staging Mode**: Hardened against Server-Side Request Forgery with strict RFC 1918 / loopback / cloud metadata IP filtering, with a configurable Local Staging toggle for authorized dev environments.
* **Deterministic SARIF Unique Rule IDs**: Granular rule IDs (`BR-CSP-INLINE`, `BR-COOKIE-SECURE`, `BR-API-GRAPHQL-INTROSPECTION`, `BR-SECRET-ENTROPY`, etc.) preventing SAST/CI/CD deduplication collisions.
* **CyberNest VIDS PDF Audit Reports**: Generates downloadable, styled PDF audit reports bifurcating actionable first-party vulnerabilities from third-party vendor observations, complete with reproducible cURL commands.
* **Threat Intelligence & Markdown Triage Export**: Supports exporting scan findings directly into authentic **STIX 2.1** JSON bundles, **TAXII 2.1** collections, and 1-click Markdown triage summaries.

---

## Installation & Setup

### Prerequisites
* Linux (Pop!_OS, Ubuntu, Debian, Fedora, Arch) or Windows 10/11.
* Python 3.9 or higher.
* Rust toolchain (`cargo`) and Go 1.21+ (optional, for compiling binary engines).

### Quickstart

1. Navigate to the project directory:
   ```bash
   cd BlackRoute-Web-Linux_VersionPopOS
   ```

2. Compile the Rust and Go high-performance engines:
   ```bash
   ./launcher.sh build_engines
   ```

3. Launch the application:
   ```bash
   ./launcher.sh launch
   ```

---

## Usage

### Interactive Dashboard Execution

```bash
./launcher.sh launch
```

Expected Terminal Output:
```text
[INFO] Verifying virtual environment...
[INFO] Activating virtual environment...
[INFO] Dependencies verified.

==================================================
  BLACKROUTE-WEB v1.0 (CyberNest Labs) BOOTING... 
==================================================
[INIT] SQLite Threat Database Initialized.
[RECON] Resource allocated. Dashboard: http://127.0.0.1:8000
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### Standalone Release Compilation

To package BlackRoute-Web as a single-file executable using PyInstaller:
```bash
./launcher.sh build_release
```
Artifact output will be generated at `dist/BlackRoute_Web_v1.0`.

---
refer to Handofff.md
