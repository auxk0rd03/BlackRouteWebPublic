# BlackRoute-Web

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](https://kernel.org)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
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
├── blackroute_web.py             # Server entrypoint and dynamic port allocation launcher
├── launcher.sh                   # Unified Linux launcher, venv manager, engine compiler
├── launcher.bat                  # Unified Windows CLI launcher
└── requirements.txt              # Python library dependencies
```

---

## Features and Capabilities

* **Polyglot Compiled Performance (Rust & Go)**: Critical asset parsing and route extraction routines are executed via a compiled Rust engine using linear-time Thompson NFA regexes. Surface topology graph construction and tech fingerprinting run in Go goroutines. Both feature seamless Python fallbacks.
* **SOC-Friendly Stealth Protocol & Evasion**: Engineered to prevent alarm fatigue and false positives on client perimeters. Uses realistic modern Chrome 124 browser personas with full L7 Client Hints (`Sec-Ch-Ua`, `Sec-Fetch-*`), benign dynamic CORS origin reflection tests (no `evil` tags), Semaphore concurrency limits, and randomized request jitter (250ms–750ms).
* **Dual Scan Profiles (Stealth vs. Active)**: Defaults to low-noise Stealth Mode (suppressing noisy `/.env` and `/.git` probes) during passive posture audits, with an explicit toggle for Active Verification when intrusive probing is authorized.
* **WAF & Rate-Limit Circuit Breaker**: Detects HTTP 429 rate-limiting and WAF block signatures (Cloudflare, AWS WAF, Akamai), automatically halting active probes and backing off to avoid escalating SOC incident severity.
* **Authorized Engagement Whitelisting**: Injects optional `X-Security-Engagement` and `X-Authorized-Audit` headers, allowing client SIEM correlation rules to automatically classify audit traffic as authorized.
* **Deep Transport & Header Posture Auditing**: Evaluates Content Security Policy (CSP), Strict-Transport-Security (HSTS), CORS origin reflection, X-Frame-Options (Clickjacking), X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
* **Session & Cookie Hygiene**: Audits all `Set-Cookie` directives for `Secure`, `HttpOnly`, and `SameSite` compliance.
* **Client-Side Secret & Token Leakage**: Inspects HTML markup and linked JavaScript bundles with **Shannon Entropy** filtering ($H(X) = -\sum p \log_2 p$) to eliminate false positives on dummy credentials while capturing authentic API keys and secrets.
* **API Surface & Debug Exposure Detection**: Probes for exposed OpenAPI/Swagger documentation, GraphQL introspection, Spring Boot actuators, environment files (`.env`), and Git metadata (`.git/HEAD`).
* **DOM Security Analysis**: Analyzes client JavaScript for DOM XSS sinks (`innerHTML`, `eval`, `document.write`) paired with unvalidated sources, as well as unvalidated `postMessage` event listeners.
* **SSRF Protection & Local Staging Mode**: Hardened against Server-Side Request Forgery with strict RFC 1918 / loopback / cloud metadata IP filtering, with a configurable Local Staging toggle for authorized dev environments.
* **CyberNest VIDS PDF Audit Reports**: Generates downloadable, styled PDF audit reports detailing findings, threat distribution, evidence, and reproducible cURL PoC commands.
* **Threat Intelligence Export**: Supports exporting scan findings directly into authentic **STIX 2.1** JSON bundles and **TAXII 2.1** collection envelopes.

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

## License

This project is licensed under the MIT License.
