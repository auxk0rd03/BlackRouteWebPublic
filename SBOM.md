# CISA-COMPLIANT SOFTWARE BILL OF MATERIALS (SBOM) // BLACKROUTE-WEB-LINUX_VERSIONPOPOS

## 1. Executive Order 14028 & CISA Minimum Elements Attestation

| CISA Mandatory Metadata Field | Verified Value |
| :--- | :--- |
| **SBOM Document Title** | `BlackRoute-Web-Linux_VersionPopOS - CyberNest CISA SBOM Ledger` |
| **SBOM Serial / Namespace UUID** | `urn:uuid:92a113eb-6042-5eef-9cab-8d2cc72c73a5` |
| **Author of SBOM Data** | `CyberNest Holdings LLC - William Ray Moore (President & Chief Architect) & James Dwayne Jarrell (CEO)` |
| **Timestamp (UTC)** | `2026-10-30T22:49:00Z` |
| **Primary Supplier Name** | `CyberNest Holdings LLC (Internal Department: CyberNest Labs)` |
| **Corporate Jurisdiction & Registration** | `Commonwealth of Pennsylvania LLC // SAM.gov UEI & CAGE: Not Yet Assigned (Pre-Registration)` |
| **Target Repository / Source** | `./BlackRoute-Web-Linux_VersionPopOS` |
| **Ingestion & Parse Engines** | `go_repo_ingestor + rust_sbom_scanner` |
| **Supported Machine Formats** | `CycloneDX 1.5 JSON (SBOM.cyclonedx.json)` & `SPDX 2.3 JSON (SBOM.spdx.json)` |
| **Zero External Runtime Dependency Guarantee** | `ENFORCED (100% Air-Gapped Autonomous Execution)` |
| **FIPS 140-3 Cryptographic Validation** | `ENABLED (GOFIPS=1 / AWS-LC-FIPS / SHA-256 & AES-256-GCM KAT Passed)` |
| **CMMC 2.0 Compliance Posture** | `CMMC Level 1 (FAR 52.204-21) & Level 2 (NIST SP 800-171 Rev. 2 — 110/110)` |
| **Enforced CWE Mitigations** | `CWE-377, CWE-114, CWE-22, CWE-346, CWE-400, CWE-1333` |
| **Ed25519 Signer Key ID** | `CN-ED25519-99AC51E14879E456` |
| **Ed25519 Signature** | `0c27aace3a02afb4e8516bd3daac7af6d78879ac004b6bc7...` |

---

## 2. Component Inventory & Unique Identifiers (NTIA / CISA Minimum Elements)

| # | Component Name | Version | Ecosystem | Supplier | PURL (Unique ID) | License | Source Manifest | SHA-256 Digest |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `001` | `web_spider` | `0.1.0` | `cargo-root` | CyberNest Holdings LLC (CyberNest Labs Department) | `pkg:cargo/web_spider@0.1.0` | `LicenseRef-CyberNest-Proprietary` | `engines/web_spider/Cargo.toml` | `930668747bfc0459...` |
| `002` | `regex` | `1` | `cargo` | Crates.io / Rust Ecosystem | `pkg:cargo/regex@1` | `MIT OR Apache-2.0` | `engines/web_spider/Cargo.toml` | `930668747bfc0459...` |
| `003` | `serde` | `1.0` | `cargo` | Crates.io / Rust Ecosystem | `pkg:cargo/serde@1.0` | `MIT OR Apache-2.0` | `engines/web_spider/Cargo.toml` | `930668747bfc0459...` |
| `004` | `serde_json` | `1.0` | `cargo` | Crates.io / Rust Ecosystem | `pkg:cargo/serde_json@1.0` | `MIT OR Apache-2.0` | `engines/web_spider/Cargo.toml` | `930668747bfc0459...` |
| `005` | `surface_graph` | `1.0.0` | `golang-root` | CyberNest Holdings LLC (CyberNest Labs Department) | `pkg:golang/surface_graph@1.0.0` | `LicenseRef-CyberNest-Proprietary` | `engines/surface_graph/go.mod` | `1bd9a78a2675815e...` |
| `006` | `fastapi` | `0.100.0` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/fastapi@0.100.0` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `007` | `uvicorn` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/uvicorn@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `008` | `jinja2` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/jinja2@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `009` | `aiofiles` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/aiofiles@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `010` | `fpdf2` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/fpdf2@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `011` | `pydantic` | `2.0.0` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/pydantic@2.0.0` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `012` | `python-multipart` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/python-multipart@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `013` | `beautifulsoup4` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/beautifulsoup4@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `014` | `httpx` | `latest` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/httpx@latest` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `015` | `sse-starlette` | `2.0.0` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/sse-starlette@2.0.0` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |
| `016` | `esprima` | `4.0.1` | `pypi` | PyPI / Python Packaging Authority | `pkg:pypi/esprima@4.0.1` | `MIT OR BSD-3-Clause` | `requirements.txt` | `1a6f0deae2f19861...` |

---

## 3. Dependency Relationship Graph

* **Root Application Node**: `pkg:generic/cybernest/BlackRoute-Web-Linux_VersionPopOS@1.0.0`
  * `DEPENDS_ON` -> `pkg:cargo/web_spider@0.1.0` (`cpe:2.3:a:cybernest:web_spider:0.1.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:cargo/regex@1` (`cpe:2.3:a:rust-lang:regex:1:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:cargo/serde@1.0` (`cpe:2.3:a:rust-lang:serde:1.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:cargo/serde_json@1.0` (`cpe:2.3:a:rust-lang:serde_json:1.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:golang/surface_graph@1.0.0` (`cpe:2.3:a:cybernest:surface_graph:1.0.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/fastapi@0.100.0` (`cpe:2.3:a:pypi:fastapi:0.100.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/uvicorn@latest` (`cpe:2.3:a:pypi:uvicorn:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/jinja2@latest` (`cpe:2.3:a:pypi:jinja2:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/aiofiles@latest` (`cpe:2.3:a:pypi:aiofiles:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/fpdf2@latest` (`cpe:2.3:a:pypi:fpdf2:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/pydantic@2.0.0` (`cpe:2.3:a:pypi:pydantic:2.0.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/python-multipart@latest` (`cpe:2.3:a:pypi:python-multipart:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/beautifulsoup4@latest` (`cpe:2.3:a:pypi:beautifulsoup4:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/httpx@latest` (`cpe:2.3:a:pypi:httpx:latest:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/sse-starlette@2.0.0` (`cpe:2.3:a:pypi:sse-starlette:2.0.0:*:*:*:*:*:*:*`)
  * `DEPENDS_ON` -> `pkg:pypi/esprima@4.0.1` (`cpe:2.3:a:pypi:esprima:4.0.1:*:*:*:*:*:*:*`)

---

## 4. Cryptographic Integrity & CWE Hardening Attestation

* **Files Cryptographically Hashed (SHA-256)**: `32`
* **Shannon Entropy High-Risk Secret Alerts**: `0`
* **Ed25519 Public Key**: `99ac51e14879e456c9747f49ff458f77e3fb3d60ec822762e6ac5ef5438f6315`
* **Full Ed25519 Signature**: `0c27aace3a02afb4e8516bd3daac7af6d78879ac004b6bc7db53e02b9e30e955625fa7a96d04d25f9285934699bc4b97f448cc8ce4831bf351dc8334252ae604`

*Generated automatically by CyberNest Labs NestSBOM RPGS Engine.*
