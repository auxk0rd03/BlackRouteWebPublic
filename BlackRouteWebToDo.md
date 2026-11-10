# BlackRoute Web: Enterprise ML Archival, Feature Engineering & MassExport Roadmap (`BlackRouteWebToDo.md`)

| METADATA FIELD | SPECIFICATION |
| :--- | :--- |
| **Document ID** | `CN-LABS-BRW-2026-02` (Audited & UI-Hardened Edition) |
| **Authority** | William R. M. (`Auxk0rd`) — President & Chief Architect, CyberNest Holdings LLC |
| **Department** | CyberNest Labs (Internal R&D & Security Software Department) |
| **Target System** | `NEXUS-DAST` (`BlackRoute` & `BlackRoute-Web` Loopback Lakehouse) |
| **Tech Stack** | Local-First RPGS (Rust, Python, Go, POSIX `sh`) + HTMX 2.0 (Vendored) + SQLite3 (WAL + `sqlite-vec`) + Zstandard (`zstd`) |
| **Compliance Baselines** | `CN-DIR-2026-004` (Bi-Launcher Parity), `CMMC 2.0 L2`, `GOFIPS=1` (FIPS 140-3), `CWE-377` / `CWE-114` / `CWE-78`, `OASIS SARIF v2.1.0` |
| **UI Standard** | **SYS.01 Tactical Crimson-Ledger** (Orthogonal `0px` Block Geometry, Exposed Wireframe Overhangs, Tabular Monospace `JetBrains Mono`, Zero Gradients/Shadows/CDNs, Strict Loopback `127.0.0.1`) |
| **Deployment Status** | **COMPLETE & VERIFIED (All 5 Phases & Section 7 Acceptance Criteria Passing)** |

---

## Implementation Checklist & Acceptance Criteria (`CN-LABS-BRW-2026-02`)

- [x] **Phase 1 (Dual-Path SQLite WAL Database Architecture):**
  - `db/init_db.sql` & `app/core/database.py`: WAL tuning pragmas (`journal_mode = WAL`, `synchronous = NORMAL`, `temp_store = MEMORY`, `mmap_size = 268435456`, `cache_size = -64000`, `foreign_keys = ON`) and tables `scan_sessions`, `findings_ml_hot`, `findings_evidence_cold`, and `findings_vec_index`.
- [x] **Phase 2 (32-Feature Differential Extractor & Cold Evidence Archiver):**
  - `services/feature_extractor.py` & `engines/web_spider/src/main.rs`: `BaselineProfiler`, `ReflectionAnalyzer`, `SignatureMatcher` (plus Rust Thompson NFA `RegexSet`), `StealthCurlBuilder`, and `AsyncSQLiteArchiver`.
- [x] **Phase 3 (Zero-OOM Streaming MassExport & Teacher Batch Ingestion):**
  - `routes/archive_api.py` & `routes/export.py`: `/api/v1/archive/export/stream` (`jsonl_ml`, `jsonl_teacher`, `csv_flat`, `parquet`, `sqlite_snapshot`, `sarif_bundle`, `stix_taxii`, `bounty_html`), `/api/v1/archive/export/sqlite-snapshot`, `/api/v1/archive/export/sarif-stix-bundle`, `/api/v1/archive/import/teacher-grades`, `/api/v1/archive/report/bounty-html/{scan_id}`, and `/api/v1/archive/label/{finding_id}`.
- [x] **Phase 4 (WebGUI Integration — `SYS.01` Orthogonal Geometry + BlackRoute Crimson/Black UI):**
  - `web/static/css/blackroute-synth.css`, `app/static/css/blackroute-synth.css`, `web/static/js/htmx.min.js`, `web/static/fonts/JetBrainsMono.woff2`, `web/templates/archive_console.html`, `web/templates/partials/triage_queue.html`, and HTMX routes in `app/routes/home.py`.
- [x] **Phase 5 (`CN-DIR-2026-004` POSIX & Loopback Hardening):**
  - `scripts/backup_and_sign.sh` and `scripts/sys_telemetry.sh`.
- [x] **Step 1 (Schema Migration):** `scripts/migrate_v2_archive.py` initializes `scan_sessions`, `findings_ml_hot`, `findings_evidence_cold`, and `findings_vec_index` in WAL mode.
- [x] **Step 2 (Backfill Historical SARIFs):** `scripts/backfill_sarif_dir.py --input ./reports/sarif/` parses BlackRoute SARIF/JSON files into the dual-path SQLite tables.
- [x] **Step 3 (Verify Zero-OOM Streaming):** `/api/v1/archive/export/stream?fmt=jsonl_ml` benchmarked with 100,000 synthetic rows with Python RSS memory growth strictly below `35 MB`.
- [x] **Step 4 (Verify `CN-LABS-H2C-2026-01` Loopback & UI Compliance):** Verified `127.0.0.1` loopback binding, `Content-Security-Policy: default-src 'self'`, locally vendored `htmx.min.js` / `JetBrainsMono.woff2`, `0px` border radius, `.frame-shell` wireframe overhangs, and `hx-swap-oob="true"` KPI updates on operator triage actions.
- [x] **Step 5 (End-to-End Distillation Loop Test):** Verified 1,000-row unlabeled export (`?fmt=jsonl_teacher&unlabeled_only=true`), `ForgeML` (`gemini-2.5-flash`) grading batch import (`/api/v1/archive/import/teacher-grades`), labeled dataset export (`?fmt=csv_flat&labeled_only=true`), and `host_group_bucket` split isolation (`train` `0..7`, `val` `8`, `test` `9`).
