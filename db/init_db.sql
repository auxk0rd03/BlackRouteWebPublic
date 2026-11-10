-- =============================================================================
-- BlackRoute-Web Dual-Path SQLite WAL Lakehouse Schema (db/init_db.sql)
-- Document ID: CN-LABS-BRW-2026-02
-- =============================================================================

-- 2.1 Engine Tuning Pragmas
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456; -- 256MB memory-mapped I/O
PRAGMA cache_size = -64000;   -- 64MB page cache
PRAGMA foreign_keys = ON;

-- 2.2 Table 1: scan_sessions (Scan-Level Metadata & Target Baseline)
CREATE TABLE IF NOT EXISTS scan_sessions (
    scan_id TEXT PRIMARY KEY,                  -- UUIDv4 or ULID
    target_root_url TEXT NOT NULL,
    target_host_hash TEXT NOT NULL,            -- SHA256(normalized_host) for GroupKFold split isolation
    scan_profile TEXT NOT NULL,                -- e.g., 'stealth_bounty', 'full_dast', 'api_fuzz'
    scanner_version TEXT NOT NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    total_requests_sent INTEGER DEFAULT 0,
    total_findings_raw INTEGER DEFAULT 0,
    baseline_latency_mean_ms REAL DEFAULT 0.0, -- Target's normal response time mean
    baseline_latency_std_ms REAL DEFAULT 1.0,  -- Target's normal response time std dev
    baseline_404_length INTEGER DEFAULT 0,     -- Byte length of target's standard soft-404 page
    baseline_404_simhash INTEGER DEFAULT 0,    -- 64-bit SimHash of target's soft-404 DOM structure
    detected_waf_vendor TEXT DEFAULT 'NONE',   -- 'CLOUDFLARE', 'AKAMAI', 'AWS_WAF', 'IMPERVA', 'NONE'
    raw_sarif_path TEXT                        -- Local path to preserved legacy SARIF file
);

CREATE INDEX IF NOT EXISTS idx_sessions_host_hash ON scan_sessions(target_host_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON scan_sessions(started_at);

-- 2.3 Table 2: findings_ml_hot (32-Feature Hot Table for Training & UI)
CREATE TABLE IF NOT EXISTS findings_ml_hot (
    finding_id TEXT PRIMARY KEY,                   -- ULID (time-sortable unique ID)
    scan_id TEXT NOT NULL REFERENCES scan_sessions(scan_id) ON DELETE CASCADE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    -- Deduplication & Grouping Hashes
    exact_dedup_hash TEXT NOT NULL,                -- SHA256(host + norm_path + rule_id + param_name + injection_point)
    fuzzy_behavior_hash TEXT NOT NULL,             -- SHA256(rule_id + http_status + reflection_context + dom_simhash_bucket)
    host_group_bucket INTEGER NOT NULL,            -- ABS(HASH(host)) % 10 (0-7=Train, 8=Val, 9=Test to prevent target leakage)
    occurrence_count INTEGER DEFAULT 1,            -- Incremented when exact_dedup_hash repeats across scans

    -- Core Rule & Endpoint Categorical Features
    rule_id TEXT NOT NULL,                         -- e.g., 'SQLI_ERR_01', 'XSS_DOM_02', 'SSRF_METADATA'
    cwe_id INTEGER NOT NULL DEFAULT 0,             -- Numeric CWE (e.g., 89 for SQLi, 79 for XSS)
    severity_scanner INTEGER NOT NULL,             -- 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
    http_method_id INTEGER NOT NULL,               -- 1=GET, 2=POST, 3=PUT, 4=DELETE, 5=PATCH, 6=OPTIONS
    injection_point_id INTEGER NOT NULL,           -- 1=Query, 2=BodyForm, 3=BodyJSON, 4=Header, 5=Cookie, 6=Path, 7=GraphQL
    endpoint_depth INTEGER NOT NULL,               -- Count of '/' segments in URL path
    is_authenticated_ctx INTEGER NOT NULL DEFAULT 0, -- 1 if scan request carried active session/bearer auth

    -- Baseline vs. Mutated Differential Features (Crucial for False-Positive Filtering)
    http_status_code INTEGER NOT NULL,             -- Mutated response status (200, 403, 500, etc.)
    baseline_status_code INTEGER NOT NULL,         -- Unmutated baseline status code
    status_code_changed INTEGER NOT NULL,          -- 1 if http_status_code != baseline_status_code
    response_length_bytes INTEGER NOT NULL,        -- Raw byte length of mutated response body
    response_length_delta INTEGER NOT NULL,        -- (mutated_bytes - baseline_bytes)
    response_length_ratio REAL NOT NULL,           -- mutated_bytes / MAX(baseline_bytes, 1)
    word_count_delta INTEGER NOT NULL,             -- Delta in whitespace-delimited tokens
    line_count_delta INTEGER NOT NULL,             -- Delta in newline count
    dom_structural_similarity REAL NOT NULL,       -- 0.0 to 1.0 SimHash/Jaccard similarity between baseline & mutated HTML tags
    soft_404_similarity REAL NOT NULL,             -- 0.0 to 1.0 similarity to target's known soft-404 page

    -- Timing & Jitter Features (Catches False-Positive Time-Based Blind Bugs)
    response_time_ms REAL NOT NULL,                -- Mutated request round-trip time in ms
    response_time_delta_ms REAL NOT NULL,          -- (mutated_ms - baseline_latency_mean_ms)
    response_time_zscore REAL NOT NULL,            -- (mutated_ms - baseline_mean) / MAX(baseline_std, 1.0)

    -- Entropy & Content-Type Features
    body_shannon_entropy REAL NOT NULL,            -- 0.0 to 8.0 Shannon entropy of response body
    entropy_delta REAL NOT NULL,                   -- (mutated_entropy - baseline_entropy)
    content_type_id INTEGER NOT NULL,              -- 1=HTML, 2=JSON, 3=XML, 4=Plain, 5=Octet/Binary, 6=Other
    content_type_mismatch INTEGER NOT NULL,        -- 1 if declared Content-Type header contradicts actual body magic bytes

    -- Payload & Contextual Reflection Features
    payload_length INTEGER NOT NULL,               -- Length of injected test payload
    payload_entropy REAL NOT NULL,                 -- Entropy of injected payload
    reflection_count INTEGER NOT NULL,             -- Exact count of canary/payload reflections in body/headers
    reflection_context_id INTEGER NOT NULL,        -- 0=None, 1=HTML_Body, 2=HTML_Attr_Quoted, 3=HTML_Attr_Unquoted, 4=Script_Tag, 5=Comment, 6=JSON_Val, 7=Header
    special_chars_preserved_ratio REAL NOT NULL,   -- 0.0 to 1.0 ratio of injected '<>"'();' chars returned unescaped

    -- Deterministic Heuristic Bitmask Flags (Bridges Text-to-Tabular Gap for LightGBM)
    has_sql_error_sig INTEGER NOT NULL DEFAULT 0,      -- 1 if regex matches DBMS syntax/driver errors
    has_stack_trace_sig INTEGER NOT NULL DEFAULT 0,    -- 1 if Python/Java/Node/.NET/PHP stack trace present
    has_os_cmd_sig INTEGER NOT NULL DEFAULT 0,         -- 1 if uid=, root:x:0:0, Windows IP Configuration, etc. present
    has_ssrf_cloud_sig INTEGER NOT NULL DEFAULT 0,     -- 1 if 169.254.169.254 / IAM role / metadata keys present
    has_waf_block_sig INTEGER NOT NULL DEFAULT 0,      -- 1 if WAF block page signature or challenge detected
    redirected_to_login INTEGER NOT NULL DEFAULT 0,    -- 1 if Location header redirects to /login, /auth, /sso

    -- Ground-Truth Labeling, Provenance & Active Learning State
    ground_truth_label INTEGER DEFAULT NULL,       -- NULL=Unlabeled, 0=False Positive, 1=True Positive
    label_source INTEGER NOT NULL DEFAULT 0,       -- 0=Unlabeled, 1=Heuristic_Auto, 2=Gemini_Teacher, 3=Human_Operator, 4=Exploit_Verified
    teacher_confidence REAL DEFAULT NULL,          -- 0.0 to 1.0 confidence from Gemini Teacher API
    teacher_model_ver TEXT DEFAULT NULL,           -- Teacher model version (e.g., gemini-2.5-flash)
    student_pred_prob REAL DEFAULT NULL,           -- 0.0 to 1.0 local ONNX model probability
    disagreement_score REAL DEFAULT 0.0,           -- ABS(teacher_confidence_signed - student_pred_prob) for Active Learning sorting
    needs_human_review INTEGER DEFAULT 0           -- 1 if queued in HTMX Triage Review UI
);

CREATE INDEX IF NOT EXISTS idx_hot_dedup ON findings_ml_hot(exact_dedup_hash);
CREATE INDEX IF NOT EXISTS idx_hot_rule ON findings_ml_hot(rule_id);
CREATE INDEX IF NOT EXISTS idx_hot_label ON findings_ml_hot(ground_truth_label, label_source);
CREATE INDEX IF NOT EXISTS idx_hot_review ON findings_ml_hot(needs_human_review, disagreement_score DESC);
CREATE INDEX IF NOT EXISTS idx_hot_split ON findings_ml_hot(host_group_bucket);

-- 2.4 Table 3: findings_evidence_cold (Zstandard Compressed Payloads & Snippets)
CREATE TABLE IF NOT EXISTS findings_evidence_cold (
    finding_id TEXT PRIMARY KEY REFERENCES findings_ml_hot(finding_id) ON DELETE CASCADE,
    target_endpoint_raw TEXT NOT NULL,             -- Full URL (can be scrubbed on export)
    vulnerable_parameter TEXT,                     -- Parameter name
    injected_payload_raw TEXT,                     -- Exact payload string
    stealth_curl_command TEXT NOT NULL,            -- Ready-to-run stealth curl command for bug bounty reproduction
    zstd_Http_exchange BLOB NOT NULL,              -- Zstandard-compressed JSON: {baseline_req, baseline_resp, mutated_req, mutated_resp_snippet}
    request_raw_zstd BLOB,                         -- Optional Zstandard-compressed raw HTTP request
    response_raw_zstd BLOB,                        -- Optional Zstandard-compressed raw HTTP response
    reflection_snippet_raw TEXT,                   -- Optional raw reflection window
    sanitized_snippet_teacher TEXT NOT NULL,       -- PII/IP-scrubbed 1.5KB snippet ready for Gemini Teacher API
    teacher_reasoning TEXT,                        -- 1-sentence technical explanation from Gemini or Operator notes
    stix_bundle_json TEXT                          -- Cached STIX 2.1 indicator/vulnerability object
);

-- 2.5 Table 4: findings_vec_index (sqlite-vec Virtual Table for Novelty Detection)
CREATE VIRTUAL TABLE IF NOT EXISTS findings_vec_index USING vec0(
    finding_id TEXT PRIMARY KEY,
    response_embedding FLOAT[384]                  -- Generated via local MiniLM / FastEmbed / Ollama
);
