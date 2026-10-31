#!/usr/bin/env bash
# ==============================================================================
# BlackRoute-Web Unified Linux Orchestrator (dev.sh / launcher.sh)
# CyberNest Labs — Standard 004 (CN-DIR-2026-004): Dual-Native Orchestration
# Hardened for CWE-377 (Symlink defense, umask 077, 0700/0600 permissions),
# CWE-114 (Explicit APP_PID tracking, zero fuser -k), FIPS 140-3 (GOFIPS=1),
# SUDO Cache Preservation, and Automated CycloneDX 1.5 & SPDX 2.3 SBOMs.
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# 1. SUDO User Cache & Toolchain Preservation (CN-DIR-2026-004 Section 2.1)
# ------------------------------------------------------------------------------
if [ -n "${SUDO_USER:-}" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
else
    REAL_USER="$(whoami)"
    REAL_HOME="$HOME"
fi

export CARGO_HOME="${CARGO_HOME:-$REAL_HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$REAL_HOME/.rustup}"
export GOPATH="${GOPATH:-$REAL_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"
export GOCACHE="${GOCACHE:-$REAL_HOME/.cache/go-build}"
export PATH="$CARGO_HOME/bin:$GOPATH/bin:/usr/local/go/bin:$PATH"

# ------------------------------------------------------------------------------
# 2. CWE-377 Symlink-Hardened User-Scoped Telemetry & Logging
# ------------------------------------------------------------------------------
APP_PID=""
LOG_DIR="${REAL_HOME}/.cache/blackroute_web"
mkdir -p -m 700 "$LOG_DIR"
chmod 700 "$LOG_DIR"
LOG_FILE="${LOG_DIR}/session.log"
[ -L "$LOG_FILE" ] && rm -f "$LOG_FILE"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# ------------------------------------------------------------------------------
# 3. CWE-114 Deterministic Process Lifecycle & Cleanup Trap
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
        kill -TERM "$APP_PID" 2>/dev/null || true
        sleep 0.2
        kill -KILL "$APP_PID" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo "[ERROR] Python 3 installation not found in PATH."
    exit 1
fi

VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

setup_venv() {
    echo "[INFO] Verifying virtual environment..."
    local need_create=0

    if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/activate" ] || [ ! -f "$VENV_PYTHON" ]; then
        need_create=1
    elif ! "$VENV_PYTHON" -c "import sys" &>/dev/null; then
        echo "[WARN] Existing virtual environment is invalid. Recreating..."
        need_create=1
    else
        # shellcheck disable=SC1091
        source "$VENV_DIR/bin/activate"
        if [ "${VIRTUAL_ENV:-}" != "$VENV_DIR" ] || [ "$(command -v python || true)" != "$VENV_PYTHON" ]; then
            echo "[WARN] Virtual environment path mismatch (directory moved). Recreating..."
            need_create=1
        fi
    fi

    if [ "$need_create" -eq 1 ]; then
        echo "[INFO] Initializing virtual environment (.venv)..."
        rm -rf "$VENV_DIR"
        "$PYTHON_BIN" -m venv "$VENV_DIR"
        # shellcheck disable=SC1091
        source "$VENV_DIR/bin/activate"
    fi

    echo "[INFO] Checking dependencies..."
    if ! "$VENV_PYTHON" -c "import fastapi, uvicorn, jinja2, aiofiles, fpdf, pydantic, multipart, bs4, httpx" &>/dev/null; then
        echo "[INFO] Installing dependencies from requirements.txt..."
        "$VENV_PYTHON" -m pip install -q --upgrade pip || true
        "$VENV_PYTHON" -m pip install -q -r requirements.txt
    else
        echo "[INFO] Dependencies verified."
    fi
}

setup_all() {
    echo "=================================================="
    echo "  BLACKROUTE-WEB - TOOLCHAIN & ENVIRONMENT SETUP"
    echo "=================================================="
    echo "[INFO] Active User: $REAL_USER ($REAL_HOME)"
    echo "[INFO] Python Binary: $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"
    if command -v cargo &>/dev/null; then
        echo "[INFO] Rust Toolchain: $(rustc --version 2>&1)"
    else
        echo "[WARN] Rust Toolchain (cargo) not detected; Python fallback active."
    fi
    if command -v go &>/dev/null; then
        echo "[INFO] Go Toolchain: $(go version 2>&1)"
    else
        echo "[WARN] Go Toolchain (go) not detected; Python fallback active."
    fi
    setup_venv
    chmod 700 "$SCRIPT_DIR/launcher.sh" 2>/dev/null || true
    chmod 700 "$SCRIPT_DIR/dev.sh" 2>/dev/null || true
    echo "[SUCCESS] Setup complete. Log file: $LOG_FILE"
}

build_engines() {
    echo ""
    echo "=================================================="
    echo "  BLACKROUTE-WEB - COMPILED ENGINE BUILD PROTOCOL"
    echo "=================================================="
    echo ""

    local BIN_DIR="$SCRIPT_DIR/bin"
    mkdir -p "$BIN_DIR"

    local ENGINES_DIR="$SCRIPT_DIR/engines"
    local RUST_COUNT=0
    local GO_COUNT=0

    # 1. Compile Rust web_spider Engine
    if command -v cargo &>/dev/null; then
        local rust_version
        rust_version=$(rustc --version 2>&1)
        echo "[INFO] Rust compiler detected: $rust_version"
        local spider_dir="$ENGINES_DIR/web_spider"

        if [ -f "$spider_dir/Cargo.toml" ]; then
            echo "[BUILD] Compiling Rust Engine: web_spider..."
            if RUSTFLAGS="--remap-path-prefix=${SCRIPT_DIR}=. --remap-path-prefix=${REAL_HOME}=~" cargo build --release --offline --manifest-path "$spider_dir/Cargo.toml" 2>&1 | while IFS= read -r line; do echo "  [CARGO] $line"; done; then
                local target_bin="$spider_dir/target/release/web_spider"
                if [ -f "$target_bin" ]; then
                    cp "$target_bin" "$BIN_DIR/web_spider"
                    strip --strip-all "$BIN_DIR/web_spider" 2>/dev/null || true
                    chmod 700 "$BIN_DIR/web_spider"
                    echo "[SUCCESS] web_spider -> bin/web_spider"
                    RUST_COUNT=$((RUST_COUNT + 1))
                else
                    echo "[ERROR] Binary not found at $target_bin"
                fi
            else
                echo "[ERROR] Cargo build failed for web_spider."
            fi
        fi
    else
        echo "[WARN] Cargo not detected. Rust engine build skipped."
    fi

    # 2. Compile Go surface_graph Engine
    if command -v go &>/dev/null; then
        local go_version
        go_version=$(go version 2>&1)
        echo ""
        echo "[INFO] Go compiler detected: $go_version"
        local graph_dir="$ENGINES_DIR/surface_graph"

        if [ -f "$graph_dir/go.mod" ]; then
            echo "[BUILD] Compiling Go Engine: surface_graph (GOFIPS=1)..."
            if (cd "$graph_dir" && GOFIPS=1 GODEBUG=fips140=on CGO_ENABLED=0 go build -trimpath -o "$BIN_DIR/surface_graph" -ldflags="-s -w" .) 2>&1 | while IFS= read -r line; do echo "  [GO] $line"; done; then
                if [ -f "$BIN_DIR/surface_graph" ]; then
                    chmod 700 "$BIN_DIR/surface_graph"
                    echo "[SUCCESS] surface_graph -> bin/surface_graph"
                    GO_COUNT=$((GO_COUNT + 1))
                fi
            else
                echo "[ERROR] Go build failed for surface_graph."
            fi
        fi
    else
        echo "[WARN] Go compiler not detected. Go engine build skipped."
    fi

    # 3. Automated CycloneDX & SPDX JSON SBOM Generation
    if [ -f "$SCRIPT_DIR/../NestSBOM/sbom_cli.py" ]; then
        echo "[SBOM] Generating CycloneDX 1.5, SPDX 2.3 & CISA SBOM manifests..."
        "$PYTHON_BIN" "$SCRIPT_DIR/../NestSBOM/sbom_cli.py" --repo "$SCRIPT_DIR" --out-dir "$SCRIPT_DIR" >/dev/null
        sed -i "s|${SCRIPT_DIR}|https://github.com/auxk0rd03/BlackRouteWebPublic.git|g" "$SCRIPT_DIR/SBOM.md" 2>/dev/null || true
    fi

    echo ""
    echo "=================================================="
    echo "  ENGINE BUILD COMPLETE: Rust: $RUST_COUNT | Go: $GO_COUNT"
    echo "=================================================="
}

run_application() {
    setup_venv
    if [ ! -f "$SCRIPT_DIR/bin/web_spider" ] || [ ! -f "$SCRIPT_DIR/bin/surface_graph" ]; then
        build_engines
    fi
    echo ""
    echo "=================================================="
    echo "     BLACKROUTE-WEB - MISSION CONTROL LAUNCH"
    echo "=================================================="
    echo "[INFO] Launching BlackRoute-Web Server..."
    echo ""
    export GOFIPS=1
    export GODEBUG=fips140=on
    "$VENV_PYTHON" blackroute_web.py "$@" &
    APP_PID=$!
    wait "$APP_PID"
}

run_cli_mode() {
    setup_venv
    if [ ! -f "$SCRIPT_DIR/bin/web_spider" ] || [ ! -f "$SCRIPT_DIR/bin/surface_graph" ]; then
        build_engines >/dev/null 2>&1 || true
    fi
    export GOFIPS=1
    export GODEBUG=fips140=on
    "$VENV_PYTHON" blackroute_web.py --cli "$@"
}

run_simulate_mode() {
    setup_venv
    if [ ! -f "$SCRIPT_DIR/bin/web_spider" ] || [ ! -f "$SCRIPT_DIR/bin/surface_graph" ]; then
        build_engines >/dev/null 2>&1 || true
    fi
    export GOFIPS=1
    export GODEBUG=fips140=on
    "$VENV_PYTHON" blackroute_web.py --cli --simulate --export "$@"
}

build_release() {
    setup_venv
    build_engines
    echo ""
    echo "=================================================="
    echo "    BLACKROUTE-WEB - LINUX RELEASE PACKAGING"
    echo "=================================================="
    "$VENV_PYTHON" -m pip install -q pyinstaller

    "$VENV_DIR/bin/pyinstaller" --noconfirm --onefile --clean --name "BlackRoute_Web_v1.0" \
        --add-data "app/templates:app/templates" \
        --add-data "app/static:app/static" \
        --add-data "bin:bin" \
        --hidden-import=uvicorn.logging \
        --hidden-import=uvicorn.loops \
        --hidden-import=uvicorn.loops.auto \
        --hidden-import=uvicorn.protocols \
        --hidden-import=uvicorn.protocols.http \
        --hidden-import=uvicorn.protocols.http.auto \
        --hidden-import=uvicorn.lifespan \
        --hidden-import=uvicorn.lifespan.on \
        blackroute_web.py

    echo ""
    echo "=================================================="
    echo "[SUCCESS] ARTIFACT LOCATION: dist/BlackRoute_Web_v1.0"
    echo "=================================================="
}

run_tests() {
    setup_venv
    echo ""
    echo "=================================================="
    echo "     BLACKROUTE-WEB - AUTOMATED TEST SUITE"
    echo "=================================================="
    if command -v go &>/dev/null && [ -f "$SCRIPT_DIR/engines/surface_graph/go.mod" ]; then
        echo "[TEST] Running Go surface_graph unit tests..."
        (cd "$SCRIPT_DIR/engines/surface_graph" && GOFIPS=1 GODEBUG=fips140=on go test -v ./...)
    fi
    if command -v cargo &>/dev/null && [ -f "$SCRIPT_DIR/engines/web_spider/Cargo.toml" ]; then
        echo "[TEST] Running Rust web_spider unit tests..."
        (cd "$SCRIPT_DIR/engines/web_spider" && cargo test --offline)
    fi
    echo "[TEST] Running Python unittest suite..."
    if [ $# -gt 0 ]; then
        "$VENV_PYTHON" -m unittest "$@"
    else
        "$VENV_PYTHON" -m unittest discover -s tests -v
    fi
}

run_fmt() {
    echo "=================================================="
    echo "     BLACKROUTE-WEB - POLYGLOT CODE FORMATTER"
    echo "=================================================="
    if command -v go &>/dev/null && [ -d "$SCRIPT_DIR/engines/surface_graph" ]; then
        echo "[FMT] Formatting Go surface_graph engine..."
        (cd "$SCRIPT_DIR/engines/surface_graph" && go fmt ./...)
    fi
    if command -v cargo &>/dev/null && [ -f "$SCRIPT_DIR/engines/web_spider/Cargo.toml" ]; then
        echo "[FMT] Formatting Rust web_spider engine..."
        (cd "$SCRIPT_DIR/engines/web_spider" && cargo fmt --all 2>/dev/null || true)
    fi
    echo "[SUCCESS] Code formatting complete."
}

case "${1:-run}" in
    setup)
        setup_all
        ;;
    build|build_engines)
        build_engines
        ;;
    launch|run|serve)
        shift || true
        run_application "$@"
        ;;
    cli)
        shift || true
        run_cli_mode "$@"
        ;;
    simulate)
        shift || true
        run_simulate_mode "$@"
        ;;
    build_release)
        build_release
        ;;
    test|tests)
        shift || true
        run_tests "$@"
        ;;
    fmt)
        run_fmt
        ;;
    --menu|menu)
        echo "=================================================="
        echo "     CYBERNEST LABS: BLACKROUTE-WEB v1.0"
        echo "=================================================="
        echo "Options:"
        echo "  [1] Launch Mission Control Dashboard (run/serve)"
        echo "  [2] Compile Polyglot Engines (build)"
        echo "  [3] Run CLI Diagnostic Audit (cli)"
        echo "  [4] Run Fault-Injection Simulation (simulate)"
        echo "  [5] Run Automated Test Suite (test)"
        echo "  [6] Build Standalone Linux Executable (build_release)"
        echo "  [7] Exit"
        echo "=================================================="
        read -r -p "Select option [1-7]: " choice
        case "$choice" in
            1) run_application ;;
            2) build_engines ;;
            3) run_cli_mode ;;
            4) run_simulate_mode ;;
            5) run_tests ;;
            6) build_release ;;
            *) exit 0 ;;
        esac
        ;;
    help|--help|-h)
        echo "Usage: ./dev.sh [setup|build|run|serve|cli|simulate|test|fmt|build_release]"
        ;;
    *)
        run_application "$@"
        ;;
esac
