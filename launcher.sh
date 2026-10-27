#!/usr/bin/env bash
# BlackRoute-Web Unified Linux Launcher & Build Protocol
# CyberNest Labs - Enterprise Web Application Security Engine

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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
        source "$VENV_DIR/bin/activate"
        if [ "$VIRTUAL_ENV" != "$VENV_DIR" ] || [ "$(command -v python || true)" != "$VENV_PYTHON" ]; then
            echo "[WARN] Virtual environment path mismatch (directory moved). Recreating..."
            need_create=1
        fi
    fi

    if [ "$need_create" -eq 1 ]; then
        echo "[INFO] Initializing virtual environment (.venv)..."
        rm -rf "$VENV_DIR"
        $PYTHON_BIN -m venv "$VENV_DIR"
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

run_application() {
    setup_venv
    echo ""
    echo "=================================================="
    echo "     BLACKROUTE-WEB - MISSION CONTROL LAUNCH"
    echo "=================================================="
    echo "[INFO] Launching BlackRoute-Web Server..."
    echo ""
    "$VENV_PYTHON" blackroute_web.py
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
            if cargo build --release --offline --manifest-path "$spider_dir/Cargo.toml" 2>&1 | while IFS= read -r line; do echo "  [CARGO] $line"; done; then
                local target_bin="$spider_dir/target/release/web_spider"
                if [ -f "$target_bin" ]; then
                    cp "$target_bin" "$BIN_DIR/web_spider"
                    chmod +x "$BIN_DIR/web_spider"
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
            echo "[BUILD] Compiling Go Engine: surface_graph..."
            if (cd "$graph_dir" && go build -o "$BIN_DIR/surface_graph" -ldflags="-s -w" .) 2>&1 | while IFS= read -r line; do echo "  [GO] $line"; done; then
                if [ -f "$BIN_DIR/surface_graph" ]; then
                    chmod +x "$BIN_DIR/surface_graph"
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

    echo ""
    echo "=================================================="
    echo "  ENGINE BUILD COMPLETE: Rust: $RUST_COUNT | Go: $GO_COUNT"
    echo "=================================================="
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
    if [ $# -gt 0 ]; then
        "$VENV_PYTHON" -m unittest "$@"
    else
        "$VENV_PYTHON" -m unittest discover -s tests -v
    fi
}

case "$1" in
    launch|run)
        run_application
        ;;
    build_engines)
        build_engines
        ;;
    build_release)
        build_release
        ;;
    test|tests)
        shift
        run_tests "$@"
        ;;
    *)
        echo "=================================================="
        echo "     CYBERNEST LABS: BLACKROUTE-WEB v1.0"
        echo "=================================================="
        echo "Options:"
        echo "  [1] Launch Mission Control Dashboard"
        echo "  [2] Compile Polyglot Engines (Rust + Go)"
        echo "  [3] Build Standalone Linux Executable (PyInstaller)"
        echo "  [4] Run Automated Test Suite (.venv)"
        echo "  [5] Exit"
        echo "=================================================="
        read -p "Select option [1-5]: " choice
        case "$choice" in
            1) run_application ;;
            2) build_engines ;;
            3) build_release ;;
            4) run_tests ;;
            *) exit 0 ;;
        esac
        ;;
esac
