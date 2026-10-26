# ==============================================================================
# CyberNest Labs: BlackRoute-Web Multi-Stage Production Container
# Stage 1: Build polyglot compiled engines (Rust web_spider & Go surface_graph)
# Stage 2: Minimal hardened Python 3.12 runtime
# ==============================================================================

# --- STAGE 1: Polyglot Engine Compiler ---
FROM golang:1.22-bookworm AS builder

# Install Rust toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential ca-certificates && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy engine sources
COPY engines/web_spider engines/web_spider
COPY engines/surface_graph engines/surface_graph

# Compile Rust engine with optimizations
WORKDIR /build/engines/web_spider
RUN cargo build --release

# Compile Go engine with symbol stripping
WORKDIR /build/engines/surface_graph
RUN go build -o /build/bin/surface_graph -ldflags="-s -w" .

RUN mkdir -p /build/bin && \
    cp /build/engines/web_spider/target/release/web_spider /build/bin/web_spider && \
    chmod +x /build/bin/*

# --- STAGE 2: Hardened Runtime Container ---
FROM python:3.12-slim AS runtime

LABEL maintainer="CyberNest Labs <labs@cybernest.internal>"
LABEL description="BlackRoute-Web: Enterprise Web Application DAST & Attack Surface Auditing Engine"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install runtime system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy compiled polyglot engine binaries from Stage 1
COPY --from=builder /build/bin /app/bin

# Copy application source code and assets
COPY app /app/app
COPY Sources /app/Sources
COPY blackroute_web.py /app/blackroute_web.py
COPY CyberNestLabsLogo.png /app/CyberNestLabsLogo.png

# Create non-root user and assign strict sandbox permissions
RUN useradd -m -u 1000 -s /usr/sbin/nologin cybernest && \
    mkdir -p /app/app/static /app/data /app/Output && \
    chown -R cybernest:cybernest /app && \
    chmod 550 /app/bin/*

USER cybernest

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/api/status || exit 1

ENTRYPOINT ["uvicorn", "blackroute_web:app", "--host", "0.0.0.0", "--port", "8000"]
