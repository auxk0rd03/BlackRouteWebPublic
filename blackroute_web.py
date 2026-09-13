import os
import sys
import socket
import webbrowser
import threading
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.core.config import resource_path, settings
from app.core.database import init_db
from app.routes import home, api

def find_available_port(start_port: int = 8000, end_port: int = 8100) -> int:
    """Scan and return the first available local TCP port."""
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except socket.error:
                continue
    raise IOError(f"No available ports found in range {start_port}-{end_port}")

def open_browser(url: str) -> None:
    """Open default web browser after allowing server startup."""
    time.sleep(1.5)
    try:
        webbrowser.open(url)
    except Exception:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("==================================================")
    print("  BLACKROUTE-WEB v1.0 (CyberNest Labs) BOOTING... ")
    print("==================================================")
    init_db()
    print("[INIT] SQLite Threat Database Initialized.")
    yield
    print("[SHUTDOWN] BlackRoute-Web Service Terminated.")

app = FastAPI(
    title="BlackRoute-Web (CyberNest Labs)",
    version="1.0.0",
    description="Automated Web Application Attack Surface & Security Analysis Engine",
    lifespan=lifespan
)

# Mount static asset directory
app.mount("/static", StaticFiles(directory=resource_path("app/static")), name="static")

# Mount route controllers
app.include_router(home.router)
app.include_router(api.router, prefix="/api")

if __name__ == "__main__":
    port = find_available_port()
    dashboard_url = f"http://127.0.0.1:{port}"

    print(f"[RECON] Resource allocated. Dashboard: {dashboard_url}")

    # Launch browser interface asynchronously
    threading.Thread(target=open_browser, args=(dashboard_url,), daemon=True).start()

    # Launch Uvicorn
    uvicorn.run(app, host="127.0.0.1", port=port, reload=False)
