import hashlib
import html
import ipaddress
import os
import socket
import urllib.parse
from pathlib import Path
from typing import Optional

def normalize_target_url(raw: str) -> str:
    """Normalize user input to a canonical HTTP/HTTPS URL."""
    clean = (raw or "").strip()
    if not clean:
        return clean

    # Strip surrounding quotes
    if (clean.startswith('"') and clean.endswith('"')) or (clean.startswith("'") and clean.endswith("'")):
        clean = clean[1:-1].strip()

    # Prepend https if scheme is absent
    if not clean.startswith(("http://", "https://")):
        clean = f"https://{clean}"

    parsed = urllib.parse.urlparse(clean)
    # Ensure scheme is lowercase and remove trailing fragments
    clean = urllib.parse.urlunparse((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # drop fragment
    ))
    return clean

def validate_target_url(url: str, allow_local_staging: bool = False) -> str:
    """
    Validate target URL against SSRF vulnerabilities.
    Blocks loopback, private, link-local, and cloud metadata networks
    unless allow_local_staging is True (which still strictly blocks cloud metadata).
    """
    clean_url = normalize_target_url(url)
    if not clean_url:
        raise ValueError("Target URL cannot be empty.")

    parsed = urllib.parse.urlparse(clean_url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got '{parsed.scheme}'.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target URL: missing hostname.")

    # Strict Cloud Metadata Block (never bypassed)
    cloud_metadata_hosts = {
        "metadata.google.internal",
        "169.254.169.254",
        "instance-data",
        "100.100.100.200"
    }
    if hostname.lower() in cloud_metadata_hosts:
        raise ValueError("Access to cloud metadata endpoints is strictly prohibited.")

    # Resolve IP addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Unable to resolve host '{hostname}': {e}")

    for item in addr_info:
        ip_str = item[4][0]
        ip_obj = ipaddress.ip_address(ip_str)

        if ip_str == "169.254.169.254":
            raise ValueError("Access to link-local cloud metadata (169.254.169.254) is blocked.")

        if not allow_local_staging:
            if (ip_obj.is_private or ip_obj.is_loopback or
                ip_obj.is_link_local or ip_obj.is_multicast or
                ip_obj.is_reserved or ip_obj.is_unspecified):
                raise ValueError(
                    f"Access to private or loopback IP address '{ip_str}' is blocked (SSRF Protection). "
                    f"Enable 'Local Staging Mode' to audit local development environments."
                )

    return clean_url

def sanitize_text(text: str) -> str:
    """Escape HTML content to prevent XSS in web terminal displays."""
    return html.escape(str(text or ""))

def calculate_sha256(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a file."""
    p = Path(filepath)
    if not p.is_file():
        return None
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()
