import hashlib
import html
import ipaddress
import os
import re
import socket
import urllib.parse
from pathlib import Path
from typing import Optional, List

# Dangerous shell metacharacters and control characters for command injection defense
_COMMAND_INJECTION_CHARS = set(";|&$`\n\r\x00!{}")
_PATH_TRAVERSAL_PATTERN = re.compile(r'(?:^|[\\/])\.\.(?:[\\/]|$)|\.\.[\\/]|[\\/]\.\.', re.IGNORECASE)


def _is_ipv6(addr: str) -> bool:
    """Return True if addr is a valid IPv6 address string."""
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False


def _sanitize_brackets(raw: str) -> str:
    """
    Sanitize bracketed inputs commonly copied from markdown, shell, or logs
    e.g. [http://localhost:3000], [127.0.0.1:8000], 127.0.0.1:[8000], <http://...>, (http://...)
    while preserving legitimate RFC 3986 IPv6 bracketed hosts like [::1] or [2001:db8::1].
    """
    s = (raw or "").strip()
    if not s:
        return s

    # Strip surrounding paired wrappers unless it's a valid IPv6 literal like [::1]
    for open_char, close_char in [('[', ']'), ('<', '>'), ('(', ')'), ('"', '"'), ("'", "'")]:
        while s.startswith(open_char) and s.endswith(close_char) and len(s) >= 2:
            inner = s[1:-1].strip()
            if open_char == '[' and close_char == ']' and _is_ipv6(inner):
                break
            s = inner

    # Strip non-IPv6 bracketed segments inside authority/host/port (e.g. [127.0.0.1]:8000, 127.0.0.1:[8080], [localhost]:3000)
    def replace_bracket(match: re.Match) -> str:
        content = match.group(1).strip()
        if _is_ipv6(content):
            return f"[{content}]"
        return content

    s = re.sub(r'\[([^\]]+)\]', replace_bracket, s)
    return s


def sanitize_target_input(raw: str) -> str:
    """
    Enforce strict security sanitization on ingested target strings.
    Proactively blocks:
    - Command injection vectors (shell metacharacters, subshells, control characters, internal whitespace)
    - Argument/flag injection (explicitly rejects hyphen-prefixed strings and hostnames)
    - Path traversal attempts ('..', backslashes, URL-encoded traversal sequences, file:// URIs)
    """
    if raw is None or not isinstance(raw, str):
        raise ValueError("Target URI must be a non-empty string.")

    clean = raw.strip()
    if not clean:
        raise ValueError("Target URI cannot be empty.")

    # 1. Explicitly reject hyphen-prefixed strings (argument/option injection defense)
    if clean.startswith("-"):
        raise ValueError(
            f"Security Violation: Hyphen-prefixed target '{clean}' is rejected (command/argument injection defense)."
        )

    # 2. Check for command injection metacharacters and control characters before any unwrapping
    if any(ch in _COMMAND_INJECTION_CHARS for ch in clean):
        raise ValueError(
            f"Security Violation: Command injection vector detected in target '{clean}'."
        )

    # 3. Check for path traversal in raw and URL-decoded representations
    unquoted_once = urllib.parse.unquote(clean)
    unquoted_twice = urllib.parse.unquote(unquoted_once)
    for candidate in (clean, unquoted_once, unquoted_twice):
        if "\\" in candidate or ".." in candidate or _PATH_TRAVERSAL_PATTERN.search(candidate):
            raise ValueError(
                f"Security Violation: Path traversal attempt detected in target '{clean}'."
            )
        if candidate.strip().startswith("-"):
            raise ValueError(
                f"Security Violation: Hyphen-prefixed target '{clean}' is rejected."
            )

    # 4. Unwrap benign markdown/log brackets if present
    unwrapped = _sanitize_brackets(clean)
    if not unwrapped:
        raise ValueError("Target URI cannot be empty.")

    if unwrapped.startswith("-"):
        raise ValueError(
            f"Security Violation: Hyphen-prefixed target '{clean}' is rejected (command/argument injection defense)."
        )

    # 5. Reject any remaining shell/injection characters or internal whitespace after bracket unwrapping
    if any(ch in unwrapped for ch in ("<", ">", "(", ")", '"', "'", " ", "\t", "\n", "\r", "\x00")):
        raise ValueError(
            f"Security Violation: Illegal characters or command injection vector in target '{clean}'."
        )

    # 6. Reject disallowed URI schemes (e.g., file://, javascript:, data:, ftp://)
    if "://" in unwrapped:
        scheme_prefix = unwrapped.split("://", 1)[0].lower()
        if scheme_prefix not in ("http", "https"):
            raise ValueError(f"URL scheme must be http or https, got '{scheme_prefix}'.")
    elif ":" in unwrapped.split("/", 1)[0]:
        # Handle scheme-like prefixes without '//' (e.g. file:/etc/passwd, javascript:alert(1))
        authority_part = unwrapped.split("/", 1)[0]
        if not authority_part.startswith("["):
            host_part, port_part = authority_part.rsplit(":", 1)
            if not port_part.isdigit():
                raise ValueError(f"Malformed or disallowed URI scheme in '{clean}'.")

    # 7. Ensure hostname/domain does not start with a hyphen
    with_scheme = unwrapped if unwrapped.startswith(("http://", "https://")) else f"https://{unwrapped}"
    try:
        parsed = urllib.parse.urlparse(with_scheme)
    except ValueError as e:
        raise ValueError(f"Malformed or invalid URL: {e}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid target URL '{clean}': missing hostname.")

    if hostname.startswith("-") or any(label.startswith("-") or label.endswith("-") for label in hostname.split(".") if label):
        raise ValueError(
            f"Security Violation: Hyphen-prefixed or malformed hostname '{hostname}' is rejected."
        )

    return unwrapped


def parse_src_list(raw_content: str) -> List[str]:
    """
    Ingest and parse the src_list format.
    Processes a strictly comma-separated list of target domain URIs
    (e.g., 'www.website01.com,www.website02.com,www.website99.com').
    Enforces strict security sanitization on every parsed target and returns
    normalized target URLs ready for the async scanning pipeline.
    """
    if raw_content is None or not isinstance(raw_content, str):
        raise ValueError("Batch input content cannot be empty.")

    # Strip UTF-8 BOM if present
    cleaned_stream = raw_content.lstrip("\ufeff").strip()
    if not cleaned_stream:
        raise ValueError("Batch input content contains no target domains.")

    raw_tokens = cleaned_stream.split(",")
    validated_targets: List[str] = []

    for token in raw_tokens:
        stripped = token.strip()
        if not stripped:
            continue

        # Strip optional CSV cell quotes only if balanced around the entire token
        if len(stripped) >= 2 and (
            (stripped.startswith('"') and stripped.endswith('"')) or
            (stripped.startswith("'") and stripped.endswith("'"))
        ):
            stripped = stripped[1:-1].strip()

        if not stripped:
            continue

        # Enforce strict security validation (rejects internal newlines/spaces if not comma-separated,
        # hyphen-prefixed strings, command injection vectors, and path traversal attempts)
        sanitize_target_input(stripped)
        normalized = normalize_target_url(stripped)
        validated_targets.append(normalized)

    if not validated_targets:
        raise ValueError("No valid target domain URIs found in src_list input.")

    return validated_targets


def normalize_target_url(raw: str) -> str:
    """Normalize user input to a canonical HTTP/HTTPS URL after security sanitization."""
    clean = (raw or "").strip()
    if not clean:
        return clean

    clean = sanitize_target_input(clean)

    # Prepend https if scheme is absent
    if not clean.startswith(("http://", "https://")):
        clean = f"https://{clean}"

    try:
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
    except ValueError as e:
        raise ValueError(f"Malformed or invalid URL: {e}")
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


def sanitize_filename(filename: str, allowed_extensions: Optional[tuple] = None) -> str:
    """
    Validate and sanitize a single filename component against path traversal,
    null bytes, control characters, and header/shell injection vectors.
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string.")
    if "\x00" in filename or "\r" in filename or "\n" in filename:
        raise ValueError("Invalid control characters or null byte in filename.")
    clean = filename.strip()
    if (
        not clean
        or clean in (".", "..")
        or ".." in clean
        or "/" in clean
        or "\\" in clean
        or os.path.basename(clean) != clean
        or clean.startswith("-")
    ):
        raise ValueError(f"Security Violation: Path traversal or invalid filename '{filename}'.")
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", clean):
        raise ValueError(f"Security Violation: Disallowed characters in filename '{filename}'.")
    if allowed_extensions:
        lower_clean = clean.lower()
        if not any(lower_clean.endswith(ext.lower()) for ext in allowed_extensions):
            raise ValueError(f"Security Violation: Disallowed file extension in '{filename}'.")
    return clean


def resolve_sandboxed_path(base_dir: Path | str, *parts: str, allow_symlinks: bool = False) -> Path:
    """
    Resolve a target path relative to base_dir and strictly enforce that it stays
    confined within base_dir (blocking '..' climbing, absolute path overrides, and symlinks).
    """
    if base_dir is None:
        raise ValueError("Sandbox base directory must be specified.")
    base_str = str(base_dir)
    if "\x00" in base_str:
        raise ValueError("Null byte detected in sandbox base directory.")
    base_resolved = Path(base_str).resolve()

    curr = Path(base_str)
    for part in parts:
        part_str = str(part)
        if "\x00" in part_str:
            raise ValueError("Null byte detected in path component.")
        p_obj = Path(part_str)
        if p_obj.is_absolute():
            raise ValueError(f"Security Violation: Absolute path '{part_str}' not permitted inside sandbox.")
        if ".." in p_obj.parts or "\\" in part_str:
            raise ValueError(f"Security Violation: Path traversal sequence detected in '{part_str}'.")
        curr = curr / p_obj

    if not allow_symlinks and curr.is_symlink():
        raise ValueError(f"Security Violation: Symlink target '{curr}' is not permitted in sandbox.")

    resolved = curr.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise ValueError(
            f"Security Violation: Path '{resolved}' escapes designated sandbox directory '{base_resolved}'."
        )
    return resolved


def is_safe_subresource_url(url: str, allow_local_staging: bool = False) -> bool:
    """
    Validate URLs discovered during crawling/chunk resolution before fetching.
    Prevents SSRF to cloud metadata or local/private network services via malicious HTML/JS assets.
    """
    if not url or not isinstance(url, str):
        return False
    if any(ch in url for ch in ("\x00", "\r", "\n", " ", "\t", "\\")):
        return False
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    hostname = (parsed.hostname or "").lower().strip()
    if not hostname or hostname.startswith("-"):
        return False

    cloud_metadata_hosts = {
        "metadata.google.internal",
        "169.254.169.254",
        "instance-data",
        "100.100.100.200",
    }
    if hostname in cloud_metadata_hosts:
        return False

    try:
        ip_obj = ipaddress.ip_address(hostname)
        if str(ip_obj) == "169.254.169.254":
            return False
        if not allow_local_staging:
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False
    except ValueError:
        if not allow_local_staging and hostname in ("localhost", "localhost.localdomain"):
            return False

    return True


def calculate_sha256(filepath: str) -> Optional[str]:
    """Calculate SHA-256 hash of a regular file (rejects symlinks and null bytes)."""
    if not filepath or "\x00" in str(filepath):
        return None
    p = Path(filepath)
    if p.is_symlink() or not p.is_file():
        return None
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()
