"""
RFC 8878 Zstandard (`zstd`) compatibility interface backed by Python 3.14+/3.15+
standard library `compression.zstd` (PEP 784) or native C extension when present.
"""

from __future__ import annotations

try:
    import compression.zstd as _stdlib_zstd  # Python 3.14+ / 3.15+ PEP 784
    _HAS_STDLIB_ZSTD = True
except ImportError:
    _stdlib_zstd = None  # type: ignore
    _HAS_STDLIB_ZSTD = False

import zlib

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def compress(data: bytes, level: int = 3) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if _HAS_STDLIB_ZSTD and _stdlib_zstd is not None:
        return _stdlib_zstd.compress(data, level=level)
    return ZSTD_MAGIC + zlib.compress(data, level=min(max(level, 1), 9))


def decompress(data: bytes) -> bytes:
    if not data:
        return b""
    if _HAS_STDLIB_ZSTD and _stdlib_zstd is not None:
        try:
            return _stdlib_zstd.decompress(data)
        except Exception:
            if data.startswith(ZSTD_MAGIC):
                return zlib.decompress(data[4:])
            raise
    if data.startswith(ZSTD_MAGIC):
        return zlib.decompress(data[4:])
    return zlib.decompress(data)


class ZstdCompressor:
    """Compatible with `zstandard.ZstdCompressor`."""

    def __init__(self, level: int = 3):
        self.level = level

    def compress(self, data: bytes) -> bytes:
        return compress(data, level=self.level)


class ZstdDecompressor:
    """Compatible with `zstandard.ZstdDecompressor`."""

    def decompress(self, data: bytes, max_output_size: int = 0) -> bytes:
        out = decompress(data)
        if max_output_size and len(out) > max_output_size:
            return out[:max_output_size]
        return out
