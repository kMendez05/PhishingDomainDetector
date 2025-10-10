# utils/normalize.py
from __future__ import annotations
from urllib.parse import urlparse
import re

__all__ = ["normalize_domain"]

_DOT_RUNS = re.compile(r"\.{2,}")

def _to_idna_ascii(host: str) -> str:
    """
    Convert Unicode host to IDNA ASCII (punycode). If already ASCII (incl. xn--),
    this is a no-op. If conversion fails, return the original lowercased host.
    """
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host

def normalize_domain(raw: str) -> str:
    """
    Normalize a domain/host string for consistent matching.

    - Trims whitespace
    - Accepts either a bare host or a full URL (http(s)://, ftp://, etc.)
    - Drops credentials and port
    - Lowercases
    - Collapses repeated dots and trims leading/trailing dots
    - Converts Unicode domains to IDNA (punycode) ASCII
    - Preserves subdomains (do NOT strip 'www' or reduce to eTLD+1)

    Returns "" if nothing usable is found.
    """
    if not raw:
        return ""

    s = raw.strip()

    # Make urlparse treat bare hosts like netlocs (by prefixing // when scheme missing)
    parsed = urlparse(s if "://" in s else f"//{s}")

    # urlparse.hostname:
    # - lowercases
    # - strips brackets on IPv6
    # - strips credentials + port
    host = parsed.hostname or ""

    host = host.strip().lower()
    if not host:
        return ""

    # Collapse repeated dots and trim leading/trailing dots
    host = _DOT_RUNS.sub(".", host).strip(".")

    # Convert Unicode to punycode ASCII (keeps 'xn--' as-is)
    host = _to_idna_ascii(host)

    # Edge-case: if normalization produced only dots/emptiness
    return host if host else ""
