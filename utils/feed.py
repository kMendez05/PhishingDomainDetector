# utils/feed.py
from __future__ import annotations

import io
import os
from typing import Set
from urllib.parse import urlparse

import requests

from utils.normalize import normalize_domain

__all__ = ["ensure_feed", "DEFAULT_FEED_URL", "FeedError"]

# Default remote feed: simple, line-separated URLs
DEFAULT_FEED_URL = "https://openphish.com/feed.txt"


class FeedError(RuntimeError):
    """Raised for feed download/parse/cache errors."""
    pass


def _download_text(url: str, timeout: int = 10) -> str:
    """
    Download the remote feed and return its text body.
    Raises FeedError on network/HTTP errors.
    """
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "phishdetector/1.0"},
        )
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        raise FeedError(f"Failed to download feed: {e}") from e


def _parse_lines_to_domains(text: str) -> Set[str]:
    """
    Parse a text blob (each line a URL or host) into a set of normalized domains.
    - Skips blank and comment lines.
    - Accepts bare hosts or full URLs.
    - Normalizes via utils.normalize.normalize_domain.
    Raises FeedError if no domains are found.
    """
    domains: Set[str] = set()
    for line in io.StringIO(text):
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        # Ensure urlparse extracts hostname for bare hosts (prefix // when no scheme)
        parsed = urlparse(s if "://" in s else f"//{s}")
        host = parsed.hostname or s

        dom = normalize_domain(host)
        if dom:
            domains.add(dom)

    if not domains:
        raise FeedError("Downloaded feed contained no domains.")
    return domains


def ensure_feed(cache_path: str, feed_url: str | None = None, refresh: bool = False) -> Set[str]:
    """
    Return a set of feed domains using a cache-first strategy.

    Behavior:
      - If refresh is False and a non-empty cache exists -> return cached domains.
      - Otherwise, download from feed_url (or DEFAULT_FEED_URL), parse, write cache, and return.

    Cache format: one normalized domain per line.
    """
    feed_url = feed_url or DEFAULT_FEED_URL

    if not refresh and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = {normalize_domain(line) for line in f if line.strip()}
            if cached:
                return cached
        except OSError:
            # If cache can't be read, fall through to re-download
            pass

    # Download + parse
    text = _download_text(feed_url)
    domains = _parse_lines_to_domains(text)

    # Best-effort cache write (don't fail the whole run if this errors)
    try:
        dirn = os.path.dirname(cache_path)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(d + "\n")
    except OSError:
        pass

    return domains
