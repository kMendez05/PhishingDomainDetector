# tests/test_feed.py
import os
from pathlib import Path
import types
import pytest

from utils.feed import ensure_feed, FeedError

class DummyResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")

def test_cold_start_downloads_and_caches(monkeypatch, tmp_path: Path):
    # mock requests.get to return two URLs
    def fake_get(url, timeout=10, headers=None):
        assert "http" in url
        return DummyResp("https://evil.example/login\nhttp://phish.bad/verify\n")
    import utils.feed as feed
    monkeypatch.setattr(feed.requests, "get", fake_get)

    cache = tmp_path / "data" / "feed_cache.txt"
    domains = ensure_feed(str(cache), feed_url="https://mock.feed/urls.txt", refresh=False)

    # domains normalized and stored
    assert "evil.example" in domains
    assert "phish.bad" in domains
    assert cache.exists()
    cached_text = cache.read_text().strip().splitlines()
    assert "evil.example" in cached_text and "phish.bad" in cached_text

def test_refresh_forces_redownload(monkeypatch, tmp_path: Path):
    # first download returns A
    def fake_get_1(url, timeout=10, headers=None):
        return DummyResp("http://first.example/a\n")
    # second download returns B
    def fake_get_2(url, timeout=10, headers=None):
        return DummyResp("http://second.example/b\n")

    import utils.feed as feed
    cache = tmp_path / "data" / "feed_cache.txt"

    # first run (cold start)
    monkeypatch.setattr(feed.requests, "get", fake_get_1)
    d1 = ensure_feed(str(cache), feed_url="https://mock.feed/urls.txt", refresh=False)
    assert "first.example" in d1

    # second run with refresh=True should ignore cache and fetch new
    monkeypatch.setattr(feed.requests, "get", fake_get_2)
    d2 = ensure_feed(str(cache), feed_url="https://mock.feed/urls.txt", refresh=True)
    assert "second.example" in d2
    assert "first.example" not in d2

def test_empty_feed_raises(monkeypatch, tmp_path: Path):
    def fake_get(url, timeout=10, headers=None):
        return DummyResp("\n\n")  # empty
    import utils.feed as feed
    monkeypatch.setattr(feed.requests, "get", fake_get)

    cache = tmp_path / "data" / "feed_cache.txt"
    with pytest.raises(FeedError):
        ensure_feed(str(cache), feed_url="https://mock.empty/urls.txt", refresh=True)
