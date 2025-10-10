# utils/api_checks.py (you write this)
from pathlib import Path
from typing import Set, Tuple, Optional, Dict
import csv

_FEED_CACHE: Dict[str, Set[str]] = {}
FEED_PATH = Path("data/phish_domains.csv")  # header: domain

def _normalize(d: str) -> str:
    # lower, strip scheme, strip path, trim dots/spaces
    d = d.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0]
    return d.strip(" .")

def load_local_feed(path: Path = FEED_PATH) -> Set[str]:
    # TODO: read CSV once, build a set of normalized domains
    # - if file missing, return empty set
    # - use csv.DictReader and look for "domain" column
    # - normalize each value and add to set
    phishing_domains = set()
    if not path.exists():
        return phishing_domains

    with path.open("r", newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            domain = row.get("domain", "").strip()
            if domain:
                phishing_domains.add(_normalize(domain))
    return phishing_domains

def check_local_feed(domain: str, path: str = "data/phish_domains.csv") -> Tuple[Optional[str], Optional[str]]:
    global _FEED_CACHE
    key = str(Path(path).resolve())

    if key not in _FEED_CACHE:
        _FEED_CACHE[key] = load_local_feed(Path(key))
    
    norm = _normalize(domain)
    if norm in _FEED_CACHE[key]:
        return "Phishing", "Found in local phishing feed"
    return None, None

def reset_feed_cache() -> None:
    _FEED_CACHE.clear()
