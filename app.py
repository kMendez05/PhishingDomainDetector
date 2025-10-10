#!/usr/bin/env python3
"""
Phishing Domain Detector
Day 4: Adds feed download + caching, with local feed override.

- Reads domains from a file (default: domains.txt)
- Normalizes and validates them
- Checks against phishing feed (local or cached remote)
- Applies heuristics and scoring
- Exports CSV/JSON and prints a table
"""

from pathlib import Path
import argparse
import os
import re
import json
from typing import List, Set, Optional

import pandas as pd

from utils.output import print_domains_table
from utils.heuristics import run_heuristics
from utils.normalize import normalize_domain
from utils.feed import ensure_feed, DEFAULT_FEED_URL

# Basic domain regex (ASCII/IDNA) — used to filter clearly invalid hosts.
DOMAIN_RE = re.compile(
    r"^(?!-)([A-Za-z0-9-]{1,63})(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def evaluate_domain(
    domain: str,
    *,
    feed_domains: Optional[Set[str]] = None,
    feed_path: Optional[str] = None,
    strict: bool = False,
) -> dict:
    """
    Backward-compatible:
      - tests can pass feed_path=".../feed.csv"
      - app can pass feed_domains={<normalized domains>}
    """
    # Resolve authoritative feed set
    if feed_domains is None:
        feed_set: Set[str] = load_local_feed(Path(feed_path)) if feed_path else set()
    else:
        feed_set = feed_domains

    # Normalize input before membership check (tests may pass raw strings)
    ndomain = normalize_domain(domain)

    # Authoritative feed hit (exact normalized match) 
    if ndomain in feed_set:
        return {
                "domain": domain,
                "status": "Phishing",
                "reason": "Listed in phishing feed",
                "risk_score": 100,
            }

    # Heuristics pipeline
    is_susp, reasons, score = run_heuristics(ndomain)
    if is_susp:
        reason_text = "; ".join(reasons)
        if len(reasons) >= 2:
            reason_text += " (multiple indicators)"
        if strict:
            return {
                "domain": domain,
                "status": "Phishing",
                "reason": reason_text,
                "risk_score": score,
            }
        if score >= 40:
            return {
                "domain": domain,
                "status": "Suspicious",
                "reason": reason_text,
                "risk_score": score,
            }
        else:
            return {
                "domain": domain,
                "status": "Safe",
                "reason": reason_text,
                "risk_score": score,
            }

    return {
        "domain": domain,
        "status": "Safe",
        "reason": "",
        "risk_score": 0,
    }


def load_domains(file_path: Path) -> List[str]:
    """
    Load and normalize domains from a text file.
    - Skips blank lines and comments (# ...)
    - Uses normalize_domain for robust URL/host handling
    - Filters obvious non-domains via DOMAIN_RE
    - De-duplicates
    """
    if not file_path.exists():
        print(f"[!] File not found: {file_path}")
        return []

    seen = set()
    domains: List[str] = []

    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            d = normalize_domain(raw)
            if d and DOMAIN_RE.match(d) and d not in seen:
                seen.add(d)
                domains.append(d)

    return domains


def load_local_feed(path: Path) -> Set[str]:
    """
    Load a local feed file (CSV or plain text) into a set of normalized domains.
    - CSV: expects a 'domain' column; if absent, uses the first column.
    - TXT: one URL/domain per line.
    """
    if not path.exists():
        return set()

    # CSV path?
    if path.suffix.lower() == ".csv":
        df = pd.read_csv(path)
        if "domain" in df.columns:
            col = df["domain"].astype(str).tolist()
        else:
            # Fallback to first column
            first_col = df.columns[0]
            col = df[first_col].astype(str).tolist()
        return {normalize_domain(x) for x in col if normalize_domain(x)}
    else:
        # Plain text
        out = set()
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.add(normalize_domain(s))
        return {d for d in out if d}


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Domain Detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--input", default="domains.txt", help="Path to input domains file")
    parser.add_argument("--csv", help="Path to save results as CSV")
    parser.add_argument("--json", help="Path to save results as JSON")
    parser.add_argument("--strict", action="store_true", help="Treat any heuristic hit as Phishing")
    parser.add_argument("--verbose", action="store_true", help="Show triggered heuristics/details")

    # Feed options
    parser.add_argument(
        "--feed",
        help="Path to local phishing feed file (CSV or TXT). Overrides cache/remote.",
        default=None,
    )
    parser.add_argument(
        "--feed-url",
        help="Remote phishing feed URL (used with cache/refresh).",
        default=None,
    )
    parser.add_argument(
        "--refresh-feed",
        help="Force re-download of the remote feed (ignores existing cache).",
        action="store_true",
    )

    args = parser.parse_args()

    src = Path(args.input)
    domains = load_domains(src)

    if not domains:
        print("[!] No valid domains found")
        return

    # Resolve feed domains
    if args.feed:
        feed_domains = load_local_feed(Path(args.feed))
    else:
        cache_path = os.path.join("data", "feed_cache.txt")
        feed_domains = ensure_feed(
            cache_path=cache_path,
            feed_url=(args.feed_url or DEFAULT_FEED_URL),
            refresh=args.refresh_feed,
        )

    # Evaluate
    rows = [evaluate_domain(d, feed_domains=feed_domains, strict=args.strict) for d in domains]
    rows.sort(key=lambda r: int(r.get("risk_score", 0)), reverse=True)

    # Exports
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(args.csv, index=False)

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)

    # Console table
    print_domains_table(rows, verbose=args.verbose)


if __name__ == "__main__":
    main()
