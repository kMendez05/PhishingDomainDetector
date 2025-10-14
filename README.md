# Phishing Domain Detector

![CI](https://github.com/kMendez05/PhishingDomainDetector/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A Python CLI that scans domains for phishing indicators using **live feeds** + **heuristics**, with risk scoring, colored output, and CSV/JSON exports.

---

## Usage

    # Install (in a venv)
    python -m venv .venv
    source .venv/bin/activate
    pip install -e .

    # Quickstart
    printf "example.org\nlogin.paypa1-secure.com\n" > domains.txt
    phishdetector --input domains.txt --refresh-feed   # first run: fetch + cache
    phishdetector --input domains.txt                  # subsequent runs use cache

    # CLI help
    phishdetector --help

    # Common flags (inline)
    # --csv PATH, --json PATH, --feed PATH, --feed-url URL, --refresh-feed, --strict, --verbose

    # Run tests
    pytest -q
