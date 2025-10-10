# import your evaluate_domain from app.py (just like you did with heuristics)
# maybe set up a tiny fake CSV feed for the feed test
from app import evaluate_domain
import pytest
import csv
from utils.api_checks import reset_feed_cache


def test_feed_overrides_heuristics(tmp_path):
    # write a tiny CSV feed containing a known domain into tmp_path
    # call evaluate_domain("bad-domain.com", feed_path=that_file)
    # assert status == "Phishing"
    # assert risk_score == 100
    reset_feed_cache()
    feed_file = tmp_path / "feed.csv"
    with open(feed_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["domain"])
        csv_writer.writerow(["bad-domain.com"])

    results = evaluate_domain("bad-domain.com", feed_path=str(feed_file))
    assert results["status"] == "Phishing"
    assert results["risk_score"] == 100


def test_heuristics_suspicious(tmp_path):
    # pick a domain like "g00gle.com"
    # call evaluate_domain(domain, feed_path="empty.csv")
    # assert status == "Suspicious"
    # assert risk_score >= 40
    empty_feed = tmp_path / "empty.csv"
    empty_feed.write_text("domain\n", encoding="utf-8")
    results = evaluate_domain("g00gle.com", feed_path=str(empty_feed))
    assert results["risk_score"] >= 40
    assert results["status"] == "Suspicious"
    assert "Homoglyph" in results["reason"]
    

def test_safe_domain(tmp_path):
    # pick "microsoft.com"
    # assert status == "Safe"
    # assert risk_score == 0
    empty_feed = tmp_path / "empty.csv"
    empty_feed.write_text("domain\n", encoding="utf-8")
    results = evaluate_domain("microsoft.com", feed_path=str(empty_feed))
    assert results["status"] == "Safe"
    assert results["risk_score"] == 0

def test_strict_flips_to_phishing(tmp_path):
    # pick something with a heuristic hit but low score
    # call evaluate_domain(domain, strict=True, feed_path="empty.csv")
    # assert status == "Phishing"
    empty_feed = tmp_path / "empty.csv"
    empty_feed.write_text("domain\n", encoding="utf-8")
    results = evaluate_domain("g0ogle.com", strict=True, feed_path=str(empty_feed))
    assert results["status"] == "Phishing"
    assert results["risk_score"] < 100

def test_punycode_label(tmp_path):
    empty_feed = tmp_path / "empty.csv"
    empty_feed.write_text("domain\n", encoding="utf-8")
    results = evaluate_domain("xn--login-9za.example.com", feed_path=str(empty_feed))
    assert results["status"] == "Safe"
    assert results["risk_score"] == 30
    assert "Punycode/IDN" in results["reason"]

def test_punycode_label_baitword_combo(tmp_path):
    empty_feed = tmp_path / "empty.csv"
    empty_feed.write_text("domain\n", encoding="utf-8")
    results = evaluate_domain("login.xn--google-qmc.com", feed_path=str(empty_feed))
    assert results["status"] == "Suspicious"
    assert results["risk_score"] == 55
    assert "Punycode/IDN" in results["reason"]
    assert "Bait words" in results["reason"]