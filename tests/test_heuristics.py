# tests/test_heuristics.py
from utils.heuristics import has_homoglyph_swaps, has_suspicious_TLD, too_many_subdomains, looks_like_typosquat
import pytest

def test_has_homoglyph_swaps_hit():
    hit, reason = has_homoglyph_swaps("micros0ft.com")
    assert hit is True
    assert "0->o" in reason  # or whatever wording you choose

def test_has_homoglyph_swaps_negative():
    hit, reason = has_homoglyph_swaps("microsoft.com")
    assert hit is False
    assert reason == "" or "Safe" in reason  # depends on how you implement

@pytest.mark.parametrize("domain", ["fileshare.mov", "site.xyz", "something.tk"])
def test_has_suspicious_tld_hits(domain):
    hit, reason = has_suspicious_TLD(domain)
    assert hit is True
    assert "Suspicious TLD:" in reason

def test_has_suspicious_tld_negatives():
    hit, reason = has_suspicious_TLD("paypal.com")
    assert hit is False
    assert reason == ""

def test_too_many_subdomains_flagged():
    hit, reason = too_many_subdomains("deep.a.b.c.example.com")
    assert hit is True
    assert "4" in reason

def test_too_many_subdomains_negative():
    hit, reason = too_many_subdomains("google.com")
    assert hit is False
    assert reason == ""

def test_too_many_subdomains_boundary():
    hit, reason = too_many_subdomains("a.b.example.com", max_allowed=2)
    assert hit is False
    assert reason == ""

def test_typosquat_flagged():
    hit, reason = looks_like_typosquat("paypai.com")
    assert hit
    assert "paypal" in reason.lower()