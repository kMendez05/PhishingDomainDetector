from utils.heuristics import has_homoglyph_swaps, has_baitword_in_subdomain, has_punycode_label
import pytest

def test_homoglyph_digit_zero():
    hit, reason = has_homoglyph_swaps("g0ogle.com")
    assert hit
    assert "0->o" in reason

def test_homoglyph_listed_once():
    hit, reason = has_homoglyph_swaps("g00gle.com")
    assert hit
    assert reason.count("0->o") == 1

def test_homoglyph_one_to_l():
    hit, reason = has_homoglyph_swaps("paypa1.com")
    assert hit
    assert "1->l" in reason

def test_homoglyph_multiple_pairs():
    hit, reason = has_homoglyph_swaps("m1cr0s0ft.com")
    assert hit
    assert "1->l" in reason
    assert "0->o" in reason

def test_homoglyph_negative():
    hit, reason = has_homoglyph_swaps("microsoft.com")
    assert not hit
    assert reason == ""

def test_homoglyph_ignored_tld_only():
    hit, reason = has_homoglyph_swaps("example.c0m")
    assert not hit

def test_has_baitword_in_subdomain():
    hit, reason = has_baitword_in_subdomain("secure-login.example.com")
    assert hit
    assert "secure" in reason
    assert "login" in reason

def test_has_baitword_in_subdomain_negative():
    hit, reason = has_baitword_in_subdomain("google.com")
    assert not hit

def test_punycode_label_hits():
    # "xn--pple-43d.com" -> hit, reason mentions "Punycode/IDN" and the label
    hit, reason = has_punycode_label("xn--pple-43d.com")
    assert hit
    assert "xn--pple-43d" in reason

def test_punycode_negative():
    # "apple.com" -> no hit
    hit, reason = has_punycode_label("apple.com")
    assert not hit
    assert reason == ""

def test_punycode_in_subdomain():
    # "xn--login-9za.example.com" -> hit
    hit, reason = has_punycode_label("xn--login-9za.example.com")
    assert hit
    assert "xn--login-9za" in reason


