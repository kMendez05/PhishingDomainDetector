# utils/heuristics.py
from typing import Tuple, List
from utils.normalize import normalize_domain


SUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".mov",".go",".xyz"]  # Commonly abused TLDs

def has_homoglyph_swaps(domain: str) -> Tuple[bool, str]:
    """
    Tests if domain has homoglyph swaps and marks them as a hit accordingly
    """
    HOMOGLYPHS = {
    # conservative set to start
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "vv": "w", "rn": "m",
    }
    swaps = []
    seen = set()
    parts = domain.strip().split(".")
    sld = parts[-2] if len(parts) > 1 else parts[0]
    sld = sld.lower()
    for key, dst in HOMOGLYPHS.items():
        if len(key) > 1 and key in sld:
            pair = f"{key}->{dst}"
            if pair not in seen:
                seen.add(pair)
                swaps.append(pair)
    for ch in sld:
        if ch in HOMOGLYPHS:
            pair = f"{ch}->{HOMOGLYPHS[ch]}"
            if pair not in seen:
                seen.add(pair)
                swaps.append(pair)
    if swaps:
        return True, "Homoglyphs: " + ", ".join(swaps)
    else:
        return False, ""


def has_suspicious_TLD(domain: str) -> Tuple[bool, str]:
    """
    Returns (hit, reason)
    Flags if the domain uses a TLD that is commonly abused.
    """
     
    domain = domain.strip().strip(".")
    parts = domain.strip().split(".")
    TLD = parts[-1].lower()
    if ("." + TLD) in SUS_TLDS:
        return True, f"Suspicious TLD: .{TLD}"
    else:
        return False, ""


def too_many_subdomains(domain: str, max_allowed=2) -> Tuple[bool, str]:
    """
    Returns (hit, reason)
    Flags if the domain has more than `max_allowed` subdomains.
    e.g. "sub.sub2.example.com" has 2 subdomains ("sub" and "sub2").
    """
    domain = domain.strip().strip(".")
    parts = domain.strip().split(".")
    count = len(parts) - 2

    if count > max_allowed:
        return True, f"Too many subdomains: {count}"
    else:
        return False, ""
    
def has_baitword_in_subdomain(domain: str) -> Tuple[bool, str]:
    BAIT = {"login","secure","verify","password","billing","account","support","update","reset"}
    bait_words = []
    seen = set()
    d = domain.strip().strip(".").lower()
    parts = d.split(".")
    if len(parts) < 3:
        return False, ""
    subs = parts[:-2]
    for s in subs:
        if not s.startswith("xn--"):
            tokens = s.split("-")
            for t in tokens:
                if t in BAIT and t not in seen:
                    seen.add(t)
                    bait_words.append(t)
    if bait_words:
        return True, "Bait words in subdomain: " + ", ".join(bait_words)
    else:
        return False, ""

def has_punycode_label(domain: str) -> Tuple[bool, str]:
    d = domain.strip().strip(".").lower()
    labels = d.split(".")
    for label in labels:
        if label.startswith("xn--"):
            return True, f"Punycode/IDN label: {label}"
    return False, ""

def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (case-insensitive)."""
    a, b = a.lower(), b.lower()
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,        # deletion
                dp[i][j - 1] + 1,        # insertion
                dp[i - 1][j - 1] + cost  # substitution
            )

    return dp[len(a)][len(b)]

def _map_digits_to_letters(s: str) -> str:
    """Simple homoglyph map so 'g00gle' -> 'google'."""
    return s.translate(str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s",
        "@": "a",
    }))

def looks_like_typosquat(domain: str) -> Tuple[bool, str]:
    # High-value brands often impersonated in phishing
    KNOWN_BRANDS = {
        # Finance & Payments
        "paypal", "chase", "bankofamerica", "wellsfargo", "citibank",
        "americanexpress", "amex",
        # Tech Giants
        "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
        "twitter", "apple", "icloud", "microsoft", "outlook", "office365",
        # Shopping / Retail
        "amazon", "ebay", "walmart", "target",
        # Extras (media / productivity)
        "netflix", "linkedin", "dropbox", "adobe",
    }

    # Normalize once
    nd = normalize_domain(domain)
    parts = [p for p in nd.split(".") if p]
    if len(parts) < 2:
        return False, ""

    sld = parts[-2]

    # If it's EXACTLY a brand as-is, don't flag as typosquat.
    if sld in KNOWN_BRANDS:
        return False, ""

    # Simple win: if digit-mapped SLD becomes a brand, call it typosquat.
    mapped = _map_digits_to_letters(sld)
    if mapped != sld and mapped in KNOWN_BRANDS:
        return True, f"Typosquat: SLD '{sld}' -> '{mapped}' via digit homoglyphs"

    # Otherwise use your existing distance rule:
    bait_hit, _ = has_baitword_in_subdomain(nd)
    for brand in KNOWN_BRANDS:
        dist = edit_distance(sld, brand)
        if dist == 1 or (dist == 2 and bait_hit):
            detail = " (baitword)" if (dist == 2 and bait_hit) else ""
            return True, f"Typosquat: SLD '{sld}' ~ '{brand}' (dist={dist}){detail}"

    return False, ""




def run_heuristics(domain: str) -> Tuple[bool, List[str], int]:
    """
    Return (is_suspicious, reasons, score)
    """
    domain = normalize_domain(domain)  # normalize once

    suspicious = False
    reasons: List[str] = []
    score = 0

    hit, reason = has_homoglyph_swaps(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 40

    hit, reason = has_suspicious_TLD(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 20

    hit, reason = too_many_subdomains(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 15

    hit, reason = has_baitword_in_subdomain(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 25

    hit, reason = has_punycode_label(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 30

    hit, reason = looks_like_typosquat(domain)
    if hit:
        suspicious = True
        reasons.append(reason)
        score += 50 

    return suspicious, reasons, score