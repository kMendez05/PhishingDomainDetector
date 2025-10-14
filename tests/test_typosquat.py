from utils.heuristics import run_heuristics

def test_typosquat_edit_distance_1():
    is_susp, reasons, score = run_heuristics("g00gle.com")  # 0->o
    assert is_susp
    assert any("Typosquat" in r for r in reasons)
    assert score >= 40

def test_typosquat_baitword_allows_distance_2():
    is_susp, reasons, score = run_heuristics("login.paypzl.co")  # 'paypzl' ~ 'paypal' (2)
    assert is_susp
    assert any("Typosquat" in r for r in reasons)

def test_exact_brand_not_flagged_as_typosquat():
    is_susp, reasons, score = run_heuristics("google.com")
    assert not any("Typosquat" in r for r in reasons)
