from src.analyzer import analyze_password, estimate_entropy

def test_empty_password():
    result = analyze_password("")
    assert result["score"] == 0

def test_long_randomish_password():
    result = analyze_password("V7!qR2#nL9@xP4$zK8")
    assert result["score"] >= 70
    assert result["entropy_bits"] > 80

def test_common_password_is_penalized():
    result = analyze_password("password")
    assert result["score"] < 40
    assert result["risks"]

def test_entropy_increases_with_length():
    e1, _ = estimate_entropy("Ab3!")
    e2, _ = estimate_entropy("Ab3!xY8@pQ")
    assert e2 > e1
