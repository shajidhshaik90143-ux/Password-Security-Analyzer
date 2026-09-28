import math
import re
import string
from collections import Counter

COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "admin", "admin123", "letmein", "welcome",
    "iloveyou", "monkey", "dragon", "football", "abc123", "000000",
    "login", "passw0rd", "root", "user", "changeme", "secret", "india123",
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwert", "asdf", "zxcv",
    "12345", "23456", "34567", "45678", "56789", "67890",
]

def _has_sequence(password, min_len=4):
    s = password.lower()
    for i in range(len(s) - min_len + 1):
        chunk = s[i:i+min_len]
        if chunk.isalpha() or chunk.isdigit():
            codes = [ord(c) for c in chunk]
            if all(codes[j] + 1 == codes[j+1] for j in range(len(codes)-1)):
                return True
            if all(codes[j] - 1 == codes[j+1] for j in range(len(codes)-1)):
                return True
    return False

def _repeated_run(password):
    return bool(re.search(r"(.)\1{2,}", password))

def _date_year_like(password):
    return bool(re.search(r"(19\d{2}|20\d{2})", password))

def _keyboard_pattern(password):
    p = password.lower()
    return any(x in p for x in KEYBOARD_PATTERNS)

def _dictionary_like(password):
    p = re.sub(r"[^a-z]", "", password.lower())
    common_fragments = [
        "password", "admin", "welcome", "qwerty", "login", "secret",
        "dragon", "football", "ilove", "hello", "computer"
    ]
    return any(fragment in p for fragment in common_fragments)

def estimate_entropy(password):
    if not password:
        return 0.0, 0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += len(string.punctuation)
    if any(ord(c) > 127 for c in password): pool += 100
    entropy = len(password) * math.log2(max(pool, 1))
    return entropy, pool

def analyze_password(password):
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    length = len(password)
    entropy, pool = estimate_entropy(password)

    composition = {
        "Lowercase letters": any(c.islower() for c in password),
        "Uppercase letters": any(c.isupper() for c in password),
        "Digits": any(c.isdigit() for c in password),
        "Symbols": any(c in string.punctuation for c in password),
        "Unicode characters": any(ord(c) > 127 for c in password),
    }

    normalized = password.lower()
    risks = []
    penalties = 0

    if length < 8:
        risks.append("Password is shorter than 8 characters.")
        penalties += 30
    elif length < 12:
        risks.append("Password is shorter than the recommended 12+ characters.")
        penalties += 15
    elif length < 16:
        penalties += 5

    if normalized in COMMON_PASSWORDS:
        risks.append("Password matches a known/common password.")
        penalties += 45

    if _repeated_run(password):
        risks.append("Contains repeated characters such as aaa, 111, or !!!.")
        penalties += 10

    if _has_sequence(password):
        risks.append("Contains an ascending or descending sequence.")
        penalties += 10

    if _keyboard_pattern(password):
        risks.append("Contains a common keyboard pattern.")
        penalties += 15

    if _date_year_like(password):
        risks.append("Contains a four-digit year-like pattern.")
        penalties += 8

    if _dictionary_like(password):
        risks.append("Contains a common dictionary/password fragment.")
        penalties += 15

    unique_ratio = len(set(password)) / max(length, 1)
    if length >= 8 and unique_ratio < 0.5:
        risks.append("Low character diversity: many characters are repeated.")
        penalties += 8

    base = min(100, max(0, entropy * 1.35))
    if length >= 16:
        base += 8
    if all(composition.values()):
        base += 5
    elif sum(composition.values()) >= 3:
        base += 2

    score = int(max(0, min(100, base - penalties)))

    if score >= 85:
        label = "Excellent"
    elif score >= 70:
        label = "Strong"
    elif score >= 50:
        label = "Moderate"
    elif score >= 30:
        label = "Weak"
    else:
        label = "Very Weak"

    recommendations = []
    if length < 16:
        recommendations.append("Use at least 16 characters for important accounts.")
    if sum(composition.values()) < 3:
        recommendations.append("Mix letters, numbers, and symbols — or use a long random passphrase.")
    if risks:
        recommendations.append("Remove predictable words, sequences, years, and repeated characters.")
    recommendations.append("Never reuse this password across different services.")
    recommendations.append("Store unique passwords in a reputable password manager.")
    if not recommendations:
        recommendations.append("Keep it unique and store it in a password manager.")

    if entropy < 40:
        brute = "Low estimated search space"
    elif entropy < 60:
        brute = "Moderate estimated search space"
    elif entropy < 80:
        brute = "High estimated search space"
    else:
        brute = "Very high estimated search space"

    resistance = {
        "Offline guessing": brute,
        "Dictionary guessing": "At risk" if _dictionary_like(password) else "Reduced risk",
        "Pattern guessing": "At risk" if (_has_sequence(password) or _keyboard_pattern(password)) else "Reduced risk",
        "Password spraying": "Never reuse; unique per service",
    }

    return {
        "score": score,
        "label": label,
        "entropy_bits": entropy,
        "pool_size": pool,
        "composition": composition,
        "risks": risks,
        "recommendations": recommendations,
        "resistance": resistance,
    }
