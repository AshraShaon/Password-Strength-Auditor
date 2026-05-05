"""
Password Strength Auditor - Core Engine
Analyzes password strength, entropy, and hash cracking.
"""

import hashlib
import math
import re
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────
#  Data Classes
# ─────────────────────────────────────────

@dataclass
class EntropyBreakdown:
    charset_size: int
    charset_description: str
    length: int
    raw_entropy_bits: float
    effective_entropy_bits: float
    patterns_detected: list[str]
    deductions: dict[str, float]


@dataclass
class CrackTimeEstimate:
    online_throttled_seconds: float    # 100 guesses/sec (rate-limited login)
    online_unthrottled_seconds: float  # 10k guesses/sec
    offline_slow_hash_seconds: float   # 10M guesses/sec (bcrypt GPU)
    offline_fast_hash_seconds: float   # 10B guesses/sec (MD5/SHA GPU)

    def human_readable(self, seconds: float) -> str:
        if seconds < 1:
            return "instantly"
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        if seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        if seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        if seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        if seconds < 3.154e9:
            return f"{seconds/31536000:.1f} years"
        return "centuries"


@dataclass
class AuditResult:
    password: str
    score: int                          # 0–100
    grade: str                          # F, D, C, B, A, A+
    entropy: EntropyBreakdown
    crack_time: CrackTimeEstimate
    patterns: list[str]
    suggestions: list[str]
    is_common: bool
    hash_md5: str
    hash_sha1: str
    hash_sha256: str


# ─────────────────────────────────────────
#  Pattern Detectors
# ─────────────────────────────────────────

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1234567890", "password",
    "abc", "abcdef", "abcdefgh",
]

LEET_MAP = str.maketrans("@48310$7", "aahbIost")  # leet-speak substitutions

DATE_PATTERNS = [
    r"\b(19|20)\d{2}\b",          # year: 1900–2099
    r"\b(0?[1-9]|1[0-2])(0?[1-9]|[12]\d|3[01])\d{2,4}\b",  # MMDDYY(YY)
    r"\b\d{2}(0?[1-9]|1[0-2])(0?[1-9]|[12]\d|3[01])\b",    # DDMMYY
]

COMMON_WORDS = [
    "password", "passwd", "pass", "letmein", "welcome",
    "monkey", "dragon", "master", "hello", "login",
    "admin", "root", "user", "test", "guest",
    "iloveyou", "sunshine", "princess", "football", "shadow",
    "mustang", "batman", "superman", "trustno1", "baseball",
]


def detect_patterns(password: str) -> list[str]:
    patterns = []
    lower = password.lower()
    deleet = lower.translate(LEET_MAP)

    # Repeated characters
    if re.search(r"(.)\1{2,}", password):
        patterns.append("repeated characters (e.g. aaa, 111)")

    # Sequential chars
    for walk in KEYBOARD_WALKS:
        if walk in lower or walk in deleet:
            patterns.append(f"keyboard/sequential pattern: '{walk[:6]}...'")
            break

    # Dates
    for pat in DATE_PATTERNS:
        if re.search(pat, password):
            patterns.append("date-like pattern detected")
            break

    # Common words
    for word in COMMON_WORDS:
        if word in lower or word in deleet:
            patterns.append(f"common word: '{word}'")
            break

    # All same case
    if password.isalpha():
        if password.islower():
            patterns.append("all lowercase letters")
        elif password.isupper():
            patterns.append("all uppercase letters")

    # Only digits
    if password.isdigit():
        patterns.append("digits only")

    # Starts with capital, ends with number/symbol (very common pattern)
    if re.match(r"^[A-Z][a-z]+\d+[!@#$%]?$", password):
        patterns.append("predictable structure: Capital + word + numbers")

    return patterns


# ─────────────────────────────────────────
#  Entropy Calculator
# ─────────────────────────────────────────

def calculate_charset_size(password: str) -> tuple[int, str]:
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    size = 0
    parts = []
    if has_lower:
        size += 26
        parts.append("lowercase (26)")
    if has_upper:
        size += 26
        parts.append("uppercase (26)")
    if has_digit:
        size += 10
        parts.append("digits (10)")
    if has_special:
        size += 32
        parts.append("special (~32)")

    desc = " + ".join(parts) if parts else "none"
    return size, desc


def compute_entropy(password: str) -> EntropyBreakdown:
    charset_size, charset_desc = calculate_charset_size(password)
    length = len(password)

    if charset_size == 0 or length == 0:
        raw = 0.0
    else:
        raw = length * math.log2(charset_size)

    # Deductions for patterns
    deductions: dict[str, float] = {}
    patterns = detect_patterns(password)

    if "digits only" in " ".join(patterns):
        deductions["digits only (predictable)"] = raw * 0.4
    if any("common word" in p for p in patterns):
        deductions["common word found"] = 20.0
    if any("keyboard" in p or "sequential" in p for p in patterns):
        deductions["keyboard/sequential pattern"] = 15.0
    if any("repeated" in p for p in patterns):
        deductions["repeated characters"] = 10.0
    if any("date" in p for p in patterns):
        deductions["date-like pattern"] = 10.0
    if any("predictable structure" in p for p in patterns):
        deductions["predictable structure"] = 12.0
    if any("all lowercase" in p or "all uppercase" in p for p in patterns):
        deductions["single case only"] = 8.0

    total_deduction = min(raw * 0.8, sum(deductions.values()))
    effective = max(0.0, raw - total_deduction)

    return EntropyBreakdown(
        charset_size=charset_size,
        charset_description=charset_desc,
        length=length,
        raw_entropy_bits=round(raw, 2),
        effective_entropy_bits=round(effective, 2),
        patterns_detected=patterns,
        deductions=deductions,
    )


# ─────────────────────────────────────────
#  Crack Time Estimator
# ─────────────────────────────────────────

def estimate_crack_time(entropy_bits: float) -> CrackTimeEstimate:
    keyspace = 2 ** entropy_bits
    half_keyspace = keyspace / 2  # average case

    return CrackTimeEstimate(
        online_throttled_seconds=half_keyspace / 100,
        online_unthrottled_seconds=half_keyspace / 10_000,
        offline_slow_hash_seconds=half_keyspace / 10_000_000,
        offline_fast_hash_seconds=half_keyspace / 10_000_000_000,
    )


# ─────────────────────────────────────────
#  Scoring & Grading
# ─────────────────────────────────────────

def score_password(entropy: EntropyBreakdown) -> tuple[int, str]:
    e = entropy.effective_entropy_bits

    if e < 20:
        base = int(e * 1.5)      # 0–30
    elif e < 40:
        base = 30 + int((e - 20) * 1.5)   # 30–60
    elif e < 60:
        base = 60 + int((e - 40) * 1.0)   # 60–80
    elif e < 80:
        base = 80 + int((e - 60) * 0.75)  # 80–95
    else:
        base = 95 + int((e - 80) * 0.05)  # 95–100

    score = min(100, max(0, base))

    grade_map = [
        (90, "A+"), (80, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")
    ]
    grade = next(g for threshold, g in grade_map if score >= threshold)

    return score, grade


# ─────────────────────────────────────────
#  Suggestions Generator
# ─────────────────────────────────────────

def generate_suggestions(password: str, entropy: EntropyBreakdown, score: int) -> list[str]:
    suggestions = []

    if entropy.length < 12:
        suggestions.append(f"Increase length to at least 12 characters (current: {entropy.length})")

    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters (A–Z)")

    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters (a–z)")

    if not re.search(r"\d", password):
        suggestions.append("Add at least one digit (0–9)")

    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add special characters (!@#$%^&*)")

    if any("common word" in p for p in entropy.patterns_detected):
        suggestions.append("Avoid dictionary words — use a passphrase or random string")

    if any("keyboard" in p or "sequential" in p for p in entropy.patterns_detected):
        suggestions.append("Avoid keyboard patterns like 'qwerty' or '12345'")

    if any("repeated" in p for p in entropy.patterns_detected):
        suggestions.append("Avoid repeating the same character multiple times")

    if any("date" in p for p in entropy.patterns_detected):
        suggestions.append("Avoid embedding dates — they reduce effective entropy significantly")

    if score >= 80:
        suggestions.append("Strong password! Consider using a password manager to store it securely.")

    return suggestions


# ─────────────────────────────────────────
#  Hash Generator
# ─────────────────────────────────────────

def hash_password(password: str) -> tuple[str, str, str]:
    encoded = password.encode("utf-8")
    return (
        hashlib.md5(encoded).hexdigest(),
        hashlib.sha1(encoded).hexdigest(),
        hashlib.sha256(encoded).hexdigest(),
    )


# ─────────────────────────────────────────
#  Dictionary Crack Checker
# ─────────────────────────────────────────

def check_common_password(password: str, wordlist_path: Optional[Path] = None) -> bool:
    """
    Check if password (or its leet-speak variant) is in a common wordlist.
    Falls back to built-in COMMON_WORDS if no wordlist provided.
    """
    lower = password.lower()
    deleet = lower.translate(LEET_MAP)

    if wordlist_path and wordlist_path.exists():
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip().lower()
                if word in (lower, deleet):
                    return True
        return False

    return any(word in (lower, deleet) for word in COMMON_WORDS)


# ─────────────────────────────────────────
#  Main Audit Function
# ─────────────────────────────────────────

def audit_password(password: str, wordlist_path: Optional[Path] = None) -> AuditResult:
    """
    Full audit of a single password. Returns an AuditResult with all metrics.
    """
    entropy = compute_entropy(password)
    score, grade = score_password(entropy)
    crack_time = estimate_crack_time(entropy.effective_entropy_bits)
    suggestions = generate_suggestions(password, entropy, score)
    is_common = check_common_password(password, wordlist_path)
    md5, sha1, sha256 = hash_password(password)

    if is_common and score > 20:
        score = min(score, 20)
        grade = "F"
        if "Found in common password list — change immediately!" not in suggestions:
            suggestions.insert(0, "Found in common password list — change immediately!")

    return AuditResult(
        password=password,
        score=score,
        grade=grade,
        entropy=entropy,
        crack_time=crack_time,
        patterns=entropy.patterns_detected,
        suggestions=suggestions,
        is_common=is_common,
        hash_md5=md5,
        hash_sha1=sha1,
        hash_sha256=sha256,
    )
