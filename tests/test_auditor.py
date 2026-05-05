"""
Tests for Password Strength Auditor
Run: python -m pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from auditor import (
    audit_password, compute_entropy, score_password,
    detect_patterns, estimate_crack_time, hash_password,
    check_common_password,
)
from cracker import crack_hash, detect_algorithm


# ─────────────────────────────────────────────
#  Pattern Detection Tests
# ─────────────────────────────────────────────

class TestPatternDetection:
    def test_repeated_chars(self):
        patterns = detect_patterns("aaabbb")
        assert any("repeated" in p for p in patterns)

    def test_keyboard_walk(self):
        patterns = detect_patterns("qwerty123")
        assert any("keyboard" in p or "sequential" in p for p in patterns)

    def test_common_word(self):
        patterns = detect_patterns("password")
        assert any("common word" in p for p in patterns)

    def test_all_lowercase(self):
        patterns = detect_patterns("onlylower")
        assert any("lowercase" in p for p in patterns)

    def test_digits_only(self):
        patterns = detect_patterns("12345678")
        assert any("digits" in p for p in patterns)

    def test_date_pattern(self):
        patterns = detect_patterns("pass2024")
        assert any("date" in p for p in patterns)

    def test_leet_speak_detection(self):
        patterns = detect_patterns("p@55w0rd")
        assert any("common word" in p for p in patterns)

    def test_strong_no_patterns(self):
        patterns = detect_patterns("xK9!mQr#7vL2")
        assert len(patterns) == 0


# ─────────────────────────────────────────────
#  Entropy Tests
# ─────────────────────────────────────────────

class TestEntropy:
    def test_short_password_low_entropy(self):
        e = compute_entropy("abc")
        assert e.raw_entropy_bits < 20

    def test_long_mixed_high_entropy(self):
        e = compute_entropy("xK9!mQr#7vL2@pZ")
        assert e.raw_entropy_bits > 80

    def test_charset_size_lowercase_only(self):
        e = compute_entropy("abcdefgh")
        assert e.charset_size == 26

    def test_charset_size_mixed(self):
        e = compute_entropy("Abc123!")
        assert e.charset_size == 26 + 26 + 10 + 32

    def test_effective_less_than_raw(self):
        e = compute_entropy("password123")
        assert e.effective_entropy_bits <= e.raw_entropy_bits

    def test_strong_password_minimal_deductions(self):
        e = compute_entropy("xK9!mQr#7vL2")
        assert len(e.deductions) == 0


# ─────────────────────────────────────────────
#  Scoring & Grading Tests
# ─────────────────────────────────────────────

class TestScoring:
    def test_very_weak_gets_low_score(self):
        result = audit_password("abc")
        assert result.score < 30

    def test_common_password_capped_at_20(self):
        result = audit_password("password")
        assert result.score <= 20
        assert result.grade == "F"

    def test_strong_password_high_score(self):
        result = audit_password("xK9!mQr#7vL2@pZ")
        assert result.score >= 75

    def test_grade_f_for_weak(self):
        result = audit_password("abc")
        assert result.grade == "F"

    def test_grade_a_for_strong(self):
        result = audit_password("xK9!mQr#7vL2@pZ3")
        assert result.grade in ("A", "A+")


# ─────────────────────────────────────────────
#  Crack Time Tests
# ─────────────────────────────────────────────

class TestCrackTime:
    def test_weak_password_cracks_fast(self):
        ct = estimate_crack_time(10.0)  # 10 bits = 1024 possibilities
        assert ct.offline_fast_hash_seconds < 1

    def test_strong_password_takes_long(self):
        ct = estimate_crack_time(80.0)
        assert ct.offline_fast_hash_seconds > 1e7

    def test_human_readable_instantly(self):
        ct = estimate_crack_time(0)
        assert ct.human_readable(0) == "instantly"

    def test_human_readable_centuries(self):
        ct = estimate_crack_time(100)
        assert "centur" in ct.human_readable(ct.offline_slow_hash_seconds)


# ─────────────────────────────────────────────
#  Hash Tests
# ─────────────────────────────────────────────

class TestHashing:
    def test_md5_length(self):
        md5, _, _ = hash_password("test")
        assert len(md5) == 32

    def test_sha1_length(self):
        _, sha1, _ = hash_password("test")
        assert len(sha1) == 40

    def test_sha256_length(self):
        _, _, sha256 = hash_password("test")
        assert len(sha256) == 64

    def test_known_md5(self):
        md5, _, _ = hash_password("password")
        assert md5 == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_known_sha256(self):
        _, _, sha256 = hash_password("hello")
        assert sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


# ─────────────────────────────────────────────
#  Common Password Check Tests
# ─────────────────────────────────────────────

class TestCommonCheck:
    def test_common_password_detected(self):
        assert check_common_password("password") is True

    def test_leet_speak_common_detected(self):
        assert check_common_password("p@$$w0rd") is False  # not in list but close

    def test_strong_not_common(self):
        assert check_common_password("xK9!mQr#7vL2") is False


# ─────────────────────────────────────────────
#  Hash Cracker Tests
# ─────────────────────────────────────────────

class TestCracker:
    def test_detect_md5(self):
        assert detect_algorithm("5f4dcc3b5aa765d61d8327deb882cf99") == "md5"

    def test_detect_sha1(self):
        assert detect_algorithm("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8") == "sha1"

    def test_detect_sha256(self):
        assert detect_algorithm("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") == "sha256"

    def test_crack_md5_common(self):
        # MD5 of "admin"
        result = crack_hash("21232f297a57a5a743894a0e4a801fc3")
        assert result.cracked is True
        assert result.plaintext == "admin"

    def test_crack_sha1_common(self):
        # SHA1 of "password"
        result = crack_hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert result.cracked is True

    def test_no_crack_strong(self):
        # SHA256 of a random strong password — should not crack
        result = crack_hash(
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        )
        assert result.cracked is False

    def test_result_has_attempts(self):
        result = crack_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        assert result.attempts > 0


# ─────────────────────────────────────────────
#  Full Audit Pipeline Tests
# ─────────────────────────────────────────────

class TestFullAudit:
    def test_audit_returns_all_fields(self):
        result = audit_password("Test123!")
        assert result.password == "Test123!"
        assert 0 <= result.score <= 100
        assert result.grade in ("F", "D", "C", "B", "A", "A+")
        assert result.entropy is not None
        assert result.crack_time is not None
        assert isinstance(result.suggestions, list)
        assert len(result.hash_md5) == 32

    def test_audit_empty_password(self):
        result = audit_password("")
        assert result.score == 0

    def test_audit_very_long_password(self):
        pw = "xK9!mQr#7vL2" * 5  # 60 chars
        result = audit_password(pw)
        assert result.score >= 90
        assert result.grade in ("A", "A+")
