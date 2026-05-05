"""
Hash Cracker - Dictionary + Rule-based attack on MD5/SHA-1/SHA-256 hashes.
"""

import hashlib
import itertools
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


SUPPORTED_ALGORITHMS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}

# Common mutation rules applied to each wordlist candidate
MUTATION_RULES = [
    lambda w: w,                         # original
    lambda w: w.lower(),
    lambda w: w.upper(),
    lambda w: w.capitalize(),
    lambda w: w + "1",
    lambda w: w + "123",
    lambda w: w + "!",
    lambda w: w + "2024",
    lambda w: w + "2023",
    lambda w: "1" + w,
    lambda w: w[0].upper() + w[1:] + "1",
    lambda w: w.translate(str.maketrans("aeiost", "431057")),  # leet-speak
    lambda w: w[::-1],                   # reverse
]


@dataclass
class CrackResult:
    hash_value: str
    algorithm: str
    cracked: bool
    plaintext: Optional[str]
    attempts: int
    elapsed_seconds: float
    method: Optional[str]  # "dictionary", "rules", "brute-force"


def _hash_string(plaintext: str, algorithm: str) -> str:
    return SUPPORTED_ALGORITHMS[algorithm](plaintext.encode("utf-8")).hexdigest()


def detect_algorithm(hash_value: str) -> Optional[str]:
    """Detect hash algorithm from length."""
    length_map = {32: "md5", 40: "sha1", 64: "sha256"}
    return length_map.get(len(hash_value))


def _brute_force_generator(max_length: int = 5) -> Iterator[str]:
    """Generate all character combos up to max_length (use carefully)."""
    charset = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def crack_hash(
    hash_value: str,
    algorithm: Optional[str] = None,
    wordlist_path: Optional[Path] = None,
    use_rules: bool = True,
    brute_force_max_len: int = 0,
    max_attempts: int = 5_000_000,
) -> CrackResult:
    """
    Attempt to crack a hash via dictionary attack with optional mutation rules.

    Args:
        hash_value:         The hash string to crack.
        algorithm:          'md5', 'sha1', or 'sha256'. Auto-detected if None.
        wordlist_path:      Path to a newline-separated wordlist file.
        use_rules:          Apply mutation rules to each candidate.
        brute_force_max_len: If > 0, fall back to brute-force up to this length.
        max_attempts:       Abort after this many hash attempts.

    Returns:
        CrackResult with cracked=True and plaintext if successful.
    """
    hash_value = hash_value.strip().lower()

    if algorithm is None:
        algorithm = detect_algorithm(hash_value)
        if algorithm is None:
            raise ValueError(
                f"Cannot detect algorithm from hash length {len(hash_value)}. "
                "Supported lengths: 32 (MD5), 40 (SHA-1), 64 (SHA-256)."
            )

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {list(SUPPORTED_ALGORITHMS)}")

    start = time.perf_counter()
    attempts = 0

    # ── Phase 1: Dictionary + Rules ──────────────────────────────────────────
    if wordlist_path and wordlist_path.exists():
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue

                candidates = [word] if not use_rules else [r(word) for r in MUTATION_RULES]

                for candidate in candidates:
                    attempts += 1
                    if attempts > max_attempts:
                        break
                    if _hash_string(candidate, algorithm) == hash_value:
                        return CrackResult(
                            hash_value=hash_value,
                            algorithm=algorithm,
                            cracked=True,
                            plaintext=candidate,
                            attempts=attempts,
                            elapsed_seconds=round(time.perf_counter() - start, 4),
                            method="dictionary+rules" if use_rules else "dictionary",
                        )

                if attempts > max_attempts:
                    break

    # ── Phase 2: Built-in Common Passwords ───────────────────────────────────
    from auditor import COMMON_WORDS
    for word in COMMON_WORDS:
        candidates = [word] if not use_rules else [r(word) for r in MUTATION_RULES]
        for candidate in candidates:
            attempts += 1
            if _hash_string(candidate, algorithm) == hash_value:
                return CrackResult(
                    hash_value=hash_value,
                    algorithm=algorithm,
                    cracked=True,
                    plaintext=candidate,
                    attempts=attempts,
                    elapsed_seconds=round(time.perf_counter() - start, 4),
                    method="built-in wordlist",
                )

    # ── Phase 3: Optional Brute Force ────────────────────────────────────────
    if brute_force_max_len > 0:
        for candidate in _brute_force_generator(brute_force_max_len):
            attempts += 1
            if attempts > max_attempts:
                break
            if _hash_string(candidate, algorithm) == hash_value:
                return CrackResult(
                    hash_value=hash_value,
                    algorithm=algorithm,
                    cracked=True,
                    plaintext=candidate,
                    attempts=attempts,
                    elapsed_seconds=round(time.perf_counter() - start, 4),
                    method="brute-force",
                )

    return CrackResult(
        hash_value=hash_value,
        algorithm=algorithm,
        cracked=False,
        plaintext=None,
        attempts=attempts,
        elapsed_seconds=round(time.perf_counter() - start, 4),
        method=None,
    )


def batch_crack(
    hashes: list[str],
    algorithm: Optional[str] = None,
    wordlist_path: Optional[Path] = None,
    use_rules: bool = True,
) -> list[CrackResult]:
    """Crack multiple hashes sequentially."""
    return [
        crack_hash(h, algorithm=algorithm, wordlist_path=wordlist_path, use_rules=use_rules)
        for h in hashes
    ]
