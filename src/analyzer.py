"""
Wordlist Analyzer - Score a list of passwords and visualize strength distribution.
"""

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

from auditor import audit_password, AuditResult


def analyze_wordlist(
    wordlist_path: Path,
    max_passwords: int = 10_000,
    output_csv: Optional[Path] = None,
    output_json: Optional[Path] = None,
) -> dict:
    """
    Audit every password in a file and return aggregate statistics.

    Args:
        wordlist_path:  Path to a newline-separated file of passwords.
        max_passwords:  Stop after this many passwords (performance guard).
        output_csv:     Optional path to write per-password CSV results.
        output_json:    Optional path to write summary JSON.

    Returns:
        Dictionary with distribution, averages, top patterns, weakest/strongest.
    """
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    results: list[AuditResult] = []
    grade_counter: Counter = Counter()
    all_patterns: Counter = Counter()

    print(f"[*] Analyzing: {wordlist_path}")

    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_passwords:
                print(f"[!] Reached limit of {max_passwords} passwords. Use --max to increase.")
                break

            pw = line.strip()
            if not pw or len(pw) > 128:
                continue

            result = audit_password(pw)
            results.append(result)
            grade_counter[result.grade] += 1
            for p in result.patterns:
                all_patterns[p.split(":")[0].strip()] += 1

            if (i + 1) % 1000 == 0:
                print(f"    {i+1} passwords processed...")

    if not results:
        print("[!] No valid passwords found in file.")
        return {}

    scores = [r.score for r in results]
    entropies = [r.entropy.effective_entropy_bits for r in results]

    summary = {
        "total_analyzed": len(results),
        "average_score": round(sum(scores) / len(scores), 1),
        "average_entropy_bits": round(sum(entropies) / len(entropies), 1),
        "grade_distribution": {
            "A+": grade_counter.get("A+", 0),
            "A":  grade_counter.get("A",  0),
            "B":  grade_counter.get("B",  0),
            "C":  grade_counter.get("C",  0),
            "D":  grade_counter.get("D",  0),
            "F":  grade_counter.get("F",  0),
        },
        "common_password_count": sum(1 for r in results if r.is_common),
        "top_patterns": dict(all_patterns.most_common(10)),
        "weakest_5": [
            {"password": r.password, "score": r.score, "grade": r.grade}
            for r in sorted(results, key=lambda x: x.score)[:5]
        ],
        "strongest_5": [
            {"password": r.password, "score": r.score, "grade": r.grade}
            for r in sorted(results, key=lambda x: x.score, reverse=True)[:5]
        ],
    }

    # ── Score histogram (buckets of 10) ──────────────────────────────────────
    histogram = {f"{i}-{i+9}": 0 for i in range(0, 100, 10)}
    for s in scores:
        bucket = (s // 10) * 10
        bucket = min(bucket, 90)
        histogram[f"{bucket}-{bucket+9}"] += 1
    summary["score_histogram"] = histogram

    # ── CSV output ────────────────────────────────────────────────────────────
    if output_csv:
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "password", "score", "grade", "entropy_bits",
                "length", "is_common", "patterns"
            ])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "password": r.password,
                    "score": r.score,
                    "grade": r.grade,
                    "entropy_bits": r.entropy.effective_entropy_bits,
                    "length": r.entropy.length,
                    "is_common": r.is_common,
                    "patterns": "; ".join(r.patterns),
                })
        print(f"[+] CSV written: {output_csv}")

    # ── JSON summary ──────────────────────────────────────────────────────────
    if output_json:
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] JSON summary written: {output_json}")

    return summary


def print_summary(summary: dict) -> None:
    """Pretty-print the analysis summary to stdout."""
    if not summary:
        return

    print("\n" + "═" * 55)
    print("  PASSWORD WORDLIST ANALYSIS SUMMARY")
    print("═" * 55)
    print(f"  Total analyzed   : {summary['total_analyzed']:,}")
    print(f"  Average score    : {summary['average_score']}/100")
    print(f"  Avg entropy      : {summary['average_entropy_bits']} bits")
    print(f"  Common passwords : {summary['common_password_count']:,}")

    print("\n  Grade Distribution:")
    total = summary["total_analyzed"]
    for grade in ["A+", "A", "B", "C", "D", "F"]:
        count = summary["grade_distribution"].get(grade, 0)
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 2)
        print(f"    {grade:2s}  {bar:<25} {count:>5,} ({pct:.1f}%)")

    print("\n  Score Histogram:")
    for bucket, count in summary["score_histogram"].items():
        pct = (count / total * 100) if total else 0
        bar = "█" * int(pct / 2)
        print(f"    {bucket:6s}  {bar:<25} {count:>5,}")

    print("\n  Top 5 Patterns Found:")
    for i, (pat, count) in enumerate(list(summary["top_patterns"].items())[:5], 1):
        print(f"    {i}. {pat} — {count:,} passwords")

    print("\n  5 Weakest Passwords:")
    for p in summary["weakest_5"]:
        print(f"    [{p['grade']}] score={p['score']:>3}  {p['password']}")

    print("═" * 55 + "\n")
