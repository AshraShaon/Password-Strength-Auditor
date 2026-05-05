#!/usr/bin/env python3
"""
Password Strength Auditor — CLI
Usage: python main.py [OPTIONS]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from auditor import audit_password
from cracker import crack_hash, batch_crack
from analyzer import analyze_wordlist, print_summary
from reporter import generate_report


# ─────────────────────────────────────────
#  ANSI colors for terminal output
# ─────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
ORANGE  = "\033[93m"
BLUE    = "\033[94m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
GRAY    = "\033[90m"


def color_score(score: int) -> str:
    if score >= 80: return f"{GREEN}{score}{RESET}"
    if score >= 60: return f"{BLUE}{score}{RESET}"
    if score >= 40: return f"{ORANGE}{score}{RESET}"
    return f"{RED}{score}{RESET}"


def color_grade(grade: str) -> str:
    palette = {"A+": GREEN, "A": GREEN, "B": BLUE, "C": ORANGE, "D": RED, "F": RED}
    c = palette.get(grade, RESET)
    return f"{BOLD}{c}{grade}{RESET}"


def print_audit(result, show_hashes: bool = False) -> None:
    ct = result.crack_time
    print(f"\n{'═'*55}")
    print(f"  {BOLD}Password Audit{RESET}  ·  Grade: {color_grade(result.grade)}  ·  Score: {color_score(result.score)}/100")
    print(f"{'═'*55}")

    # Entropy
    print(f"\n  {CYAN}ENTROPY{RESET}")
    print(f"    Length          : {result.entropy.length} characters")
    print(f"    Character set   : {result.entropy.charset_description}")
    print(f"    Raw entropy     : {result.entropy.raw_entropy_bits:.1f} bits")
    print(f"    Effective       : {BOLD}{result.entropy.effective_entropy_bits:.1f} bits{RESET}")
    if result.entropy.deductions:
        print(f"    Deductions:")
        for k, v in result.entropy.deductions.items():
            print(f"      {RED}- {k}: -{v:.0f} bits{RESET}")

    # Patterns
    print(f"\n  {CYAN}PATTERNS DETECTED{RESET}")
    if result.patterns:
        for p in result.patterns:
            print(f"    {ORANGE}⚠  {p}{RESET}")
    else:
        print(f"    {GREEN}✓  None detected{RESET}")

    # Common password check
    print(f"\n  {CYAN}COMMON PASSWORD CHECK{RESET}")
    if result.is_common:
        print(f"    {RED}✗  Found in common password list — extremely weak!{RESET}")
    else:
        print(f"    {GREEN}✓  Not in common password list{RESET}")

    # Crack times
    print(f"\n  {CYAN}ESTIMATED CRACK TIME{RESET}")
    rows = [
        ("Online throttled (100/s)",     ct.human_readable(ct.online_throttled_seconds)),
        ("Online unthrottled (10k/s)",   ct.human_readable(ct.online_unthrottled_seconds)),
        ("Offline bcrypt (10M/s)",        ct.human_readable(ct.offline_slow_hash_seconds)),
        ("Offline MD5/GPU (10B/s)",       ct.human_readable(ct.offline_fast_hash_seconds)),
    ]
    for label, val in rows:
        print(f"    {label:<35} {BOLD}{val}{RESET}")

    # Suggestions
    print(f"\n  {CYAN}RECOMMENDATIONS{RESET}")
    for s in result.suggestions:
        print(f"    → {s}")

    # Hashes
    if show_hashes:
        print(f"\n  {CYAN}HASH VALUES{RESET}")
        print(f"    MD5     : {GRAY}{result.hash_md5}{RESET}")
        print(f"    SHA-1   : {GRAY}{result.hash_sha1}{RESET}")
        print(f"    SHA-256 : {GRAY}{result.hash_sha256}{RESET}")

    print(f"\n{'═'*55}\n")


# ─────────────────────────────────────────
#  Subcommand handlers
# ─────────────────────────────────────────

def cmd_audit(args) -> None:
    wordlist = Path(args.wordlist) if args.wordlist else None
    results = []

    if args.password:
        passwords = args.password if isinstance(args.password, list) else [args.password]
        for pw in passwords:
            result = audit_password(pw, wordlist_path=wordlist)
            results.append(result)
            print_audit(result, show_hashes=args.hashes)
    elif args.file:
        path = Path(args.file)
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    result = audit_password(pw, wordlist_path=wordlist)
                    results.append(result)
                    print_audit(result, show_hashes=args.hashes)
    else:
        print("Enter passwords to audit (Ctrl+D / Ctrl+Z to finish):")
        try:
            while True:
                pw = input("  password> ").strip()
                if pw:
                    result = audit_password(pw, wordlist_path=wordlist)
                    results.append(result)
                    print_audit(result, show_hashes=args.hashes)
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Done.")

    if args.report and results:
        out = Path(args.report)
        generate_report(results, out, mask_passwords=not args.unmask)
        print(f"[+] HTML report saved: {out}")


def cmd_crack(args) -> None:
    wordlist = Path(args.wordlist) if args.wordlist else None
    hashes = args.hash if isinstance(args.hash, list) else [args.hash]

    for h in hashes:
        print(f"\n[*] Cracking: {h}")
        result = crack_hash(
            h,
            algorithm=args.algo or None,
            wordlist_path=wordlist,
            use_rules=not args.no_rules,
            brute_force_max_len=args.brute or 0,
        )
        if result.cracked:
            print(f"    {GREEN}✓ CRACKED{RESET}  →  {BOLD}{result.plaintext}{RESET}")
        else:
            print(f"    {RED}✗ NOT CRACKED{RESET}")
        print(f"    Algorithm : {result.algorithm.upper()}")
        print(f"    Attempts  : {result.attempts:,}")
        print(f"    Time      : {result.elapsed_seconds}s")
        if result.method:
            print(f"    Method    : {result.method}")


def cmd_analyze(args) -> None:
    wordlist = Path(args.file)
    output_csv  = Path(args.csv)  if args.csv  else None
    output_json = Path(args.json) if args.json else None
    output_html = Path(args.report) if args.report else None

    summary = analyze_wordlist(
        wordlist,
        max_passwords=args.max,
        output_csv=output_csv,
        output_json=output_json,
    )
    print_summary(summary)

    if output_html and summary:
        # Re-audit top weakest for HTML
        from auditor import audit_password
        sample = [r["password"] for r in summary.get("weakest_5", [])]
        results = [audit_password(pw) for pw in sample]
        generate_report(results, output_html, mask_passwords=False)
        print(f"[+] HTML report (weakest passwords): {output_html}")


# ─────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-auditor",
        description="Password Strength Auditor — analyze, crack, and visualize password security",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # audit
    p_audit = sub.add_parser("audit", help="Audit one or more passwords")
    p_audit.add_argument("-p", "--password", nargs="+", help="Password(s) to audit")
    p_audit.add_argument("-f", "--file", help="File of passwords (one per line)")
    p_audit.add_argument("-w", "--wordlist", help="Common password wordlist file")
    p_audit.add_argument("--hashes", action="store_true", help="Show hash values")
    p_audit.add_argument("--report", help="Save HTML report to this path")
    p_audit.add_argument("--unmask", action="store_true", help="Show full passwords in report")

    # crack
    p_crack = sub.add_parser("crack", help="Attempt to crack a hash")
    p_crack.add_argument("hash", nargs="+", help="Hash(es) to crack")
    p_crack.add_argument("-a", "--algo", choices=["md5", "sha1", "sha256"], help="Force algorithm")
    p_crack.add_argument("-w", "--wordlist", help="Wordlist file")
    p_crack.add_argument("--no-rules", action="store_true", help="Disable mutation rules")
    p_crack.add_argument("--brute", type=int, default=0, metavar="LEN",
                         help="Brute-force up to LEN characters (0=disabled)")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze a wordlist's strength distribution")
    p_analyze.add_argument("file", help="Wordlist file to analyze")
    p_analyze.add_argument("--max", type=int, default=10_000, help="Max passwords to process")
    p_analyze.add_argument("--csv", help="Export per-password CSV")
    p_analyze.add_argument("--json", help="Export summary JSON")
    p_analyze.add_argument("--report", help="Export HTML report of weakest passwords")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {"audit": cmd_audit, "crack": cmd_crack, "analyze": cmd_analyze}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
