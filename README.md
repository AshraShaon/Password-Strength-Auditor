# 🔐 Password Strength Auditor

A Python tool for analyzing password strength, estimating crack times, cracking hashes via dictionary + rule-based attacks, and visualizing the security distribution of password wordlists.

Built as part of a cybersecurity portfolio for research and education.

---

## Features

- **Entropy Analysis** — raw and effective Shannon entropy with pattern-aware deductions
- **Pattern Detection** — keyboard walks, leet-speak, repeated chars, date patterns, common words
- **Crack Time Estimation** — four threat models from rate-limited login to GPU-accelerated offline attack
- **Hash Cracker** — dictionary + mutation rules against MD5, SHA-1, and SHA-256
- **Wordlist Analyzer** — batch-audit a list of passwords; grade distribution + histogram
- **HTML Report Generator** — color-coded, dark-theme reports with per-finding severity
- **CLI Interface** — three subcommands: `audit`, `crack`, `analyze`

---

## Problem

Most users and organizations have no systematic way to measure password strength. Simple "strength meters" count character types but ignore entropy deductions from predictable patterns (keyboard walks, dates, leet-speak substitutions, common words). This leads to passwords that *look* strong but are trivially crackable.

## Approach

### Entropy Model

Raw entropy is calculated as:

```
H_raw = L × log₂(N)
```

where `L` = password length and `N` = size of the character set used.

We then apply pattern-specific deductions to compute **effective entropy**:

| Pattern | Entropy Deduction |
|---|---|
| Common word (dictionary) | −20 bits |
| Keyboard/sequential walk | −15 bits |
| Predictable structure (Capital+word+digits) | −12 bits |
| Date-like substring | −10 bits |
| Repeated characters | −10 bits |
| Single case only | −8 bits |

### Crack Time Model

Estimated crack time uses average-case analysis (half the keyspace) against four attacker models:

| Scenario | Guesses/sec | Represents |
|---|---|---|
| Online throttled | 100 | Rate-limited login form |
| Online unthrottled | 10,000 | Unprotected login endpoint |
| Offline slow hash | 10,000,000 | bcrypt on GPU cluster |
| Offline fast hash | 10,000,000,000 | MD5/SHA on GPU farm |

### Hash Cracking Pipeline

1. Dictionary attack against provided wordlist
2. Mutation rules: capitalization, `+1`, `+123`, `+!`, leet-speak, reversal, year suffix
3. Built-in common password list fallback
4. Optional brute-force (configurable max length)

---

## Installation

```bash
git clone https://github.com/AshraShaon/password-strength-auditor
cd password-strength-auditor
# No external dependencies required — uses Python stdlib only
python main.py --help
```

Optional (for testing):
```bash
pip install pytest pytest-cov
python -m pytest tests/ -v
```

---

## Usage

### Audit a password

```bash
python main.py audit -p "Summer2024!"
```

```
═══════════════════════════════════════════════════════
  Password Audit  ·  Grade: A  ·  Score: 80/100
═══════════════════════════════════════════════════════

  ENTROPY
    Length          : 11 characters
    Character set   : lowercase (26) + uppercase (26) + digits (10) + special (~32)
    Raw entropy     : 71.9 bits
    Effective       : 61.9 bits
    Deductions:
      - date-like pattern: -10 bits

  PATTERNS DETECTED
    ⚠  date-like pattern detected

  CRACK TIME
    Online throttled (100/s)          centuries
    Online unthrottled (10k/s)        centuries
    Offline bcrypt (10M/s)            3.7 years
    Offline MD5/GPU (10B/s)           13.2 days

  RECOMMENDATIONS
    → Avoid embedding dates — they reduce effective entropy significantly
```

### Audit multiple passwords + generate report

```bash
python main.py audit -p "password" "Test123!" "xK9!mQr#7vL2" --report report.html --hashes
```

### Crack a hash

```bash
python main.py crack 5f4dcc3b5aa765d61d8327deb882cf99
```

```
[*] Cracking: 5f4dcc3b5aa765d61d8327deb882cf99
    ✓ CRACKED  →  password
    Algorithm : MD5
    Attempts  : 1
    Time      : 0.0001s
    Method    : built-in wordlist
```

With a custom wordlist and brute-force fallback:

```bash
python main.py crack <hash> -w wordlists/rockyou.txt --brute 4
```

### Analyze a wordlist

```bash
python main.py analyze wordlists/sample.txt --csv results.csv --report weakest.html
```

```
═══════════════════════════════════════════════════════
  PASSWORD WORDLIST ANALYSIS SUMMARY
═══════════════════════════════════════════════════════
  Total analyzed   : 38
  Average score    : 41.2/100
  Avg entropy      : 22.1 bits
  Common passwords : 18

  Grade Distribution:
    A+  ████████                      4 (10.5%)
    A   ██                            1  (2.6%)
    B   ████                          2  (5.3%)
    C   ████████████                  6 (15.8%)
    D   ██████                        3  (7.9%)
    F   ████████████████████████     22 (57.9%)
```

---

## Project Structure

```
password-strength-auditor/
├── main.py                  # CLI entry point
├── src/
│   ├── auditor.py           # Core engine: entropy, patterns, scoring
│   ├── cracker.py           # Dictionary + rule-based hash cracker
│   ├── analyzer.py          # Batch wordlist analysis
│   └── reporter.py          # HTML report generator
├── tests/
│   └── test_auditor.py      # Unit tests (37 test cases)
├── wordlists/
│   └── sample.txt           # Sample wordlist for testing
└── reports/                 # Generated HTML reports (gitignored)
```

---

## Sample Results

| Password | Score | Grade | Effective Entropy | Crack Time (GPU) |
|---|---|---|---|---|
| `password` | 11 | F | 0 bits | instantly |
| `P@ssw0rd` | 20 | F | 12.1 bits | instantly |
| `Test123!` | 30 | F | 19.3 bits | < 1 second |
| `Summer2024!` | 80 | A | 61.9 bits | 13.2 days |
| `correct-horse-battery-staple` | 99 | A+ | 131.1 bits | centuries |
| `xK9!mQr#7vL2@pZ3` | 96 | A+ | 110.4 bits | centuries |

---

## Limitations

- Entropy model assumes random character selection. Real passwords from humans are less random than the raw bits suggest, so effective entropy after deductions is still an upper bound.
- The cracker uses dictionary + rules — it does not implement Markov chains or neural-network-guided guessing (Hashcat-style advanced attacks would crack significantly more).
- Crack time estimates assume single-threaded, sequential guessing. Real attackers use parallelism; scale times down accordingly for large GPU farms.
- No rainbow table support — the tool cracks by computation, not lookup.

---

## Related Concepts

This tool maps to several MITRE ATT&CK techniques:

- **T1110.001** — Brute Force: Password Guessing
- **T1110.002** — Brute Force: Password Cracking
- **T1552** — Unsecured Credentials

---

## Ethical Use

This tool is intended for:
- Security auditing of your own passwords
- Penetration testing with explicit authorization
- Academic research and coursework

Do not use against systems or accounts you do not own or have permission to test.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
