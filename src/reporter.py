"""
Report Generator - Produce color-coded HTML reports from audit results.
"""

from pathlib import Path
from datetime import datetime
from auditor import AuditResult


_GRADE_COLORS = {
    "A+": ("#00c853", "#e8f5e9"),
    "A":  ("#43a047", "#f1f8e9"),
    "B":  ("#1e88e5", "#e3f2fd"),
    "C":  ("#fb8c00", "#fff3e0"),
    "D":  ("#e53935", "#ffebee"),
    "F":  ("#b71c1c", "#ffcdd2"),
}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Audit Report</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --green: #3fb950;
    --blue: #58a6ff;
    --orange: #d29922;
    --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 14px; line-height: 1.6; padding: 2rem; }}
  h1 {{ font-size: 1.5rem; color: var(--blue); margin-bottom: 0.25rem; }}
  .meta {{ color: var(--muted); font-size: 12px; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card-title {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 1rem; }}
  .score-row {{ display: flex; align-items: center; gap: 1.5rem; margin-bottom: 1rem; }}
  .grade-badge {{ font-size: 2.5rem; font-weight: 700; padding: 0.4rem 1rem; border-radius: 6px; }}
  .score-num {{ font-size: 3rem; font-weight: 700; }}
  .score-bar-bg {{ background: var(--border); border-radius: 4px; height: 8px; flex: 1; }}
  .score-bar {{ height: 8px; border-radius: 4px; transition: width 0.6s; }}
  table {{ width: 100%; border-collapse: collapse; }}
  td, th {{ padding: 0.4rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 400; }}
  .label {{ color: var(--muted); min-width: 180px; }}
  .val {{ color: var(--text); }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; background: #1c2128; border: 1px solid var(--border); margin: 2px; }}
  .tag.warn {{ background: #2d1a0e; border-color: #7d4c14; color: #d29922; }}
  .suggest {{ padding: 0.4rem 0; display: flex; gap: 0.5rem; }}
  .suggest::before {{ content: "→"; color: var(--blue); }}
  .hash-row {{ font-size: 11px; word-break: break-all; }}
  .algo {{ color: var(--muted); min-width: 80px; display: inline-block; }}
  .crack-row {{ display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px solid var(--border); }}
  .crack-row:last-child {{ border: none; }}
  .crack-label {{ color: var(--muted); }}
  footer {{ color: var(--muted); font-size: 11px; text-align: center; margin-top: 3rem; }}
</style>
</head>
<body>
<h1>🔐 Password Audit Report</h1>
<div class="meta">Generated: {timestamp} · Password Strength Auditor v1.0</div>

{cards}

<footer>Password Strength Auditor · For educational and security research purposes only.</footer>
</body>
</html>"""


def _bar_color(score: int) -> str:
    if score >= 80: return "#3fb950"
    if score >= 60: return "#58a6ff"
    if score >= 40: return "#d29922"
    return "#f85149"


def _mask_password(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def render_single_card(result: AuditResult, mask: bool = True) -> str:
    ct = result.crack_time
    grade_color, grade_bg = _GRADE_COLORS.get(result.grade, ("#888", "#eee"))
    bar_color = _bar_color(result.score)
    display_pw = _mask_password(result.password) if mask else result.password

    # Patterns
    pattern_tags = "".join(
        f'<span class="tag warn">{p}</span>' for p in result.patterns
    ) or '<span class="tag">None detected</span>'

    # Suggestions
    suggestion_html = "".join(
        f'<div class="suggest">{s}</div>' for s in result.suggestions
    )

    # Crack times
    crack_rows = [
        ("Online (rate-limited, 100/s)", ct.human_readable(ct.online_throttled_seconds)),
        ("Online (unthrottled, 10k/s)", ct.human_readable(ct.online_unthrottled_seconds)),
        ("Offline slow hash (10M/s, bcrypt)", ct.human_readable(ct.offline_slow_hash_seconds)),
        ("Offline fast hash (10B/s, MD5/GPU)", ct.human_readable(ct.offline_fast_hash_seconds)),
    ]
    crack_html = "".join(
        f'<div class="crack-row"><span class="crack-label">{lbl}</span><span>{val}</span></div>'
        for lbl, val in crack_rows
    )

    common_flag = '<span style="color:#f85149">⚠ Found in common password lists</span>' if result.is_common \
                  else '<span style="color:#3fb950">✓ Not in common list</span>'

    return f"""
<div class="card">
  <div class="card-title">Password Analysis · <code>{display_pw}</code></div>

  <div class="score-row">
    <div class="grade-badge" style="color:{grade_color};background:{grade_bg}20;border:1px solid {grade_color}40">{result.grade}</div>
    <div>
      <div class="score-num" style="color:{bar_color}">{result.score}<span style="font-size:1.2rem;color:#8b949e">/100</span></div>
    </div>
    <div class="score-bar-bg" style="flex:1">
      <div class="score-bar" style="width:{result.score}%;background:{bar_color}"></div>
    </div>
  </div>

  <div style="margin-bottom:1.5rem">{common_flag}</div>

  <div class="card" style="margin-bottom:1rem">
    <div class="card-title">Entropy Analysis</div>
    <table>
      <tr><td class="label">Password length</td><td class="val">{result.entropy.length} characters</td></tr>
      <tr><td class="label">Character set</td><td class="val">{result.entropy.charset_description}</td></tr>
      <tr><td class="label">Charset size</td><td class="val">{result.entropy.charset_size} symbols</td></tr>
      <tr><td class="label">Raw entropy</td><td class="val">{result.entropy.raw_entropy_bits} bits</td></tr>
      <tr><td class="label">Effective entropy</td><td class="val"><strong>{result.entropy.effective_entropy_bits} bits</strong></td></tr>
    </table>
    {'<div style="margin-top:0.8rem"><span style="color:var(--muted);font-size:12px">Entropy deductions:</span><br>' + ''.join(f'<div style="font-size:12px;padding:2px 0">- {k}: <span style="color:#f85149">-{v:.0f} bits</span></div>' for k, v in result.entropy.deductions.items()) + '</div>' if result.entropy.deductions else ''}
  </div>

  <div class="card" style="margin-bottom:1rem">
    <div class="card-title">Patterns Detected</div>
    {pattern_tags}
  </div>

  <div class="card" style="margin-bottom:1rem">
    <div class="card-title">Estimated Crack Time</div>
    {crack_html}
  </div>

  <div class="card" style="margin-bottom:1rem">
    <div class="card-title">Recommendations</div>
    {suggestion_html}
  </div>

  <div class="card">
    <div class="card-title">Hash Values</div>
    <div class="hash-row"><span class="algo">MD5</span> {result.hash_md5}</div>
    <div class="hash-row"><span class="algo">SHA-1</span> {result.hash_sha1}</div>
    <div class="hash-row"><span class="algo">SHA-256</span> {result.hash_sha256}</div>
  </div>
</div>"""


def generate_report(
    results: list[AuditResult],
    output_path: Path,
    mask_passwords: bool = True,
) -> Path:
    """Generate an HTML report for one or more audit results."""
    cards = "".join(render_single_card(r, mask=mask_passwords) for r in results)
    html = _HTML_TEMPLATE.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        cards=cards,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
