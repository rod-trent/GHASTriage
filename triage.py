"""GitHub Advanced Security alert triage report.

Walks every repo for an owner (default: authenticated gh user) and pulls open
Dependabot, code scanning, and secret scanning alerts. Emits Markdown + HTML
reports ranked so the worst-affected repos surface first.

Auth: piggybacks on the local `gh` CLI — no token plumbing needed.
"""

from __future__ import annotations

import argparse
import html
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "unknown"]
DISABLED_HINTS = (
    "not enabled",
    "disabled",
    "no analysis found",
    "advanced security",
    "must be enabled",
)


@dataclass
class AlertBucket:
    status: str = "ok"  # ok | disabled | error
    detail: str = ""
    items: list[dict] = field(default_factory=list)


@dataclass
class RepoReport:
    name: str
    full_name: str
    url: str
    private: bool
    archived: bool
    dependabot: AlertBucket = field(default_factory=AlertBucket)
    code_scanning: AlertBucket = field(default_factory=AlertBucket)
    secret_scanning: AlertBucket = field(default_factory=AlertBucket)

    @property
    def total_alerts(self) -> int:
        return (
            len(self.dependabot.items)
            + len(self.code_scanning.items)
            + len(self.secret_scanning.items)
        )

    @property
    def risk_score(self) -> int:
        score = 0
        for sev in self._all_severities():
            score += SEVERITY_WEIGHTS.get(sev, 1)
        # Secret scanning has no severity field — treat each as high.
        score += len(self.secret_scanning.items) * SEVERITY_WEIGHTS["high"]
        return score

    def _all_severities(self) -> list[str]:
        sevs: list[str] = []
        for a in self.dependabot.items:
            sevs.append(_dependabot_severity(a))
        for a in self.code_scanning.items:
            sevs.append(_code_scanning_severity(a))
        return sevs

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for sev in self._all_severities():
            counts[sev] = counts.get(sev, 0) + 1
        if self.secret_scanning.items:
            counts["secrets"] = counts.get("secrets", 0) + len(self.secret_scanning.items)
        return counts


def _dependabot_severity(alert: dict) -> str:
    adv = alert.get("security_advisory") or {}
    return (adv.get("severity") or "unknown").lower()


def _code_scanning_severity(alert: dict) -> str:
    rule = alert.get("rule") or {}
    sev = rule.get("security_severity_level") or rule.get("severity") or "unknown"
    return sev.lower()


def gh_api(path: str, paginate: bool = True) -> tuple[list | dict | None, str]:
    """Call `gh api`. Returns (parsed_json, error_message). One side will be empty."""
    cmd = ["gh", "api", "-H", "Accept: application/vnd.github+json"]
    if paginate:
        cmd.append("--paginate")
    cmd.append(path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding='utf-8', errors='replace'))
    except FileNotFoundError:
        return None, "gh CLI not found on PATH"
    if result.returncode != 0:
        return None, (result.stderr or result.stdout).strip()
    out = result.stdout.strip()
    if not out:
        return [], ""
    # --paginate concatenates JSON arrays back-to-back as `][`. Patch it.
    if paginate and "][" in out:
        out = out.replace("][", ",")
    try:
        return json.loads(out), ""
    except json.JSONDecodeError as e:
        return None, f"JSON parse error: {e}"


def classify_error(err: str) -> str:
    low = err.lower()
    if any(hint in low for hint in DISABLED_HINTS):
        return "disabled"
    if "404" in err or "not found" in low:
        return "disabled"
    if "403" in err:
        return "disabled"
    return "error"


def fetch_alerts(owner: str, repo: str, kind: str) -> AlertBucket:
    endpoint = {
        "dependabot": f"/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100",
        "code_scanning": f"/repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100",
        "secret_scanning": f"/repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100",
    }[kind]
    data, err = gh_api(endpoint)
    if err:
        status = classify_error(err)
        return AlertBucket(status=status, detail=err.splitlines()[0][:200])
    if not isinstance(data, list):
        return AlertBucket(status="error", detail="unexpected response shape")
    return AlertBucket(status="ok", items=data)


def list_repos(owner: str, include_archived: bool, include_forks: bool) -> list[dict]:
    # /user/repos returns repos the authenticated user owns/collaborates on.
    # affiliation=owner restricts to ones they own.
    if owner == "@me":
        path = "/user/repos?affiliation=owner&per_page=100"
    else:
        path = f"/users/{owner}/repos?per_page=100"
    data, err = gh_api(path)
    if err:
        print(f"ERROR listing repos: {err}", file=sys.stderr)
        sys.exit(1)
    repos = data or []
    if not include_archived:
        repos = [r for r in repos if not r.get("archived")]
    if not include_forks:
        repos = [r for r in repos if not r.get("fork")]
    return repos


def collect_repo_report(repo: dict, owner: str) -> RepoReport:
    rr = RepoReport(
        name=repo["name"],
        full_name=repo["full_name"],
        url=repo["html_url"],
        private=repo.get("private", False),
        archived=repo.get("archived", False),
    )
    rr.dependabot = fetch_alerts(owner, repo["name"], "dependabot")
    rr.code_scanning = fetch_alerts(owner, repo["name"], "code_scanning")
    rr.secret_scanning = fetch_alerts(owner, repo["name"], "secret_scanning")
    return rr


def aggregate_severity(reports: list[RepoReport]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for r in reports:
        for sev, n in r.severity_counts().items():
            totals[sev] = totals.get(sev, 0) + n
    return totals


def render_markdown(reports: list[RepoReport], owner: str, generated: str) -> str:
    affected = [r for r in reports if r.total_alerts > 0]
    affected.sort(key=lambda r: (-r.risk_score, -r.total_alerts, r.name))
    totals = aggregate_severity(reports)

    total_alerts = sum(r.total_alerts for r in reports)
    enabled_counts = {
        "Dependabot": sum(1 for r in reports if r.dependabot.status == "ok"),
        "Code scanning": sum(1 for r in reports if r.code_scanning.status == "ok"),
        "Secret scanning": sum(1 for r in reports if r.secret_scanning.status == "ok"),
    }

    lines: list[str] = []
    lines.append(f"# GitHub Advanced Security Triage — `{owner}`")
    lines.append("")
    lines.append(f"_Generated {generated}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Repos scanned:** {len(reports)}")
    lines.append(f"- **Repos with open alerts:** {len(affected)}")
    lines.append(f"- **Total open alerts:** {total_alerts}")
    lines.append("")
    lines.append("**Alerts by severity**")
    lines.append("")
    if totals:
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for sev in SEVERITY_ORDER + ["secrets"]:
            if totals.get(sev):
                lines.append(f"| {sev} | {totals[sev]} |")
    else:
        lines.append("_No open alerts found._")
    lines.append("")
    lines.append("**Alert sources enabled**")
    lines.append("")
    lines.append("| Source | Repos enabled |")
    lines.append("|---|---:|")
    for name, n in enabled_counts.items():
        lines.append(f"| {name} | {n} / {len(reports)} |")
    lines.append("")

    if affected:
        lines.append("## Top focus areas")
        lines.append("")
        lines.append("| # | Repo | Risk score | Total | Critical | High | Medium | Low | Secrets |")
        lines.append("|---:|---|---:|---:|---:|---:|---:|---:|---:|")
        for i, r in enumerate(affected[:20], start=1):
            sc = r.severity_counts()
            lines.append(
                f"| {i} | [{r.full_name}]({r.url}) | {r.risk_score} | {r.total_alerts} "
                f"| {sc.get('critical', 0)} | {sc.get('high', 0)} | {sc.get('medium', 0)} "
                f"| {sc.get('low', 0)} | {sc.get('secrets', 0)} |"
            )
        lines.append("")

    lines.append("## Per-repo detail")
    lines.append("")
    if not affected:
        lines.append("_No repos with open alerts._")
        lines.append("")
    for r in affected:
        lines.append(f"### [{r.full_name}]({r.url})")
        lines.append("")
        flags = []
        if r.private:
            flags.append("private")
        if r.archived:
            flags.append("archived")
        if flags:
            lines.append(f"_{', '.join(flags)}_")
            lines.append("")
        _render_bucket_md(lines, "Dependabot", r.dependabot, _dep_row)
        _render_bucket_md(lines, "Code scanning", r.code_scanning, _code_row)
        _render_bucket_md(lines, "Secret scanning", r.secret_scanning, _secret_row)

    # Status of disabled / errored sources, in case the user wants to enable them.
    lines.append("## Coverage gaps")
    lines.append("")
    gap_rows: list[str] = []
    for r in reports:
        for label, b in [
            ("Dependabot", r.dependabot),
            ("Code scanning", r.code_scanning),
            ("Secret scanning", r.secret_scanning),
        ]:
            if b.status != "ok":
                gap_rows.append(
                    f"| [{r.full_name}]({r.url}) | {label} | {b.status} | {b.detail} |"
                )
    if gap_rows:
        lines.append("| Repo | Source | Status | Detail |")
        lines.append("|---|---|---|---|")
        lines.extend(gap_rows)
    else:
        lines.append("_All sources enabled on every repo._")
    lines.append("")
    return "\n".join(lines)


def _render_bucket_md(lines, title, bucket: AlertBucket, row_fn) -> None:
    if bucket.status == "disabled":
        return  # noise — covered in Coverage gaps section
    if bucket.status == "error":
        lines.append(f"**{title}** — error: `{bucket.detail}`")
        lines.append("")
        return
    if not bucket.items:
        return
    lines.append(f"**{title}** ({len(bucket.items)})")
    lines.append("")
    header, sep = row_fn(None)
    lines.append(header)
    lines.append(sep)
    for a in bucket.items:
        lines.append(row_fn(a))
    lines.append("")


def _dep_row(a):
    if a is None:
        return (
            "| Severity | Package | Vulnerability | Summary |",
            "|---|---|---|---|",
        )
    adv = a.get("security_advisory") or {}
    pkg = ((a.get("dependency") or {}).get("package") or {}).get("name", "?")
    sev = _dependabot_severity(a)
    ghsa = adv.get("ghsa_id", "")
    summary = (adv.get("summary") or "").replace("|", "\\|")
    return f"| {sev} | `{pkg}` | {ghsa} | {summary} |"


def _code_row(a):
    if a is None:
        return (
            "| Severity | Rule | Path | Message |",
            "|---|---|---|---|",
        )
    rule = a.get("rule") or {}
    inst = a.get("most_recent_instance") or {}
    loc = (inst.get("location") or {}).get("path", "")
    msg = ((inst.get("message") or {}).get("text") or "").replace("|", "\\|")[:160]
    return f"| {_code_scanning_severity(a)} | `{rule.get('id', '?')}` | `{loc}` | {msg} |"


def _secret_row(a):
    if a is None:
        return (
            "| Type | Created | Link |",
            "|---|---|---|",
        )
    kind = a.get("secret_type_display_name") or a.get("secret_type", "?")
    url = a.get("html_url", "")
    link = f"[view]({url})" if url else ""
    return f"| `{kind}` | {a.get('created_at', '')} | {link} |"


# ---------- HTML ----------

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GHAS Triage — {owner}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
    --muted: #8b949e; --link: #58a6ff;
    --critical: #b62324; --high: #db6d28; --medium: #d4a72c; --low: #2f81f7;
    --secret: #a371f7; --ok: #238636;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{ --bg: #ffffff; --card: #f6f8fa; --border: #d0d7de; --text: #1f2328;
             --muted: #57606a; --link: #0969da; }}
  }}
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
          background: var(--bg); color: var(--text); margin: 0; padding: 2rem;
          line-height: 1.5; }}
  h1, h2, h3 {{ border-bottom: 1px solid var(--border); padding-bottom: .3em; }}
  h1 {{ margin-top: 0; }}
  a {{ color: var(--link); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .meta {{ color: var(--muted); font-size: .9em; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem; margin: 1rem 0 2rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px;
           padding: 1rem; }}
  .card .num {{ font-size: 2rem; font-weight: 600; }}
  .card .lbl {{ color: var(--muted); font-size: .85em; text-transform: uppercase;
                letter-spacing: .05em; }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem;
           font-size: .92em; }}
  th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border);
            vertical-align: top; }}
  th {{ background: var(--card); font-weight: 600; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{ display: inline-block; padding: .15em .55em; border-radius: 999px;
            font-size: .78em; font-weight: 600; color: white; text-transform: lowercase; }}
  .badge.critical {{ background: var(--critical); }}
  .badge.high     {{ background: var(--high); }}
  .badge.medium   {{ background: var(--medium); color: #1f2328; }}
  .badge.low      {{ background: var(--low); }}
  .badge.warning  {{ background: var(--high); }}
  .badge.note     {{ background: var(--low); }}
  .badge.unknown  {{ background: var(--muted); }}
  .badge.secrets, .badge.secret {{ background: var(--secret); }}
  .badge.ok       {{ background: var(--ok); }}
  details {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px;
             margin: .5rem 0; padding: 0 1rem; }}
  details summary {{ cursor: pointer; padding: .8rem 0; font-weight: 600; list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::before {{ content: "▶ "; color: var(--muted); }}
  details[open] summary::before {{ content: "▼ "; }}
  details .repo-meta {{ color: var(--muted); font-weight: normal; font-size: .85em;
                        margin-left: .5rem; }}
  code {{ background: var(--card); padding: .1em .4em; border-radius: 4px;
          font-size: .9em; }}
  .gap-status {{ font-style: italic; color: var(--muted); }}
</style>
</head>
<body>
<h1>GHAS Triage — <code>{owner}</code></h1>
<div class="meta">Generated {generated}</div>

<div class="cards">
  <div class="card"><div class="num">{n_repos}</div><div class="lbl">Repos scanned</div></div>
  <div class="card"><div class="num">{n_affected}</div><div class="lbl">Repos with alerts</div></div>
  <div class="card"><div class="num">{n_alerts}</div><div class="lbl">Open alerts</div></div>
  <div class="card"><div class="num">{n_critical}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num">{n_high}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num">{n_secrets}</div><div class="lbl">Secrets</div></div>
</div>

<h2>Coverage by source</h2>
<table>
<tr><th>Source</th><th class="num">Enabled</th><th class="num">Disabled / no access</th></tr>
{coverage_rows}
</table>

<h2>Top focus areas</h2>
{top_table}

<h2>Per-repo detail</h2>
{repo_sections}

<h2>Coverage gaps</h2>
{gap_table}
</body>
</html>
"""


def _badge(text: str, kind: str | None = None) -> str:
    cls = (kind or text).lower()
    return f'<span class="badge {html.escape(cls)}">{html.escape(text)}</span>'


def render_html(reports: list[RepoReport], owner: str, generated: str) -> str:
    affected = [r for r in reports if r.total_alerts > 0]
    affected.sort(key=lambda r: (-r.risk_score, -r.total_alerts, r.name))
    totals = aggregate_severity(reports)
    n_alerts = sum(r.total_alerts for r in reports)

    # Coverage table
    coverage = [
        ("Dependabot", "dependabot"),
        ("Code scanning", "code_scanning"),
        ("Secret scanning", "secret_scanning"),
    ]
    cov_rows: list[str] = []
    for label, attr in coverage:
        enabled = sum(1 for r in reports if getattr(r, attr).status == "ok")
        disabled = len(reports) - enabled
        cov_rows.append(
            f"<tr><td>{label}</td><td class='num'>{enabled}</td>"
            f"<td class='num'>{disabled}</td></tr>"
        )

    # Top table
    if affected:
        rows = []
        for i, r in enumerate(affected[:20], start=1):
            sc = r.severity_counts()
            rows.append(
                f"<tr><td class='num'>{i}</td>"
                f"<td><a href='{html.escape(r.url)}'>{html.escape(r.full_name)}</a></td>"
                f"<td class='num'>{r.risk_score}</td>"
                f"<td class='num'>{r.total_alerts}</td>"
                f"<td class='num'>{sc.get('critical', 0)}</td>"
                f"<td class='num'>{sc.get('high', 0)}</td>"
                f"<td class='num'>{sc.get('medium', 0)}</td>"
                f"<td class='num'>{sc.get('low', 0)}</td>"
                f"<td class='num'>{sc.get('secrets', 0)}</td></tr>"
            )
        top_table = (
            "<table><tr><th class='num'>#</th><th>Repo</th><th class='num'>Risk</th>"
            "<th class='num'>Total</th><th class='num'>Critical</th><th class='num'>High</th>"
            "<th class='num'>Medium</th><th class='num'>Low</th><th class='num'>Secrets</th></tr>"
            + "".join(rows)
            + "</table>"
        )
    else:
        top_table = "<p><em>No repos with open alerts.</em></p>"

    # Per-repo sections
    sections: list[str] = []
    for r in affected:
        flags = []
        if r.private:
            flags.append("private")
        if r.archived:
            flags.append("archived")
        flag_str = f" · {', '.join(flags)}" if flags else ""
        sc = r.severity_counts()
        sev_summary = " ".join(
            _badge(f"{sev} {n}", sev) for sev, n in sc.items() if n
        )
        body_parts: list[str] = []
        if r.dependabot.items:
            body_parts.append(_html_dependabot(r.dependabot))
        if r.code_scanning.items:
            body_parts.append(_html_code(r.code_scanning))
        if r.secret_scanning.items:
            body_parts.append(_html_secret(r.secret_scanning))
        sections.append(
            f"<details><summary>"
            f"<a href='{html.escape(r.url)}'>{html.escape(r.full_name)}</a> "
            f"<span class='repo-meta'>· {r.total_alerts} alerts · risk {r.risk_score}{flag_str}</span> "
            f"{sev_summary}</summary>"
            + "".join(body_parts)
            + "</details>"
        )
    repo_sections = "".join(sections) if sections else "<p><em>No repos with open alerts.</em></p>"

    # Coverage gaps
    gap_rows: list[str] = []
    for r in reports:
        for label, attr in coverage:
            b = getattr(r, attr)
            if b.status != "ok":
                gap_rows.append(
                    f"<tr><td><a href='{html.escape(r.url)}'>{html.escape(r.full_name)}</a></td>"
                    f"<td>{label}</td><td><span class='gap-status'>{html.escape(b.status)}</span></td>"
                    f"<td><code>{html.escape(b.detail)}</code></td></tr>"
                )
    if gap_rows:
        gap_table = (
            "<table><tr><th>Repo</th><th>Source</th><th>Status</th><th>Detail</th></tr>"
            + "".join(gap_rows)
            + "</table>"
        )
    else:
        gap_table = "<p><em>All sources enabled on every repo.</em></p>"

    return HTML_TEMPLATE.format(
        owner=html.escape(owner),
        generated=html.escape(generated),
        n_repos=len(reports),
        n_affected=len(affected),
        n_alerts=n_alerts,
        n_critical=totals.get("critical", 0),
        n_high=totals.get("high", 0),
        n_secrets=totals.get("secrets", 0),
        coverage_rows="\n".join(cov_rows),
        top_table=top_table,
        repo_sections=repo_sections,
        gap_table=gap_table,
    )


def _html_dependabot(b: AlertBucket) -> str:
    rows = []
    for a in b.items:
        adv = a.get("security_advisory") or {}
        pkg = ((a.get("dependency") or {}).get("package") or {}).get("name", "?")
        sev = _dependabot_severity(a)
        ghsa = adv.get("ghsa_id", "")
        ghsa_url = adv.get("references", [{}])[0].get("url") if adv.get("references") else ""
        ghsa_link = (
            f"<a href='{html.escape(ghsa_url)}'>{html.escape(ghsa)}</a>" if ghsa_url else html.escape(ghsa)
        )
        summary = html.escape(adv.get("summary") or "")
        rows.append(
            f"<tr><td>{_badge(sev)}</td><td><code>{html.escape(pkg)}</code></td>"
            f"<td>{ghsa_link}</td><td>{summary}</td></tr>"
        )
    return (
        f"<h4>Dependabot ({len(b.items)})</h4>"
        "<table><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Summary</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def _html_code(b: AlertBucket) -> str:
    rows = []
    for a in b.items:
        rule = a.get("rule") or {}
        inst = a.get("most_recent_instance") or {}
        loc = (inst.get("location") or {}).get("path", "")
        msg = (inst.get("message") or {}).get("text") or ""
        url = a.get("html_url", "")
        rule_id = rule.get("id", "?")
        rule_cell = (
            f"<a href='{html.escape(url)}'><code>{html.escape(rule_id)}</code></a>"
            if url
            else f"<code>{html.escape(rule_id)}</code>"
        )
        rows.append(
            f"<tr><td>{_badge(_code_scanning_severity(a))}</td>"
            f"<td>{rule_cell}</td>"
            f"<td><code>{html.escape(loc)}</code></td>"
            f"<td>{html.escape(msg[:240])}</td></tr>"
        )
    return (
        f"<h4>Code scanning ({len(b.items)})</h4>"
        "<table><tr><th>Severity</th><th>Rule</th><th>Path</th><th>Message</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def _html_secret(b: AlertBucket) -> str:
    rows = []
    for a in b.items:
        kind = a.get("secret_type_display_name") or a.get("secret_type", "?")
        url = a.get("html_url", "")
        link = f"<a href='{html.escape(url)}'>view</a>" if url else ""
        rows.append(
            f"<tr><td>{_badge('secret')}</td>"
            f"<td><code>{html.escape(kind)}</code></td>"
            f"<td>{html.escape(a.get('created_at', ''))}</td>"
            f"<td>{link}</td></tr>"
        )
    return (
        f"<h4>Secret scanning ({len(b.items)})</h4>"
        "<table><tr><th></th><th>Type</th><th>Created</th><th>Link</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Generate a GHAS triage report across your repos.")
    p.add_argument("--owner", default="@me",
                   help="GitHub user/org to scan (default: authenticated user)")
    p.add_argument("--output-dir", default=".", help="Where to write the reports")
    p.add_argument("--include-archived", action="store_true")
    p.add_argument("--include-forks", action="store_true")
    p.add_argument("--workers", type=int, default=6, help="Parallel repo fetches")
    args = p.parse_args()

    if not shutil.which("gh"):
        print("gh CLI not found on PATH", file=sys.stderr)
        return 1

    # Resolve @me to a real login so it shows up in the report.
    if args.owner == "@me":
        data, err = gh_api("/user", paginate=False)
        if err or not isinstance(data, dict):
            print(f"Could not resolve authenticated user: {err}", file=sys.stderr)
            return 1
        owner = data["login"]
    else:
        owner = args.owner

    print(f"Listing repos for {owner}...", file=sys.stderr)
    repos = list_repos(args.owner, args.include_archived, args.include_forks)
    print(f"Found {len(repos)} repos. Scanning alerts...", file=sys.stderr)

    reports: list[RepoReport] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(collect_repo_report, r, owner): r for r in repos}
        for i, fut in enumerate(as_completed(futures), start=1):
            rr = fut.result()
            reports.append(rr)
            print(f"  [{i}/{len(repos)}] {rr.full_name} - {rr.total_alerts} alerts",
                  file=sys.stderr)

    reports.sort(key=lambda r: r.full_name)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "security-report.md"
    html_path = out_dir / "security-report.html"
    md_path.write_text(render_markdown(reports, owner, generated), encoding="utf-8")
    html_path.write_text(render_html(reports, owner, generated), encoding="utf-8")
    print(f"\nWrote {md_path}", file=sys.stderr)
    print(f"Wrote {html_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
