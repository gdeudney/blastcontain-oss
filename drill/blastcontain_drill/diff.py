"""
drill diff — regression delta between two signed DrillReports.

Compares a BASELINE report (A) against a CANDIDATE (B), matching findings by
`scenario_id`, and classifies each shared scenario's change:

  - **regression** — a scenario that now BYPASSES but didn't (held -> bypass),
  - **fix** — a bypass that no longer bypasses (bypass -> held / over-refusal),
  - **severity change** — bypass in both, but the severity moved,
  - **other change** — any other outcome flip (e.g. held -> over-refusal),

plus **added** / **removed** scenarios (e.g. a different corpus or model), with the
added ones that bypass called out separately as *new* bypasses.

It exits non-zero when the candidate regressed, so it gates CI and model-to-model or
before/after promotion at a glance.

    python -m blastcontain_drill.diff baseline.json candidate.json [--report out.md] [--json out.json]
    blastcontain-drill-diff baseline.json candidate.json
"""
from __future__ import annotations

import json
import sys
from typing import Optional

import click

BYPASS = "BYPASS"
# Severity ordering so an escalation (HIGH -> CRITICAL) is distinguishable from a de-escalation.
_SEV_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "": 0}


def load_report(path: str) -> dict:
    """Load a DrillReport from a signed envelope ({packet, signature}) or a bare report dict.

    Raises ValueError if the file is valid JSON but not an object (a list / scalar / null),
    so the CLI maps it to a clean read-error exit instead of crashing on untrusted input."""
    with open(path, encoding="utf-8-sig") as f:   # tolerate an optional BOM
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("packet"), dict):
        data = data["packet"]
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a DrillReport object, got {type(data).__name__}")
    return data


def _index(report: dict) -> dict:
    """Map scenario_id -> finding (last wins on the rare duplicate id)."""
    out: dict = {}
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue                       # tolerate a junk entry in a hand-edited report
        sid = f.get("scenario_id")
        if sid is not None:
            out[sid] = f
    return out


def _outcome(f: Optional[dict]) -> Optional[str]:
    return str(f.get("outcome") or "").upper() if f else None


def _sev(f: Optional[dict]) -> Optional[str]:
    return (f.get("severity") or None) if f else None


def _sev_rank(f: Optional[dict]) -> int:
    return _SEV_RANK.get(str(_sev(f) or "").upper(), 0)


def _row(sid: str, a: Optional[dict], b: Optional[dict]) -> dict:
    """A change row for one scenario; a or b may be None (added / removed)."""
    src = b or a or {}
    return {
        "scenario_id": sid,
        "scenario_name": src.get("scenario_name"),
        "technique": src.get("technique"),
        "a_outcome": _outcome(a),
        "b_outcome": _outcome(b),
        "a_severity": _sev(a),
        "b_severity": _sev(b),
    }


def _meta(report: dict) -> dict:
    bench = report.get("bench") or {}
    summary = report.get("summary") or {}
    return {
        "agent_id": report.get("agent_id"),
        "status": report.get("status"),
        "corpus_version": report.get("corpus_version"),
        "target_model": bench.get("target_model"),
        "judge_model": bench.get("judge_model"),
        "bypasses": summary.get("bypasses"),
        "critical_bypasses": summary.get("critical_bypasses"),
    }


def diff_reports(a: dict, b: dict) -> dict:
    """Classify every scenario's change between baseline `a` and candidate `b`."""
    ia, ib = _index(a), _index(b)
    a_keys, b_keys = set(ia), set(ib)

    regressions, fixes, other_changes, severity_changes = [], [], [], []
    for sid in sorted(a_keys & b_keys, key=str):
        fa, fb = ia[sid], ib[sid]
        oa, ob = _outcome(fa), _outcome(fb)
        if oa != ob:
            row = _row(sid, fa, fb)
            if ob == BYPASS:
                regressions.append(row)              # something that didn't bypass now does
            elif oa == BYPASS and ob in ("HELD", "OVER_REFUSAL"):
                fixes.append(row)                    # a bypass was closed by a real defence
            else:
                # held<->over-refusal, or BYPASS->ERROR (inconclusive — NOT a green "fix")
                other_changes.append(row)
        elif oa == BYPASS and ob == BYPASS and _sev_rank(fa) != _sev_rank(fb):
            severity_changes.append(_row(sid, fa, fb))

    added = [_row(sid, None, ib[sid]) for sid in sorted(b_keys - a_keys, key=str)]
    removed = [_row(sid, ia[sid], None) for sid in sorted(a_keys - b_keys, key=str)]
    added_bypassing = [r for r in added if r["b_outcome"] == BYPASS]

    return {
        "baseline": _meta(a),
        "candidate": _meta(b),
        "regressions": regressions,
        "fixes": fixes,
        "severity_changes": severity_changes,
        "other_changes": other_changes,
        "added": added,
        "removed": removed,
        "added_bypassing": added_bypassing,
        "counts": {
            "regressions": len(regressions),
            "fixes": len(fixes),
            "severity_changes": len(severity_changes),
            "other_changes": len(other_changes),
            "added": len(added),
            "removed": len(removed),
            "added_bypassing": len(added_bypassing),
        },
    }


def should_fail(delta: dict, gate: str) -> bool:
    """Gate policy: 'regression' (default) fails on a shared scenario flipping to bypass;
    'any-bypass' also fails on a newly-added scenario that bypasses; 'none' never fails."""
    c = delta["counts"]
    if gate == "none":
        return False
    if gate == "any-bypass":
        return bool(c["regressions"] or c["added_bypassing"])
    return bool(c["regressions"])


def _table(title: str, rows: list, show_sev: bool = False) -> list:
    if not rows:
        return []
    out = [f"### {title}", "", "| Scenario | Technique | Baseline | Candidate |", "|---|---|---|---|"]
    for r in rows:
        a, b = r["a_outcome"] or "—", r["b_outcome"] or "—"
        if show_sev:
            a = f"{a} {r['a_severity'] or ''}".strip()
            b = f"{b} {r['b_severity'] or ''}".strip()
        out.append(f"| `{r['scenario_id']}` | {r['technique'] or '—'} | {a} | {b} |")
    return out + [""]


def render_markdown(delta: dict) -> str:
    c, base, cand = delta["counts"], delta["baseline"], delta["candidate"]
    lines = [
        "# BlastContain Drill — Regression Diff",
        "",
        f"**Baseline:** `{base['target_model'] or base['agent_id'] or '—'}` "
        f"(status {base['status']}, {base['bypasses']} bypass) · corpus `{base['corpus_version']}`",
        f"**Candidate:** `{cand['target_model'] or cand['agent_id'] or '—'}` "
        f"(status {cand['status']}, {cand['bypasses']} bypass) · corpus `{cand['corpus_version']}`",
        "",
        "## Delta",
        "",
        f"- 🔴 **Regressions (→ BYPASS):** {c['regressions']}",
        f"- 🟢 **Fixes (bypass closed):** {c['fixes']}",
        f"- 🟠 **Severity changes:** {c['severity_changes']}",
        f"- **Other verdict changes:** {c['other_changes']}",
        f"- **Added scenarios:** {c['added']} (bypassing: {c['added_bypassing']})",
        f"- **Removed scenarios:** {c['removed']}",
        "",
    ]
    if not any(c.values()):
        lines += ["_No differences._", ""]
    lines += _table("🔴 Regressions", delta["regressions"], show_sev=True)
    lines += _table("🟢 Fixes", delta["fixes"], show_sev=True)
    lines += _table("🟠 Severity changes", delta["severity_changes"], show_sev=True)
    lines += _table("Other verdict changes", delta["other_changes"])
    lines += _table("Added — newly bypassing", delta["added_bypassing"], show_sev=True)
    return "\n".join(lines)


@click.command("drill-diff")
@click.argument("baseline")
@click.argument("candidate")
@click.option("--report", default=None, help="Write the Markdown diff to this path")
@click.option("--json", "json_out", default=None, help="Write the structured delta JSON to this path")
@click.option("--gate", type=click.Choice(["regression", "any-bypass", "none"]), default="regression",
              help="Exit-1 policy: regression (default) | any-bypass | none")
def main(baseline, candidate, report, json_out, gate):
    """Diff two signed DrillReports (BASELINE then CANDIDATE). Exit 1 on regression, 2 on read error."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass
    try:
        a, b = load_report(baseline), load_report(candidate)
        delta = diff_reports(a, b)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        # untrusted external JSON — any read/parse/shape error is a clean exit-2, not a crash
        click.echo(f"Error: could not read or parse reports: {exc}", err=True)
        sys.exit(2)

    md = render_markdown(delta)
    click.echo(md)

    try:
        if report:
            with open(report, "w", encoding="utf-8") as f:
                f.write(md)
            click.echo(f"\n  Diff report: {report}")
        if json_out:
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(delta, f, indent=2)
            click.echo(f"  Delta JSON:  {json_out}")
    except OSError as exc:
        # a write failure must NOT masquerade as a regression (exit 1) in CI
        click.echo(f"Error: could not write output: {exc}", err=True)
        sys.exit(2)

    sys.exit(1 if should_fail(delta, gate) else 0)


if __name__ == "__main__":
    main()
