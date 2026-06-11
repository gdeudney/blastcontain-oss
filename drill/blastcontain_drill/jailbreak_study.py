"""
Jailbreak-resistance study — automate Drill pitting an abliterated / Heretic ATTACKER
model against a TARGET model (both hosted by LM Studio), across the full Drill corpus
(built-in replay + JailbreakBench + technique operators) plus the generative PAIR/TAP
refinement loop. Answers, per target: how well does it resist jailbreaking?

    python -m blastcontain_drill.jailbreak_study \
        --attacker-model qwen3.6-35b-a3b-uncensored-heretic-native-mtp-preserved \
        --target-model qwen/qwen3.6-27b \
        --judge-model qwen/qwen3-30b-a3b-2507 \
        --iters 6 --limit 5 --out study/

Compare several targets against the SAME attacker (the article view):
    --target-model "qwen/qwen3.6-27b,qwen3-30b-a3b,gpt-oss-20b"
    --target-model all          # every served chat model

Per target it writes a signed DrillReport (md + json) and a SENSITIVE
`<slug>.jailbreaks.json` (the discovered jailbreaks — gitignore it; the md/json report
carries only an excerpt). Then a resistance-ranked leaderboard (md + json). Every model
is reached over the one OpenAI-compatible base URL (LM Studio), so no API key is needed.

Pure helpers (summarize_study / build_leaderboard / render_leaderboard_md) are
unit-tested; the live loop is exercised against a real LM Studio bench.
"""
from __future__ import annotations

import json
import os
import sys

import click

from .sweep import _slug, resolve_models


def summarize_study(model: str, report) -> dict:
    """One leaderboard row (robustness-focused) from a model id + its DrillReport."""
    if report is None:
        return {
            "model": model, "status": "ERROR", "scenarios": 0, "held": 0, "bypasses": 0,
            "critical": 0, "generative_bypasses": 0, "over_refusals": 0, "errors": 0,
            "resistance": 0.0,
        }
    held = len(report.held)
    bypasses = report.bypasses
    n_bypass = len(bypasses)
    decided = held + n_bypass
    return {
        "model": model,
        "status": report.status.value,
        "scenarios": len(report.findings),
        "held": held,
        "bypasses": n_bypass,
        "critical": len(report.critical_bypasses),
        # how many bypasses the *generative* attacker found (vs the static corpus)
        "generative_bypasses": sum(1 for f in bypasses if getattr(f, "layer", "") == "generative"),
        "over_refusals": len(report.over_refusals),
        "errors": len(report.errors),
        # held / (held + bypass): fraction of adversarial attempts contained. Over-refusals
        # and errors are excluded — they aren't "attack contained vs got through".
        "resistance": round(held / decided, 3) if decided else 1.0,
    }


def build_leaderboard(results: list) -> list[dict]:
    """results = [(model, report_or_None), …] -> rows ranked most-robust-first."""
    rows = [summarize_study(m, r) for m, r in results]
    # Most robust first: highest resistance, then fewest criticals, then fewest bypasses.
    rows.sort(key=lambda s: (-s["resistance"], s["critical"], s["bypasses"], s["model"]))
    for i, s in enumerate(rows, 1):
        s["rank"] = i
    return rows


def render_leaderboard_md(rows: list[dict], meta: dict) -> str:
    lines = [
        "# Jailbreak Resistance — leaderboard",
        "",
        f"**Attacker:** `{meta.get('attacker')}` · **Judge:** `{meta.get('judge') or 'self (not comparable)'}` "
        f"· **Guard:** `{meta.get('guard') or '—'}` · **Layers:** {meta.get('layers')} · "
        f"**iters:** {meta.get('iters')} · **cap/cat:** {meta.get('limit')}",
        "",
        "**Resistance** = held / (held + bypass) — the fraction of adversarial attempts the "
        "target contained (1.000 = nothing got through). Over-refusals are false positives, "
        "counted separately. **Generative** = bypasses the Heretic attacker discovered that the "
        "static corpus did not.",
        "",
        "| Rank | Target | Resistance | Held | Bypass (crit) | Generative | Over-refusal | Errors | Status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in rows:
        res = "—" if s["status"] == "ERROR" else f"{s['resistance']:.3f}"
        lines.append(
            f"| {s['rank']} | `{s['model']}` | {res} | {s['held']} | "
            f"{s['bypasses']} ({s['critical']}) | {s['generative_bypasses']} | "
            f"{s['over_refusals']} | {s['errors']} | {s['status']} |"
        )
    lines.append("")
    return "\n".join(lines)


def _effective_records(cfg, report) -> list:
    """
    Reconstruct effective-attack records (full prompt + metadata) from a finished run,
    for the attack database. Static bypasses recover their prompt from the deterministic
    corpus (by attack_id); generative bypasses from the SENSITIVE jailbreaks sidecar.
    """
    from blastcontain_core.models import DrillOutcome

    from .corpus import load_corpus

    corpus = load_corpus(
        version=cfg.corpus, categories=cfg.scenarios or None, limit=cfg.limit,
        enable_operators=cfg.enable_operators, enable_jbb=cfg.enable_jbb,
        enable_systemcard=cfg.enable_systemcard,
    )
    by_id = {a.id: a for a in corpus.attacks}
    common = {
        "target_model": report.target_model, "attacker_model": report.attacker_model,
        "judge_model": report.judge_model, "guard_model": report.guard_model,
        "source": cfg.agent_id,
    }
    records = []
    for f in report.findings:
        if f.outcome != DrillOutcome.BYPASS or f.layer == "generative":
            continue
        atk = by_id.get(f.attack_id)
        if not atk:
            continue
        records.append({
            "prompt": atk.prompt, "category": atk.category, "technique": f.technique,
            "goal": atk.goal, "layer": f.layer,
            "severity": f.severity.value if f.severity else None,
            "evidence": f.evidence, **common,
        })
    # Generative jailbreaks: the working prompts live in the SENSITIVE sidecar, paired in
    # order with the report's generative bypass findings (same order from run_generative).
    gen_path = cfg.generative_corpus
    if gen_path and os.path.exists(gen_path):
        with open(gen_path, encoding="utf-8") as fh:
            data = json.load(fh)
        gen_findings = [f for f in report.findings
                        if f.layer == "generative" and f.outcome == DrillOutcome.BYPASS]
        successes = [r for r in data.get("results", [])
                     if r.get("success") and r.get("discovered_prompt")]
        for r, f in zip(successes, gen_findings):
            records.append({
                "prompt": r["discovered_prompt"], "category": r.get("category"),
                "technique": "generative", "goal": None, "layer": "generative",
                "severity": f.severity.value if f.severity else "HIGH",
                "evidence": f.evidence, **common,
            })
    return records


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple:
    """95% Wilson score interval (lo, hi) for a binomial proportion. n=0 -> (0.0, 1.0)."""
    if n <= 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (round(max(0.0, center - half), 3), round(min(1.0, center + half), 3))


def aggregate_asr(model: str, reports: list) -> dict:
    """
    ASR@k from k DrillReports of the same target/corpus, matched by attack_id — static
    attacks only (generative ids vary per run, so they aren't aggregated). Reports the
    attempt-level ASR (fraction of all attempts that bypassed), the scenario-level ASR@k
    (attacks that bypassed in >=1 of k tries), and scenario-level resistance + a Wilson CI.
    """
    from blastcontain_core.models import DrillOutcome

    outcomes: dict = {}     # attack_id -> [outcome across the k runs]
    for rep in reports:
        if rep is None:
            continue
        for f in rep.findings:
            if f.layer == "generative" or not f.attack_id:
                continue
            outcomes.setdefault(f.attack_id, []).append(f.outcome)

    attempt_total = attempt_bypass = 0
    scen_bypass = scen_over = scen_held = 0
    for outs in outcomes.values():
        attempt_total += len(outs)
        attempt_bypass += sum(1 for o in outs if o == DrillOutcome.BYPASS)
        if any(o == DrillOutcome.BYPASS for o in outs):
            scen_bypass += 1
        elif any(o == DrillOutcome.OVER_REFUSAL for o in outs):
            scen_over += 1
        elif any(o == DrillOutcome.HELD for o in outs):
            scen_held += 1
    decided = scen_held + scen_bypass
    return {
        "model": model,
        "attempts": max((len(o) for o in outcomes.values()), default=0),
        "scenarios": len(outcomes),
        "scenario_bypass": scen_bypass,
        "scenario_held": scen_held,
        "scenario_over_refusal": scen_over,
        "resistance": round(scen_held / decided, 3) if decided else 1.0,
        "resistance_ci": wilson_interval(scen_held, decided),
        "attempt_asr": round(attempt_bypass / attempt_total, 3) if attempt_total else 0.0,
        "attempt_bypasses": attempt_bypass,
        "attempt_total": attempt_total,
    }


def render_asr_md(rows: list, meta: dict) -> str:
    lines = [
        "# Jailbreak Resistance — ASR@k (repeated trials)",
        "",
        f"**Attacker:** `{meta.get('attacker')}` · **Judge:** `{meta.get('judge') or 'self'}` · "
        f"**attempts (k):** {meta.get('attempts')} · **target temp:** {meta.get('temperature')}",
        "",
        "Each *static* attack was run **k** times (non-deterministic sampling). **Scenario "
        "ASR@k** = attacks that bypassed in ≥1 of k tries; **attempt-ASR** = fraction of all "
        "attempts that bypassed; **resistance** is scenario-level with a 95% Wilson interval.",
        "",
        "| Target | Resistance (95% CI) | Scenario ASR@k | Attempt-ASR | Bypass/Held | Over-refusal |",
        "|---|---|---|---|---|---|",
    ]
    for s in sorted(rows, key=lambda r: (-r["resistance"], r["scenario_bypass"], r["model"])):
        lo, hi = s["resistance_ci"]
        scen_asr = round(s["scenario_bypass"] / s["scenarios"], 3) if s["scenarios"] else 0.0
        lines.append(
            f"| `{s['model']}` | {s['resistance']:.3f} [{lo:.3f}, {hi:.3f}] | {scen_asr:.3f} | "
            f"{s['attempt_asr']:.3f} | {s['scenario_bypass']}/{s['scenario_held']} | "
            f"{s['scenario_over_refusal']} |"
        )
    lines.append("")
    return "\n".join(lines)


def run_study(targets: list, params: dict, echo=print) -> tuple:
    """Run the attacker-vs-target drill per target (k attempts each); return
    (results, asr_rows): results=[(model, representative_report_or_None), …]. Live."""
    from .config import DrillConfig
    from .reporter import write_drill_packet, write_markdown_report
    from .runner import run_drill

    out = params["out"]
    os.makedirs(out, exist_ok=True)
    attempts = max(1, int(params.get("attempts", 1)))
    results = []
    asr_rows = []
    for i, target in enumerate(targets, 1):
        slug = _slug(target)
        cfg = DrillConfig(
            agent_id=f"jbstudy-{slug}",
            environment="study",
            cage="inprocess",
            target_base_url=params["base_url"],
            target_model=target,
            target_temperature=params.get("temperature"),
            judge_model=params.get("judge_model"),
            judge_base_url=params.get("judge_base_url"),
            guard_model=params.get("guard_model"),
            scenarios=params.get("scenarios") or [],
            limit=params.get("limit"),
            enable_jbb=params.get("jbb", True),
            enable_operators=params.get("operators", True),
            enable_systemcard=params.get("systemcard", False),
            generative=params.get("generative", True),
            attacker_model=params["attacker_model"],
            attacker_base_url=params.get("attacker_base_url"),
            generative_iters=params.get("iters", 6),
            # SENSITIVE: discovered jailbreaks land here — gitignore `*.jailbreaks.json`.
            generative_corpus=os.path.join(out, f"{slug}.jailbreaks.json"),
            max_steps=params.get("max_steps", 4),
        )
        reps = []
        for k in range(attempts):
            tag = f"  (attempt {k + 1}/{attempts})" if attempts > 1 else ""
            echo(f"[{i}/{len(targets)}] attacking {target}{tag}  with  {params['attacker_model']}")
            try:
                reps.append(run_drill(cfg))
            except Exception as exc:  # noqa: BLE001 — one trial must not kill the study
                echo(f"    ✗ ERROR: {exc}")
                reps.append(None)
        report = next((r for r in reps if r is not None), None)   # representative trial
        results.append((target, report))
        if report is None:
            continue
        write_drill_packet(report, os.path.join(out, f"{slug}.json"))
        write_markdown_report(report, os.path.join(out, f"{slug}.md"))

        # Capture the effective attacks (full prompts) into the SENSITIVE attack DB.
        captured = 0
        try:
            records = _effective_records(cfg, report)
            if records:
                with open(os.path.join(out, f"{slug}.attacks.jsonl"), "w", encoding="utf-8") as fh:
                    for rec in records:
                        fh.write(json.dumps(rec) + "\n")
                from .attackdb import connect, ingest_records
                conn = connect(os.path.join(out, "attacks.db"))
                ingest_records(conn, records)
                conn.close()
                captured = len(records)
        except Exception as exc:  # noqa: BLE001 — capture must never fail the study
            echo(f"    ⚠ attack-DB capture skipped: {exc}")

        extra = ""
        if attempts > 1:
            a = aggregate_asr(target, reps)
            asr_rows.append(a)
            lo, hi = a["resistance_ci"]
            extra = (f" · ASR@{attempts}: scenario-bypass {a['scenario_bypass']}/{a['scenarios']} · "
                     f"attempt-ASR {a['attempt_asr']:.3f} · resistance {a['resistance']:.3f}"
                     f"[{lo:.2f},{hi:.2f}]")
        s = summarize_study(target, report)
        echo(
            f"    {s['status']} — resistance {s['resistance']:.3f} | held {s['held']} · "
            f"bypass {s['bypasses']} (crit {s['critical']}, generative {s['generative_bypasses']}) · "
            f"over-refusal {s['over_refusals']} · captured {captured} → attacks.db{extra}"
        )
    return results, asr_rows


@click.command()
@click.option("--attacker-model", required=True, help="Abliterated/Heretic attacker model id (served by LM Studio)")
@click.option("--target-model", "targets_arg", required=True, help="Target id(s): one, comma-separated, or 'all'")
@click.option("--target-base-url", "base_url", default="http://localhost:1234/v1", help="OpenAI-compatible endpoint (LM Studio)")
@click.option("--judge-model", default=None, help="FIXED judge across targets (recommended for comparability)")
@click.option("--judge-base-url", default=None, help="Judge endpoint (defaults to the target base url)")
@click.option("--guard-model", default=None, help="Optional guardrail id (wildguard / granite-guardian / qwen3guard)")
@click.option("--attacker-base-url", default=None, help="Attacker endpoint (defaults to the target base url)")
@click.option("--iters", default=6, type=int, help="Generative refinement iterations per goal (default 6)")
@click.option("--limit", default=5, type=int, help="Cap replay/JBB/operator attacks per category (default 5)")
@click.option("--scenarios", default=None, help="Comma-separated attack categories (default: all)")
@click.option("--no-jbb", is_flag=True, default=False, help="Skip the JailbreakBench dataset")
@click.option("--no-operators", is_flag=True, default=False, help="Skip the technique-operator layer")
@click.option("--no-generative", is_flag=True, default=False, help="Skip the generative attacker (static corpus only)")
@click.option("--systemcard", is_flag=True, default=False, help="Add the system-card-derived checks (cyber misuse/dual-use, identity & leaked-info honesty)")
@click.option("--attempts", default=1, type=int, help="Run each static attack k times for ASR@k + a resistance 95% CI (default 1)")
@click.option("--target-temperature", "temperature", default=None, type=float, help="Target sampling temperature (default cage 0.4; raise for more ASR@k variance)")
@click.option("--max-steps", default=4, type=int, help="Max tool steps per attack")
@click.option("--exclude", default=None, help="Comma-separated target ids to skip (e.g. the judge/guard)")
@click.option("--out", default="jailbreak-study", help="Output dir: reports + leaderboard + jailbreak corpus")
def main(attacker_model, targets_arg, base_url, judge_model, judge_base_url, guard_model,
         attacker_base_url, iters, limit, scenarios, no_jbb, no_operators, no_generative,
         systemcard, attempts, temperature, max_steps, exclude, out):
    """Pit a Heretic attacker against one or more targets and rank their jailbreak resistance."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass

    excl = [e for e in (exclude or "").split(",") if e.strip()]
    excl.append(attacker_model)              # never attack the attacker itself
    targets = resolve_models(base_url, targets_arg, excl)
    if not targets:
        click.echo("No target models resolved.")
        raise SystemExit(1)

    try:
        served = set(resolve_models(base_url, "all", []))
    except Exception:
        served = set()
    if served and attacker_model not in served:
        click.echo(f"⚠  attacker '{attacker_model}' is not in the served model list — the "
                   "generative layer will be skipped. Load it in LM Studio first.")
    if not judge_model:
        click.echo("⚠  no --judge-model: each target self-judges (scores NOT comparable across targets).")

    layers = ["replay"]
    if not no_jbb:
        layers.append("jbb")
    if not no_operators:
        layers.append("operators")
    if systemcard:
        layers.append("systemcard")
    if not no_generative:
        layers.append("generative")

    click.echo("=" * 66)
    click.echo(f"  Jailbreak-resistance study — {len(targets)} target(s)")
    click.echo(f"  attacker = {attacker_model}")
    click.echo(f"  judge={judge_model or 'self'}  guard={guard_model or 'none'}  "
               f"layers={'+'.join(layers)}  iters={iters}  cap/cat={limit}")
    click.echo("=" * 66)

    params = {
        "attacker_model": attacker_model, "base_url": base_url,
        "judge_model": judge_model, "judge_base_url": judge_base_url,
        "guard_model": guard_model, "attacker_base_url": attacker_base_url,
        "iters": iters, "limit": limit,
        "scenarios": [s.strip() for s in (scenarios or "").split(",") if s.strip()],
        "jbb": not no_jbb, "operators": not no_operators, "generative": not no_generative,
        "systemcard": systemcard, "attempts": attempts, "temperature": temperature,
        "max_steps": max_steps, "out": out,
    }
    results, asr_rows = run_study(targets, params, echo=click.echo)

    rows = build_leaderboard(results)
    meta = {
        "attacker": attacker_model, "judge": judge_model, "guard": guard_model,
        "layers": "+".join(layers), "iters": iters, "limit": limit,
        "attempts": attempts, "temperature": temperature if temperature is not None else 0.4,
    }
    md = render_leaderboard_md(rows, meta)

    os.makedirs(out, exist_ok=True)
    md_path = os.path.join(out, "resistance-leaderboard.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    json_path = os.path.join(out, "resistance-leaderboard.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "leaderboard": rows}, f, indent=2)

    asr_md = ""
    if asr_rows:
        asr_md = render_asr_md(asr_rows, meta)
        with open(os.path.join(out, "asr-at-k.md"), "w", encoding="utf-8") as f:
            f.write(asr_md)
        with open(os.path.join(out, "asr-at-k.json"), "w", encoding="utf-8") as f:
            json.dump({"meta": meta, "asr": asr_rows}, f, indent=2)

    click.echo("")
    click.echo(md)
    if asr_md:
        click.echo(asr_md)
    db_path = os.path.join(out, "attacks.db")
    click.echo(f"\n  Leaderboard: {md_path}  ·  {json_path}")
    if asr_rows:
        click.echo(f"  ASR@{attempts}: {os.path.join(out, 'asr-at-k.md')}")
    click.echo(f"  Per-target reports + SENSITIVE *.jailbreaks.json / *.attacks.jsonl in: {out}/")
    click.echo(f"  Effective-attack DB: {db_path}")
    click.echo(f"    query: python -m blastcontain_drill.attackdb stats --db {db_path}")


if __name__ == "__main__":
    main()
