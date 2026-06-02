"""
BlastContain Verify — scan orchestrator.

Thin orchestrator: runs each check group module, collects results,
derives final status, posts to Ledger if configured.

Each check group is wrapped in try/except so a single failing check
produces a synthetic ERROR finding and the remaining groups continue
to run.

User-specified `skip_checks` are filtered from each check group's
results post-hoc: the check runs (because the result feeds other
checks like MEM-05), but any matching findings are downgraded to
SKIP and any passes/skips with the same ID are coerced to the
"User-requested skip" reason.
"""
from __future__ import annotations

import traceback

from .augmentation import AUGMENTATION_FLAGS
from .config import VerifyConfig
from .constants import TIER_BLAST_WEIGHTS
from .models import InfraFinding, ScanResult, ScanStatus, Severity

from .checks import (
    environment,
    filesystem,
    credentials,
    process,
    network,
    persistence,
    memory,
    skills,
    api,
    mcp,
    code,
    supply_chain,
    tls,
    local,
)


def _error_finding(group_name: str, exc: BaseException) -> InfraFinding:
    """Synthetic finding emitted when a check group raises an unexpected exception."""
    tb_short = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    return InfraFinding(
        check_id=f"SCAN-{group_name.upper()}",
        finding_type="blastcontain.scanner.check_group_failed",
        severity=Severity.HIGH,
        title=f"Check group '{group_name}' raised an unexpected exception",
        detail=(
            f"The check group `{group_name}` raised an unhandled exception during scan. "
            "Remaining check groups continued to run, but this group's results are "
            "incomplete. This is a scanner bug — please file an issue with the "
            "traceback below."
        ),
        remediation=(
            "Re-run with `--verbose` for the full traceback. "
            "If the issue persists, downgrade to the previous Verify version or "
            "file an issue at https://github.com/<org>/blastcontain/issues."
        ),
        evidence=tb_short[:500],
    )


def _apply_skip_filter(
    findings: list[InfraFinding],
    passed: list[str],
    skipped: list[dict],
    skip_checks: set[str],
) -> tuple[list[InfraFinding], list[str], list[dict]]:
    """
    Move any check_id in skip_checks out of findings/passed and into skipped.

    Returns filtered (findings, passed, skipped) tuples.
    """
    if not skip_checks:
        return findings, passed, skipped

    # Findings that match skip_checks become SKIP records
    kept_findings: list[InfraFinding] = []
    coerced_skips: list[dict] = []
    for f in findings:
        if f.check_id in skip_checks:
            coerced_skips.append({
                "check_id": f.check_id,
                "reason": "User-requested skip (--skip-checks)",
            })
        else:
            kept_findings.append(f)

    # Passes that match skip_checks become SKIP records
    kept_passed: list[str] = []
    for pid in passed:
        if pid in skip_checks:
            coerced_skips.append({
                "check_id": pid,
                "reason": "User-requested skip (--skip-checks)",
            })
        else:
            kept_passed.append(pid)

    # Existing skips for the same check_id keep the first reason recorded
    seen = {s["check_id"] for s in skipped}
    for entry in coerced_skips:
        if entry["check_id"] not in seen:
            skipped.append(entry)
            seen.add(entry["check_id"])

    return kept_findings, kept_passed, skipped


def run_scan(cfg: VerifyConfig) -> ScanResult:
    """
    Run all check groups and return a ScanResult.

    Check groups run in dependency order:
    1. Process + privilege checks (no dependencies)
    2. Environment checks  (ENV-02 result feeds MEM-05)
    3. Filesystem + network + persistence + local (independent)
    4. Credentials (independent)
    5. Memory (depends on ENV-02 and CRED-02 results)
    6. Code + supply chain + TLS (independent)
    7. Skills + API + MCP (depend on config inputs)
    """
    result = ScanResult(
        agent_id=cfg.agent_id,
        environment=cfg.environment,
        blast_radius_factor=TIER_BLAST_WEIGHTS.get(cfg.max_tier, 1.0),
        max_tier=cfg.max_tier,
        augmentation=AUGMENTATION_FLAGS,
    )

    all_findings: list[InfraFinding] = []
    all_passed: list[str] = []
    all_skipped: list[dict] = []
    scanner_errored = False

    skip_set: set[str] = {c.strip().upper() for c in cfg.skip_checks if c.strip()}

    def collect(group_name: str, module_run_fn, **kwargs) -> list[InfraFinding]:
        """
        Run a check group inside a try/except. On exception, emit a synthetic
        SCAN-<group> error finding and return [].
        """
        nonlocal scanner_errored
        try:
            f, p, s = module_run_fn(**kwargs)
        except BaseException as exc:  # noqa: BLE001 — we want to catch everything
            scanner_errored = True
            err = _error_finding(group_name, exc)
            all_findings.append(err)
            return [err]

        f, p, s = _apply_skip_filter(f, p, s, skip_set)
        all_findings.extend(f)
        all_passed.extend(p)
        all_skipped.extend(s)
        return f

    # ── Privilege + process ────────────────────────────────────────────────────
    collect("process", process.run)

    # ── Environment ───────────────────────────────────────────────────────────
    env_findings = collect(
        "environment",
        environment.run,
        model_dir=cfg.model_dir,
        egress_probe_target=cfg.egress_probe_target,
    )
    env02_fired = any(f.check_id == "ENV-02" for f in env_findings)

    # ── Filesystem, network, persistence, local ────────────────────────────────
    collect("filesystem", filesystem.run, environment=cfg.environment)
    collect("network", network.run, egress_probe_target=cfg.egress_probe_target)
    collect("persistence", persistence.run)
    collect("local", local.run)

    # ── Credentials ───────────────────────────────────────────────────────────
    collect("credentials", credentials.run, search_path=cfg.search_path)

    # ── Memory (uses ENV-02 result) ────────────────────────────────────────────
    collect(
        "memory",
        memory.run,
        context_file=cfg.context_file,
        env02_fired=env02_fired,
    )

    # ── Code + supply chain + TLS ─────────────────────────────────────────────
    collect("code", code.run, search_path=cfg.search_path)
    collect("supply_chain", supply_chain.run, model_dir=cfg.model_dir)
    collect("tls", tls.run, search_path=cfg.search_path)

    # ── Skills + API + MCP ────────────────────────────────────────────────────
    collect(
        "skills",
        skills.run,
        skills_dir=cfg.effective_skills_dir() if cfg.skills_dir or cfg.search_path else None,
    )
    collect("api", api.run, api_spec=cfg.api_spec, live_probe=cfg.api_live_probe)
    collect(
        "mcp",
        mcp.run,
        mcp_config=cfg.mcp_config,
        permitted_tools=None,  # Phase 3: pull from Charter
        cisco_api_key=cfg.cisco_api_key,
    )

    result.findings = all_findings
    result.passed = all_passed
    result.skipped = all_skipped

    if scanner_errored:
        result.status = ScanStatus.ERROR
    else:
        result.status = result.derive_status()

    return result
