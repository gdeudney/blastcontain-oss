"""
BlastContain Verify — scan orchestrator.

Thin orchestrator: walks the check-group registry (built-ins + entry-point
plugins, see `registry.py`), collects each group's typed result, derives the
final status, and returns a ScanResult.

Resilience contract — nothing here may kill the scan:
  - every group's run() is wrapped in `except BaseException`; a crash becomes
    a synthetic SCAN-<GROUP> finding and the remaining groups continue;
  - a plugin that fails to load or collides with existing check IDs becomes a
    SCAN-PLUGIN finding the same way.
Either case flips the overall status to ERROR, and the audit packet is still
written so the failure is auditable.

User-specified `skip_checks` are filtered from each group's results post-hoc:
the check runs, but matching findings/passes are coerced to SKIP with the
"User-requested skip" reason. Coerced findings are NOT recorded in
ScanState.fired, so skipping a prerequisite (e.g. ENV-02) also suppresses its
composites (MEM-05) — longstanding behavior, preserved.
"""
from __future__ import annotations

import traceback

from .augmentation import AUGMENTATION_FLAGS
from .config import VerifyConfig
from .constants import TIER_BLAST_WEIGHTS
from .contract import CheckContext, ScanState
from .models import InfraFinding, ScanResult, ScanStatus, Severity
from .registry import BUILTIN_GROUPS, load_plugin_groups


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


def _plugin_error_finding(error: str) -> InfraFinding:
    """Synthetic finding for a plugin that failed to load or register."""
    return InfraFinding(
        check_id="SCAN-PLUGIN",
        finding_type="blastcontain.scanner.plugin_failed",
        severity=Severity.HIGH,
        title="A check plugin failed to load",
        detail=(
            "A third-party check group registered via the "
            "'blastcontain_verify.checks' entry point could not be used, so its "
            "checks did not run and this scan is incomplete. "
            f"Loader error: {error}"
        ),
        remediation=(
            "Fix or uninstall the plugin package. A plugin must expose a "
            "CheckGroup (non-empty `provides`, callable `run(ctx)`) and must not "
            "claim check IDs that already exist. See docs/plugins.md."
        ),
        evidence=error[:500],
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
    Run every registered check group, in registry order, and return a ScanResult.

    Order is part of the registry contract: groups that feed composites run
    before their consumers (environment before memory — MEM-05 reads ENV-02
    from ScanState.fired). Plugins run after all built-ins.
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

    state = ScanState()
    ctx = CheckContext(cfg=cfg, state=state)

    plugin_groups, plugin_errors = load_plugin_groups()
    for error in plugin_errors:
        scanner_errored = True
        all_findings.append(_plugin_error_finding(error))

    for group in (*BUILTIN_GROUPS, *plugin_groups):
        try:
            group_result = group.run(ctx)
        except BaseException as exc:  # noqa: BLE001 — quarantine: nothing kills the scan
            scanner_errored = True
            all_findings.append(_error_finding(group.name, exc))
            continue

        f, p, s = _apply_skip_filter(
            group_result.findings, group_result.passed, group_result.skipped, skip_set,
        )
        all_findings.extend(f)
        all_passed.extend(p)
        all_skipped.extend(s)
        state.fired.update(finding.check_id for finding in f)

    result.findings = all_findings
    result.passed = all_passed
    result.skipped = all_skipped

    if scanner_errored:
        result.status = ScanStatus.ERROR
    else:
        result.status = result.derive_status()

    return result
