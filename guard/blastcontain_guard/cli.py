"""
BlastContain Guard — CLI.

  blastcontain-guard lint      POLICY                 validate a ruleset
  blastcontain-guard simulate  --policy P --tool T    dry-run a decision
  blastcontain-guard compile   CHARTER                charter.yaml -> ruleset YAML
  blastcontain-guard hook      --policy P             run as a Claude Code hook

The library is what teams embed; the CLI is for authoring, testing, and the
Claude Code integration.
"""
from __future__ import annotations

import sys
from typing import Optional

import click

from . import __version__
from .adapters.claude_code import run_hook
from .compile import compile_charter_file
from .config import GuardConfig, load_config
from .guard import Guard
from .models import Action
from .policy import PolicyError, load_ruleset
from .telemetry import JsonlSink, LedgerSink

_ACTION_MARK = {Action.ALLOW: "✅ allow", Action.ASK: "🟡 ask", Action.DENY: "⛔ deny"}


def _fix_console() -> None:
    # Windows consoles default to cp1252 and choke on the status glyphs.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def _parse_kv(pairs: tuple[str, ...]) -> dict:
    out: dict = {}
    for pair in pairs:
        if "=" not in pair:
            raise click.BadParameter(f"expected key=value, got {pair!r}")
        key, _, value = pair.partition("=")
        out[key.strip()] = _coerce(value.strip())
    return out


def _coerce(value: str):
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def _build_guard(cfg: GuardConfig, *, with_sinks: bool = False) -> Guard:
    """Construct a Guard from a config's policy or charter source."""
    extra_sinks = []
    if with_sinks:
        if cfg.log:
            extra_sinks.append(JsonlSink(cfg.log))
        if cfg.blastcontain_url and not cfg.dry_run and cfg.agent_id:
            extra_sinks.append(LedgerSink(cfg.blastcontain_url, cfg.agent_id))

    agt = None
    if cfg.agt_enabled:
        from .backends import AgtBackend

        agt = AgtBackend(enabled=True, degrade_to_native=cfg.degrade_to_native)

    common = dict(
        agent_id=cfg.agent_id or None,
        environment=cfg.environment or None,
        autonomy_mode=cfg.autonomy_mode,
        extra_sinks=extra_sinks or None,
        agt=agt,
        hitl_timeout_sec=cfg.hitl_timeout_sec,
        escalation_contact=cfg.escalation_contact,
    )

    if cfg.policy:
        return Guard.from_yaml(cfg.policy, **common)
    if cfg.charter:
        # autonomy_mode rides along in `common` (consumed by from_charter_file).
        return Guard.from_charter_file(cfg.charter, **common)
    raise click.UsageError("no policy source: pass --policy <ruleset.yaml> or --charter <charter.yaml>")


@click.group()
@click.version_option(__version__, prog_name="blastcontain-guard")
def main() -> None:
    """BlastContain Guard — the in-process enforcer for copilot agents."""
    _fix_console()


@main.command()
@click.argument("policy", required=False)
@click.option("--charter", default=None, help="Compile and lint a charter.yaml instead")
@click.option("--autonomy-mode", default="interactive", help="interactive | autonomous")
def lint(policy: Optional[str], charter: Optional[str], autonomy_mode: str) -> None:
    """Validate a ruleset (or a compiled Charter) and print its shape."""
    try:
        if charter:
            ruleset = compile_charter_file(charter, autonomy_mode=autonomy_mode)
        elif policy:
            ruleset = load_ruleset(policy)
        else:
            raise click.UsageError("pass a POLICY path or --charter <charter.yaml>")
    except (PolicyError, FileNotFoundError, ValueError) as exc:
        click.echo(f"⛔ invalid: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✅ ok — {ruleset.name}  ({ruleset.api_version})")
    click.echo(f"   default_action: {ruleset.default_action.value}")
    if ruleset.autonomy_mode:
        click.echo(f"   autonomy_mode:  {ruleset.autonomy_mode}")
    click.echo(f"   rules: {len(ruleset.rules)}")
    for rule in ruleset.rules:
        approvers = f" [{', '.join(rule.approvers)}]" if rule.approvers else ""
        concern = f"  ({rule.concern})" if rule.concern else ""
        click.echo(f"     · {rule.name}: {rule.action.value}{approvers}{concern}")
        click.echo(f"         when: {rule.condition}")


@main.command()
@click.option("--policy", "-p", default=None, help="A governance.toolkit/v1 ruleset YAML")
@click.option("--charter", default=None, help="A charter.yaml, compiled offline")
@click.option("--autonomy-mode", default="interactive", help="interactive | autonomous")
@click.option("--tool", required=True, help="Tool name being called")
@click.option("--action-type", default=None, help="Override the action verb (read/write/delete/send/exec)")
@click.option("--arg", "args_kv", multiple=True, help="Tool arg as key=value (repeatable)")
@click.option("--identity", "identity_kv", multiple=True, help="Identity field as key=value (repeatable)")
@click.option("--as-json", is_flag=True, default=False, help="Emit the decision as JSON")
def simulate(
    policy, charter, autonomy_mode, tool, action_type, args_kv, identity_kv, as_json
) -> None:
    """Evaluate one tool call against a policy and print the decision."""
    cfg = GuardConfig(policy=policy, charter=charter, autonomy_mode=autonomy_mode)
    guard = _build_guard(cfg)
    decision = guard.explain(
        tool,
        action_type=action_type,
        args=_parse_kv(args_kv),
        identity=_parse_kv(identity_kv),
    )

    if as_json:
        import json

        click.echo(json.dumps({"tool": tool, **decision.as_dict()}, indent=2))
        return

    click.echo(f"{_ACTION_MARK.get(decision.action, decision.action.value)}  {tool}")
    click.echo(f"   rule:      {decision.rule or '— (default)'}")
    if decision.approvers:
        click.echo(f"   approvers: {', '.join(decision.approvers)}")
    if decision.risk_tag:
        click.echo(f"   risk:      {decision.risk_tag}")
    click.echo(f"   reason:    {decision.reason}")


@main.command(name="compile")
@click.argument("charter")
@click.option("--autonomy-mode", default="interactive", help="interactive | autonomous")
@click.option("--output", "-o", default=None, help="Write the ruleset here (default: stdout)")
def compile_cmd(charter: str, autonomy_mode: str, output: Optional[str]) -> None:
    """Compile a charter.yaml into a governance.toolkit/v1 ruleset."""
    try:
        ruleset = compile_charter_file(charter, autonomy_mode=autonomy_mode)
    except (PolicyError, FileNotFoundError, ValueError) as exc:
        click.echo(f"⛔ cannot compile: {exc}", err=True)
        sys.exit(1)
    text = ruleset.to_yaml()
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)
        click.echo(f"✅ wrote {output}")
    else:
        click.echo(text)


@main.command(name="export-agt")
@click.option("--policy", "-p", default=None, help="A governance.toolkit/v1 ruleset YAML")
@click.option("--charter", default=None, help="A charter.yaml, compiled offline")
@click.option("--autonomy-mode", default=None, help="interactive | autonomous (override)")
@click.option("--endpoint", default=None, help="POST the policy to a running AGT admin endpoint")
@click.option("--token", default=None, help="Bearer token for --endpoint")
@click.option("--output", "-o", default=None, help="Write the AGT policy YAML here (default: stdout)")
@click.option("--no-metadata", is_flag=True, default=False, help="Emit a minimal AGT doc (drop BlastContain metadata)")
def export_agt(policy, charter, autonomy_mode, endpoint, token, output, no_metadata) -> None:
    """Emit (and optionally push) the AGT governance.toolkit/v1 policy for this agent.

    Guard and AGT enforce the same compiled policy; this renders the AGT form of
    it (charter -> ruleset -> clean governance.toolkit/v1, autonomy switch applied).
    """
    from .agt_export import push_to_agt, to_agt_yaml

    try:
        if policy:
            ruleset = load_ruleset(policy)
        elif charter:
            ruleset = compile_charter_file(charter, autonomy_mode=autonomy_mode or "interactive")
        else:
            raise click.UsageError("pass --policy <ruleset.yaml> or --charter <charter.yaml>")
    except (PolicyError, FileNotFoundError, ValueError) as exc:
        click.echo(f"⛔ cannot export: {exc}", err=True)
        sys.exit(1)

    include_metadata = not no_metadata

    if endpoint:
        result = push_to_agt(
            ruleset, endpoint=endpoint, token=token,
            autonomy_mode=autonomy_mode, include_metadata=include_metadata,
        )
        click.echo(f"{'✅' if result.delivered else '⛔'} {result.detail}")
        sys.exit(0 if result.delivered else 1)

    text = to_agt_yaml(ruleset, autonomy_mode=autonomy_mode, include_metadata=include_metadata)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(text)
        click.echo(f"✅ wrote {output}")
    else:
        click.echo(text)


@main.command()
@click.option("--policy", "-p", default=None, help="A governance.toolkit/v1 ruleset YAML")
@click.option("--charter", default=None, help="A charter.yaml, compiled offline")
@click.option("--config", "-c", default=None, help="blastcontain-guard.yaml")
@click.option("--autonomy-mode", default=None, help="interactive | autonomous")
@click.option("--agent-id", default=None, help="Agent id (for telemetry)")
@click.option("--env", default=None, help="Environment")
@click.option("--log", default=None, help="Append decisions to this JSONL file")
@click.option("--fail-closed", is_flag=True, default=False, help="Deny on hook/parse error (default: fail open)")
def hook(policy, charter, config, autonomy_mode, agent_id, env, log, fail_closed) -> None:
    """Run as a Claude Code PreToolUse hook (reads stdin, writes a decision)."""
    cfg = load_config(
        config_file=config,
        cli_overrides={
            "policy": policy, "charter": charter, "autonomy_mode": autonomy_mode,
            "agent_id": agent_id, "environment": env, "log": log,
        },
    )
    try:
        guard = _build_guard(cfg, with_sinks=True)
    except (PolicyError, FileNotFoundError, ValueError, click.UsageError) as exc:
        # Can't even load policy. Fail closed -> deny; else fail open -> allow.
        import json

        decision = "deny" if fail_closed else "allow"
        click.echo(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": f"blastcontain-guard could not load policy: {exc}",
            }
        }))
        sys.exit(0)

    sys.exit(run_hook(guard, fail_open=not fail_closed))


if __name__ == "__main__":
    main()
