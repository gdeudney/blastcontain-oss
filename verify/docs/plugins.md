# Writing a check plugin

Since 0.4.0, organizations can add their own checks to `blastcontain-verify`
**without forking**: publish a package that exposes a *check group* through the
`blastcontain_verify.checks` entry point. The scanner discovers it at scan
time, runs it after the built-ins, and folds its results into the same report,
signed audit packet, and SARIF output.

A complete working example lives in
[`examples/plugin-check/`](../examples/plugin-check/).

## The contract

A check group is any object with three members
(`blastcontain_verify.contract.CheckGroup`):

```python
from blastcontain_core.models import InfraFinding, Severity
from blastcontain_verify.contract import CheckContext, CheckGroupResult

class OrgPolicyGroup:
    name = "orgpolicy"                      # shows up in SCAN-<NAME> if you crash
    provides = frozenset({"ORG-01"})        # the check IDs this group owns

    def run(self, ctx: CheckContext) -> CheckGroupResult:
        # ctx.cfg    — the full VerifyConfig (search_path, env, flags...)
        # ctx.state  — cross-group facts; ctx.state.fired holds the check IDs
        #              that produced findings in groups that ran earlier
        ...
        return CheckGroupResult(
            findings=[...],                  # InfraFinding per failed check
            passed=["ORG-01"],               # check IDs that passed
            skipped=[{"check_id": "ORG-02",  # checks that could not run,
                      "reason": "..."}],     #   with a human-readable reason
        )
```

Register it in your package's `pyproject.toml`:

```toml
[project.entry-points."blastcontain_verify.checks"]
orgpolicy = "orgpolicy_demo:OrgPolicyGroup"   # a CheckGroup class or instance
```

`pip install` your package next to `blastcontain-verify` — that's the whole
integration. The startup scan picks it up automatically.

## Rules the loader enforces

- **`provides` must be non-empty and `run` callable** — otherwise the plugin is
  rejected with a `SCAN-PLUGIN` finding and the scan status becomes ERROR
  (an installed-but-broken plugin means the scan is incomplete; that must be
  visible in the packet, never silent).
- **Check IDs are unique across the whole registry.** A plugin claiming an ID
  that a built-in or another plugin owns is rejected. Use an org-specific
  prefix (`ORG-`, `ACME-`) and you will never collide.
- **Crashes are quarantined.** An exception in `run()` becomes a synthetic
  `SCAN-<NAME>` finding; the remaining groups still run and the packet is
  still written — same contract as built-in groups.

## Rules you should follow

- **Report into all three buckets.** A check that can't run must SKIP with a
  reason — in a compliance tool, "we never looked" must be distinguishable
  from "we looked and it's clean."
- **No network calls** (the scan runs under `--network none`), no writes
  outside `/tmp`, and degrade gracefully when an optional dependency is
  missing — see the augmentation checklist in
  [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-augmentation).
- **Map findings to a taxonomy** where you can (`mit_domain` /
  `mit_causal_id` on `InfraFinding`) so downstream tooling can filter them
  like built-in findings.

## Trust model — read this

Plugins are **arbitrary code running in the scanner's process**. Installing a
plugin means trusting its author exactly as much as you trust
`blastcontain-verify` itself. There is deliberately no sandbox — the honest
control is the hardened container the scan runs in (read-only rootfs, no
network, dropped capabilities), which bounds what any code in the scan
process, plugin or not, can do. Review plugin code like you would review a CI
action.
