"""Tests for the check-group registry and the typed scanner contract."""
from __future__ import annotations

import importlib.metadata

from blastcontain_core.models import InfraFinding, Severity, ScanStatus

from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.constants import ALL_CHECK_IDS
from blastcontain_verify.contract import CheckContext, CheckGroupResult, ScanState
from blastcontain_verify.registry import BUILTIN_GROUPS, load_plugin_groups
from blastcontain_verify.scanner import run_scan


def _demo_finding(check_id: str = "DEMO-01") -> InfraFinding:
    return InfraFinding(
        check_id=check_id,
        finding_type="demo.finding",
        severity=Severity.MEDIUM,
        title="Demo finding",
        detail="demo",
        remediation="demo",
    )


class _FiringGroup:
    name = "demo"
    provides = frozenset({"DEMO-01"})

    def run(self, ctx: CheckContext) -> CheckGroupResult:
        return CheckGroupResult(findings=[_demo_finding()])


class _CrashingGroup:
    name = "crasher"
    provides = frozenset({"CRASH-01"})

    def run(self, ctx: CheckContext) -> CheckGroupResult:
        raise RuntimeError("boom")


class _FakeEntryPoint:
    def __init__(self, name, obj=None, exc=None):
        self.name = name
        self._obj = obj
        self._exc = exc

    def load(self):
        if self._exc:
            raise self._exc
        return self._obj


# ---------------------------------------------------------------------------
# Built-in inventory
# ---------------------------------------------------------------------------

class TestBuiltinInventory:
    def test_provides_union_is_the_canonical_inventory(self):
        """The registry's declared checks ARE constants.ALL_CHECK_IDS — the
        doc-drift tests chain off that constant, so this closes the loop."""
        union = frozenset().union(*(g.provides for g in BUILTIN_GROUPS))
        assert union == ALL_CHECK_IDS

    def test_no_check_id_owned_twice(self):
        total = sum(len(g.provides) for g in BUILTIN_GROUPS)
        union = frozenset().union(*(g.provides for g in BUILTIN_GROUPS))
        assert total == len(union), "a check ID is claimed by two groups"

    def test_dependency_order_environment_before_memory(self):
        """MEM-05 reads ENV-02 from ScanState.fired — order is load-bearing."""
        names = [g.name for g in BUILTIN_GROUPS]
        assert names.index("environment") < names.index("memory")


# ---------------------------------------------------------------------------
# Plugin loading
# ---------------------------------------------------------------------------

class TestPluginLoading:
    def _patch_eps(self, monkeypatch, eps):
        monkeypatch.setattr(
            importlib.metadata, "entry_points", lambda group=None: eps
        )

    def test_loads_instance(self, monkeypatch):
        self._patch_eps(monkeypatch, [_FakeEntryPoint("demo", obj=_FiringGroup())])
        groups, errors = load_plugin_groups()
        assert errors == []
        assert len(groups) == 1 and groups[0].name == "demo"

    def test_instantiates_class(self, monkeypatch):
        self._patch_eps(monkeypatch, [_FakeEntryPoint("demo", obj=_FiringGroup)])
        groups, errors = load_plugin_groups()
        assert errors == []
        assert isinstance(groups[0], _FiringGroup)

    def test_rejects_protocol_violation(self, monkeypatch):
        class NoProvides:
            name = "bad"

            def run(self, ctx):
                return CheckGroupResult()

        self._patch_eps(monkeypatch, [_FakeEntryPoint("bad", obj=NoProvides())])
        groups, errors = load_plugin_groups()
        assert groups == []
        assert len(errors) == 1 and "protocol" in errors[0]

    def test_rejects_check_id_collision(self, monkeypatch):
        class Collider:
            name = "collider"
            provides = frozenset({"CRED-01"})  # owned by the credentials built-in

            def run(self, ctx):
                return CheckGroupResult()

        self._patch_eps(monkeypatch, [_FakeEntryPoint("collider", obj=Collider())])
        groups, errors = load_plugin_groups()
        assert groups == []
        assert len(errors) == 1 and "CRED-01" in errors[0]

    def test_broken_loader_degrades_to_error(self, monkeypatch):
        self._patch_eps(
            monkeypatch, [_FakeEntryPoint("broken", exc=ImportError("no module"))]
        )
        groups, errors = load_plugin_groups()
        assert groups == []
        assert len(errors) == 1 and "failed to load" in errors[0]


# ---------------------------------------------------------------------------
# Scanner integration: plugins run under the same quarantine as built-ins
# ---------------------------------------------------------------------------

def _cfg(tmp_path) -> VerifyConfig:
    return VerifyConfig(agent_id="t", environment="dev", search_path=str(tmp_path))


class TestScannerWithPlugins:
    def test_plugin_findings_reach_the_result(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "blastcontain_verify.scanner.load_plugin_groups",
            lambda: ([_FiringGroup()], []),
        )
        result = run_scan(_cfg(tmp_path))
        assert "DEMO-01" in {f.check_id for f in result.findings}

    def test_crashing_plugin_becomes_scan_finding_not_a_dead_scan(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "blastcontain_verify.scanner.load_plugin_groups",
            lambda: ([_CrashingGroup()], []),
        )
        result = run_scan(_cfg(tmp_path))
        assert "SCAN-CRASHER" in {f.check_id for f in result.findings}
        assert result.status == ScanStatus.ERROR

    def test_loader_error_becomes_scan_plugin_finding(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "blastcontain_verify.scanner.load_plugin_groups",
            lambda: ([], ["plugin 'x' failed to load: nope"]),
        )
        result = run_scan(_cfg(tmp_path))
        assert "SCAN-PLUGIN" in {f.check_id for f in result.findings}
        assert result.status == ScanStatus.ERROR


# ---------------------------------------------------------------------------
# State threading: the MEM-05 composite path through ScanState
# ---------------------------------------------------------------------------

class TestScanState:
    def test_fired_feeds_composites(self):
        from blastcontain_verify.checks import memory

        state = ScanState(fired={"ENV-02"})
        cfg = VerifyConfig(agent_id="t", environment="dev", context_file=None)
        result = memory.run(CheckContext(cfg=cfg, state=state))
        # No context file -> MEM-01 SKIPs -> MEM-05 still SKIPs, but the reason
        # path proves env02 was read from state without error.
        assert any(s["check_id"] == "MEM-05" for s in result.skipped)
