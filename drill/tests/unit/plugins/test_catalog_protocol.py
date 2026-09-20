"""Metadata discovery and wire trust boundaries; no container required."""

from dataclasses import replace
import io
import json
import sys

from click.testing import CliRunner
import pytest

from blastcontain_drill.contracts import AcceptanceRecord, ContractError, Injection, PluginManifest
from blastcontain_drill.contracts.legacy import scenario_from_attack
from blastcontain_drill.corpus import BuiltinReplaySource
from blastcontain_drill.plugins.catalog import (
    check_acceptance,
    discover,
    read_acceptances,
    read_metadata,
    review_digest,
    select,
)
from blastcontain_drill.plugins.cli import main
from blastcontain_drill.plugins.protocol import ProtocolError, decode, encode
from blastcontain_drill.plugins.runtime import WorkerError, WorkerLimits, validate_isolation
from blastcontain_drill.plugins.sdk import Broker, serve


def manifest(**changes):
    return replace(
        PluginManifest(
            "example",
            "1.0",
            "sha256:" + "a" * 64,
            ("attack_strategy",),
            ("prompt.single",),
            "Apache-2.0",
            access_requests=("broker.target",),
        ),
        **changes,
    )


def accepted(item):
    return AcceptanceRecord(
        item.id,
        "plugin",
        review_digest(item),
        "fixture-reviewer",
        "accepted",
        "2026-09-20T00:00:00Z",
        "Controlled test image",
        item.access_requests,
    )


def write_manifest(path, item):
    path.write_text(json.dumps(item.to_dict()))


def test_discovery_never_imports_installed_plugin_code(tmp_path, monkeypatch):
    marker = tmp_path / "imported.txt"
    (tmp_path / "malicious.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    item = manifest(upstream="malicious:plugin")
    write_manifest(tmp_path / "example.drill-plugin.json", item)
    result = discover([tmp_path], [accepted(item)], lambda _: True)[0]
    assert result.installed and result.compatible and result.accepted and result.available
    assert not marker.exists() and "malicious" not in sys.modules
    assert select([tmp_path], "example", [accepted(item)]) == item


def test_installed_accepted_compatible_and_available_are_independent(tmp_path):
    item = manifest()
    write_manifest(tmp_path / "example.drill-plugin.json", item)
    result = discover([tmp_path])[0]
    assert result.installed and result.compatible
    assert not result.accepted and not result.available
    result = discover([tmp_path], [accepted(item)], lambda _: False)[0]
    assert result.accepted and not result.available


def test_duplicate_ids_incompatible_versions_and_unsupported_grants(tmp_path):
    item = manifest()
    for name in ("one", "two"):
        write_manifest(tmp_path / f"{name}.drill-plugin.json", item)
    assert all(not p.compatible for p in discover([tmp_path], [accepted(item)]))
    with pytest.raises(ContractError):
        select([tmp_path], item.id, [accepted(item)])
    data = item.to_dict()
    data["id"], data["adapter_api"] = "incompatible", 2
    (tmp_path / "three.drill-plugin.json").write_text(json.dumps(data))
    assert not next(p for p in discover([tmp_path]) if p.id == "incompatible").compatible
    write_manifest(
        tmp_path / "four.drill-plugin.json",
        manifest(id="network", access_requests=("network.host",)),
    )
    assert not next(p for p in discover([tmp_path]) if p.id == "network").compatible


@pytest.mark.parametrize(
    "change",
    [
        dict(version="2"),
        dict(artifact_digest="sha256:" + "b" * 64),
        dict(capabilities=("inject.mcp_response",)),
        dict(notices=("new",)),
        dict(access_requests=("broker.attacker",)),
    ],
)
def test_any_reviewed_metadata_change_stales_acceptance(change):
    item = manifest()
    with pytest.raises(ContractError, match="stale"):
        check_acceptance(replace(item, **change), [accepted(item)])


def test_revocation_and_scope_cannot_reuse_old_acceptance(tmp_path):
    item = manifest()
    record = accepted(item)
    for records in (
        [],
        [record, replace(record, decision="revoked")],
        [replace(record, granted_access=())],
    ):
        with pytest.raises(ContractError):
            check_acceptance(item, records)
    document = tmp_path / "acceptances.json"
    document.write_text(json.dumps({"schema_version": 1, "records": [record.to_dict()]}))
    assert read_acceptances(document) == [record]
    document.write_text('{"schema_version":1,"records":[],"execute":"bad"}')
    with pytest.raises(ContractError):
        read_acceptances(document)


@pytest.mark.parametrize("content", [b'{"id":"a","id":"b"}', b'{"n":NaN}', b"\xff", b"[]" * 40000])
def test_hostile_metadata_is_not_loaded(tmp_path, content):
    path = tmp_path / "bad.drill-plugin.json"
    path.write_bytes(content)
    assert not discover([tmp_path])[0].compatible


def test_symlink_metadata_is_rejected(tmp_path):
    target = tmp_path / "target.json"
    write_manifest(target, manifest())
    link = tmp_path / "link.drill-plugin.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("This account cannot create symlinks")
    with pytest.raises(ContractError):
        read_metadata(link)


def test_doctor_does_not_execute_or_implicitly_accept(tmp_path):
    write_manifest(tmp_path / "example.drill-plugin.json", manifest())
    result = CliRunner().invoke(main, ["--directory", str(tmp_path)])
    assert result.exit_code == 0
    status = json.loads(result.output)["plugins"][0]
    assert status["installed"] and not status["accepted"] and not status["available"]


def request(method="prepare", number=1, params=None):
    return {
        "protocol": 1,
        "type": "request",
        "id": number,
        "method": method,
        "params": params or {},
    }


@pytest.mark.parametrize(
    "change",
    [
        dict(protocol=True),
        dict(protocol=2),
        dict(id=-1),
        dict(id=True),
        dict(method=[]),
        dict(type=[]),
        dict(extra="x"),
        dict(params=[]),
        dict(type="unknown"),
    ],
)
def test_protocol_rejects_malformed_frames(change):
    with pytest.raises(ProtocolError):
        encode({**request(), **change})


def test_protocol_byte_limits_and_invalid_json():
    assert decode(encode(request())) == request()
    for frame in (b'{"protocol":1,"protocol":1}\n', b"{}", b"x" * 65536 + b"\n", b"\xff\n"):
        with pytest.raises(ProtocolError):
            decode(frame)
    with pytest.raises(ProtocolError):
        encode(request(params={"large": "x" * 65536}))


def test_sdk_lifecycle_and_broker_roundtrip():
    class Plugin:
        def prepare(self, config):
            self.calls = ["prepare"]

        def reset(self, scenario):
            self.calls.append(scenario.id)

        def execute(self, broker):
            self.calls.append("execute")
            return {"ok": True}

        def close(self):
            self.calls.append("close")

    spec = scenario_from_attack(BuiltinReplaySource().dataset()[0])
    wire = b"".join(
        encode(request(method, i + 1, params))
        for i, (method, params) in enumerate(
            [("prepare", {}), ("reset", spec.to_dict()), ("execute", {}), ("close", {})]
        )
    )
    output, plugin = io.BytesIO(), Plugin()
    serve(plugin, io.BytesIO(wire), output)
    assert plugin.calls == ["prepare", spec.id, "execute", "close"]
    assert len(output.getvalue().splitlines()) == 4
    reply = encode(
        {
            "protocol": 1,
            "type": "reply",
            "id": 1,
            "call_id": 1,
            "result": {"response_text": "refused"},
        }
    )
    broker_output = io.BytesIO()
    broker = Broker(io.BytesIO(reply), broker_output)
    broker.request_id = 1
    assert broker.call("target", Injection("user", "controlled test")) == {
        "response_text": "refused"
    }
    assert decode(broker_output.getvalue())["payload"]["surface"] == "user"


def test_sdk_rejects_execute_before_reset():
    output = io.BytesIO()
    serve(object(), io.BytesIO(encode(request("execute"))), output)
    assert decode(output.getvalue())["type"] == "error"


@pytest.mark.parametrize(
    "limits",
    [
        dict(wall_seconds=0),
        dict(wall_seconds=float("nan")),
        dict(max_calls=True),
        dict(max_messages=0),
        dict(max_frame_bytes=1000000),
    ],
)
def test_invalid_worker_limits(limits):
    with pytest.raises(ValueError):
        WorkerLimits(**limits)


def test_isolation_inspection_rejects_extra_mount_even_with_safe_flags():
    with pytest.raises(WorkerError):
        validate_isolation(
            {"HostConfig": {"NetworkMode": "none"}, "Mounts": [{"Source": "/home"}]},
            "sha256:" + "a" * 64,
            1,
        )


def test_unsupported_runtime_never_falls_back_to_host(monkeypatch):
    import asyncio
    from blastcontain_drill.plugins.runtime import PodmanWorker

    monkeypatch.setattr("blastcontain_drill.plugins.runtime.sys.platform", "win32")
    item = manifest()

    async def target(injection, context):
        pytest.fail("Unsupported runtime must not dispatch a target request")

    worker = PodmanWorker(item, [accepted(item)], bindings={"target": target})
    with pytest.raises(WorkerError, match="no host fallback"):
        asyncio.run(worker.start())
    assert worker.process is None


def test_configuration_schema_is_not_silently_ignored(tmp_path):
    item = manifest(config_schema={"type": "object", "required": ["secret"]})
    write_manifest(tmp_path / "example.drill-plugin.json", item)
    status = discover([tmp_path], [accepted(item)])[0]
    assert status.accepted and not status.compatible
    with pytest.raises(ContractError):
        select([tmp_path], item.id, [accepted(item)])
