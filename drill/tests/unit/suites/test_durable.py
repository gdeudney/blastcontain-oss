"""Persistent trust boundaries: bytes, signer, privacy, stopping and fresh reruns."""

import asyncio
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    ContractError,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
)
from blastcontain_drill.suites import durable
from blastcontain_drill.suites.artifacts import digest
from blastcontain_drill.suites.broker import ModelReply
from blastcontain_drill.suites.catalog import SourceSnapshot, builtin_catalog
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.privacy import private, read_json, write_json
from blastcontain_drill.suites.run_store import RunStore, request_cancel
from blastcontain_drill.suites.schema import ModelSettings, Selection, SuiteSpec, TargetSpec
from blastcontain_drill.suites.service import ExecutionInputs
from blastcontain_drill.suites.signatures import Signer

TIME = "2026-09-21T00:00:00Z"
SECRET = "UNIQUE_SECRET_SENTINEL_928173"


@pytest.fixture(scope="module")
def catalog():
    base = builtin_catalog()
    scenario = ScenarioSpec(
        "controlled",
        "jailbreak",
        "fixture",
        SourceRef("controlled", "1"),
        "Controlled test " + SECRET,
        SecurityExpectation("content"),
        attack_objective="Controlled objective",
    )
    source = SourceSnapshot("controlled", "1", base.sources[0].code_digest, (scenario,))
    return replace(base, sources=(*base.sources, source))


def accepted(catalog, *, adaptive=False, live=False, **changes):
    channels = (("target",) if live else ()) + (("attacker",) if adaptive else ())
    spec = SuiteSpec(
        "durable-tests",
        TargetSpec("agent", "builtin.target.llm" if live else "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        (
            Selection(
                "test", "controlled", ("*",), strategy="builtin.strategy.pair" if adaptive else None
            ),
        ),
        models=tuple(
            ModelSettings(c, "http://127.0.0.1:1234/v1", "fixture", credential_ref="key")
            for c in channels
        ),
    )
    spec = replace(spec, **changes)
    source = next(s for s in catalog.sources if s.id == "controlled")

    def decision(subject, kind, value):
        return AcceptanceRecord(subject, kind, value, SECRET, "accepted", TIME, SECRET)

    records = (decision(source.id, "content", source.content_digest),)
    plan = plan_suite(spec, catalog, records=records)
    assert plan.ready
    records += (decision(spec.id, "suite", plan.content_digest),)
    return create_lock(plan, catalog, records=records), ExecutionInputs(catalog, records)


def execute(tmp_path, lock, inputs, **options):
    return asyncio.run(
        durable.execute_run(lock, tmp_path / "runs", current_inputs=lambda: inputs, **options)
    )


def signer():
    return Signer(Ed25519PrivateKey.generate())


@pytest.mark.parametrize("configured", [False, True])
def test_roundtrip_signature_trust_reduction_and_sanitized_artifacts(catalog, tmp_path, configured):
    lock, inputs = accepted(catalog, live=True)
    key = signer() if configured else None

    async def transport(settings, messages, secret, *args):
        assert secret == "PROVIDER_KEY_SENTINEL" and SECRET in messages[-1]["content"]
        return ModelReply("DONE: I cannot help. OUTPUT_SENTINEL PROVIDER_KEY_SENTINEL")

    stored = execute(
        tmp_path,
        lock,
        inputs,
        signer=key,
        require_signing=configured,
        credentials=lambda ref: "PROVIDER_KEY_SENTINEL",
        transport=transport,
    )
    assert stored.run.passed
    for path in stored.directory.rglob("*"):
        private(path, directory=path.is_dir())
        if path.is_file():
            data = path.read_bytes()
            assert all(
                value not in data
                for value in (SECRET.encode(), b"PROVIDER_KEY_SENTINEL", b"OUTPUT_SENTINEL")
            )
    assert not tuple((stored.directory / "raw").iterdir())
    summary = durable.inspect_run(stored.directory)
    assert (
        summary["status"] == "finished"
        and summary["reported_security_passed"]
        and not summary["trusted"]
    )
    public = key.public_key if key else None
    with pytest.raises(ContractError, match="trusted"):
        durable.verify_run(stored.directory)
    incomplete = durable.verify_run(
        stored.directory, trusted_public_key=public, allow_advisory=not configured
    )
    assert not incomplete.replayed and not incomplete.security_passed
    verified = durable.verify_run(
        stored.directory, lock=lock, trusted_public_key=public, allow_advisory=not configured
    )
    assert verified.replayed and verified.security_passed and verified.trusted is configured
    assert verified.attested_pass is configured
    projected = durable.legacy_projection(
        stored.directory, lock=lock, trusted_public_key=public, allow_advisory=not configured
    )
    assert projected["summary"]["held"] == 1 and projected["warnings"]
    with pytest.raises(ContractError):
        durable.verify_run(stored.directory, lock=lock, trusted_public_key=signer().public_key)


@pytest.mark.parametrize(
    "part", ["envelope", "initial", "evidence", "missing_evidence", "raw_lock", "missing_raw"]
)
def test_tamper_or_missing_signed_inputs_fail_verification(catalog, tmp_path, part):
    lock, inputs = accepted(catalog)
    key = signer()
    stored = execute(tmp_path, lock, inputs, signer=key, raw_retention_seconds=60)
    if part in ("envelope", "initial"):
        path = stored.directory / (part + ".json")
        value = read_json(path)
        value["payload"]["reported_security_passed"] = not value["payload"][
            "reported_security_passed"
        ]
        write_json(path, value, replace=True)
    else:
        folder = "evidence" if "evidence" in part else "raw"
        path = next((stored.directory / folder).glob("*.json"))
        if part.startswith("missing"):
            path.unlink()
        else:
            path.write_bytes(
                path.read_bytes().replace(b'"schema_version":1', b'"schema_version":2', 1)
            )
    with pytest.raises((ContractError, OSError)):
        durable.verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)


def test_re_signed_false_summary_cannot_replace_evidence_reduction(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    key = signer()
    stored = execute(tmp_path, lock, inputs, signer=key)
    envelope = read_json(stored.directory / "envelope.json")
    envelope["payload"]["cases"][0]["legacy_outcome"] = "BYPASS"
    write_json(stored.directory / "envelope.json", key.sign(envelope["payload"]), replace=True)
    with pytest.raises(ContractError, match="reduction"):
        durable.verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)


def test_lock_substitution_and_roster_tamper_fail(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    key = signer()
    stored = execute(tmp_path, lock, inputs, signer=key)
    other, _ = accepted(catalog, seeds=(1,))
    with pytest.raises(ContractError, match="lock"):
        durable.verify_run(stored.directory, lock=other, trusted_public_key=key.public_key)
    envelope = read_json(stored.directory / "envelope.json")
    envelope["payload"]["cases"][0]["required"] = False
    write_json(stored.directory / "envelope.json", key.sign(envelope["payload"]), replace=True)
    with pytest.raises(ContractError, match="roster"):
        durable.verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)


@pytest.mark.parametrize("retain", [False, True])
def test_adaptive_raw_inputs_are_opt_in_bounded_and_explicitly_expire(catalog, tmp_path, retain):
    lock, inputs = accepted(catalog, adaptive=True, live=True)
    key, now = signer(), [1000.0]
    calls = []

    async def transport(settings, *args):
        calls.append(settings.channel)
        return ModelReply(
            "GENERATED_PRIVATE_PROMPT"
            if settings.channel == "attacker"
            else "DONE: controlled violation"
        )

    stored = execute(
        tmp_path,
        lock,
        inputs,
        signer=key,
        credentials=lambda ref: "PROVIDER_KEY_SENTINEL",
        transport=transport,
        raw_retention_seconds=10 if retain else None,
        clock=lambda: now[0],
    )

    def verify(**kw):
        return durable.verify_run(
            stored.directory, trusted_public_key=key.public_key, clock=lambda: now[0], **kw
        )

    result = verify(lock=lock)
    assert result.replayed is retain and not result.security_passed
    normal = b"".join(
        p.read_bytes() for p in stored.directory.rglob("*.json") if p.parent.name != "raw"
    )
    assert b"GENERATED_PRIVATE_PROMPT" not in normal and SECRET.encode() not in normal
    scenarios = {a.case_id: a.scenario for c in stored.run.cases for a in c.attempts}
    assert verify(lock=lock, scenarios=scenarios).replayed
    if retain:
        assert verify().replayed
        raw = b"".join(p.read_bytes() for p in (stored.directory / "raw").iterdir())
        assert b"GENERATED_PRIVATE_PROMPT" in raw and SECRET.encode() in raw
        assert b"PROVIDER_KEY_SENTINEL" not in raw
        now[0] = 1011.0
        assert not verify(lock=lock).replayed
        assert durable.purge_expired_raw(stored.directory, clock=lambda: now[0]) > 0
        assert not tuple((stored.directory / "raw").iterdir())
        assert verify(lock=lock, scenarios=scenarios).replayed


def test_required_signing_fails_before_dispatch_without_fallback(catalog, tmp_path, monkeypatch):
    lock, inputs = accepted(catalog)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "legacy-fallback-must-not-be-used")
    with pytest.raises(ContractError, match="explicit"):
        execute(tmp_path, lock, inputs, require_signing=True)
    assert not (tmp_path / "runs").exists()
    with pytest.raises(ContractError, match="Ed25519"):
        Signer.from_pem(b"SECRET-invalid-key")


def test_signing_failure_leaves_no_completed_marker(catalog, tmp_path, monkeypatch):
    lock, inputs = accepted(catalog)
    original = Signer.sign
    calls = []

    def fail_on_final(self, payload):
        calls.append(True)
        if len(calls) == 2:
            raise RuntimeError("signer unavailable")
        return original(self, payload)

    monkeypatch.setattr(Signer, "sign", fail_on_final)
    with pytest.raises(RuntimeError):
        execute(tmp_path, lock, inputs, signer=signer(), require_signing=True)
    directory = next((tmp_path / "runs").iterdir())
    assert not (directory / "envelope.json").exists()
    assert durable.inspect_run(directory)["status"] == "interrupted"


def test_storage_failure_cancels_and_never_publishes_completion(catalog, tmp_path, monkeypatch):
    lock, inputs = accepted(catalog, live=True, concurrency=2, seeds=(1, 2))
    original = RunStore.write

    def fail_evidence(self, name, data, **kwargs):
        if name.startswith("evidence"):
            raise OSError("PRIVATE_PATH_SECRET")
        return original(self, name, data, **kwargs)

    monkeypatch.setattr(RunStore, "write", fail_evidence)

    async def transport(*args):
        return ModelReply("DONE: I cannot help.")

    with pytest.raises(ContractError, match="persistence") as error:
        execute(tmp_path, lock, inputs, credentials=lambda ref: "key-value", transport=transport)
    assert "PRIVATE_PATH_SECRET" not in str(error.value)
    directory = next((tmp_path / "runs").iterdir())
    assert not (directory / "envelope.json").exists()
    assert not durable.inspect_run(directory)["reported_security_passed"]


def test_roster_is_durable_before_first_dispatch(catalog, tmp_path):
    lock, inputs = accepted(catalog, live=True, seeds=(1, 2, 3))
    directories = []

    async def transport(*args):
        doc = read_json(directories[0] / "initial.json")["payload"]
        assert [c["case_id"] for c in doc["cases"]] == [c.id for c in lock.plan.cases]
        assert all(c["disposition"] == "pending" for c in doc["cases"])
        return ModelReply("DONE: I cannot help.")

    execute(
        tmp_path,
        lock,
        inputs,
        credentials=lambda ref: "key-value",
        transport=transport,
        on_created=directories.append,
    )


@pytest.mark.parametrize("forged", ["mac", "stale_run", "malformed"])
def test_cancel_request_is_scoped_authenticated_and_stops_pending_cases(catalog, tmp_path, forged):
    lock, inputs = accepted(catalog, live=True, seeds=(1, 2, 3), concurrency=2)
    key = signer()

    async def exercise():
        ready = asyncio.Event()
        directories, calls, stopped = [], [], []

        async def blocking(*args):
            calls.append(True)
            if len(calls) == 2:
                ready.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(True)

        task = asyncio.create_task(
            durable.execute_run(
                lock,
                tmp_path / "runs",
                current_inputs=lambda: inputs,
                signer=key,
                credentials=lambda ref: "key-value",
                transport=blocking,
                on_created=directories.append,
            )
        )
        await asyncio.wait_for(ready.wait(), 10)
        directory = directories[0]
        from blastcontain_drill.suites.run_store import _control, cancel_message

        control = _control(RunStore(directory))
        message = cancel_message(control)
        if forged == "mac":
            message["mac"] = "0" * 64
        elif forged == "stale_run":
            message = cancel_message({**control, "run_id": "1" * 32})
        else:
            message = {"pid": os.getpid(), "action": "cancel"}
        write_json(directory / "cancel.json", message)
        await asyncio.sleep(0.2)
        assert not task.done() and not stopped
        assert durable.inspect_run(directory)["status"] == "running"
        assert request_cancel(directory)
        stored = await asyncio.wait_for(task, 10)
        assert len(calls) == len(stopped) == 2
        assert all(c.disposition == "cancelled" for c in stored.run.cases)
        assert not request_cancel(directory)
        verified = durable.verify_run(directory, lock=lock, trusted_public_key=key.public_key)
        assert verified.replayed and not verified.security_passed

    asyncio.run(exercise())


def test_rerun_has_new_identity_and_revalidates_current_acceptance(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    key = signer()
    first = execute(tmp_path, lock, inputs, signer=key)
    second = asyncio.run(
        durable.rerun_run(
            first.directory,
            tmp_path / "runs",
            lock=lock,
            current_inputs=lambda: inputs,
            trusted_public_key=key.public_key,
            signer=key,
        )
    )
    assert second.directory != first.directory
    doc = read_json(second.directory / "envelope.json")["payload"]
    assert doc["parent_run_id"] == first.directory.name
    assert doc["parent_envelope_digest"] == digest(read_json(first.directory / "envelope.json"))
    assert second.run.cases[0].environment_identity != first.run.cases[0].environment_identity
    revoked = replace(
        inputs, records=(*inputs.records, replace(inputs.records[-1], decision="revoked"))
    )
    with pytest.raises(ContractError):
        asyncio.run(
            durable.rerun_run(
                first.directory,
                tmp_path / "runs",
                lock=lock,
                current_inputs=lambda: revoked,
                trusted_public_key=key.public_key,
                signer=key,
            )
        )
    assert len(tuple((tmp_path / "runs").iterdir())) == 2


def test_crashed_controller_leaves_interrupted_full_roster(tmp_path):
    script = r"""
import asyncio
from pathlib import Path
import sys
from blastcontain_drill.contracts import AcceptanceRecord
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.schema import SuiteSpec, TargetSpec, Selection, ModelSettings
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.service import ExecutionInputs
from blastcontain_drill.suites.durable import execute_run
cat = builtin_catalog()
s = next(s for src in cat.sources if src.id == 'builtin' for s in src.scenarios if s.security.goal == 'content' and not s.injections)
spec = SuiteSpec('crash', TargetSpec('agent','builtin.target.llm'), 'builtin.environment.fixture', ('builtin.evaluator.heuristic',), (Selection('test','builtin',(s.id,)),), models=(ModelSettings('target','http://127.0.0.1:1234/v1','fixture'),), seeds=(1,2))
plan = plan_suite(spec,cat)
records=(AcceptanceRecord('crash','suite',plan.content_digest,'tester','accepted','2026-09-21T00:00:00Z','Controlled crash'),)
lock=create_lock(plan,cat,records=records)
async def blocked(*args):
    print('ACTIVE',flush=True)
    await asyncio.Event().wait()
asyncio.run(execute_run(lock,Path(sys.argv[1]),current_inputs=lambda:ExecutionInputs(cat,records),transport=blocked,on_created=lambda path: print(path,flush=True)))
"""
    process = subprocess.Popen(
        [sys.executable, "-u", "-c", script, str(tmp_path / "runs")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        directory = Path(process.stdout.readline().strip())
        assert process.stdout.readline().strip() == "ACTIVE"
        assert durable.inspect_run(directory)["status"] == "running"
        process.kill()
        process.wait(timeout=10)
        summary = durable.inspect_run(directory)
        assert summary["status"] == "interrupted" and not summary["reported_security_passed"]
        assert len(summary["cases"]) == 2 and all(
            c["disposition"] == "incomplete" for c in summary["cases"]
        )
        assert not request_cancel(directory)
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def test_private_permissions_links_and_storage_limits(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    with pytest.raises(ContractError, match="storage"):
        execute(tmp_path, lock, inputs, storage_limit=1024)
    directory = next((tmp_path / "runs").iterdir())
    assert not (directory / "envelope.json").exists()
    store = RunStore(directory)
    with pytest.raises(ContractError, match="path"):
        store.write("../escape", {})
    if os.name != "nt":
        (tmp_path / "runs").chmod(0o755)
        try:
            with pytest.raises(ContractError, match="owner-only"):
                execute(tmp_path, lock, inputs)
        finally:
            (tmp_path / "runs").chmod(0o700)


@pytest.mark.parametrize("link", ["symbolic", "hard"])
def test_evidence_links_cannot_escape_private_storage(catalog, tmp_path, link):
    lock, inputs = accepted(catalog)
    key = signer()
    stored = execute(tmp_path, lock, inputs, signer=key)
    evidence = next((stored.directory / "evidence").iterdir())
    original = evidence.read_bytes()
    external = tmp_path / "unrelated"
    external.write_bytes(original)
    evidence.unlink()
    try:
        if link == "symbolic":
            evidence.symlink_to(external)
        else:
            os.link(external, evidence)
    except OSError:
        pytest.skip("This filesystem does not support the selected link type")
    with pytest.raises(ContractError):
        durable.verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)
    assert external.read_bytes() == original


def test_caller_cancellation_still_publishes_signed_cancelled_roster(catalog, tmp_path):
    lock, inputs = accepted(catalog, live=True, seeds=(1, 2))
    key = signer()

    async def exercise():
        started = asyncio.Event()
        directories = []

        async def blocking(*args):
            started.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(
            durable.execute_run(
                lock,
                tmp_path / "runs",
                signer=key,
                current_inputs=lambda: inputs,
                credentials=lambda ref: "key-value",
                transport=blocking,
                on_created=directories.append,
            )
        )
        await asyncio.wait_for(started.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10)
        verified = durable.verify_run(directories[0], lock=lock, trusted_public_key=key.public_key)
        assert verified.replayed and all(c.disposition == "cancelled" for c in verified.run.cases)

    asyncio.run(exercise())


def test_raw_retention_requires_bounded_explicit_duration(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    for duration in (0, -1, True, 32 * 86400):
        with pytest.raises(ContractError, match="retention"):
            execute(tmp_path, lock, inputs, raw_retention_seconds=duration)


def test_credentials_echoed_by_provider_are_removed_from_trace_and_child(catalog, tmp_path):
    lock, inputs = accepted(catalog, live=True)

    async def transport(*args):
        return ModelReply("DONE: I cannot help. PROVIDER_KEY_SENTINEL")

    stored = execute(
        tmp_path,
        lock,
        inputs,
        raw_retention_seconds=60,
        credentials=lambda ref: "PROVIDER_KEY_SENTINEL",
        transport=transport,
    )
    all_bytes = b"".join(p.read_bytes() for p in stored.directory.rglob("*.json"))
    assert b"PROVIDER_KEY_SENTINEL" not in all_bytes
    assert b"[credential removed]" in all_bytes
    assert durable.verify_run(stored.directory, allow_advisory=True).replayed


def test_credential_redaction_cannot_expand_beyond_broker_output_limit(catalog, tmp_path):
    lock, inputs = accepted(catalog, live=True)

    async def transport(*args):
        return ModelReply("x" * 30000)

    stored = execute(tmp_path, lock, inputs, credentials=lambda ref: "x", transport=transport)
    assert not stored.run.passed
    verified = durable.verify_run(stored.directory, lock=lock, allow_advisory=True)
    assert verified.replayed and not verified.security_passed


def test_interrupted_run_can_purge_expired_raw_without_trusting_progress(
    catalog, tmp_path, monkeypatch
):
    lock, inputs = accepted(catalog, live=True)
    original = Signer.sign
    calls = []

    def fail_final(self, payload):
        calls.append(payload)
        if len(calls) > 1:
            raise RuntimeError("Interrupted completion")
        return original(self, payload)

    monkeypatch.setattr(Signer, "sign", fail_final)

    async def transport(*args):
        return ModelReply("DONE: I cannot help. RAW_PRIVATE_SENTINEL")

    with pytest.raises(RuntimeError):
        execute(
            tmp_path,
            lock,
            inputs,
            signer=signer(),
            raw_retention_seconds=1,
            clock=lambda: 1000.0,
            transport=transport,
            credentials=lambda ref: "key-value",
        )
    directory = next((tmp_path / "runs").iterdir())
    assert len(tuple((directory / "raw").iterdir())) == 2
    assert durable.purge_expired_raw(directory, clock=lambda: 1000.0) == 0
    # Unsigned state cannot extend retention or authorize deleting unrelated files.
    (directory / "state.json").write_text('{"raw_expires_at":9999999999}')
    assert durable.purge_expired_raw(directory, clock=lambda: 1002.0) == 2
    assert tuple((directory / "evidence").iterdir())
    assert durable.inspect_run(directory)["status"] == "interrupted"


@pytest.mark.parametrize("failure", ["signer", "initial_write"])
def test_initial_commit_failure_never_writes_raw_inputs(catalog, tmp_path, monkeypatch, failure):
    lock, inputs = accepted(catalog)
    if failure == "signer":

        def fail_sign(*args):
            raise RuntimeError("Signer unavailable")

        monkeypatch.setattr(Signer, "sign", fail_sign)
    else:
        original = RunStore.write

        def fail_initial(self, name, data, **kwargs):
            if name == "initial.json":
                raise RuntimeError("Initial storage unavailable")
            return original(self, name, data, **kwargs)

        monkeypatch.setattr(RunStore, "write", fail_initial)
    with pytest.raises(RuntimeError):
        execute(tmp_path, lock, inputs, signer=signer(), raw_retention_seconds=60)
    directory = next((tmp_path / "runs").iterdir())
    assert not tuple((directory / "raw").iterdir())
    assert all(SECRET.encode() not in p.read_bytes() for p in directory.rglob("*") if p.is_file())


def test_partial_raw_write_remains_expirable_after_startup_failure(catalog, tmp_path, monkeypatch):
    from blastcontain_drill.suites.privacy import write_private

    lock, inputs = accepted(catalog)
    original = RunStore.write

    def interrupted_raw_write(self, name, data, **kwargs):
        if Path(name).parts[0] == "raw":
            assert (self.directory / "initial.json").exists()
            write_private(
                self.directory / "raw" / (".write-" + "a" * 32), b"partial-sensitive-input"
            )
            raise RuntimeError("Interrupted raw publication")
        return original(self, name, data, **kwargs)

    monkeypatch.setattr(RunStore, "write", interrupted_raw_write)
    with pytest.raises(RuntimeError):
        execute(tmp_path, lock, inputs, raw_retention_seconds=1, clock=lambda: 1000.0)
    directory = next((tmp_path / "runs").iterdir())
    assert durable.inspect_run(directory)["status"] == "interrupted"
    assert durable.purge_expired_raw(directory, clock=lambda: 1000.0) == 0
    assert durable.purge_expired_raw(directory, clock=lambda: 1002.0) == 1
    assert not tuple((directory / "raw").iterdir())


def test_retention_can_expire_during_startup_without_breaking_signed_inventory(catalog, tmp_path):
    lock, inputs = accepted(catalog)
    ticks = iter([1000.0])

    def clock():
        return next(ticks, 1002.0)

    stored = execute(tmp_path, lock, inputs, raw_retention_seconds=1, clock=clock)
    assert not tuple((stored.directory / "raw").iterdir())
    verified = durable.verify_run(stored.directory, lock=lock, allow_advisory=True, clock=clock)
    assert verified.replayed and verified.security_passed
