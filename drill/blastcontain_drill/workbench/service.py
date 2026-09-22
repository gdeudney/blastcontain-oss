"""Private workbench documents; suite policy and execution stay in shared services."""

from __future__ import annotations

import asyncio
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import re
import threading
from typing import Any, Literal, NotRequired, TypedDict

from ..contracts import AcceptanceRecord, ContractError, PluginManifest
from ..contracts.wire import WireRecord
from ..plugins.catalog import review_digest
from ..plugins.runtime import probe_local_image
from ..suites.artifacts import canonical, digest
from ..suites.catalog import RuntimeProbe, SourceSnapshot, build_digest, builtin_catalog
from ..suites.durable import execute_run, inspect_run, verify_run
from ..suites.lock import SuiteLock, create_lock
from ..suites.planner import plan_suite
from ..suites.privacy import lease, mkdir_private, private, read_json, write_json
from ..suites.review import record_decision
from ..suites.run_store import request_cancel
from ..suites.schema import Selection, SuiteSpec, TargetSpec
from ..suites.service import ExecutionInputs

MAX_DOCUMENT = 2 * 1024 * 1024
MAX_ARTIFACTS = 64 * 1024 * 1024


@dataclass(frozen=True)
class WorkspaceState(WireRecord):
    suite: SuiteSpec
    sources: dict[str, list[str]]
    plugins: dict[str, list[str]]
    probes: dict[str, str]
    acceptances: str | None = None
    lock: str | None = None
    schema_version: Literal[1] = 1

    def validate(self):
        values = [self.acceptances, self.lock, *self.probes.values()]
        for versions in (*self.sources.values(), *self.plugins.values()):
            if not versions:
                raise ContractError("Artifact history cannot be empty")
            values.extend(versions)
        for value in values:
            if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
                raise ContractError("Invalid workspace artifact reference")


class Workspace:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if not self.root.exists():
            mkdir_private(self.root)
        private(self.root, directory=True)
        self.guard = threading.RLock()
        self._lease: AbstractContextManager | None = lease(self.root / "workspace.lease")
        if not self._lease.__enter__():
            self._lease.__exit__(None, None, None)
            raise ContractError("Another workbench owns this workspace")
        try:
            for name in ("artifacts", "runs"):
                path = self.root / name
                if not path.exists():
                    mkdir_private(path)
                private(path, directory=True)
            if not (self.root / "workspace.json").exists():
                source = builtin_catalog().sources[0]
                suite = SuiteSpec(
                    "workbench-suite",
                    TargetSpec("agent", "builtin.target.resistant"),
                    "builtin.environment.fixture",
                    ("builtin.evaluator.heuristic",),
                    (Selection("preview", source.id, (source.scenarios[0].id,)),),
                )
                write_json(
                    self.root / "workspace.json", WorkspaceState(suite, {}, {}, {}).to_dict()
                )
            self.read()
        except BaseException:
            self.close()
            raise

    def close(self):
        with self.guard:
            if self._lease is not None:
                self._lease.__exit__(None, None, None)
                self._lease = None

    def read(self):
        if self._lease is None:
            raise ContractError("Workspace is closed")
        return WorkspaceState.from_dict(read_json(self.root / "workspace.json"))

    def revision(self, state=None):
        return digest({"state": (state or self.read()).to_dict(), "runtime": build_digest()})

    def _get(self, reference):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
            raise ContractError("Invalid artifact reference")
        value = read_json(self.root / "artifacts" / (reference[7:] + ".json"))
        if digest(value) != reference:
            raise ContractError("Workspace artifact changed")
        return value

    def _put(self, value):
        encoded = canonical(value)
        if len(encoded) > MAX_DOCUMENT:
            raise ContractError("Workspace document exceeds 2 MiB")
        reference = digest(value)
        path = self.root / "artifacts" / (reference[7:] + ".json")
        if path.exists():
            self._get(reference)
        else:
            if (
                sum(p.stat().st_size for p in (self.root / "artifacts").iterdir()) + len(encoded)
                > MAX_ARTIFACTS
            ):
                raise ContractError("Workspace artifact storage limit reached")
            write_json(path, value)
        return reference

    def inputs(self, state=None):
        with self.guard:
            state = state or self.read()
            sources = tuple(
                SourceSnapshot.from_dict(self._get(v[-1])) for v in state.sources.values()
            )
            plugins = tuple(
                PluginManifest.from_dict(self._get(v[-1])) for v in state.plugins.values()
            )
            probes = tuple(RuntimeProbe.from_dict(self._get(v)) for v in state.probes.values())
            if {s.id for s in sources} != set(state.sources) or {p.id for p in plugins} != set(
                state.plugins
            ):
                raise ContractError("Workspace artifact identity changed")
            history: dict[str, Any] = (
                self._get(state.acceptances)
                if state.acceptances
                else {"schema_version": 1, "records": []}
            )
            if set(history) != {"schema_version", "records"} or history["schema_version"] != 1:
                raise ContractError("Invalid workspace acceptance history")
            return ExecutionInputs(
                builtin_catalog(external_sources=sources, plugins=plugins),
                tuple(AcceptanceRecord.from_dict(r) for r in history["records"]),
                probes,
            )

    def _edit(self, expected_revision, operation):
        with self.guard:
            state = self.read()
            if expected_revision != self.revision(state):
                raise ContractError("Workspace changed; reload the latest state before editing")
            updated = operation(state)
            # Validate the complete proposed catalog/plan before publishing any state.
            result = self.snapshot(updated)
            write_json(self.root / "workspace.json", updated.to_dict(), replace=True)
            return result

    def import_artifact(self, kind, value, expected_revision):
        if kind not in ("source", "plugin"):
            raise ContractError("Only source and plugin metadata can be imported")
        artifact = (SourceSnapshot if kind == "source" else PluginManifest).from_dict(value)

        def apply(state):
            inputs = self.inputs()
            if kind == "source" and artifact.id in inputs.catalog.builtin_sources:
                raise ContractError("Cannot replace a built-in source")
            records = dict(state.sources if kind == "source" else state.plugins)
            reference = self._put(artifact.to_dict())
            old = records.get(artifact.id, [])
            records[artifact.id] = old if old and old[-1] == reference else [*old, reference]
            return replace(
                state, **{("sources" if kind == "source" else "plugins"): records}, lock=None
            )

        return self._edit(expected_revision, apply)

    def save_suite(self, value, expected_revision):
        spec = SuiteSpec.from_dict(value)
        return self._edit(expected_revision, lambda state: replace(state, suite=spec, lock=None))

    def probe(self, plugin_id, expected_revision):
        with self.guard:
            state = self.read()
            if expected_revision != self.revision(state) or plugin_id not in state.plugins:
                raise ContractError("Workspace changed or plugin is unknown")
            plugin = PluginManifest.from_dict(self._get(state.plugins[plugin_id][-1]))
        availability = probe_local_image(plugin.artifact_digest)
        observation = RuntimeProbe(
            plugin.id,
            plugin.artifact_digest,
            availability.available,
            datetime.now(timezone.utc).isoformat(),
        )

        def apply(state):
            return replace(
                state,
                probes={**state.probes, plugin_id: self._put(observation.to_dict())},
                lock=None,
            )

        result = self._edit(expected_revision, apply)
        result["probe_diagnostic"] = availability.diagnostic
        return result

    def plan(self):
        with self.guard:
            inputs = self.inputs()
            return plan_suite(
                self.read().suite, inputs.catalog, records=inputs.records, probes=inputs.probes
            )

    @staticmethod
    def plan_document(plan):
        return {
            "schema_version": 1,
            "content_digest": plan.content_digest,
            "ready": plan.ready,
            "plan": plan.to_dict(),
        }

    def decide(
        self,
        *,
        kind,
        subject,
        expected_digest,
        actor,
        rationale,
        decision,
        grants,
        expected_revision,
    ):
        def apply(state):
            if kind == "suite":
                if subject != state.suite.id:
                    raise ContractError("Unknown suite")
                artifact = self.plan_document(self.plan())
            elif kind in ("plugin", "content"):
                entries = state.plugins if kind == "plugin" else state.sources
                if subject not in entries:
                    raise ContractError("Unknown review subject")
                artifact = self._get(entries[subject][-1])
            else:
                raise ContractError("Unknown review kind")
            history = record_decision(
                artifact,
                kind=kind,
                expected_digest=expected_digest,
                actor=actor,
                rationale=rationale,
                decision=decision,
                grants=grants,
                current_inputs=self.inputs,
            )
            return replace(state, acceptances=self._put(history), lock=None)

        return self._edit(expected_revision, apply)

    def lock(self, expected_revision):
        def apply(state):
            inputs = self.inputs()
            locked = create_lock(
                self.plan(), inputs.catalog, records=inputs.records, probes=inputs.probes
            )
            return replace(state, lock=self._put(locked.to_dict()))

        return self._edit(expected_revision, apply)

    def selected_lock(self, expected_revision):
        with self.guard:
            state = self.read()
            if expected_revision != self.revision(state) or state.lock is None:
                raise ContractError("Create a current accepted lock before running")
            return SuiteLock.from_dict(self._get(state.lock))

    def snapshot(self, state=None):
        with self.guard:
            state = state or self.read()
            inputs = self.inputs(state)
            plan = plan_suite(
                state.suite, inputs.catalog, records=inputs.records, probes=inputs.probes
            )
            imported = []
            for kind, entries in (("content", state.sources), ("plugin", state.plugins)):
                for identifier, versions in entries.items():
                    current = self._get(versions[-1])
                    reviewed = (
                        review_digest(PluginManifest.from_dict(current))
                        if kind == "plugin"
                        else SourceSnapshot.from_dict(current).content_digest
                    )
                    record = next(
                        (
                            r
                            for r in reversed(inputs.records)
                            if r.kind == kind and r.subject_id == identifier
                        ),
                        None,
                    )
                    imported.append(
                        {
                            "id": identifier,
                            "kind": kind,
                            "document": current,
                            "previous": self._get(versions[-2]) if len(versions) > 1 else None,
                            "review_digest": reviewed,
                            "decision": record.to_dict() if record else None,
                            "current_acceptance": bool(
                                record
                                and record.decision == "accepted"
                                and record.artifact_digest == reviewed
                            ),
                        }
                    )
            return {
                "revision": self.revision(state),
                "suite": state.suite.to_dict(),
                "lock_digest": SuiteLock.from_dict(self._get(state.lock)).lock_digest
                if state.lock
                else None,
                "plan": self.plan_document(plan),
                "artifacts": imported,
                "sources": [
                    {
                        "id": s.id,
                        "builtin": s.id in inputs.catalog.builtin_sources,
                        "scenarios": [
                            {
                                "id": c.id,
                                "category": c.category,
                                "layer": c.layer,
                                "goal": c.security.goal,
                            }
                            for c in s.scenarios
                        ],
                    }
                    for s in inputs.catalog.sources
                ],
                "bindings": [b.to_dict() for b in inputs.catalog.bindings],
                "decisions": [r.to_dict() for r in inputs.records],
                "probes": [p.to_dict() for p in inputs.probes],
            }

    def export(self):
        with self.guard:
            state = self.read()
            return {
                "suite": state.suite.to_dict(),
                "sources": [self._get(v[-1]) for v in state.sources.values()],
                "plugins": [self._get(v[-1]) for v in state.plugins.values()],
                "probes": [self._get(v) for v in state.probes.values()],
                "acceptances": self._get(state.acceptances)
                if state.acceptances
                else {"schema_version": 1, "records": []},
                "lock": self._get(state.lock) if state.lock else None,
            }


class RunJob(TypedDict):
    run_id: str | None
    error: str | None
    cancel: threading.Event
    request: tuple[str, int | None]
    thread: NotRequired[threading.Thread]


class Runs:
    def __init__(self, workspace, *, signer=None, credentials=None, transport=None):
        self.workspace, self.signer, self.credentials, self.transport = (
            workspace,
            signer,
            credentials,
            transport,
        )
        self.guard = threading.RLock()
        self.jobs: dict[str, RunJob] = {}
        self.closed = False

    def start(self, expected_revision, *, request_id, raw_retention_seconds=None):
        if raw_retention_seconds is not None and (
            type(raw_retention_seconds) is not int or not 1 <= raw_retention_seconds <= 86400
        ):
            raise ContractError("UI raw retention must be absent or between 1 and 86400 seconds")
        if type(request_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", request_id):
            raise ContractError("Run request ID must be 32 hexadecimal characters")
        with self.guard:
            if self.closed:
                raise ContractError("Run service is closed")
            if request_id in self.jobs:
                if self.jobs[request_id]["request"] != (expected_revision, raw_retention_seconds):
                    raise ContractError("Run request ID was already used for a different action")
                return {"job_id": request_id}
            if len(self.jobs) >= 128:
                raise ContractError("This UI session has reached its 128-run limit")
            if any(job["thread"].is_alive() for job in self.jobs.values()):
                raise ContractError("A workbench run is already active")
            lock = self.workspace.selected_lock(expected_revision)
            identifier = request_id
            job: RunJob = {
                "run_id": None,
                "error": None,
                "cancel": threading.Event(),
                "request": (expected_revision, raw_retention_seconds),
            }

            def run():
                async def execute():
                    cancel = asyncio.Event()

                    def created(path):
                        with self.guard:
                            job["run_id"] = path.name
                            if job["cancel"].is_set():
                                cancel.set()

                    await execute_run(
                        lock,
                        self.workspace.root / "runs",
                        current_inputs=self.workspace.inputs,
                        signer=self.signer,
                        require_signing=self.signer is not None,
                        credentials=self.credentials,
                        transport=self.transport,
                        raw_retention_seconds=raw_retention_seconds,
                        on_created=created,
                        cancel=cancel,
                    )

                try:
                    asyncio.run(execute())
                except Exception:
                    with self.guard:
                        job["error"] = (
                            "Run failed; inspect its preserved evidence and current inputs"
                        )

            job["thread"] = threading.Thread(
                target=run, name="drill-run-" + identifier, daemon=True
            )
            self.jobs[identifier] = job
            job["thread"].start()
            return {"job_id": identifier}

    def cancel(self, identifier):
        with self.guard:
            job = self.jobs.get(identifier)
            if job is None:
                raise ContractError("Unknown active job")
            job["cancel"].set()
            if job["run_id"] is not None:
                request_cancel(self.workspace.root / "runs" / job["run_id"])
            return {"requested": True}

    def snapshot(self):
        with self.guard:
            jobs = [
                {
                    "job_id": key,
                    "run_id": job["run_id"],
                    "active": job["thread"].is_alive(),
                    "error": job["error"],
                }
                for key, job in self.jobs.items()
            ]
        runs = []
        for directory in sorted((self.workspace.root / "runs").iterdir(), reverse=True):
            if not re.fullmatch(r"[0-9a-f]{32}", directory.name):
                continue
            try:
                runs.append(inspect_run(directory))
            except (ContractError, OSError):
                runs.append(
                    {
                        "run_id": directory.name,
                        "status": "unavailable",
                        "reported_security_passed": False,
                    }
                )
        return {"jobs": jobs, "runs": runs, "configured_signing": self.signer is not None}

    def verify(self, run_id, *, research=None):
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise ContractError("Invalid run ID")
        # Immutable workspace locks remain available after new edits/reviews.
        directory = self.workspace.root / "runs" / run_id
        summary = inspect_run(directory)
        lock = None
        for path in (self.workspace.root / "artifacts").iterdir():
            value = read_json(path)
            if type(value) is dict and value.get("lock_digest") == summary["lock_digest"]:
                lock = SuiteLock.from_dict(value)
                break
        verified = verify_run(
            directory,
            lock=lock,
            trusted_public_key=self.signer.public_key if self.signer else None,
            allow_advisory=self.signer is None,
        )
        provenance = {"available": False, "reason": "Research tracing is not configured"}
        if research is not None and lock is not None:
            try:
                provenance = research.trace(lock, verified)
            except Exception:
                provenance = {
                    "available": False,
                    "reason": "Research mapping check failed; refresh research inputs",
                }
        planned = {case.id: case for case in lock.plan.cases} if lock else {}
        return {
            "run_id": run_id,
            "research": provenance,
            "trusted": verified.trusted,
            "replayed": verified.replayed,
            "security_passed": verified.security_passed,
            "attested_pass": verified.attested_pass,
            "usage": verified.run.usage.to_dict() if verified.run else None,
            "cases": [
                {
                    "case_id": c.case_id,
                    "source_id": planned[c.case_id].source_id if c.case_id in planned else None,
                    "scenario_id": planned[c.case_id].scenario_id if c.case_id in planned else None,
                    "result": c.result.to_dict() if c.result else None,
                    "diagnostics": list(c.diagnostics),
                }
                for c in verified.run.cases
            ]
            if verified.run
            else [],
        }

    def close(self):
        with self.guard:
            self.closed = True
        for identifier in tuple(self.jobs):
            if self.jobs[identifier]["thread"].is_alive():
                self.cancel(identifier)
        for job in self.jobs.values():
            job["thread"].join(timeout=15)
        if any(job["thread"].is_alive() for job in self.jobs.values()):
            raise ContractError("Run cleanup has not completed")
