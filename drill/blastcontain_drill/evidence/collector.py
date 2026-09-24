"""Host-owned evidence authority. Plugins receive no registration or emitter handles."""

from __future__ import annotations

import hashlib

from ..contracts import ContractError, ScenarioSpec
from ..contracts.wire import _json_data
from ..suites.artifacts import canonical, digest
from .artifacts import ArtifactStore
from .records import (
    Action,
    ArtifactRef,
    Claim,
    Coverage,
    Delivery,
    Effect,
    Error,
    Evaluation,
    EvidenceBundle,
    EvidenceReceipt,
    EvidenceRecord,
    Output,
    Payload,
    Producer,
    Started,
    StateObservation,
    TaskCheck,
    Terminal,
)


class EvidenceLimitError(ContractError):
    """Collection stopped with a retained partial prefix; it cannot establish HELD."""


def authorize(producer: Producer, payload: Payload):
    """Same allowlist at capture and replay. Payload text cannot grant authority."""
    if isinstance(payload, (Started, Terminal, Error)):
        permitted = producer.role == "runtime"
    elif isinstance(payload, Claim):
        permitted = producer.role == "plugin"
    elif isinstance(payload, Output):
        permitted = producer.role == "environment" and "model_output" in producer.observations
    elif isinstance(payload, Delivery):
        permitted = producer.role == "environment" and "payload_delivery" in producer.observations
    elif isinstance(payload, Coverage):
        permitted = producer.role == "environment" and set(payload.channels) <= set(
            producer.observations
        )
    elif isinstance(payload, (Action, StateObservation)):
        permitted = producer.role == "environment" and "tool_actions" in producer.observations
    elif isinstance(payload, Effect):
        permitted = producer.role == "environment" and producer.scope == "independent"
    elif isinstance(payload, Evaluation):
        permitted = producer.role == "evaluator" and payload.axis in producer.axes
    elif isinstance(payload, TaskCheck):
        permitted = producer.role == "evaluator" and payload.check_id in producer.task_checks
    else:
        permitted = False
    if not permitted:
        raise ContractError("Producer cannot supply this evidence kind or scope")


class EvidenceCollector:
    def __init__(
        self,
        case_id: str,
        scenario: ScenarioSpec,
        *,
        store: ArtifactStore | None = None,
        max_records=2048,
        max_bytes=4_194_304,
        max_artifact_bytes=8_388_608,
    ):
        for name, value, cap in (
            ("records", max_records, 10000),
            ("bytes", max_bytes, 16_000_000),
            ("artifact bytes", max_artifact_bytes, 64_000_000),
        ):
            if type(value) is not int or not 1 <= value <= cap:
                raise ContractError(f"Invalid evidence {name} limit")
        self.case_id = case_id
        self.scenario_digest = digest(scenario.to_dict())
        self._scope = digest({"case": self.case_id, "scenario": self.scenario_digest})[7:]
        self.store = store
        self.max_records, self.max_bytes = max_records, max_bytes
        self.max_artifact_bytes = max_artifact_bytes
        self._bytes = 0
        self._artifact_bytes = 0
        self._producers: dict[object, Producer] = {}
        self._records: list[EvidenceRecord] = []
        self._artifacts: dict[str, ArtifactRef] = {}
        self._closed = False
        self._truncated = False
        self._runtime = self.register(Producer("collector", "runtime", "host"))
        self.record(self._runtime, Started())

    def register(self, producer: Producer) -> object:
        """Trusted application composition only; never expose through worker/broker JSON."""
        self._open()
        producer.to_dict()
        if any(p.id == producer.id for p in self._producers.values()):
            raise ContractError("Duplicate producer ID")
        if len(self._producers) >= 128:
            self._limit()
        handle = object()
        self._producers[handle] = producer
        return handle

    def _open(self):
        if self._closed:
            raise ContractError("Evidence collection is closed")

    def _producer(self, handle):
        try:
            return self._producers[handle]
        except (KeyError, TypeError) as exc:
            raise ContractError("Unknown collector-issued producer handle") from exc

    def _limit(self):
        self._truncated = True
        self._closed = True
        raise EvidenceLimitError("Evidence limit exhausted; retained trace is partial")

    def record(self, handle, payload: Payload) -> str:
        self._open()
        producer = self._producer(handle)
        authorize(producer, payload)
        if isinstance(payload, Started) and self._records:
            raise ContractError("Evidence cannot restart")
        event = EvidenceRecord(len(self._records), producer.id, payload)
        size = len(canonical(event.to_dict()))
        if len(self._records) >= self.max_records or self._bytes + size > self.max_bytes:
            self._limit()
        self._records.append(event)
        self._bytes += size
        if isinstance(payload, Terminal):
            self._closed = True
        return f"evidence:{self._scope}:{event.sequence}"

    def output(self, handle, text: str) -> str:
        if type(text) is not str:
            raise ContractError("Expected model output text")
        return self.record(
            handle, Output("sha256:" + hashlib.sha256(text.encode()).hexdigest(), len(text))
        )

    def claim(self, plugin_id: str, data) -> str:
        """Ingest arbitrary worker claims as digests only; ignore their authority/emitter fields."""
        self._open()
        try:
            _json_data(data, "claim")
        except RecursionError as exc:
            raise ContractError("Claim too deeply nested") from exc
        encoded = canonical(data)
        if len(encoded) > self.max_bytes - self._bytes:
            self._limit()
        # Producer IDs are host-assigned, never taken from the claim payload.
        producer = Producer("plugin:" + plugin_id, "plugin", "claim")
        handle = next((h for h, p in self._producers.items() if p == producer), None)
        if handle is None:
            handle = self.register(producer)
        return self.record(
            handle, Claim("sha256:" + hashlib.sha256(encoded).hexdigest(), len(encoded))
        )

    def artifact(self, handle, data) -> ArtifactRef:
        self._open()
        producer = self._producer(handle)
        if producer.role != "environment" or producer.scope != "independent":
            raise ContractError("Only registered independent observers retain effect proof")
        if self.store is None:
            raise ContractError("Proof artifact store is not configured")
        # Bound storage before writing. Exact envelope size is checked by the store too.
        _json_data(data, "proof")
        encoded_size = (
            len(
                canonical(
                    {
                        "schema_version": 1,
                        "case_id": self.case_id,
                        "scenario_digest": self.scenario_digest,
                        "emitter": producer.id,
                        "data": data,
                    }
                )
            )
            + 1
        )
        if self._artifact_bytes + encoded_size > self.max_artifact_bytes:
            self._limit()
        try:
            ref = self.store.put(self.case_id, self.scenario_digest, producer.id, data)
        except (OSError, ContractError):
            self._truncated = self._closed = True
            raise
        if ref.digest not in self._artifacts:
            self._artifacts[ref.digest] = ref
            self._artifact_bytes += ref.size_bytes
        return ref

    def error(self, reason="collector_error"):
        return self.record(self._runtime, Error(reason))

    def finish(self, reason="completed"):
        return self.record(self._runtime, Terminal(reason))

    def truncate(self):
        """Host supervisor stopped retention; preserve the prefix without claiming completion."""
        self._truncated = self._closed = True

    def snapshot(self) -> tuple[EvidenceBundle, EvidenceReceipt]:
        bundle = EvidenceBundle(
            self.case_id,
            self.scenario_digest,
            tuple(sorted(self._producers.values(), key=lambda p: p.id)),
            tuple(self._records),
            tuple(sorted(self._artifacts.values(), key=lambda a: a.digest)),
            self._truncated,
        )
        return bundle, EvidenceReceipt(self.case_id, self.scenario_digest, digest(bundle.to_dict()))
