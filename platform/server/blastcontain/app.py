"""
BlastContain Platform — the FastAPI application (Charter + Ledger + Fleet).

Charter lifecycle is charter-spec §7/§8; the serving contract is the one the
OSS Guard consumes (``GET /v1/charters/{agent_id}?env=`` → a signed
``{packet, signature}`` bundle whose packet embeds the compiled
``governance.toolkit/v1`` policy). Decisions stream in from Guard/AGT as
CloudEvents on ``POST /v1/agents/{agent_id}/decisions``.

The Ledger half (roadmap P2): findings + decisions are **scrubbed**
(PII/secrets hashed) before persist, priced (MPL exposure index with per-org
calibration and the human-oversight factor), measured (HITL quality, drift),
streamed (``/stream`` SSE), and summarized into a **signed Audit Packet** —
the regulatory artifact. Decommission emits a final packet.

Auth: set ``BLASTCONTAIN_API_TOKEN`` to require ``Authorization: Bearer`` on
every ``/v1`` route. Signing: ``BLASTCONTAIN_SIGNING_KEY_PATH`` (Ed25519) or
``BLASTCONTAIN_SIGNING_KEY`` (HMAC) — without a real key the platform signs
*advisory* bundles, which Guard rejects unless explicitly allowed.

Still planned: ``push_to_agt`` (Phase 5), multi-tenancy, LLM-judge HITL sampling.
"""
from __future__ import annotations

import asyncio
import collections
import datetime
import json
import os
from pathlib import Path

from blastcontain_core.signing import sign_packet, verify_packet
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import PlainTextResponse, StreamingResponse

from .charter.compiler import CompileResult, compile_document
from .charter.derive import derive_document
from .charter.lifecycle import LifecycleError, transition
from .charter.schema import CharterDocument, ExceptionRecord, Standard
from .ledger.audit_packet import build_audit_packet
from .ledger.drift import compute_drift
from .ledger.hitl import compute_hitl_metrics
from .ledger.mpl import MPLCalibration, MPLInput, mpl_report, oversight_level
from .ledger import notify
from .ledger.notify import Notifier
from .ledger.scrub import scrub_packet
from .store import Store

API_VERSION = "0.2.0"

TOMBSTONE_FINDING_TYPE = "blastcontain.lifecycle.tombstone_traffic"


class EventLog:
    """In-process fan-out for /stream — a bounded log SSE clients poll."""

    def __init__(self, maxlen: int = 1000):
        self._events: collections.deque = collections.deque(maxlen=maxlen)
        self._seq = 0

    @property
    def last_seq(self) -> int:
        return self._seq

    def publish(self, event_type: str, agent_id: str, at: str, data: dict) -> None:
        self._seq += 1
        self._events.append({
            "seq": self._seq, "type": event_type, "agent_id": agent_id,
            "at": at, "data": data,
        })

    def since(self, seq: int) -> list[dict]:
        return [e for e in self._events if e["seq"] > seq]


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signer() -> tuple[str, str]:
    return (
        os.environ.get("BLASTCONTAIN_SIGNER_DID", "did:key:local-platform"),
        os.environ.get("BLASTCONTAIN_SIGNING_KEY_ID", "local"),
    )


def _bump_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 3 and parts[2].isdigit():
        return ".".join([parts[0], parts[1], str(int(parts[2]) + 1)])
    return f"{version}.1"


def create_app(db_url: str | None = None) -> FastAPI:
    app = FastAPI(
        title="BlastContain",
        description="Agent Governance Platform — Charter + Ledger + Fleet API",
        version=API_VERSION,
    )
    store = Store(db_url)
    app.state.store = store
    events = EventLog()
    app.state.events = events
    notifier = Notifier.from_env()
    app.state.notifier = notifier

    # Serve the curated OpenAPI document (server/docs/openapi.yaml) — handlers
    # take plain dicts, so the auto-generated schema has no body shapes. The
    # curated spec is what the frontend builds against; a doc-drift test pins
    # it to the registered routes. Falls back to auto-generation if missing.
    def curated_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        spec_path = Path(__file__).resolve().parents[1] / "docs" / "openapi.yaml"
        if spec_path.exists():
            import yaml  # type: ignore

            app.openapi_schema = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
        else:
            app.openapi_schema = get_openapi(
                title=app.title, version=app.version,
                description=app.description, routes=app.routes,
            )
        return app.openapi_schema

    app.openapi = curated_openapi  # type: ignore[method-assign]

    # ── auth ───────────────────────────────────────────────────────────────────

    def require_token(request: Request) -> None:
        expected = os.environ.get("BLASTCONTAIN_API_TOKEN", "")
        if not expected:
            return
        supplied = request.headers.get("authorization", "")
        if supplied != f"Bearer {expected}":
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    auth = Depends(require_token)

    # ── helpers ────────────────────────────────────────────────────────────────

    def _standards() -> tuple[Standard, ...]:
        return tuple(Standard.from_dict(row.document) for row in store.list_standards())

    def _exceptions(agent_id: str, environment: str) -> tuple[ExceptionRecord, ...]:
        return tuple(
            ExceptionRecord(
                objective_id=r.objective_id, agent_id=r.agent_id, environment=r.environment,
                justification=r.justification, granted_by=r.granted_by,
                granted_at=r.granted_at, expires_at=r.expires_at, scope=r.scope,
            )
            for r in store.list_exceptions(agent_id, environment)
        )

    def _compile(doc: CharterDocument) -> CompileResult:
        return compile_document(
            doc,
            standards=_standards(),
            exceptions=_exceptions(doc.agent_id, doc.environment),
            now_iso=_now(),
        )

    def _issue_bundle(doc: CharterDocument, compiled: dict) -> tuple[dict, dict]:
        """Sign the packet (control + intent + state + compiled policy)."""
        now = _now()
        signed_by, key_id = _signer()
        doc.control.signed_at = now
        doc.control.signed_by = signed_by
        doc.control.signing_key_id = key_id
        packet = doc.to_packet(compiled_policy=compiled)
        signature = sign_packet(packet, signed_at=now, key_id=key_id)
        document = doc.to_packet()                  # stored copy, sans compiled_policy
        return document, {"packet": packet, "signature": signature}

    def _restamp(row, new_state: str, extra: dict | None = None) -> dict:
        """Re-issue a signed row's envelope so the signature covers the new state."""
        bundle = row.bundle or {}
        packet = dict(bundle.get("packet") or row.document)
        packet["state"] = new_state
        packet.update(extra or {})
        now = _now()
        _signed_by, key_id = _signer()
        signature = sign_packet(packet, signed_at=now, key_id=key_id)
        document = {k: v for k, v in packet.items() if k != "compiled_policy"}
        new_bundle = {"packet": packet, "signature": signature}
        store.restamp(row.id, new_state, new_bundle, document, now)
        return new_bundle

    def _lifecycle_op(agent_id: str, env: str, op: str, actor: str,
                      reason: str = "", params: dict | None = None,
                      extra_packet_fields: dict | None = None) -> dict:
        row = store.latest_signed(agent_id, env)
        if row is None:
            raise HTTPException(status_code=404,
                                detail=f"no signed Charter for {agent_id}/{env}")
        if not actor:
            raise HTTPException(status_code=400, detail="actor is required (named accountability)")
        try:
            operation = transition(op, row.state, agent_id, env, actor, _now(),
                                   reason=reason, params=params)
        except LifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if operation.to_state != row.state or extra_packet_fields:
            _restamp(row, operation.to_state, extra_packet_fields)
        store.log_operation(operation.to_dict())
        events.publish("operation", agent_id, _now(), operation.to_dict())
        return {"agent_id": agent_id, "environment": env,
                "state": operation.to_state, "operation": operation.to_dict()}

    # ── health ─────────────────────────────────────────────────────────────────

    @app.get("/health")
    def health():
        return {"status": "ok", "version": API_VERSION, "timestamp": _now()}

    # ── charters: authoring ────────────────────────────────────────────────────

    @app.post("/v1/charters", status_code=201, dependencies=[auth])
    def create_charter(body: dict):
        """Create or update a draft Charter (signing is a separate, deliberate gate)."""
        try:
            doc = CharterDocument.from_dict(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        doc.state = "draft"
        doc.control.draft = True
        problems = doc.validate()
        if problems:
            raise HTTPException(status_code=400, detail="; ".join(problems))
        result = _compile(doc)
        row = store.upsert_draft(doc.to_packet(), _now())
        return {
            "accepted": True,
            "charter_id": f"{doc.agent_id}:{doc.environment}",
            "state": "draft",
            "draft_row": row.id,
            "conflicts": [c.to_dict() for c in result.conflicts],
        }

    @app.post("/v1/charters/{agent_id}/derive", status_code=201, dependencies=[auth])
    def derive_charter(agent_id: str, body: dict, env: str = "prod"):
        """Derive-then-ratify: auto-draft a tight Charter from observed reality."""
        doc = derive_document(
            agent_id, env,
            audit_packet=body.get("audit_packet"),
            observed=body.get("observed"),
            autonomy_mode=body.get("autonomy_mode", "interactive"),
            base_strictness=body.get("base_strictness", "balanced"),
            owner=body.get("owner"),
        )
        result = _compile(doc)
        store.upsert_draft(doc.to_packet(), _now())
        return {
            "accepted": True,
            "charter_id": f"{agent_id}:{env}",
            "state": "draft",
            "document": doc.to_packet(),
            "conflicts": [c.to_dict() for c in result.conflicts],
        }

    @app.post("/v1/charters/{agent_id}/sign", dependencies=[auth])
    def sign_charter(agent_id: str, body: dict, env: str = "prod"):
        """Sign + register the draft: draft → Active. The commitment gate (§3.5)."""
        actor = str(body.get("actor", ""))
        draft = store.get_draft(agent_id, env)
        if draft is None:
            raise HTTPException(status_code=404, detail=f"no draft Charter for {agent_id}/{env}")
        doc = CharterDocument.from_dict(draft.document)
        if body.get("version"):
            doc.control.version = str(body["version"])

        result = _compile(doc)
        if result.blocking_conflicts:
            raise HTTPException(status_code=409, detail={
                "message": "blocking conflicts — reconcile or file an Exception (§3.6)",
                "conflicts": [c.to_dict() for c in result.blocking_conflicts],
            })

        try:
            operation = transition("register", "draft", agent_id, env, actor, _now())
        except LifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        doc.state = "active"
        doc.control.draft = False
        doc.objectives = result.resolved_objectives
        document, bundle = _issue_bundle(doc, result.policy)
        store.add_signed_version(document, bundle, _now())
        store.delete_draft(agent_id, env)
        store.log_operation(operation.to_dict())
        return {
            "signed": True,
            "state": "active",
            "version": doc.version,
            "advisory_signature": bool(bundle["signature"].get("advisory")),
            "conflicts": [c.to_dict() for c in result.conflicts],
            "bundle": bundle,
        }

    # ── charters: serving (the Guard contract) ─────────────────────────────────

    @app.get("/v1/charters/{agent_id}", dependencies=[auth])
    def get_charter(agent_id: str, env: str = "prod", include_draft: bool = False):
        """Fetch the signed Charter bundle for agent + environment."""
        if include_draft:
            draft = store.get_draft(agent_id, env)
            if draft is not None:
                return {"draft": True, "document": draft.document}
        row = store.latest_signed(agent_id, env)
        if row is None or row.bundle is None:
            raise HTTPException(status_code=404,
                                detail=f"Charter not found for {agent_id}/{env}")
        return row.bundle

    @app.get("/v1/charters/{agent_id}/versions", dependencies=[auth])
    def list_charter_versions(agent_id: str, env: str = "prod"):
        rows = store.list_versions(agent_id, env)
        return {"agent_id": agent_id, "environment": env, "versions": [
            {"version": r.version, "state": r.state, "superseded": r.superseded,
             "created_at": r.created_at, "updated_at": r.updated_at}
            for r in rows
        ]}

    @app.get("/v1/charters/{agent_id}/policy", dependencies=[auth])
    def get_compiled_policy(agent_id: str, env: str = "prod", fmt: str = "json",
                            draft: bool = False):
        """The compiled governance.toolkit/v1 policy (§6.2)."""
        if draft:
            draft_row = store.get_draft(agent_id, env)
            if draft_row is None:
                raise HTTPException(status_code=404, detail="no draft to compile")
            result = _compile(CharterDocument.from_dict(draft_row.document))
            policy = result.policy
        else:
            row = store.latest_signed(agent_id, env)
            if row is None or row.bundle is None:
                raise HTTPException(status_code=404, detail="no signed Charter")
            policy = (row.bundle.get("packet") or {}).get("compiled_policy")
            if not policy:
                raise HTTPException(status_code=404, detail="signed Charter has no compiled policy")
        if fmt == "yaml":
            import yaml  # type: ignore

            return PlainTextResponse(
                yaml.safe_dump(policy, sort_keys=False, default_flow_style=False),
                media_type="application/yaml",
            )
        return policy

    @app.get("/v1/charters/{agent_id}/diff", dependencies=[auth])
    def diff_charter(agent_id: str, env: str = "prod", from_version: str = "",
                     to_version: str = ""):
        """Diff two versions — surfaces capability creep (§8)."""
        a = store.get_version(agent_id, env, from_version) if from_version else None
        b = store.get_version(agent_id, env, to_version) if to_version else None
        if a is None or b is None:
            raise HTTPException(status_code=404, detail="from/to version not found "
                                "(use ?from_version=&to_version=)")
        return _diff_documents(a.document, b.document)

    # ── charters: governance operations ────────────────────────────────────────

    @app.post("/v1/charters/{agent_id}/promote", dependencies=[auth])
    def promote_charter(agent_id: str, body: dict):
        """Promotion is a governance gate, not a pipeline step (§7.3)."""
        from_env = str(body.get("from_env", ""))
        to_env = str(body.get("to_env", ""))
        actor = str(body.get("actor", ""))
        if not from_env or not to_env or not actor:
            raise HTTPException(status_code=400, detail="from_env, to_env, actor required")
        source = store.latest_signed(agent_id, from_env)
        if source is None:
            raise HTTPException(status_code=404,
                                detail=f"no signed Charter for {agent_id}/{from_env}")
        if source.state != "active":
            raise HTTPException(status_code=409,
                                detail=f"source Charter is {source.state}, not active")

        unaddressed = _unaddressed_criticals(agent_id, from_env, source.document)
        if unaddressed:
            raise HTTPException(status_code=409, detail={
                "message": "promotion blocked: CRITICAL findings without remediation proof",
                "finding_types": unaddressed,
            })

        doc = CharterDocument.from_dict(source.document)
        doc.control.environment = to_env
        doc.state = "draft"
        doc.control.draft = True
        doc.control.signed_at = None
        doc.control.signed_by = None
        store.upsert_draft(doc.to_packet(), _now())
        operation = transition("promote", source.state, agent_id, from_env, actor, _now(),
                               params={"from_env": from_env, "to_env": to_env})
        store.log_operation(operation.to_dict())
        return {"promoted": True, "draft_environment": to_env,
                "note": "promotion drafted; prod promotion requires sign-off (POST .../sign)"}

    @app.post("/v1/charters/{agent_id}/rollback", dependencies=[auth])
    def rollback_charter(agent_id: str, body: dict, env: str = "prod"):
        """Revert to the last-known-good signed version (§7.3)."""
        actor = str(body.get("actor", ""))
        if not actor:
            raise HTTPException(status_code=400, detail="actor required")
        current = store.latest_signed(agent_id, env)
        if current is None:
            raise HTTPException(status_code=404, detail="no signed Charter")
        versions = [r for r in store.list_versions(agent_id, env) if r.id != current.id]
        if not versions:
            raise HTTPException(status_code=409, detail="no prior version to roll back to")
        prior = versions[-1]
        try:
            operation = transition("rollback", current.state, agent_id, env, actor, _now(),
                                   reason=str(body.get("reason", "")),
                                   params={"from_version": current.version,
                                           "to_version": prior.version})
        except LifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        doc = CharterDocument.from_dict(prior.document)
        doc.state = "active"
        result = _compile(doc)
        document, bundle = _issue_bundle(doc, result.policy)
        store.add_signed_version(document, bundle, _now())
        store.log_operation(operation.to_dict())
        return {"rolled_back": True, "version": prior.version, "state": "active"}

    @app.post("/v1/charters/{agent_id}/recertify", dependencies=[auth])
    def recertify_charter(agent_id: str, body: dict, env: str = "prod"):
        """Quarantine → Active, only via a proof addressing the trigger (§7.4)."""
        actor = str(body.get("actor", ""))
        proof = body.get("proof") or {}
        if not actor or not proof.get("finding_type") or not proof.get("evidence_uri"):
            raise HTTPException(status_code=400,
                                detail="actor and proof{finding_type, evidence_uri} required")
        row = store.latest_signed(agent_id, env)
        if row is None:
            raise HTTPException(status_code=404, detail="no signed Charter")

        quarantine_op = store.last_operation(agent_id, env, "quarantine")
        trigger = (quarantine_op.params or {}).get("finding_type") if quarantine_op else None
        if trigger and proof["finding_type"] != trigger:
            raise HTTPException(status_code=409, detail={
                "message": "the proof must address the FindingType that triggered quarantine",
                "required": trigger, "supplied": proof["finding_type"],
            })

        try:
            operation = transition("recertify", row.state, agent_id, env, actor, _now(),
                                   params={"proof": proof})
        except LifecycleError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        doc = CharterDocument.from_dict(row.document)
        doc.control.remediation_proofs.append(_as_proof(proof))
        doc.control.version = _bump_patch(doc.control.version)
        doc.state = "active"
        result = _compile(doc)
        if result.blocking_conflicts:
            raise HTTPException(status_code=409, detail={
                "message": "the remediated Charter still has blocking conflicts",
                "conflicts": [c.to_dict() for c in result.blocking_conflicts],
            })
        document, bundle = _issue_bundle(doc, result.policy)
        store.add_signed_version(document, bundle, _now())
        store.log_operation(operation.to_dict())
        return {"recertified": True, "version": doc.version, "state": "active",
                "proof_of_remediation": proof}

    @app.post("/v1/charters/{agent_id}/exceptions", status_code=201, dependencies=[auth])
    def file_exception(agent_id: str, body: dict, env: str = "prod"):
        """Break-glass deviation from a mandatory objective — expires (§3.6)."""
        record = dict(body)
        record.setdefault("agent_id", agent_id)
        record.setdefault("environment", env)
        record.setdefault("granted_at", _now())
        try:
            exc_record = ExceptionRecord.from_dict(record)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        latest = store.latest_signed(agent_id, env) or store.get_draft(agent_id, env)
        owner = (latest.document or {}).get("owner") if latest else None
        if owner and owner == exc_record.granted_by:
            raise HTTPException(status_code=403, detail=(
                "separation of duties: the owner cannot approve their own Exception — "
                "central sign-off required (§3.6)"
            ))
        store.add_exception(exc_record.to_dict())
        operation = transition("exception", latest.state if latest else "draft",
                               agent_id, env, exc_record.granted_by, _now(),
                               reason=exc_record.justification,
                               params={"objective_id": exc_record.objective_id,
                                       "expires_at": exc_record.expires_at})
        store.log_operation(operation.to_dict())
        return {"accepted": True, "exception": exc_record.to_dict()}

    # ── standards ──────────────────────────────────────────────────────────────

    @app.post("/v1/standards", status_code=201, dependencies=[auth])
    def upsert_standard(body: dict):
        try:
            standard = Standard.from_dict(body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store.upsert_standard(standard.to_dict(), _now())
        return {"accepted": True, "standard_id": standard.id}

    @app.get("/v1/standards", dependencies=[auth])
    def list_standards():
        return {"standards": [row.document for row in store.list_standards()]}

    # ── agent lifecycle ────────────────────────────────────────────────────────

    @app.post("/v1/agents/{agent_id}/pause", dependencies=[auth])
    def pause_agent(agent_id: str, body: dict, env: str = "prod"):
        mode = str(body.get("mode", "deny-all"))
        result = _lifecycle_op(agent_id, env, "pause", str(body.get("actor", "")),
                               reason=str(body.get("reason", "")), params={"mode": mode})
        result["impact"] = {
            "deny-all": "agent stays alive; every action denied; fully reversible",
            "drain": "in-flight actions complete; new ones denied",
            "halt": "process stopped — heaviest; resume restarts enforcement",
        }.get(mode)
        return result

    @app.post("/v1/agents/{agent_id}/resume", dependencies=[auth])
    def resume_agent(agent_id: str, body: dict, env: str = "prod"):
        return _lifecycle_op(agent_id, env, "resume", str(body.get("actor", "")),
                             reason=str(body.get("reason", "")))

    @app.post("/v1/agents/{agent_id}/stop", dependencies=[auth])
    def emergency_stop(agent_id: str, body: dict, env: str = "prod"):
        """Break-glass kill: immediate hard stop, lands in paused pending review (§7.1)."""
        return _lifecycle_op(agent_id, env, "kill", str(body.get("actor", "")),
                             reason=str(body.get("reason", "")))

    @app.post("/v1/agents/{agent_id}/decommission", dependencies=[auth])
    def decommission_agent(agent_id: str, body: dict, env: str = "prod"):
        """End-of-life: revoke, block, retain the record, watch the tombstone (§7.5).

        Emits the **final Audit Packet** — the closing record (compliance grade,
        lifetime exposure, finding + approval history).
        """
        result = _lifecycle_op(agent_id, env, "decommission", str(body.get("actor", "")),
                               reason=str(body.get("reason", "")))
        packet_row, bundle = _generate_audit_packet(agent_id, env, kind="final")
        result["final_audit_packet"] = {
            "id": packet_row.id,
            "grade": packet_row.grade,
            "generated_at": packet_row.generated_at,
        }
        return result

    @app.post("/v1/agents/{agent_id}/owner", dependencies=[auth])
    def transfer_owner(agent_id: str, body: dict, env: str = "prod"):
        new_owner = str(body.get("owner", ""))
        if not new_owner:
            raise HTTPException(status_code=400, detail="owner required")
        result = _lifecycle_op(agent_id, env, "transfer_owner", str(body.get("actor", "")),
                               params={"owner": new_owner},
                               extra_packet_fields={"owner": new_owner})
        draft = store.get_draft(agent_id, env)
        if draft is not None:
            document = dict(draft.document)
            document["owner"] = new_owner
            store.upsert_draft(document, _now())
        result["owner"] = new_owner
        return result

    @app.get("/v1/agents/{agent_id}/operations", dependencies=[auth])
    def list_operations(agent_id: str, env: str = ""):
        """The decision-rights log: date · change · rationale · approver (§2.5)."""
        ops = store.list_operations(agent_id, env)
        return {"agent_id": agent_id, "operations": [
            {"op": o.op, "from_state": o.from_state, "to_state": o.to_state,
             "actor": o.actor, "reason": o.reason, "params": o.params, "at": o.at}
            for o in ops
        ]}

    # ── findings (Ledger ingest) ───────────────────────────────────────────────

    @app.post("/v1/agents/{agent_id}/findings", status_code=201, dependencies=[auth])
    def ingest_findings(agent_id: str, body: dict):
        """Ingest a scan packet from Verify / Drill / Discovery.

        Accepts a bare packet or a signed ``{packet, signature}`` bundle; signed
        packets are verified (P2 ingest hardening). Evidence is **scrubbed**
        (PII/secrets hashed) after verification, before persist — the stored
        packet keeps the verification verdict, not the raw secrets. A CRITICAL
        finding against a signed prod Charter auto-quarantines the agent
        (§7.2/§7.4).
        """
        if "packet" in body and "signature" in body:
            packet = body["packet"]
            signature_verified = verify_packet(body)
        else:
            packet = body
            signature_verified = None
        packet, scrubbed = scrub_packet(packet)
        environment = str(packet.get("environment", ""))
        store.add_finding_packet(agent_id, environment, packet, signature_verified, _now())
        events.publish("finding", agent_id, _now(), {
            "environment": environment,
            "status": packet.get("status"),
            "finding_count": len(packet.get("findings", [])),
        })

        # A Discovery report carries `assets`, not `findings`: alert on shadow AI.
        shadow = [a for a in packet.get("assets", [])
                  if a.get("classification") == "UNKNOWN_SHADOW_AI"]
        for asset in shadow:
            notifier.notify(
                notify.SHADOW_DISCOVERED, str(asset.get("asset_id", agent_id)), environment,
                notify.summarize(notify.SHADOW_DISCOVERED, str(asset.get("asset_id", "?")),
                                 f"{asset.get('asset_type', '?')} at {asset.get('location', '?')}"),
                _now(), discovered_by=agent_id, asset_type=asset.get("asset_type"),
            )

        quarantined = False
        critical = [f for f in packet.get("findings", [])
                    if f.get("severity") == "CRITICAL"]
        if critical:
            trigger = critical[0].get("finding_type", "unknown")
            notifier.notify(
                notify.CRITICAL_FINDING, agent_id, environment,
                notify.summarize(notify.CRITICAL_FINDING, agent_id,
                                 f"{len(critical)} CRITICAL — {trigger}"),
                _now(), finding_types=[f.get("finding_type") for f in critical],
            )
            if environment == "prod":
                row = store.latest_signed(agent_id, environment)
                if row is not None and row.state == "active":
                    operation = transition(
                        "quarantine", row.state, agent_id, environment,
                        actor="platform:auto", at=_now(),
                        reason="CRITICAL finding on a prod Charter",
                        params={"finding_type": trigger},
                    )
                    _restamp(row, operation.to_state)
                    store.log_operation(operation.to_dict())
                    quarantined = True
                    events.publish("operation", agent_id, _now(), operation.to_dict())
                    notifier.notify(
                        notify.QUARANTINE, agent_id, environment,
                        notify.summarize(notify.QUARANTINE, agent_id, trigger),
                        _now(), finding_type=trigger,
                    )

        return {
            "accepted": True,
            "finding_count": len(packet.get("findings", [])),
            "signature_verified": signature_verified,
            "evidence_scrubbed": scrubbed,
            "quarantined": quarantined,
        }

    @app.get("/v1/agents/{agent_id}/findings", dependencies=[auth])
    def get_findings(agent_id: str, env: str = ""):
        rows = store.list_finding_packets(agent_id, env)
        return {"agent_id": agent_id, "findings": [r.packet for r in rows]}

    # ── decisions (Guard / AGT runtime stream) ─────────────────────────────────

    @app.post("/v1/agents/{agent_id}/decisions", status_code=202, dependencies=[auth])
    def ingest_decision(agent_id: str, body: dict):
        """Ingest a Guard/AGT decision CloudEvent (the Art. 12/14 evidence stream).

        Payloads are scrubbed (PII/secrets hashed) before persist.
        """
        body, _scrubbed = scrub_packet(body)
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        environment = str(data.get("environment", ""))
        store.add_decision(
            agent_id, environment,
            tool=str(data.get("tool", body.get("subject", ""))),
            decision=str(data.get("decision", "")),
            final=str(data.get("final", "")),
            event=body, now=_now(),
        )
        events.publish("decision", agent_id, _now(), {
            "environment": environment,
            "tool": str(data.get("tool", "")),
            "decision": str(data.get("decision", "")),
            "final": str(data.get("final", "")),
        })

        # Tombstone monitoring (§7.5): traffic for a decommissioned agent is a finding.
        row = store.latest_signed(agent_id, environment or "prod")
        if row is not None and row.state in ("decommissioned", "archived"):
            store.add_finding_packet(agent_id, environment, {
                "environment": environment,
                "findings": [{
                    "finding_type": "blastcontain.lifecycle.tombstone_traffic",
                    "severity": "HIGH",
                    "title": "Decision traffic for a decommissioned agent",
                    "detail": f"agent {agent_id} is {row.state} but a decision event "
                              "arrived — stale chain, reused agent_id, or an attacker.",
                }],
            }, signature_verified=None, now=_now())
            notifier.notify(
                notify.TOMBSTONE, agent_id, environment or "prod",
                notify.summarize(notify.TOMBSTONE, agent_id, f"state={row.state}"),
                _now(), tool=str(data.get("tool", "")),
            )
            return {"accepted": True, "tombstone_alert": True}
        return {"accepted": True}

    @app.get("/v1/agents/{agent_id}/decisions", dependencies=[auth])
    def list_decisions(agent_id: str, env: str = "", limit: int = 200):
        rows = store.list_decisions(agent_id, env, limit)
        return {"agent_id": agent_id, "decisions": [r.event for r in rows]}

    # ── ledger / fleet ─────────────────────────────────────────────────────────

    def _calibration() -> MPLCalibration:
        return MPLCalibration.from_dict(store.get_setting("mpl_calibration"))

    def _decision_events(agent_id: str, env: str, limit: int = 1000) -> list[dict]:
        return [r.event for r in store.list_decisions(agent_id, env, limit)]

    def _latest_scan(agent_id: str, env: str) -> dict | None:
        # The newest packet that is an actual scan (tombstone alerts etc. carry
        # findings but no scan status).
        for row in reversed(store.list_finding_packets(agent_id, env)):
            if "status" in row.packet or "summary" in row.packet:
                return row.packet
        return None

    @app.get("/v1/agents/{agent_id}/mpl", dependencies=[auth])
    def mpl_estimate(agent_id: str, env: str = "prod",
                     classification: str = "INTERNAL", volume: int = 1,
                     regime: str = "STANDARD", business_context: str = "STANDARD",
                     hops: int = 1):
        """Exposure index (MPL) — calibrated, oversight-aware, banded."""
        row = store.latest_signed(agent_id, env)
        document = (row.document or {}) if row else {}
        trust_tier = int(document.get("trust_tier", 0))
        scan = _latest_scan(agent_id, env)
        max_tier = int((scan or {}).get("max_tier", trust_tier))

        hitl = compute_hitl_metrics(_decision_events(agent_id, env))
        oversight = oversight_level(document.get("autonomy_mode", "none"), hitl)

        inp = MPLInput(
            classification_label=classification, volume_records=volume,
            regulatory_regime=regime, business_context=business_context,
            hops=hops, agent_trust_tier=trust_tier, max_tier_in_chain=max_tier,
            oversight=oversight,
        )
        report = mpl_report(inp, _calibration())
        return {
            "agent_id": agent_id, "environment": env,
            **report,
            "mpl_usd": report["exposure"],     # back-compat alias
            "inputs": {"classification": classification, "volume": volume,
                       "regime": regime, "business_context": business_context,
                       "hops": hops, "trust_tier": trust_tier,
                       "max_tier_in_chain": max_tier, "oversight": oversight},
        }

    @app.get("/v1/agents/{agent_id}/hitl", dependencies=[auth])
    def hitl_metrics(agent_id: str, env: str = "", limit: int = 1000):
        """HITL quality (roadmap P2 ★): is the human gate real or rubber-stamped?"""
        metrics = compute_hitl_metrics(_decision_events(agent_id, env, limit))
        return {"agent_id": agent_id, "environment": env or "all", **metrics}

    @app.get("/v1/agents/{agent_id}/drift", dependencies=[auth])
    def drift_report(agent_id: str, env: str = "prod", limit: int = 1000):
        """Declared-vs-observed drift: unused grants, unlisted attempts,
        learning candidates, scan contradictions."""
        row = store.latest_signed(agent_id, env)
        if row is None:
            raise HTTPException(status_code=404, detail="no signed Charter to drift against")
        report = compute_drift(
            row.document or {},
            _decision_events(agent_id, env, limit),
            _latest_scan(agent_id, env),
        )
        return {"agent_id": agent_id, "environment": env,
                "charter_version": row.version, **report}

    @app.get("/v1/ledger/calibration", dependencies=[auth])
    def get_calibration():
        return {"calibration": _calibration().to_dict()}

    @app.post("/v1/ledger/calibration", dependencies=[auth])
    def set_calibration(body: dict):
        """Per-org MPL calibration (roadmap P2 ★) — the dollars are yours, not ours."""
        try:
            calibration = MPLCalibration.from_dict(body)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid calibration: {exc}") from exc
        store.set_setting("mpl_calibration", calibration.to_dict(), _now())
        return {"accepted": True, "calibration": calibration.to_dict()}

    # ── audit packets (the regulatory artifact) ────────────────────────────────

    def _generate_audit_packet(agent_id: str, env: str, kind: str = "periodic"):
        row = store.latest_signed(agent_id, env)
        document = (row.document or {}) if row else None
        state = row.state if row else "discovered"
        advisory_signed = bool(((row.bundle or {}).get("signature") or {}).get("advisory")) \
            if row else False

        scan = _latest_scan(agent_id, env)
        open_criticals = _unaddressed_criticals(agent_id, env, document or {})
        tombstones = sum(
            1
            for packet_row in store.list_finding_packets(agent_id, env)
            for finding in packet_row.packet.get("findings", [])
            if finding.get("finding_type") == TOMBSTONE_FINDING_TYPE
        )
        decision_events = _decision_events(agent_id, env)
        hitl = compute_hitl_metrics(decision_events)
        drift = compute_drift(document or {}, decision_events, scan)
        oversight = oversight_level(
            (document or {}).get("autonomy_mode", "none"), hitl
        )
        mpl_summary = mpl_report(MPLInput(
            agent_trust_tier=int((document or {}).get("trust_tier", 0)),
            max_tier_in_chain=int((scan or {}).get("max_tier", 0)),
            oversight=oversight,
        ), _calibration())

        now = _now()
        packet = build_audit_packet(
            agent_id=agent_id, environment=env, generated_at=now, kind=kind,
            charter_document=document, charter_state=state,
            versions=[{"version": r.version, "state": r.state,
                       "superseded": r.superseded, "created_at": r.created_at}
                      for r in store.list_versions(agent_id, env)],
            latest_scan=scan, open_critical_types=open_criticals,
            mpl_summary=mpl_summary, hitl=hitl, drift=drift,
            operations=[{"op": o.op, "from_state": o.from_state, "to_state": o.to_state,
                         "actor": o.actor, "reason": o.reason, "at": o.at}
                        for o in store.list_operations(agent_id, env)],
            exceptions=[{"objective_id": e.objective_id, "granted_by": e.granted_by,
                         "expires_at": e.expires_at, "justification": e.justification}
                        for e in store.list_exceptions(agent_id, env)],
            tombstone_findings=tombstones,
            advisory_signed=advisory_signed,
        )
        _signed_by, key_id = _signer()
        bundle = {"packet": packet, "signature": sign_packet(packet, signed_at=now,
                                                             key_id=key_id)}
        grade = packet["compliance"]["grade"]
        packet_row = store.add_audit_packet(agent_id, env, kind, grade, bundle, now)
        return packet_row, bundle

    @app.get("/v1/agents/{agent_id}/audit-packet", dependencies=[auth])
    def audit_packet(agent_id: str, env: str = "prod"):
        """Generate (and retain) a signed Audit Packet for the agent now."""
        _packet_row, bundle = _generate_audit_packet(agent_id, env, kind="periodic")
        return bundle

    @app.get("/v1/agents/{agent_id}/audit-packets", dependencies=[auth])
    def list_audit_packets(agent_id: str, env: str = ""):
        rows = store.list_audit_packets(agent_id, env)
        return {"agent_id": agent_id, "audit_packets": [
            {"id": r.id, "environment": r.environment, "kind": r.kind,
             "grade": r.grade, "generated_at": r.generated_at}
            for r in rows
        ]}

    # ── stream (SSE) ───────────────────────────────────────────────────────────

    @app.get("/stream", dependencies=[auth])
    async def stream(request: Request):
        """Server-sent events: findings, decisions, lifecycle operations."""
        async def generate():
            last = events.last_seq          # only events after connect
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    return
                for event in events.since(last):
                    last = event["seq"]
                    yield f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                await asyncio.sleep(0.25)

        return StreamingResponse(generate(), media_type="text/event-stream")

    @app.get("/v1/agents", dependencies=[auth])
    def list_agents(env: str = ""):
        agents = [
            {"agent_id": a, "environment": e, "state": st}
            for (a, e, st) in store.list_agents()
            if not env or e == env
        ]
        return {"agents": agents}

    @app.get("/fleet", dependencies=[auth])
    def fleet():
        """Fleet-wide compliance status."""
        agents = []
        charter_states = {(a, e): st for (a, e, st) in store.list_agents()}
        latest_scans: dict[str, dict] = {}
        for row in store.all_finding_packets():
            latest_scans[row.agent_id] = row.packet
        agent_ids = {a for (a, _e) in charter_states} | set(latest_scans)
        for agent_id in sorted(agent_ids):
            scan = latest_scans.get(agent_id, {})
            states = {e: st for (a, e), st in charter_states.items() if a == agent_id}
            agents.append({
                "agent_id": agent_id,
                "status": scan.get("status", "UNKNOWN"),
                "last_scan": scan.get("scanned_at"),
                "critical": scan.get("summary", {}).get("critical", 0),
                "charters": states,
            })
        return {"agents": agents, "total": len(agents)}

    @app.get("/violations", dependencies=[auth])
    def violations():
        """All CRITICAL/HIGH findings across the fleet."""
        result = []
        for row in store.all_finding_packets():
            for finding in row.packet.get("findings", []):
                if finding.get("severity") in ("CRITICAL", "HIGH"):
                    result.append({"agent_id": row.agent_id, **finding})
        return {"violations": result, "total": len(result)}

    # ── module-level helpers bound to the store ────────────────────────────────

    def _unaddressed_criticals(agent_id: str, env: str, document: dict) -> list[str]:
        latest = _latest_scan(agent_id, env)
        if not latest:
            return []
        critical_types = {
            f.get("finding_type", "unknown")
            for f in latest.get("findings", [])
            if f.get("severity") == "CRITICAL"
        }
        proven = {p.get("finding_type") for p in document.get("remediation_proofs", [])}
        return sorted(critical_types - proven)

    return app


def _as_proof(raw: dict):
    from blastcontain_core.charter import RemediationProof

    return RemediationProof(
        finding_type=str(raw["finding_type"]),
        evidence_uri=str(raw["evidence_uri"]),
        verified_by=raw.get("verified_by"),
        verified_at=raw.get("verified_at"),
    )


def _diff_documents(a: dict, b: dict) -> dict:
    """Capability diff between two charter documents (§8 — surfaces creep)."""
    def listdiff(key: str, items=None):
        get = items or (lambda d: d.get(key) or [])
        old, new = get(a), get(b)
        old_set = {repr(x) for x in old}
        new_set = {repr(x) for x in new}
        added = [x for x in new if repr(x) not in old_set]
        removed = [x for x in old if repr(x) not in new_set]
        return added, removed

    tools_added, tools_removed = listdiff("permitted_tools")
    apis_added, apis_removed = listdiff("permitted_apis")
    mcp_added, mcp_removed = listdiff("mcp_servers")
    obj_added, obj_removed = listdiff(
        "objectives", lambda d: [o.get("id") for o in d.get("objectives") or []]
    )

    constraints_changed = {}
    for field_name in ("read_only_rootfs", "egress_blocked", "max_trust_tier", "verify_required"):
        old = (a.get("environment_constraints") or {}).get(field_name)
        new = (b.get("environment_constraints") or {}).get(field_name)
        if old != new:
            constraints_changed[field_name] = {"from": old, "to": new}

    tier_from = a.get("trust_tier")
    tier_to = b.get("trust_tier")

    creep = bool(
        tools_added or apis_added or mcp_added or obj_removed
        or (tier_to or 0) > (tier_from or 0)
        or any(c["from"] is True and c["to"] is False for c in constraints_changed.values()
               if isinstance(c["from"], bool))
    )
    return {
        "from_version": a.get("version"), "to_version": b.get("version"),
        "permitted_tools": {"added": tools_added, "removed": tools_removed},
        "permitted_apis": {"added": apis_added, "removed": apis_removed},
        "mcp_servers": {"added": mcp_added, "removed": mcp_removed},
        "objectives": {"added": obj_added, "removed": obj_removed},
        "environment_constraints": constraints_changed,
        "trust_tier": {"from": tier_from, "to": tier_to},
        "autonomy_mode": {"from": a.get("autonomy_mode"), "to": b.get("autonomy_mode")},
        "capability_creep": creep,
    }
