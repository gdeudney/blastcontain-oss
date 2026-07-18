"""
Persistence (roadmap P2) — SQLAlchemy over SQLite by default.

Replaces the Phase-4 in-memory dicts. Schema is created on startup
(``create_all``); Alembic migrations come with the first deployed tenant.
``BLASTCONTAIN_DB_URL`` selects the database (default ``sqlite:///blastcontain.db``;
tests pass ``sqlite:///:memory:``).

Charter versioning model: one mutable **draft** row per ``(agent_id, env)``,
plus an append-only history of **signed version** rows. A signed row's
document is immutable; its lifecycle ``state`` and serving envelope
(``bundle`` = ``{packet, signature}``) are re-stamped on state changes so the
served packet always carries — and the signature always covers — the current
state.
"""
from __future__ import annotations

import json
import os

from sqlalchemy import JSON, Boolean, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

DEFAULT_DB_URL = "sqlite:///blastcontain.db"


class Base(DeclarativeBase):
    pass


class CharterRow(Base):
    __tablename__ = "charters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default="draft")
    draft: Mapped[bool] = mapped_column(Boolean, default=True)
    document: Mapped[dict] = mapped_column(JSON)                 # packet-shaped CharterDocument
    bundle: Mapped[dict | None] = mapped_column(JSON, nullable=True)   # {packet, signature}
    superseded: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class OperationRow(Base):
    __tablename__ = "operations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64))
    op: Mapped[str] = mapped_column(String(32))
    from_state: Mapped[str] = mapped_column(String(32))
    to_state: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(Text, default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[str] = mapped_column(String(40))


class FindingPacketRow(Base):
    __tablename__ = "finding_packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64), default="")
    packet: Mapped[dict] = mapped_column(JSON)
    signature_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ingested_at: Mapped[str] = mapped_column(String(40))


class DecisionRow(Base):
    __tablename__ = "decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64), default="")
    tool: Mapped[str] = mapped_column(String(255), default="")
    decision: Mapped[str] = mapped_column(String(32), default="")
    final: Mapped[str] = mapped_column(String(32), default="")
    event: Mapped[dict] = mapped_column(JSON)
    ingested_at: Mapped[str] = mapped_column(String(40))


class ExceptionRow(Base):
    __tablename__ = "exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64))
    objective_id: Mapped[str] = mapped_column(String(128))
    justification: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text, default="")
    granted_by: Mapped[str] = mapped_column(String(255))
    granted_at: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))


class StandardRow(Base):
    __tablename__ = "standards"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(64))
    document: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[str] = mapped_column(String(40))


class SettingRow(Base):
    """Org-level configuration (e.g. the `mpl_calibration` document)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[str] = mapped_column(String(40))


class AuditPacketRow(Base):
    __tablename__ = "audit_packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    environment: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), default="periodic")  # periodic | final
    grade: Mapped[str] = mapped_column(String(2), default="")
    bundle: Mapped[dict] = mapped_column(JSON)                         # {packet, signature}
    generated_at: Mapped[str] = mapped_column(String(40))


class Store:
    """Thin repository over the tables; sessions are per-call."""

    def __init__(self, db_url: str | None = None):
        url = db_url or os.environ.get("BLASTCONTAIN_DB_URL", DEFAULT_DB_URL)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        # A single shared connection keeps sqlite:///:memory: coherent across sessions.
        pool_kwargs = {"poolclass": None}
        if url.endswith(":memory:"):
            from sqlalchemy.pool import StaticPool

            pool_kwargs = {"poolclass": StaticPool}
        self.engine = create_engine(url, connect_args=connect_args, json_serializer=json.dumps,
                                    **{k: v for k, v in pool_kwargs.items() if v is not None})
        Base.metadata.create_all(self.engine)

    def session(self) -> Session:
        return Session(self.engine)

    # ── charters: draft ──────────────────────────────────────────────────────────

    def get_draft(self, agent_id: str, environment: str) -> CharterRow | None:
        with self.session() as s:
            return s.scalar(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(True))
                .order_by(CharterRow.id.desc())
            )

    def upsert_draft(self, document: dict, now: str) -> CharterRow:
        agent_id = document["agent_id"]
        environment = document["environment"]
        with self.session() as s:
            row = s.scalar(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(True))
            )
            if row is None:
                row = CharterRow(
                    agent_id=agent_id, environment=environment,
                    version=document.get("version", "0.1.0"),
                    state="draft", draft=True, document=document,
                    created_at=now, updated_at=now,
                )
                s.add(row)
            else:
                row.document = document
                row.version = document.get("version", row.version)
                row.updated_at = now
            s.commit()
            s.refresh(row)
            return row

    def delete_draft(self, agent_id: str, environment: str) -> None:
        with self.session() as s:
            row = s.scalar(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(True))
            )
            if row is not None:
                s.delete(row)
                s.commit()

    # ── charters: signed versions ────────────────────────────────────────────────

    def add_signed_version(self, document: dict, bundle: dict, now: str) -> CharterRow:
        agent_id = document["agent_id"]
        environment = document["environment"]
        with self.session() as s:
            for prior in s.scalars(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(False),
                       CharterRow.superseded.is_(False))
            ):
                prior.superseded = True
            row = CharterRow(
                agent_id=agent_id, environment=environment,
                version=document.get("version", ""),
                state=document.get("state", "active"), draft=False,
                document=document, bundle=bundle,
                created_at=now, updated_at=now,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            return row

    def latest_signed(self, agent_id: str, environment: str) -> CharterRow | None:
        with self.session() as s:
            return s.scalar(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(False),
                       CharterRow.superseded.is_(False))
                .order_by(CharterRow.id.desc())
            )

    def get_version(self, agent_id: str, environment: str, version: str) -> CharterRow | None:
        with self.session() as s:
            return s.scalar(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.version == version,
                       CharterRow.draft.is_(False))
                .order_by(CharterRow.id.desc())
            )

    def list_versions(self, agent_id: str, environment: str) -> list[CharterRow]:
        with self.session() as s:
            return list(s.scalars(
                select(CharterRow)
                .where(CharterRow.agent_id == agent_id,
                       CharterRow.environment == environment,
                       CharterRow.draft.is_(False))
                .order_by(CharterRow.id.asc())
            ))

    def restamp(self, row_id: int, state: str, bundle: dict, document: dict, now: str) -> None:
        """Update a signed row's lifecycle state + serving envelope (§7 ops)."""
        with self.session() as s:
            row = s.get(CharterRow, row_id)
            if row is None:
                raise KeyError(f"charter row {row_id} vanished")
            row.state = state
            row.bundle = bundle
            row.document = document
            row.updated_at = now
            s.commit()

    def list_agents(self) -> list[tuple[str, str, str]]:
        """Distinct (agent_id, environment, state) across signed charters + drafts.

        A working draft never masks a signed charter's lifecycle state: when a
        pair has both, the signed state wins — a draft alongside an active
        charter must not read as if enforcement lapsed. Drafts represent only
        pairs that have never been signed.
        """
        with self.session() as s:
            rows = s.scalars(
                select(CharterRow)
                .where(CharterRow.superseded.is_(False))
                .order_by(CharterRow.id.asc())
            )
            seen: dict[tuple[str, str], str] = {}
            for row in rows:
                key = (row.agent_id, row.environment)
                if row.state == "draft" and key in seen:
                    continue
                seen[key] = row.state
            return [(a, e, st) for (a, e), st in seen.items()]

    # ── operations log ───────────────────────────────────────────────────────────

    def log_operation(self, op: dict) -> None:
        with self.session() as s:
            s.add(OperationRow(**op))
            s.commit()

    def list_operations(self, agent_id: str, environment: str = "") -> list[OperationRow]:
        with self.session() as s:
            stmt = select(OperationRow).where(OperationRow.agent_id == agent_id)
            if environment:
                stmt = stmt.where(OperationRow.environment == environment)
            return list(s.scalars(stmt.order_by(OperationRow.id.asc())))

    def last_operation(self, agent_id: str, environment: str, op: str) -> OperationRow | None:
        with self.session() as s:
            return s.scalar(
                select(OperationRow)
                .where(OperationRow.agent_id == agent_id,
                       OperationRow.environment == environment,
                       OperationRow.op == op)
                .order_by(OperationRow.id.desc())
            )

    # ── findings ─────────────────────────────────────────────────────────────────

    def add_finding_packet(self, agent_id: str, environment: str, packet: dict,
                           signature_verified: bool | None, now: str) -> FindingPacketRow:
        with self.session() as s:
            row = FindingPacketRow(
                agent_id=agent_id, environment=environment, packet=packet,
                signature_verified=signature_verified, ingested_at=now,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            return row

    def list_finding_packets(self, agent_id: str, environment: str = "") -> list[FindingPacketRow]:
        with self.session() as s:
            stmt = select(FindingPacketRow).where(FindingPacketRow.agent_id == agent_id)
            if environment:
                stmt = stmt.where(FindingPacketRow.environment == environment)
            return list(s.scalars(stmt.order_by(FindingPacketRow.id.asc())))

    def all_finding_packets(self) -> list[FindingPacketRow]:
        with self.session() as s:
            return list(s.scalars(select(FindingPacketRow).order_by(FindingPacketRow.id.asc())))

    # ── decisions (Guard / AGT runtime stream) ───────────────────────────────────

    def add_decision(self, agent_id: str, environment: str, tool: str, decision: str,
                     final: str, event: dict, now: str) -> None:
        with self.session() as s:
            s.add(DecisionRow(
                agent_id=agent_id, environment=environment, tool=tool,
                decision=decision, final=final, event=event, ingested_at=now,
            ))
            s.commit()

    def list_decisions(self, agent_id: str, environment: str = "",
                       limit: int = 200) -> list[DecisionRow]:
        with self.session() as s:
            stmt = select(DecisionRow).where(DecisionRow.agent_id == agent_id)
            if environment:
                stmt = stmt.where(DecisionRow.environment == environment)
            return list(s.scalars(stmt.order_by(DecisionRow.id.desc()).limit(limit)))

    # ── exceptions ───────────────────────────────────────────────────────────────

    def add_exception(self, record: dict) -> None:
        with self.session() as s:
            s.add(ExceptionRow(**record))
            s.commit()

    def list_exceptions(self, agent_id: str, environment: str) -> list[ExceptionRow]:
        with self.session() as s:
            return list(s.scalars(
                select(ExceptionRow)
                .where(ExceptionRow.agent_id == agent_id,
                       ExceptionRow.environment == environment)
                .order_by(ExceptionRow.id.asc())
            ))

    # ── standards ────────────────────────────────────────────────────────────────

    def upsert_standard(self, standard: dict, now: str) -> None:
        with self.session() as s:
            row = s.get(StandardRow, standard["id"])
            if row is None:
                s.add(StandardRow(
                    id=standard["id"], name=standard.get("name", standard["id"]),
                    version=standard.get("version", "1"), document=standard, updated_at=now,
                ))
            else:
                row.name = standard.get("name", row.name)
                row.version = standard.get("version", row.version)
                row.document = standard
                row.updated_at = now
            s.commit()

    def list_standards(self) -> list[StandardRow]:
        with self.session() as s:
            return list(s.scalars(select(StandardRow).order_by(StandardRow.id.asc())))

    # ── settings ─────────────────────────────────────────────────────────────────

    def get_setting(self, key: str) -> dict | None:
        with self.session() as s:
            row = s.get(SettingRow, key)
            return row.value if row is not None else None

    def set_setting(self, key: str, value: dict, now: str) -> None:
        with self.session() as s:
            row = s.get(SettingRow, key)
            if row is None:
                s.add(SettingRow(key=key, value=value, updated_at=now))
            else:
                row.value = value
                row.updated_at = now
            s.commit()

    # ── audit packets ────────────────────────────────────────────────────────────

    def add_audit_packet(self, agent_id: str, environment: str, kind: str,
                         grade: str, bundle: dict, now: str) -> AuditPacketRow:
        with self.session() as s:
            row = AuditPacketRow(
                agent_id=agent_id, environment=environment, kind=kind,
                grade=grade, bundle=bundle, generated_at=now,
            )
            s.add(row)
            s.commit()
            s.refresh(row)
            return row

    def list_audit_packets(self, agent_id: str, environment: str = "") -> list[AuditPacketRow]:
        with self.session() as s:
            stmt = select(AuditPacketRow).where(AuditPacketRow.agent_id == agent_id)
            if environment:
                stmt = stmt.where(AuditPacketRow.environment == environment)
            return list(s.scalars(stmt.order_by(AuditPacketRow.id.asc())))
