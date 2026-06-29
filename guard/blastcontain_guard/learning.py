"""
blastcontain_guard.learning — the derive-then-ratify signal (guard-spec §7).

When a user answers an *ask* with **allow always**, that is evidence the Charter
is too tight: the tool should probably be in ``permitted_tools``. Guard does not
silently widen policy — that would violate the platform's founding tenet (derive
then ratify; the human ratifies the change later, logged). Instead it *records a
proposal* and emits it as telemetry. A human (or the Platform's review UI) turns
accumulated proposals into a Charter change.

The store is intentionally dumb: an append-only list of proposals, de-duplicated
by (tool, action), optionally mirrored to a JSON file a reviewer can read.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from .models import LearningProposal

ProposalSink = Callable[[LearningProposal], None]


class LearningStore:
    """Accumulates ``permitted_tools`` proposals from ``allow always`` choices."""

    def __init__(self, sink: Optional[ProposalSink] = None):
        self._proposals: list[LearningProposal] = []
        self._seen: set[tuple[str, str]] = set()
        self._sink = sink

    def propose_permitted_tool(
        self,
        agent_id: str,
        tool_name: str,
        action_type: str = "",
        approver_id: Optional[str] = None,
    ) -> Optional[LearningProposal]:
        """Record a proposal to add ``tool_name`` to ``permitted_tools``.

        De-duplicated per (tool, action): a tool a user keeps allow-always-ing
        produces one standing proposal, not a pile. Returns the new proposal, or
        ``None`` if one already exists for that pair.
        """
        key = (tool_name, action_type)
        if key in self._seen:
            return None
        self._seen.add(key)
        proposal = LearningProposal(
            agent_id=agent_id,
            tool_name=tool_name,
            action_type=action_type,
            approver_id=approver_id,
        )
        self._proposals.append(proposal)
        if self._sink is not None:
            try:
                self._sink(proposal)
            except Exception:
                # A learning signal must never break enforcement.
                pass
        return proposal

    def pending(self) -> list[LearningProposal]:
        return list(self._proposals)

    def write(self, path: str) -> dict:
        """Write pending proposals to JSON for human ratification."""
        payload = {
            "_note": (
                "Derive-then-ratify proposals from 'allow always'. These are NOT "
                "applied automatically — a human ratifies them into the Charter."
            ),
            "generator": "blastcontain-guard",
            "proposals": [p.as_dict() for p in self._proposals],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return payload
