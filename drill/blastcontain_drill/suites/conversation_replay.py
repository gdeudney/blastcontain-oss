"""Validate signed conversation graphs against scope grants and observed model calls."""

from ..contracts import ContractError
from .artifacts import digest


def validate_conversations(saved, planned, lock, document):
    grants = next(
        (
            r.granted_access
            for r in lock.acceptances
            if r.kind == "plugin" and r.subject_id == planned.strategy
        ),
        (),
    )
    conversation_grants = {g for g in grants if g.endswith(".conversation")}
    calls = {}
    for call in document.model_calls:
        if call.case_id == saved.case_id and call.conversation_scope is not None:
            key = (call.conversation_scope, call.conversation_sequence)
            if key in calls:
                raise ContractError("Conversation call binding reused")
            calls[key] = call
    if (
        conversation_grants and saved.disposition == "completed" or calls
    ) and saved.conversations is None:
        raise ContractError("Accepted conversation route has no retained history audit")
    if saved.conversations is None:
        return
    if document.schema_version < 2:
        raise ContractError("Conversation audit requires run schema 2")
    settings = {m.channel: m for m in lock.plan.spec.models}
    for audit in saved.conversations:
        audit.to_dict()  # Rooted history, branch rules and all nested records.
        if (
            audit.run_id != document.run_id
            or audit.case_id != saved.case_id
            or f"broker.{audit.channel}.conversation" not in grants
            or audit.channel not in settings
            or audit.settings_digest != digest(settings[audit.channel].to_dict())
        ):
            raise ContractError("Conversation differs from the accepted run/case/model scope")
        if audit.limits.allow_branching and f"broker.{audit.channel}.branch" not in grants:
            raise ContractError("Conversation branching was not accepted")
        if not audit.closed:
            raise ContractError("Completed run contains an open conversation")
        if audit.limits.max_attempts > 32 or audit.limits.max_history_bytes > 65536:
            raise ContractError("Conversation exceeds supported route limits")
        for event in audit.events:
            call = calls.pop((audit.scope_digest, event.sequence), None)
            if call is None:
                if event.response_digest is not None or event.status == "completed":
                    raise ContractError("Conversation model evidence is missing")
                continue  # Authorization/budget may reject before model dispatch.
            if (
                call.channel != audit.channel
                or call.request_digest != event.model_request_digest
                or call.response_digest != event.response_digest
                or call.status == "pending"
                or event.status == "completed"
                and call.status != "completed"
            ):
                raise ContractError("Conversation model evidence mismatch")
    if calls:
        raise ContractError("Observed conversation calls are missing their history audit")
