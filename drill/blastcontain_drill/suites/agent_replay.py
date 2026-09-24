"""Offline verification of retained synthetic state, graph edges and target attempts."""

from ..contracts import ContractError
from .artifacts import digest
from .fixture_state import FixtureState


def restore_fixture_states(store, saved, scenario, states, *, trial):
    if saved.fixture_input_digest is None:
        if saved.fixture_output_digest or saved.raw_fixture_input or saved.raw_fixture_output:
            raise ContractError("Orphan Agent checkpoint state")
        return None, None
    if not trial or store.document.schema_version < 3:
        raise ContractError("Agent checkpoint state requires a schema 3 adaptive attempt")
    restored: list[FixtureState | None] = []
    for state_digest, ref in (
        (saved.fixture_input_digest, saved.raw_fixture_input),
        (saved.fixture_output_digest, saved.raw_fixture_output),
    ):
        if state_digest is None:
            restored.append(None)
            continue
        state = states.get(state_digest)
        if (
            state is None
            and ref is not None
            and store.document.raw_expires_at is not None
            and store.clock() < store.document.raw_expires_at
        ):
            state = FixtureState.from_dict(store.read(ref))
        if state is None:
            return None
        if type(state) is not FixtureState or state.state_digest != state_digest:
            raise ContractError("Agent state differs from its signed checkpoint")
        restored.append(state)
    before, after = restored
    if before is None:
        raise ContractError("Agent turn is missing its initial state")
    if after is not None:
        before.validate_successor(after, scenario.entry_prompt)
    elif saved.disposition == "completed":
        raise ContractError("Completed Agent turn is missing its resulting state")
    return before, after


def validate_agent_conversations(saved, planned, lock, document, attempts):
    grants = next(
        (
            r.granted_access
            for r in lock.acceptances
            if r.kind == "plugin" and r.subject_id == planned.strategy
        ),
        (),
    )
    required = "broker.target.conversation" in grants
    observed = {a.case_id: a for a in attempts if a.fixture_input is not None}
    if (
        required
        and saved.disposition == "completed"
        and saved.agent_conversations is None
        or observed
        and saved.agent_conversations is None
    ):
        raise ContractError("Agent conversation history is missing")
    if saved.agent_conversations is None:
        return
    if document.schema_version < 3 or not required:
        raise ContractError("Agent conversation lacks its accepted scope/schema")
    ordered = [a.case_id for a in attempts if a.fixture_input is not None]
    recorded = [t.attempt_id for audit in saved.agent_conversations for t in audit.turns]
    if ordered != recorded:
        raise ContractError("Agent observed turn ordering differs from its conversation audit")
    for audit in saved.agent_conversations:
        audit.to_dict()
        if (
            audit.run_id != document.run_id
            or audit.case_id != planned.id
            or audit.lock_digest != lock.lock_digest
            or not audit.closed
            or audit.branching
            and "broker.target.branch" not in grants
        ):
            raise ContractError("Agent conversation differs from its accepted scope")
        for turn in audit.turns:
            attempt = observed.pop(turn.attempt_id, None)
            if attempt is None or attempt.fixture_input.state_digest != turn.input_digest:
                raise ContractError("Agent turn is missing its observed attempt/state")
            if digest(attempt.scenario.entry_prompt) != turn.prompt_digest:
                raise ContractError("Agent turn prompt differs from observed attempt")
            after = attempt.fixture_output
            if (after.state_digest if after is not None else None) != turn.output_digest:
                raise ContractError("Agent turn checkpoint differs from observed state")
    if observed:
        raise ContractError("Observed Agent attempts are missing from conversation history")
