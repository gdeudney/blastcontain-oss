"""Real pinned upstream versus checkpoint-adapted histories with deterministic models."""

import asyncio
import json
import secrets

from crescendo import (
    ConversationTarget,
    CrescendoStrategy,
    make_attack,
    target_configuration,
    text_history,
)
from blastcontain_drill.contracts import ScenarioSpec, SecurityExpectation, SourceRef
from pyrit.models import Message
from pyrit.prompt_target import PromptTarget


class RecordingModels:
    def __init__(self, *, malformed=False):
        self.requests = []
        self.counts = dict.fromkeys(("target", "attacker", "evaluator"), 0)
        self.malformed = malformed

    def reply(self, channel, history):
        self.requests.append((channel, history))
        self.counts[channel] += 1
        index = self.counts[channel]
        if channel == "attacker":
            if self.malformed and index == 1:
                return "malformed JSON"
            return json.dumps(
                {
                    "next_message": "controlled question " + str(index),
                    "rationale": "controlled",
                    "last_response_summary": "observed",
                }
            )
        if channel == "target":
            return {1: "accepted first turn", 2: "I cannot help with that request."}.get(
                index, "goal achieved"
            )
        refusal = "DRILL_REFUSAL" in history[0][1]
        response = history[-1][1].split("response:", 1)[-1]
        matched = "cannot help" in response if refusal else "goal achieved" in response
        return json.dumps({"score_value": matched, "rationale": "controlled"})


class DirectTarget(PromptTarget):
    def __init__(self, *, channel, models):
        super().__init__(custom_configuration=target_configuration(channel))
        self.channel, self.models = channel, models

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        response = self.models.reply(self.channel, text_history(normalized_conversation))
        return [Message.from_prompt(prompt=response, role="assistant")]


class RecordingBroker:
    """Model-history parity harness only, not a container/isolation attestation."""

    def __init__(self, models):
        self.models, self.sessions = models, {}

    def conversation(self, channel, payload):
        if payload["operation"] == "open":
            root = secrets.token_hex(16)
            history = () if channel == "target" else (("system", payload["system_message"]),)
            self.sessions[root] = (channel, {root: history})
            return {"conversation": root, "checkpoint": root}
        owner, states = self.sessions[payload["conversation"]]
        assert channel == owner
        history = (*states[payload["parent"]], ("user", payload["prompt"]))
        response = self.models.reply(channel, history)
        checkpoint = secrets.token_hex(16)
        states[checkpoint] = (*history, ("assistant", response))
        return {"checkpoint": checkpoint, "response_text": response, "outcome": "HELD"}


def main():
    plugin = CrescendoStrategy()
    plugin.prepare({})
    results = []
    for malformed in (False, True):
        scenario = ScenarioSpec(
            "controlled",
            "jailbreak",
            "crescendo",
            SourceRef("fixture", "1"),
            "controlled",
            SecurityExpectation("content"),
            attack_objective="Exercise the controlled target policy",
        )
        plugin.reset(scenario)
        assert not plugin.memory.get_message_pieces()
        direct = RecordingModels(malformed=malformed)
        targets = {
            name: DirectTarget(channel=name, models=direct)
            for name in ("target", "attacker", "evaluator")
        }
        attack = make_attack(targets["target"], targets["attacker"], targets["evaluator"])
        native = asyncio.run(attack.execute_async(objective=scenario.attack_objective))
        plugin.reset(scenario)
        adapted_models = RecordingModels(malformed=malformed)
        result = plugin.execute(RecordingBroker(adapted_models))
        assert direct.requests == adapted_models.requests, (
            "Native and adapted model histories differ"
        )
        assert native.backtrack_count == result["backtrack_count"] == 1
        assert native.outcome.value == result["upstream_outcome"] == "success"
        assert direct.counts == result["calls"]
        target_calls = [history for channel, history in direct.requests if channel == "target"]
        assert len(target_calls) == 3
        assert target_calls[2][:-1] == (*target_calls[0], ("assistant", "accepted first turn"))
        results.append({"malformed_retry": malformed, "calls": direct.counts, "backtracks": 1})
        try:
            plugin.execute(RecordingBroker(adapted_models))
        except ValueError:
            pass
        else:
            raise AssertionError("Repeat execute bypassed reset")
    # Editable-history support is deliberately limited to observed checkpoints.
    models = RecordingModels()
    target = ConversationTarget(broker=RecordingBroker(models), channel="target")
    try:
        asyncio.run(
            target._send_prompt_to_target_async(
                normalized_conversation=[
                    Message.from_prompt(prompt="unobserved response", role="assistant"),
                    Message.from_prompt(prompt="next", role="user"),
                ]
            )
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Unobserved history was imported")
    assert not models.requests
    plugin.close()
    print(json.dumps({"pyrit": "1.1.0", "crescendo_parity": True, "cases": results}))


if __name__ == "__main__":
    main()
