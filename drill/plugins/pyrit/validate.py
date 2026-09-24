"""Real upstream parity and reset checks; run inside the pinned image or pinned venv."""

import asyncio
from contextlib import redirect_stdout
import io
import json

from worker import StaticStrategy
from blastcontain_drill.contracts import ScenarioSpec, SecurityExpectation, SourceRef
from pyrit.executor.attack import PromptSendingAttack
from pyrit.models import Message
from pyrit.prompt_target import PromptTarget


class DirectTarget(PromptTarget):
    def __init__(self, *, received, response):
        super().__init__()
        self.received, self.response = received, response

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        self.received.append([(m.api_role, m.get_value()) for m in normalized_conversation])
        return [Message.from_prompt(prompt=self.response, role="assistant")]


class RecordingBroker:
    def __init__(self, response):
        self.received, self.response = [], response

    def call(self, channel, injection):
        assert channel == "target" and injection.surface == "user"
        self.received.append([("user", injection.payload)])
        return {"response_text": self.response, "outcome": "BYPASS"}


def main():
    plugin = StaticStrategy()
    plugin.prepare({})
    for index, response in enumerate(("I cannot help.", "Controlled compliant response")):
        scenario = ScenarioSpec(
            f"fixture-{index}",
            "controlled",
            "pyrit-static",
            SourceRef("fixture", "1"),
            f"Controlled prompt {index}",
            SecurityExpectation("content"),
            attack_objective="Exercise the controlled text fixture",
        )
        plugin.reset(scenario)
        assert not plugin.memory.get_message_pieces()
        direct_messages = []
        direct = PromptSendingAttack(
            objective_target=DirectTarget(received=direct_messages, response=response),
            max_attempts_on_failure=0,
        )
        result = asyncio.run(
            direct.execute_async(
                objective=scenario.attack_objective,
                next_message=Message.from_prompt(prompt=scenario.entry_prompt, role="user"),
            )
        )
        plugin.reset(scenario)
        broker, output = RecordingBroker(response), io.StringIO()
        with redirect_stdout(output):
            adapted = plugin.execute(broker)
        assert not output.getvalue(), "Framework output must not corrupt the SDK stream"
        assert broker.received == direct_messages == [[("user", scenario.entry_prompt)]]
        assert adapted["target_calls"] == 1
        assert adapted["upstream_outcome"] == result.outcome.value == "undetermined"
        # The hostile broker outcome label above never becomes an upstream success claim.
        try:
            plugin.execute(broker)
        except ValueError:
            pass
        else:
            raise AssertionError("Repeat execute bypassed reset")
    plugin.close()
    print(
        json.dumps(
            {"pyrit": "1.1.0", "direct_adapter_parity": True, "fresh_memory": True, "cases": 2}
        )
    )


if __name__ == "__main__":
    main()
