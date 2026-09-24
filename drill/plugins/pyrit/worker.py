"""A bounded static PyRIT adapter; no multi-turn or framework verdict authority."""

import asyncio
from contextlib import redirect_stdout
from importlib.metadata import version
import os
import sys

# Fixed local resource settings before importing numerical dependencies.
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"

from blastcontain_drill.contracts import Injection  # noqa: E402
from blastcontain_drill.plugins.sdk import serve  # noqa: E402
from pyrit.executor.attack import PromptSendingAttack  # noqa: E402
from pyrit.memory import CentralMemory, SQLiteMemory  # noqa: E402
from pyrit.models import Message  # noqa: E402
from pyrit.prompt_target import PromptTarget  # noqa: E402

PIN = "1.1.0"


class BrokerTarget(PromptTarget):
    """Pass one text request through the accepted host binding, never a direct client."""

    def __init__(self, *, broker):
        super().__init__()
        self.broker = broker
        self.calls = 0

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        if len(normalized_conversation) != 1:
            raise ValueError("Static adapter requires a single message")
        message = normalized_conversation[0]
        piece = message.get_piece()
        if (
            len(message.message_pieces) != 1
            or message.api_role != "user"
            or piece.converted_value_data_type != "text"
        ):
            raise ValueError("Static adapter accepts one user text piece")
        payload = message.get_value()
        if not payload.strip() or len(payload.encode()) > 32768 or self.calls:
            raise ValueError("Static target call limit exceeded")
        self.calls += 1
        reply = self.broker.call("target", Injection("user", payload))
        response = reply.get("response_text")
        if type(response) is not str or len(response.encode()) > 32768:
            raise ValueError("Invalid host response")
        return [Message.from_prompt(prompt=response, role="assistant")]


class StaticStrategy:
    def prepare(self, config):
        if config or version("pyrit") != PIN:
            raise ValueError("Unsupported configuration or PyRIT version")
        with redirect_stdout(sys.stderr):
            self.memory = SQLiteMemory(db_path=":memory:", silent=True)
            CentralMemory.set_memory_instance(self.memory)
            self.memory.reset_database()
        self.scenario = None
        self.executed = False

    def reset(self, scenario):
        if (
            scenario.turns
            or scenario.injections
            or not scenario.attack_objective
            or not scenario.entry_prompt.strip()
            or len(scenario.entry_prompt.encode()) > 32768
        ):
            raise ValueError("Static adapter requires one reviewed prompt and objective")
        with redirect_stdout(sys.stderr):
            self.memory.reset_database()
        self.scenario = scenario
        self.executed = False

    def execute(self, broker):
        if self.scenario is None or self.executed:
            raise ValueError("Reset before each static execution")
        self.executed = True
        with redirect_stdout(sys.stderr):
            target = BrokerTarget(broker=broker)
            attack = PromptSendingAttack(objective_target=target, max_attempts_on_failure=0)
            result = asyncio.run(
                attack.execute_async(
                    objective=self.scenario.attack_objective,
                    next_message=Message.from_prompt(
                        prompt=self.scenario.entry_prompt, role="user"
                    ),
                )
            )
        return {
            "framework": "pyrit",
            "version": PIN,
            "strategy": "PromptSendingAttack",
            "target_calls": target.calls,
            "upstream_outcome": result.outcome.value,
        }

    def close(self):
        with redirect_stdout(sys.stderr):
            self.memory.dispose_engine()
        self.scenario = None


if __name__ == "__main__":
    serve(StaticStrategy())
