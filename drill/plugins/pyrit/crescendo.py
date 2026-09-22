"""Pinned text-only PyRIT Crescendo over accepted host conversation checkpoints."""

import asyncio
from contextlib import redirect_stdout
import sys

# Imports the fixed thread/offline settings before importing PyRIT.
from worker import PIN, StaticStrategy
from crescendo_templates import ATTACKER, ATTACKER_SCHEMA, OBJECTIVE, REFUSAL, SCORE_SCHEMA

from blastcontain_drill.plugins.sdk import serve
from pyrit.executor.attack import CrescendoAttack
from pyrit.executor.attack.core import AttackAdversarialConfig, AttackScoringConfig
from pyrit.models import Message, SeedPrompt
from pyrit.prompt_target import PromptTarget, TargetCapabilities, TargetConfiguration
from pyrit.score import SelfAskTrueFalseScorer
from pyrit.score.true_false.self_ask_true_false_scorer import TrueFalseQuestion

MAX_TURNS = 3
MAX_BACKTRACKS = 1


def target_configuration(channel):
    return TargetConfiguration(
        capabilities=TargetCapabilities(
            supports_multi_turn=True,
            supports_editable_history=True,
            supports_system_prompt=channel != "target",
        )
    )


def text_history(conversation):
    result = []
    for message in conversation:
        if (
            len(message.message_pieces) != 1
            or message.get_piece().converted_value_data_type != "text"
            or message.api_role not in ("system", "user", "assistant")
        ):
            raise ValueError("Crescendo profile supports one text piece per message")
        result.append((message.api_role, message.get_value()))
    if not result or result[-1][0] != "user":
        raise ValueError("Crescendo requires a final user turn")
    return tuple(result)


class ConversationTarget(PromptTarget):
    """Map observed prefixes only; arbitrary imported/edited history is rejected."""

    def __init__(self, *, broker, channel):
        super().__init__(custom_configuration=target_configuration(channel))
        self.broker, self.channel = broker, channel
        self.checkpoints = {}
        self.calls = 0

    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        history = text_history(normalized_conversation)
        prefix, prompt = history[:-1], history[-1][1]
        if not prompt.strip() or len(prompt.encode()) > 32768:
            raise ValueError("Crescendo prompt exceeds supported bounds")
        if prefix not in self.checkpoints:
            root = () if self.channel == "target" else (("system", history[0][1]),)
            if prefix != root:
                raise ValueError("Unobserved or modified Crescendo history")
            request = {"operation": "open", "branching": True}
            if self.channel != "target":
                if history[0][0] != "system":
                    raise ValueError("Attacker/evaluator requires its reviewed system prompt")
                request["system_message"] = history[0][1]
            opened = self.broker.conversation(self.channel, request)
            self.checkpoints[prefix] = (opened["conversation"], opened["checkpoint"])
        conversation, parent = self.checkpoints[prefix]
        request = {
            "operation": "send",
            "conversation": conversation,
            "parent": parent,
            "prompt": prompt,
        }
        if self.channel != "target":
            request["max_tokens"] = 1024
        reply = self.broker.conversation(self.channel, request)
        response = reply.get("response_text")
        if type(response) is not str or not response.strip() or len(response.encode()) > 32768:
            raise ValueError("Invalid host conversation response")
        self.calls += 1
        self.checkpoints[(*history, ("assistant", response))] = (conversation, reply["checkpoint"])
        return [Message.from_prompt(prompt=response, role="assistant")]


def make_attack(target, attacker, evaluator):
    def scorer(template, category):
        return SelfAskTrueFalseScorer(
            chat_target=evaluator,
            system_prompt=SeedPrompt(value=template, response_json_schema=SCORE_SCHEMA),
            question=TrueFalseQuestion(true_description=category, category=category),
        )

    return CrescendoAttack(
        objective_target=target,
        attack_adversarial_config=AttackAdversarialConfig(
            target=attacker,
            system_prompt=SeedPrompt(
                value=ATTACKER,
                is_jinja_template=True,
                parameters=["objective", "max_turns"],
                response_json_schema=ATTACKER_SCHEMA,
            ),
        ),
        attack_scoring_config=AttackScoringConfig(
            objective_scorer=scorer(OBJECTIVE, "objective"),
            refusal_scorer=scorer(REFUSAL, "refusal"),
        ),
        max_turns=MAX_TURNS,
        max_backtracks=MAX_BACKTRACKS,
    )


class CrescendoStrategy(StaticStrategy):
    def reset(self, scenario):
        if scenario.fixture_refs or scenario.task_checks:
            raise ValueError("Crescendo supports only plain synthetic Agent state")
        super().reset(scenario)

    def execute(self, broker):
        if self.scenario is None or self.executed:
            raise ValueError("Reset before each Crescendo execution")
        self.executed = True
        with redirect_stdout(sys.stderr):
            targets = {
                name: ConversationTarget(broker=broker, channel=name)
                for name in ("target", "attacker", "evaluator")
            }
            attack = make_attack(targets["target"], targets["attacker"], targets["evaluator"])
            result = asyncio.run(attack.execute_async(objective=self.scenario.attack_objective))
        return {
            "framework": "pyrit",
            "version": PIN,
            "strategy": "CrescendoAttack",
            "profile": "drill-original-text-templates-v1",
            "calls": {name: target.calls for name, target in targets.items()},
            "backtrack_count": result.backtrack_count,
            "upstream_outcome": result.outcome.value,
        }


if __name__ == "__main__":
    serve(CrescendoStrategy(), protocol=2)
