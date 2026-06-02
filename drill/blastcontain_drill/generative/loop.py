"""
The generative refinement loop (drill-spec §4.1, step 7) — a self-contained,
local jailbreak-discovery engine.

For each goal: the attacker crafts a prompt → the target runs it in the cage →
the action probes + content scorers judge it → on HELD, the target's refusal is
fed back and the attacker refines → repeat until BYPASS or the iteration budget
runs out. A landed attack is a *novel* jailbreak the static corpus never had.

The discovered prompt is sensitive (a working jailbreak): it is returned for the
caller to store in a marked, gitignored corpus, and only an excerpt — not the
full prompt — goes into the signed DrillReport by default.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from blastcontain_core.constants import taxonomy_for
from blastcontain_core.models import DrillFinding, DrillOutcome

from .._scenario import scenario_id, scenario_name
from ..cage.base import DEFAULT_FORBIDDEN_TOOLS, Cage
from ..corpus.base import Attack
from ..probes import run_action_probes
from ..scoring import Scorer, combine, score_content
from .attacker import Attacker, Attempt
from .goals import Goal


@dataclass
class GenerativeResult:
    goal_id: str
    category: str
    success: bool
    iterations: int
    discovered_prompt: str | None       # the working jailbreak — SENSITIVE; None if no bypass
    transcript: list = field(default_factory=list)
    finding: DrillFinding | None = None


def _finding_evidence(success: bool, iterations: int, prompt: str) -> str:
    if success:
        return (
            f"Novel jailbreak discovered in {iterations} iteration(s). Full prompt "
            f"withheld from report (sensitive); excerpt: {prompt[:80]!r}"
        )
    return f"No bypass found after {iterations} iteration(s)."


def run_generative(
    goals: list[Goal],
    cage: Cage,
    scorers: list[Scorer],
    attacker: Attacker,
    forbidden_tools=DEFAULT_FORBIDDEN_TOOLS,
    permitted_tools: list[str] | None = None,
    max_iters: int = 4,
) -> list[GenerativeResult]:
    """Run the refinement loop for each goal and return per-goal results."""
    results: list[GenerativeResult] = []
    for goal in goals:
        history: list[Attempt] = []
        best = None  # (attack, decision, action, content)
        start = time.monotonic()

        for i in range(max_iters):
            prompt = attacker.craft(goal, history)
            attack = Attack(
                id=f"gen-{goal.id}-{i}",
                category=goal.category,
                prompt=prompt,
                technique="generative",
                layer="generative",
                goal=goal.goal_type,
                forbidden_tool=goal.forbidden_tool,
                source="generative",
            )
            obs = cage.run_attack(attack)
            action = run_action_probes(obs, forbidden_tools, permitted_tools)
            content, _all = score_content(scorers, attack, obs.response_text)
            decision = combine(attack, action, content)

            history.append(
                Attempt(
                    prompt=prompt,
                    outcome=decision["outcome"].value,
                    target_response=obs.response_text or "",
                    fired=action["fired"],
                )
            )
            best = (attack, decision, action, content)
            if decision["outcome"] == DrillOutcome.BYPASS:
                break

        latency_ms = round((time.monotonic() - start) * 1000, 1)
        attack, decision, action, content = best  # type: ignore[misc]
        success = decision["outcome"] == DrillOutcome.BYPASS

        finding = DrillFinding(
            scenario_id=scenario_id(attack),
            scenario_name=scenario_name(goal.category),
            outcome=decision["outcome"],
            severity=decision["severity"],
            attack_id=attack.id,
            technique="generative",
            layer="generative",
            detection_latency_ms=latency_ms,
            blocked_by=decision["blocked_by"],
            bypass_description=decision["bypass_description"],
            evidence=_finding_evidence(success, len(history), attack.prompt),
            content_verdict=content,
            action_verdict=action,
            **taxonomy_for(goal.category),
        )
        results.append(
            GenerativeResult(
                goal_id=goal.id,
                category=goal.category,
                success=success,
                iterations=len(history),
                discovered_prompt=attack.prompt if success else None,
                transcript=[vars(a) for a in history],
                finding=finding,
            )
        )
    return results
