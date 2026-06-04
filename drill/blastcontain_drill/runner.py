"""
BlastContain Drill — the orchestrator.

For each attack: drive the agent in the cage, run the action probes over the
cage's ground truth, score the response on the content plane, and combine the
two into a HELD/BYPASS DrillFinding. Mirrors Verify's scanner pattern — each
scenario is wrapped so one failure becomes an ERROR finding and the run continues.

`run_corpus` is the low-level entry (a cage + scorers + a corpus) that tests
drive with a stub cage; `run_drill` builds everything from a DrillConfig.
"""
from __future__ import annotations

import time
import traceback
from typing import Optional

from blastcontain_core.constants import taxonomy_for
from blastcontain_core.models import (
    DrillFinding,
    DrillOutcome,
    DrillReport,
)

from ._scenario import scenario_id, scenario_name
from .cage.base import DEFAULT_FORBIDDEN_TOOLS, Cage
from .config import DrillConfig
from .corpus import Corpus, load_corpus
from .probes import run_action_probes
from .scoring import Scorer, combine, score_content

def _scenario_id(attack) -> str:
    return scenario_id(attack)


def _scenario_name(attack) -> str:
    return scenario_name(attack.category)


def run_corpus(
    cage: Cage,
    corpus: Corpus,
    scorers: list[Scorer],
    forbidden_tools=DEFAULT_FORBIDDEN_TOOLS,
    permitted_tools: Optional[list[str]] = None,
) -> list[DrillFinding]:
    """Run every attack in the corpus through the cage + probes + scorers."""
    findings: list[DrillFinding] = []
    for attack in corpus.attacks:
        tax = taxonomy_for(attack.category)
        start = time.monotonic()
        try:
            obs = cage.run_attack(attack)
            action = run_action_probes(obs, forbidden_tools, permitted_tools)
            content, _all = score_content(scorers, attack, obs.response_text)
            decision = combine(attack, action, content)
            latency_ms = round((time.monotonic() - start) * 1000, 1)
            findings.append(
                DrillFinding(
                    scenario_id=_scenario_id(attack),
                    scenario_name=_scenario_name(attack),
                    outcome=decision["outcome"],
                    severity=decision["severity"],
                    attack_id=attack.id,
                    technique=attack.technique,
                    layer=attack.layer,
                    vector=attack.vector,
                    detection_latency_ms=latency_ms,
                    blocked_by=decision["blocked_by"],
                    bypass_description=decision["bypass_description"],
                    evidence=decision["evidence"],
                    content_verdict=content,
                    action_verdict=action,
                    **tax,
                )
            )
        except Exception as exc:  # noqa: BLE001 — one scenario must not kill the run
            findings.append(
                DrillFinding(
                    scenario_id=_scenario_id(attack),
                    scenario_name=_scenario_name(attack),
                    outcome=DrillOutcome.ERROR,
                    attack_id=attack.id,
                    technique=attack.technique,
                    layer=attack.layer,
                    bypass_description=f"scenario error: {exc}",
                    evidence="".join(
                        traceback.format_exception_only(type(exc), exc)
                    ).strip()[:300],
                    **tax,
                )
            )
    return findings


def _load_permitted_tools(charter_path: Optional[str]) -> Optional[list[str]]:
    if not charter_path:
        return None
    try:
        from blastcontain_core.charter import load_charter

        return load_charter(charter_path).permitted_tools or None
    except Exception:
        return None


def build_scorers(cfg: DrillConfig) -> tuple[list[Scorer], dict]:
    """
    Build the content scorers in **authority order**: judge -> guard -> heuristic.

    The reasoning judge decides comply/refuse; Qwen3Guard is a secondary
    content-safety signal; the heuristic is the model-free fallback. (See
    scoring.score_content for why a weak scorer must not override a strong one.)
    """
    from .llm import ChatClient
    from .scoring import HeuristicContentScorer, LLMJudge, make_guard_scorer

    scorers: list[Scorer] = []
    flags: dict = {}
    judge_url = cfg.effective_judge_base_url()

    judge_model = cfg.effective_judge_model()
    if judge_model:
        judge = LLMJudge(ChatClient(judge_url, judge_model), judge_model)
        flags["llm-judge"] = judge.is_available()
        if flags["llm-judge"]:
            scorers.append(judge)

    if cfg.guard_model:
        guard = make_guard_scorer(ChatClient(judge_url, cfg.guard_model), cfg.guard_model)
        flags[guard.name] = guard.is_available()
        if flags[guard.name]:
            scorers.append(guard)

    scorers.append(HeuristicContentScorer())
    flags["heuristic"] = True
    return scorers, flags


def run_drill(cfg: DrillConfig) -> DrillReport:
    """Build the bench from config and run the full drill."""
    from .llm import ChatClient

    permitted = _load_permitted_tools(cfg.charter)
    extra_sources = []
    if cfg.enable_aig:
        # Live AIG: red-team the SAME model under test (not a hardcoded default) and
        # score with the judge model; the service URL/token come from the environment
        # (BLASTCONTAIN_AIG_URL / BLASTCONTAIN_AIG_TOKEN).
        from .corpus import AIGAttackSource

        extra_sources.append(
            AIGAttackSource(
                target_model=cfg.target_model,
                target_base_url=cfg.target_base_url,
                eval_model=cfg.effective_judge_model(),
                eval_base_url=cfg.effective_judge_base_url(),
            )
        )
    corpus = load_corpus(
        version=cfg.corpus,
        categories=cfg.scenarios or None,
        limit=cfg.limit,
        extra_sources=extra_sources or None,
        enable_operators=cfg.enable_operators,
        enable_jbb=cfg.enable_jbb,
    )
    scorers, scorer_flags = build_scorers(cfg)

    report = DrillReport(
        agent_id=cfg.agent_id,
        environment=cfg.environment,
        corpus_version=corpus.version,
        corpus_sources=corpus.sources,
        agent_url=cfg.agent_url,
        cage=cfg.cage,
        scorers=scorer_flags,
        judge_model=cfg.effective_judge_model() if scorer_flags.get("llm-judge") else None,
        guard_model=cfg.guard_model if (
            scorer_flags.get("qwen3guard")
            or scorer_flags.get("granite-guardian")
            or scorer_flags.get("wildguard")
        ) else None,
    )

    if cfg.cage == "podman":
        from .cage import PodmanCage

        cage: Cage = PodmanCage(max_steps=cfg.max_steps)
        report.target_model = "stub-agent (podman --network none)"
    else:
        cage = _build_inprocess_cage(cfg, ChatClient)
        report.target_model = cfg.target_model

    if not cfg.generative_only:
        report.findings = run_corpus(cage, corpus, scorers, permitted_tools=permitted)

    if cfg.generative and cfg.attacker_model:
        _run_generative_layer(cfg, report, cage, scorers, permitted, ChatClient)

    report.status = report.derive_status()
    return report


def _run_generative_layer(cfg, report, cage, scorers, permitted, ChatClient):
    """Run the generative refinement loop and append its findings to the report."""
    from .generative import LLMAttacker, goals_for, run_generative

    attacker = LLMAttacker(
        ChatClient(cfg.effective_attacker_base_url(), cfg.attacker_model),
        cfg.attacker_model,
    )
    if not attacker.is_available():
        return
    report.attacker_model = cfg.attacker_model
    results = run_generative(
        goals_for(cfg.scenarios or None),
        cage,
        scorers,
        attacker,
        permitted_tools=permitted,
        max_iters=cfg.generative_iters,
    )
    report.findings.extend(r.finding for r in results)
    if cfg.generative_corpus:
        from .reporter import write_generative_corpus

        write_generative_corpus(results, cfg.generative_corpus)


def _build_inprocess_cage(cfg: DrillConfig, ChatClient):
    from .cage import InProcessCage

    backend = ChatClient(cfg.target_base_url, cfg.target_model)
    return InProcessCage(backend, max_steps=cfg.max_steps)
