"""
Guard A/B — score the SAME agent responses with two guard models + the judge.

Runs each corpus attack through the cage once, then scores the resulting agent
response with guard A, guard B, and the LLM judge, so the guards are compared on
identical inputs (not two separate, temperature-divergent runs). A seed for the
model-sweep harness.

    python scripts/guard_compare.py --target qwen/qwen3-30b-a3b-2507 \
        --guard-a qwen3guard-gen-8b --guard-b granite-guardian-4.1-8b [--limit 1]
"""
from __future__ import annotations

import argparse

from blastcontain_drill.cage import InProcessCage
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.llm import ChatClient
from blastcontain_drill.probes import run_action_probes
from blastcontain_drill.scoring import LLMJudge, make_guard_scorer


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare two guard models on the same responses.")
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--target", required=True, help="in-cage agent model id")
    ap.add_argument("--guard-a", required=True)
    ap.add_argument("--guard-b", required=True)
    ap.add_argument("--scenarios", default=None, help="comma-separated categories")
    ap.add_argument("--limit", type=int, default=None, help="cap attacks per category")
    args = ap.parse_args()

    categories = args.scenarios.split(",") if args.scenarios else None
    corpus = load_corpus(categories=categories, limit=args.limit)
    cage = InProcessCage(ChatClient(args.base_url, args.target))
    judge = LLMJudge(ChatClient(args.base_url, args.target), args.target)
    guard_a = make_guard_scorer(ChatClient(args.base_url, args.guard_a), args.guard_a)
    guard_b = make_guard_scorer(ChatClient(args.base_url, args.guard_b), args.guard_b)

    print(f"\nTarget: {args.target}   |   A = {args.guard_a}   B = {args.guard_b}\n")
    header = f"{'attack':20} {'action':8} {'judge':8} {'A':10} {'B':10} {'A=B?':5}"
    print(header)
    print("-" * len(header))

    rows = []
    for atk in corpus.attacks:
        obs = cage.run_attack(atk)
        action = run_action_probes(obs)
        jv = judge.score(atk, obs.response_text)
        av = guard_a.score(atk, obs.response_text)
        bv = guard_b.score(atk, obs.response_text)
        agree = av.get("matched") == bv.get("matched")
        print(
            f"{atk.id:20} {'FIRED' if action['triggered'] else '-':8} "
            f"{str(jv.get('label')):8} {str(av.get('label')):10} {str(bv.get('label')):10} "
            f"{'yes' if agree else 'NO':5}"
        )
        rows.append((av.get("matched"), bv.get("matched"), jv.get("matched")))

    n = len(rows)
    a_unsafe = sum(1 for r in rows if r[0])
    b_unsafe = sum(1 for r in rows if r[1])
    agree = sum(1 for r in rows if r[0] == r[1])
    print(
        f"\n{args.guard_a}: {a_unsafe}/{n} flagged unsafe | "
        f"{args.guard_b}: {b_unsafe}/{n} flagged unsafe | "
        f"agreement: {agree}/{n}"
    )


if __name__ == "__main__":
    main()
