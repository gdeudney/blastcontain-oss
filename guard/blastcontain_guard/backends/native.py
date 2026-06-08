"""
blastcontain_guard.backends.native — the always-on, in-process primary (§8).

Guard-native owns the tool-call interception, the decision, and the *ask* UX.
It is the only enforcer for side-of-desk copilots where AGT can't be injected.
A thin wrapper over the pure evaluator so the backend seam is uniform.
"""
from __future__ import annotations

from ..evaluator import evaluate
from ..models import Decision, EvalInput
from ..policy import Ruleset


class NativeBackend:
    name = "native"

    def evaluate(self, ruleset: Ruleset, inp: EvalInput) -> Decision:
        return evaluate(ruleset, inp)
