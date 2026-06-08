"""
blastcontain_guard.condition — a safe, eval-free expression evaluator.

Rules carry a ``condition`` string in AGT's ``governance.toolkit/v1`` style:

    tool_name in ['query_db', 'send_notification']
    action.type in ['drop', 'delete', 'truncate']
    action.type == 'send' and 'pii' in args.tags

A policy enforcer must **never** ``eval()`` its own policy language — that is the
exact CODE-01 finding Verify raises. Instead we parse the expression with the
``ast`` module and walk it under a strict allowlist of node types: comparisons,
boolean combinators, attribute access into the input namespace, and literals.
Anything else — a function call, a dunder, an arithmetic op, a subscript — is
rejected at *compile* time, so a malformed or hostile condition fails loudly
when the policy is loaded, not silently at the tool-call boundary.

The grammar, deliberately small:
  * names:        tool_name · action · args · identity · agent_id · environment · delegation
  * attributes:   action.type, args.path, identity.role, delegation.parent_agent_id, ...
  * operators:    in · not in · == · != · < · <= · > · >=
  * combinators:  and · or · not
  * literals:     'strings', 123, 1.5, True, False, None, ['lists', 'of', 'literals']

Missing fields resolve to ``None`` (a rule referencing an absent attribute simply
does not match), so adapters that cannot classify every field stay safe.
"""
from __future__ import annotations

import ast
from typing import Any

# The only root identifiers a condition may reference. A typo or an attempt to
# reach anything else is a compile-time error, which makes `guard lint` catch
# policy bugs before deployment.
ALLOWED_NAMES: frozenset[str] = frozenset(
    {"tool_name", "action", "args", "identity", "agent_id", "environment", "delegation"}
)

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Expression,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not,
    ast.Compare,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Name, ast.Load,
    ast.Attribute,
    ast.Constant,
    ast.List, ast.Tuple, ast.Set,
)

_MAX_NODES = 500  # defense-in-depth against pathological policy expressions


class ConditionError(ValueError):
    """Raised when a condition string is malformed or uses a disallowed form."""


class CompiledCondition:
    """A parsed, validated condition. ``matches(context)`` is pure and total."""

    __slots__ = ("source", "_tree")

    def __init__(self, source: str, tree: ast.Expression):
        self.source = source
        self._tree = tree

    def matches(self, context: dict[str, Any]) -> bool:
        """Evaluate the condition against an input context. Never raises."""
        try:
            return bool(_eval(self._tree.body, context))
        except ConditionError:
            raise
        except Exception:
            # A type mismatch at runtime (e.g. ordering None < 5) is a non-match,
            # not a crash — enforcement must stay on the rails.
            return False

    def referenced_names(self) -> set[str]:
        return {n.id for n in ast.walk(self._tree) if isinstance(n, ast.Name)}


def compile_condition(expr: str) -> CompiledCondition:
    """Parse and validate a condition string. Raises ConditionError if invalid."""
    if not isinstance(expr, str) or not expr.strip():
        raise ConditionError("condition must be a non-empty string")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ConditionError(f"cannot parse condition {expr!r}: {exc.msg}") from exc

    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_NODES:
        raise ConditionError(f"condition too complex ({len(nodes)} nodes)")

    for node in nodes:
        if not isinstance(node, _ALLOWED_NODES):
            raise ConditionError(
                f"disallowed expression in condition {expr!r}: "
                f"{type(node).__name__} is not permitted"
            )
        if isinstance(node, ast.Name) and node.id not in ALLOWED_NAMES:
            raise ConditionError(
                f"unknown name {node.id!r} in condition {expr!r}; "
                f"allowed: {', '.join(sorted(ALLOWED_NAMES))}"
            )
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise ConditionError(f"dunder attribute access is not permitted: {node.attr!r}")
        if isinstance(node, ast.Constant) and not isinstance(
            node.value, (str, int, float, bool, type(None))
        ):
            raise ConditionError(
                f"only str/number/bool/None literals are permitted, got {node.value!r}"
            )
    return CompiledCondition(expr, tree)


# ── the evaluator ──────────────────────────────────────────────────────────────

def _eval(node: ast.AST, ctx: dict[str, Any]) -> Any:
    if isinstance(node, ast.BoolOp):
        values = (_eval(v, ctx) for v in node.values)
        if isinstance(node.op, ast.And):
            result: Any = True
            for v in values:
                if not v:
                    return False
                result = v
            return result
        # Or — return the first truthy, else the last value (Python semantics).
        last: Any = False
        for v in values:
            if v:
                return v
            last = v
        return last

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval(node.operand, ctx)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, ctx)
            if not _compare(op, left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.Name):
        return ctx.get(node.id)

    if isinstance(node, ast.Attribute):
        return _getattr(_eval(node.value, ctx), node.attr)

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_eval(e, ctx) for e in node.elts]

    raise ConditionError(f"unexpected node during evaluation: {type(node).__name__}")


def _getattr(base: Any, attr: str) -> Any:
    """Resolve ``base.attr`` over dicts or objects; missing -> None."""
    if base is None:
        return None
    if isinstance(base, dict):
        return base.get(attr)
    return getattr(base, attr, None)


def _compare(op: ast.cmpop, left: Any, right: Any) -> bool:
    if isinstance(op, ast.In):
        return _in(left, right)
    if isinstance(op, ast.NotIn):
        return not _in(left, right)
    if isinstance(op, ast.Eq):
        return left == right
    if isinstance(op, ast.NotEq):
        return left != right
    # Ordered comparisons only make sense for mutually comparable, non-None
    # operands; anything else is a non-match rather than a TypeError.
    try:
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
    except TypeError:
        return False
    raise ConditionError(f"unsupported comparison operator: {type(op).__name__}")


def _in(needle: Any, haystack: Any) -> bool:
    try:
        if haystack is None:
            return False
        return needle in haystack
    except TypeError:
        return False
