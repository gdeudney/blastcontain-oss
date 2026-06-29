"""
blastcontain_guard.constants — the action taxonomy and a tool-name heuristic.

Guard gates *actions* (blast radius), not content (guard-spec §11). A policy is
written against the verb a tool performs — ``action.type in ['drop','delete']``.
Adapters and callers should supply ``action_type`` explicitly; when they don't,
``infer_action_type`` maps the tool name to a verb so action-typed rules still
fire. The map is deliberately conservative: an unknown tool is left ``""`` and
matched only by name, never mis-classified into a destructive bucket.
"""
from __future__ import annotations

import re

# The action verbs policies reason about. Open-ended (action_type is just a
# string), but these are the well-known buckets the heuristic and the example
# policies use.
ACTION_TYPES: frozenset[str] = frozenset(
    {
        "read",       # list, get, fetch, query, search — observe state
        "write",      # create, update, put, set, append — mutate state
        "delete",     # delete, drop, truncate, remove, purge — destroy state
        "send",       # email, post, notify, publish, message — egress / outward
        "exec",       # run, shell, eval, spawn — code execution
        "admin",      # grant, revoke, configure, deploy — privilege / control plane
    }
)

# Ordered most-specific first: the first verb whose pattern hits the tool name
# wins. Destructive verbs are checked before generic ones so ``delete_record``
# classifies as ``delete``, not ``write``.
_INFER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("delete", re.compile(r"\b(delete|destroy|drop|truncate|remove|purge|rm|wipe|erase)\b", re.I)),
    ("exec", re.compile(r"\b(exec|execute|eval|run_shell|shell|spawn|subprocess|system|run_code)\b", re.I)),
    ("admin", re.compile(r"\b(grant|revoke|chmod|chown|deploy|provision|configure|set_role|sudo)\b", re.I)),
    ("send", re.compile(r"\b(send|email|post|publish|notify|message|sms|webhook|upload|push|exfil)\b", re.I)),
    ("write", re.compile(r"\b(write|create|update|put|set|insert|append|modify|edit|patch|save|commit)\b", re.I)),
    ("read", re.compile(r"\b(read|get|list|fetch|query|search|find|view|describe|show|cat|head)\b", re.I)),
)


def infer_action_type(tool_name: str) -> str:
    """Best-effort verb for a tool name. Returns ``""`` when nothing matches.

    Splits camelCase / snake_case / dotted names so ``deleteRecord``,
    ``delete_record`` and ``db.delete`` all resolve to ``delete``.
    """
    if not tool_name:
        return ""
    # Normalise camelCase and separators into space-delimited words.
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tool_name)
    spaced = re.sub(r"[._\-/]+", " ", spaced)
    for verb, pattern in _INFER_RULES:
        if pattern.search(spaced):
            return verb
    return ""
