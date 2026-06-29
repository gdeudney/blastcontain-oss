"""
blastcontain_guard.adapters.generic — guard a plain callable.

For hand-rolled agents the ``@guard.tool`` decorator (on the Guard object) is the
primary path. ``wrap_callable`` is the non-decorator equivalent: wrap an existing
function so every call is evaluated, raising ``GuardDenied`` when blocked. Useful
when the tool function isn't yours to decorate (a third-party callable).
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional

from ..errors import GuardDenied
from ..guard import _bind_args


def wrap_callable(
    guard: Any,
    fn: Callable,
    *,
    action_type: Optional[str] = None,
    name: Optional[str] = None,
) -> Callable:
    """Return a guarded wrapper around ``fn``. Raises GuardDenied if blocked."""
    tool_name = name or getattr(fn, "__name__", "callable")
    try:
        sig: Optional[inspect.Signature] = inspect.signature(fn)
    except (ValueError, TypeError):
        sig = None

    @functools.wraps(fn)
    def wrapper(*a: Any, **kw: Any) -> Any:
        args = _bind_args(sig, a, kw)
        result = guard.check(tool_name, action_type=action_type, args=args)
        if not result.allowed:
            raise GuardDenied(result)
        return fn(*a, **kw)

    wrapper.__guarded__ = True  # type: ignore[attr-defined]
    return wrapper
