"""Request-local budget for explicit authoring tests; runtime defaults are unchanged."""

from contextlib import contextmanager
from contextvars import ContextVar
from time import monotonic

_DEADLINE = ContextVar("authoring_evaluation_deadline", default=None)


def remaining(default=None):
    deadline = _DEADLINE.get()
    if deadline is None:
        return default
    seconds = deadline - monotonic()
    if seconds <= 0:
        raise TimeoutError("Authoring evaluation budget exceeded")
    return seconds if default is None else min(seconds, default)


@contextmanager
def budget(seconds):
    token = _DEADLINE.set(monotonic() + seconds)
    try:
        yield
    finally:
        _DEADLINE.reset(token)
