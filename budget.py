"""Per-session credit accounting.

Shodan credits are real money. A Membership account gets 100 query credits a
month, and an agent that decides to page through a broad search can spend all
of them in under a minute without anyone noticing until the bill or the wall.

So the plugin keeps its own ledger. Before any credit-costing call it asks
whether the budget covers it, and it refuses rather than spending past the
line. The refusal is not a dead end: it tells the model to use shodan_count,
which is free and answers most of the questions that push agents toward
search in the first place.

This is deliberately client-side and approximate. The authoritative number is
whatever /api-info reports, which we surface alongside our own count so the
model can see both.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from .errors import BudgetError


@dataclass
class Ledger:
    query_credits_spent: int = 0
    scan_credits_spent: int = 0
    calls: int = 0
    cache_saves: int = 0

    def snapshot(self, query_limit: int, scan_limit: int) -> dict[str, object]:
        return {
            "query_credits_spent": self.query_credits_spent,
            "query_credits_budget": query_limit,
            "query_credits_remaining": max(0, query_limit - self.query_credits_spent),
            "scan_credits_spent": self.scan_credits_spent,
            "scan_credits_budget": scan_limit,
            "scan_credits_remaining": max(0, scan_limit - self.scan_credits_spent),
            "api_calls": self.calls,
            "credit_saving_cache_hits": self.cache_saves,
        }


class BudgetTracker:
    """One ledger per session.

    Tool handlers receive a ``task_id`` in kwargs when Hermes has one, so
    concurrent gateway conversations and subagents each get their own budget
    rather than fighting over a single global counter. Calls with no task_id
    (CLI one-shots, direct dispatch) share the ``"default"`` bucket.
    """

    def __init__(self) -> None:
        self._ledgers: dict[str, Ledger] = {}
        self._lock = threading.Lock()

    def _key(self, session_id: str | None) -> str:
        return str(session_id) if session_id else "default"

    def ledger(self, session_id: str | None = None) -> Ledger:
        key = self._key(session_id)
        with self._lock:
            return self._ledgers.setdefault(key, Ledger())

    def check(
        self,
        cost: int,
        *,
        limit: int,
        session_id: str | None = None,
        kind: str = "query",
    ) -> None:
        """Raise BudgetError if spending ``cost`` would cross the line.

        A limit of 0 for scan credits means "no scanning", which is the
        default and is enforced here rather than silently allowing one call
        through. A limit of 0 for query credits means the same thing.
        """
        if cost <= 0:
            return
        led = self.ledger(session_id)
        with self._lock:
            spent = led.scan_credits_spent if kind == "scan" else led.query_credits_spent
            if spent + cost > limit:
                remaining = max(0, limit - spent)
                raise BudgetError(
                    f"Session {kind} credit budget exhausted: this call needs "
                    f"{cost} but only {remaining} of {limit} remain.",
                    details={
                        "kind": kind,
                        "requested": cost,
                        "remaining": remaining,
                        "budget": limit,
                    },
                )

    def spend(
        self,
        cost: int,
        *,
        session_id: str | None = None,
        kind: str = "query",
    ) -> None:
        led = self.ledger(session_id)
        with self._lock:
            if kind == "scan":
                led.scan_credits_spent += cost
            else:
                led.query_credits_spent += cost

    def record_call(self, session_id: str | None = None) -> None:
        led = self.ledger(session_id)
        with self._lock:
            led.calls += 1

    def record_cache_save(self, session_id: str | None = None) -> None:
        led = self.ledger(session_id)
        with self._lock:
            led.cache_saves += 1

    def reset(self, session_id: str | None = None) -> None:
        """Clear one session's ledger, or all of them when given nothing."""
        with self._lock:
            if session_id is None:
                self._ledgers.clear()
            else:
                self._ledgers.pop(self._key(session_id), None)


# Process-wide. Hermes runs one AIAgent per process and every frontend shares
# it, so a module-level tracker is the right scope.
tracker = BudgetTracker()


def estimate_search_cost(query: str, page: int = 1) -> int:
    """How many query credits a /shodan/host/search call will cost.

    Shodan's rule: one credit if the query contains any filter, plus one per
    100 results past the first page. So a bare keyword search on page one is
    free, and 'apache country:DE' is not. We mirror that rather than assuming
    every search costs something, because the free case is genuinely common
    and charging the budget for it would make the guard fire too early.
    """
    has_filter = ":" in (query or "")
    pages_past_first = max(0, int(page or 1) - 1)
    if not has_filter and pages_past_first == 0:
        return 0
    return (1 if has_filter else 0) + pages_past_first
