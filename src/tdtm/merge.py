"""Merge generated threats into a Threat Dragon document. SPEC section 6. PLAN task 2.4.

Contract:
- `merge(doc, generated, *, prune=False, mode="inline"|"sidecar") -> MergeSummary`
- Never modifies threats without a tdtm key. Never overwrites a tdtm threat whose fingerprint
  shows a human edit. Recomputes `data.hasOpenThreats` on every touched cell.
- Deterministic: same inputs give byte-identical output.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MergeSummary:
    added: list[str] = field(default_factory=list)
    refreshed: list[str] = field(default_factory=list)
    kept_edited: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    pruned: list[str] = field(default_factory=list)


def merge(doc, generated, *, prune: bool = False, mode: str = "inline") -> MergeSummary:
    raise NotImplementedError("PLAN 2.4")
