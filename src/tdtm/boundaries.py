"""Trust boundary geometry. SPEC section 5. PLAN task 1.4.

Contract:
- `assign_zones(diagram)`: set `Element.zone` on every node to the innermost boundary box
  containing its centre (None = outer zone).
- `assign_crossings(diagram)`: set `Element.crosses` on every flow to the boundary cell ids
  (boxes and curves) it crosses.
Pure geometry on `model.Point`/`model.Rect`; no Threat Dragon JSON in here.
"""

from __future__ import annotations

from .model import Diagram


def assign_zones(diagram: Diagram) -> None:
    raise NotImplementedError("PLAN 1.4")


def assign_crossings(diagram: Diagram) -> None:
    raise NotImplementedError("PLAN 1.4")
