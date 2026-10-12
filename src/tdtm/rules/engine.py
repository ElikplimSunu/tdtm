"""Run a template over a model. SPEC section 3.5 and 7.1. PLAN task 2.2.

Contract:
- `run_sdl(model, template, *, include_legacy=False) -> list[GeneratedThreat]`
- One interaction per flow; bidirectional flows give two (direction "fwd"/"rev").
- Placeholders {source.Name}, {target.Name}, {flow.Name} substituted case-insensitively.
- Output sorted by (diagram, flow cell id, direction, rule id) so runs are deterministic.
"""

from __future__ import annotations


def run_sdl(model, template, *, include_legacy: bool = False):
    raise NotImplementedError("PLAN 2.2")
