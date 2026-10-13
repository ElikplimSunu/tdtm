"""Run a template over a model. SPEC section 3.5 and 7.1. PLAN task 2.2.

`run_sdl(model, template, *, include_legacy=False) -> list[GeneratedThreat]`, after
`resolve.resolve(model, template)` has filled in stencils, attributes and crossings.

- Only STRIDE diagrams; others are skipped with a warning (SPEC 2.1).
- One interaction per flow; bidirectional flows give two (direction "fwd"/"rev").
- An interaction is skipped when the flow, or both its ends, are out of scope.
- Placeholders {source.Name}, {target.Name}, {flow.Name} substituted case-insensitively.
- Output order: diagram, flow (file order), direction, rule (template order). Deterministic.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..model import Diagram, Element, GeneratedThreat, Kind, Model
from .filters import Context, evaluate, parse

PLACEHOLDER = re.compile(r"\{(source|target|flow)\.name\}", re.IGNORECASE)


def fill_placeholders(text: str, names: dict[str, str]) -> str:
    return PLACEHOLDER.sub(lambda m: names[m.group(1).lower()], text)


def interactions(d: Diagram) -> Iterator[tuple[Element, Element, Element, str | None]]:
    for f in d.of_kind(Kind.FLOW):
        s, t = d.elements[f.source_id], d.elements[f.target_id]
        if f.out_of_scope or (s.out_of_scope and t.out_of_scope):
            continue
        if f.td_props.get("isBidirectional"):
            yield s, f, t, "fwd"
            yield t, f, s, "rev"
        else:
            yield s, f, t, None


def run_sdl(model: Model, template, *, include_legacy: bool = False) -> list[GeneratedThreat]:
    rules = [
        (tt, parse(tt.include), parse(tt.exclude) if tt.exclude else None)
        for tt in template.threat_types
        if include_legacy or not tt.legacy
    ]
    out = []
    for d in model.diagrams:
        if d.diagram_type != "STRIDE":
            model.warnings.append(f"diagram {d.title!r} is a {d.diagram_type} diagram; skipped")
            continue
        for s, f, t, direction in interactions(d):
            ctx = Context(template, s, f, t, [d.elements[b].stencil for b in f.crosses])
            names = {"source": s.label, "target": t.label, "flow": f.label}
            for tt, include, exclude in rules:
                if evaluate(include, ctx) and not (exclude and evaluate(exclude, ctx)):
                    out.append(
                        GeneratedThreat(
                            pack="sdl",
                            rule_id=tt.id,
                            cell_id=f.cell_id,
                            direction=direction,
                            category=tt.category,
                            title=fill_placeholders(tt.short_title, names),
                            description=fill_placeholders(tt.description, names),
                            severity=tt.priority or "TBD",
                        )
                    )
    return out
