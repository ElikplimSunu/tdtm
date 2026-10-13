"""Which template rules can fire from Threat Dragon properties alone. PLAN task 3.1.

Brute force rather than reasoning over filter logic: build every distinct element Threat Dragon's
own properties can express (SPEC 4.1, 4.2), try every source x flow x target x crossing, and see
which rules ever fire. Exact, and small enough (about 26,000 interactions) to run in a second.
"""

from __future__ import annotations

from itertools import product

from .model import Element, Kind
from .resolve import TD_ATTRIBUTES, _resolve_element
from .rules.filters import And, AttrIs, Context, Crosses, Is, Or, evaluate, parse

CROSSINGS = ([], ["GE.TB.B"], ["GE.TB.L"])  # none, a boundary box, a boundary curve


def td_elements(template) -> dict[Kind, list[Element]]:
    """Every distinct element (by stencil and attributes) Threat Dragon can express, resolved."""
    protocols = [""] + [s.name for s in template.stencils.values() if s.root == "GE.DF"]
    store_flags = list(TD_ATTRIBUTES[Kind.STORE])
    variants = {
        Kind.ACTOR: [{"providesAuthentication": b} for b in (False, True)],
        Kind.PROCESS: [{"isWebApplication": b} for b in (False, True)],
        Kind.STORE: [
            dict(zip(store_flags, bits, strict=True)) for bits in product((False, True), repeat=4)
        ],
        Kind.FLOW: [{"protocol": p, "isEncrypted": b} for p in protocols for b in (False, True)],
    }
    out = {}
    for kind, props in variants.items():
        distinct = {}
        for p in props:
            e = Element("x", 0, kind, kind.value, td_props=p)
            _resolve_element(e, template, [], lambda _: None)
            distinct.setdefault((e.stencil, tuple(sorted(e.attributes.items()))), e)
        out[kind] = list(distinct.values())
    return out


def _atoms(node):
    if isinstance(node, (And, Or)):
        for n in node.items:
            yield from _atoms(n)
    else:
        yield node


def _hints(node, node_text: str, template, els: dict[Kind, list[Element]]) -> list[str]:
    """What tags the rule's Include asks for that Threat Dragon cannot express."""
    everything = [e for group in els.values() for e in group]
    stencils = {e.stencil for e in everything} | {c for crossing in CROSSINGS for c in crossing}
    values = {(n, v) for e in everything for n, v in e.attributes.items()}
    hints = []
    for a in _atoms(node):
        if isinstance(a, Is) and not any(template.is_a(s, a.stencil) for s in stencils):
            hints.append(f"{a.subject}: @tmt: {template.stencils[a.stencil].name}")
        elif isinstance(a, Crosses) and a.stencil not in stencils:
            hints.append(f"boundary: @tmt: {template.stencils[a.stencil].name}")
        elif isinstance(a, AttrIs) and (a.attr, a.value) not in values:
            hints.append(f"{a.subject}: @tmt: {a.attr}={a.value}")
    # each part is reachable alone, but no Threat Dragon setting combines them
    return list(dict.fromkeys(hints)) or [f"tag attributes so that: {node_text}"]


def coverage(template) -> list[tuple]:
    """-> [(threat type, fires from Threat Dragon alone, hints)] in template order."""
    els = td_elements(template)
    ends = els[Kind.ACTOR] + els[Kind.PROCESS] + els[Kind.STORE]
    contexts = [
        Context(template, s, f, t, list(c))
        for s, t, f, c in product(ends, ends, els[Kind.FLOW], CROSSINGS)
    ]
    out = []
    for tt in template.threat_types:
        include, exclude = parse(tt.include), parse(tt.exclude) if tt.exclude else None
        fires = any(
            evaluate(include, c) and not (exclude and evaluate(exclude, c)) for c in contexts
        )
        out.append((tt, fires, [] if fires else _hints(include, tt.include, template, els)))
    return out
