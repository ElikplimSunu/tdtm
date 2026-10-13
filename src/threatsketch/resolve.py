"""Resolve what each element is in TMT terms. SPEC 3.5, 4.1, 4.2, 5. PLAN task 1.5.

`resolve(model, template) -> list[str]` sets zones and crossings, then each element's stencil and
effective attributes. Precedence per attribute: stencil static value > `@tmt` tag > Threat Dragon
property > template default. Returns tag errors; other problems go to `model.warnings`.
"""

from __future__ import annotations

from .boundaries import assign_crossings, assign_zones
from .model import KIND_ROOT, Element, Kind, Model
from .tags import _norm, parse_tags, stencil_index

# SPEC 4.2: Threat Dragon property (when true) -> TMT attributes set to "Yes".
TD_ATTRIBUTES: dict[Kind, dict[str, tuple[str, ...]]] = {
    Kind.FLOW: {"isEncrypted": ("providesConfidentiality", "providesIntegrity")},
    Kind.ACTOR: {"providesAuthentication": ("authenticatesItself",)},
    Kind.STORE: {
        "storesCredentials": ("storesCredentials",),
        "isALog": ("storesLogData",),
        "isEncrypted": ("Encrypted",),
        "isSigned": ("Signed",),
    },
}
PROTOCOL_ALIASES = {"http/s": "https"}


def default_stencil(e: Element, template) -> str:
    """SPEC 4.1: what an untagged element is."""
    if e.kind is Kind.PROCESS and e.td_props.get("isWebApplication"):
        return "SE.P.TMCore.WebApp"
    if e.kind is Kind.FLOW:
        protocol = _norm(str(e.td_props.get("protocol") or ""))
        found = stencil_index(template, "GE.DF").get(PROTOCOL_ALIASES.get(protocol, protocol))
        if protocol and found:
            return found
    return KIND_ROOT[e.kind]


def _resolve_element(e: Element, template, errors: list[str], warn) -> None:
    label = f"{e.kind.value} {e.name!r}"
    tags = parse_tags(e.description, e.kind, template)
    errors.extend(f"{label}: {msg}" for msg in tags.errors)
    e.stencil = tags.stencil or default_stencil(e, template)
    stencil_name = template.stencils[e.stencil].name

    td = {
        attr: "Yes"
        for prop, attrs in TD_ATTRIBUTES.get(e.kind, {}).items()
        if e.td_props.get(prop) is True
        for attr in attrs
    }
    e.attributes, e.attr_source = {}, {}
    for name, a in template.attributes_for(e.stencil).items():
        tagged = tags.attributes.get(name)
        if a.static:
            value, source = a.default, "static"
            if tagged is not None and tagged != value:
                warn(f"{label}: {name} is fixed to {value!r} by {stencil_name}; tag ignored")
        elif tagged is not None:
            value, source = tagged, "tag"
        elif td.get(name) in a.values:
            value, source = td[name], "TD"
        else:
            value, source = a.default, "default"
        e.attributes[name], e.attr_source[name] = value, source


def resolve(model: Model, template) -> list[str]:
    errors: list[str] = []
    for d in model.diagrams:
        assign_zones(d)
        assign_crossings(d)
        for e in d.elements.values():
            _resolve_element(e, template, errors, model.warnings.append)
    return errors
