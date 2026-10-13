"""What the ThreatSketch app (`app/`) calls: plain dicts and strings in and out, no files.

The app runs this module in the browser under Pyodide, so it stays stdlib-only and never touches
the filesystem except to read the bundled template. Every function takes a Threat Dragon v2 model
as a dict and patches it in place, the same way the CLI does, so nothing it does not understand
is dropped.

- `new_model(title)`: an empty model with one STRIDE diagram.
- `analyze(raw)`: generate and merge SDL threats; returns the merged model, TMT-style threat rows,
  each element's resolved stencil and attributes, warnings and merge counts.
- `palette()`: every stencil per element kind, for the app's stencil palette.
- `set_element(raw, cell_id, stencil, attributes)`: record a stencil and attribute choice in the
  element's hidden `@tmt:` line (SPEC 4.3), so files stay readable by the CLI and Threat Dragon.
- `set_threat(raw, key, state, priority, justification)`: triage one threat, TMT's way.
- `import_tm7(data, title)`, `export_tm7(raw)`, `report_html(raw)`, `report_csv(raw)`.
"""

from __future__ import annotations

from .merge import merge
from .model import KIND_ROOT, Kind, Model
from .report import generated_by, render, render_csv, review, tmt_category, tmt_changed, tmt_state
from .resolve import resolve
from .rules.engine import run_sdl
from .rules.tb7 import load_template
from .tags import TAG_LINE
from .td_adapter import load_raw

STATES = {  # TMT state -> (Threat Dragon status, tmtState kept under the threat's threatsketch key)
    "Not Started": ("Open", ""),
    "Needs Investigation": ("Open", "Needs Investigation"),
    "Not Applicable": ("NotApplicable", ""),
    "Mitigated": ("Mitigated", ""),
}
PRIORITIES = ("High", "Medium", "Low", "Critical", "TBD")

_template = None


def template():
    global _template
    if _template is None:
        _template = load_template()
    return _template


def new_model(title: str = "Untitled threat model") -> dict:
    diagram = {
        "id": 0,
        "title": "Main diagram",
        "diagramType": "STRIDE",
        "placeholder": "New STRIDE diagram description",
        "thumbnail": "./public/content/images/thumbnail.stride.jpg",
        "version": "2.6.2",
        "cells": [],
    }
    return {
        "version": "2.6.2",
        "summary": {"title": title, "owner": "", "description": "", "id": 0},
        "detail": {
            "contributors": [],
            "diagramTop": 1,
            "reviewer": "",
            "threatTop": 0,
            "diagrams": [diagram],
        },
    }


def threat_rows(model: Model, tpl) -> list[dict]:
    """Every threat in the model as TMT's Analysis View lists it."""
    rows = []
    for d in model.diagrams:
        for e in d.elements.values():
            flow = e.kind is Kind.FLOW
            for i, t in enumerate(e.threats):
                rows.append(
                    {
                        "key": t.tdtm_key or t.id or f"{e.cell_id}:{i}",
                        "id": t.raw.get("number"),
                        "cell": e.cell_id,
                        "diagram": d.title,
                        "interaction": e.label,
                        "source": d.elements[e.source_id].label if flow else "",
                        "target": d.elements[e.target_id].label if flow else "",
                        "state": tmt_state(t),
                        "title": t.title,
                        "category": tmt_category(t, tpl),
                        "description": t.description,
                        "justification": t.mitigation,
                        "priority": t.severity,
                        "changedBy": tmt_changed(t)[0],
                        "lastModified": tmt_changed(t)[1],
                        "generatedBy": generated_by(t),
                        "editable": bool(t.tdtm_key),
                    }
                )
    return rows


def _elements(model: Model, tpl) -> dict:
    out = {}
    for d in model.diagrams:
        for e in d.elements.values():
            out[e.cell_id] = {
                "kind": e.kind.value,
                "stencil": e.stencil,
                "stencilName": tpl.stencils[e.stencil].name,
                "zone": e.zone,
                "crosses": e.crosses,
                "attributes": [
                    {
                        "name": name,
                        "label": a.display_name or name,
                        "value": e.attributes[name],
                        "values": a.values,
                        "source": e.attr_source[name],
                        "static": a.static,
                    }
                    for name, a in tpl.attributes_for(e.stencil).items()
                ],
            }
    return out


def analyze(raw: dict) -> dict:
    tpl = template()
    model, doc = load_raw(raw)
    errors = resolve(model, tpl)
    s = merge(doc, run_sdl(model, tpl), packs=("sdl",))
    merged, _ = load_raw(doc.raw)  # re-read so the rows hold the merged threats
    resolve(merged, tpl)
    return {
        "model": doc.raw,
        "threats": threat_rows(merged, tpl),
        "elements": _elements(merged, tpl),
        "warnings": model.warnings + [f"tag error: {e}" for e in errors],
        "review": review(merged, tpl),
        "counts": {
            "added": len(s.added),
            "refreshed": len(s.refreshed),
            "unchanged": len(s.unchanged),
            "edited": len(s.kept_edited),
            "stale": len(s.stale),
        },
    }


ICON_AT = {  # TMT's ImageLocation, as the app places the icon
    "Centered on stencil": "center",
    "Lower right of stencil": "lower-right",
    "Before label": "before-label",
}


def palette() -> dict:
    """Kind -> stencils under it, generic element first, in template order."""
    tpl = template()
    return {
        kind.value: [
            {
                "id": s.id,
                "name": s.name,
                "generic": s.id == root,
                "icon": f"data:image/png;base64,{s.image}",
                "iconAt": ICON_AT.get(s.image_location, "center"),
            }
            for s in sorted(
                (s for s in tpl.stencils.values() if s.root == root), key=lambda s: s.id != root
            )
        ]
        for kind, root in KIND_ROOT.items()
    }


def _cell(raw: dict, cell_id: str) -> dict:
    for d in raw.get("detail", {}).get("diagrams", []):
        for c in d.get("cells", []):
            if c.get("id") == cell_id:
                return c
    raise KeyError(f"no cell {cell_id!r}")


def _resolve_with(raw: dict, cell_id: str, description: str):
    _cell(raw, cell_id)["data"]["description"] = description
    model, _ = load_raw(raw)
    resolve(model, template())
    return next(e for d in model.diagrams for e in d.elements.values() if e.cell_id == cell_id)


def set_element(raw: dict, cell_id: str, stencil: str, attributes: dict[str, str]) -> dict:
    """Write the `@tmt:` line that makes the element this stencil with these attribute values.

    Only what differs from the untagged element is written: the stencil when it is not the one
    the element gets anyway, and attribute values that differ from what it gets without a tag.
    Static attributes are fixed by the stencil and never written.
    """
    tpl = template()
    data = _cell(raw, cell_id).setdefault("data", {})
    text = TAG_LINE.sub("", data.get("description") or "").strip("\n")
    untagged = _resolve_with(raw, cell_id, text)
    if stencil not in tpl.stencils or tpl.stencils[stencil].root != KIND_ROOT[untagged.kind]:
        _cell(raw, cell_id)["data"]["description"] = data.get("description", "")
        raise ValueError(f"{stencil!r} is not a {untagged.kind.value} stencil")
    items = [tpl.stencils[stencil].name] if stencil != untagged.stencil else []
    baseline = _resolve_with(raw, cell_id, _with_tag(text, items))
    for name, a in tpl.attributes_for(stencil).items():
        value = attributes.get(name)
        if value is None or a.static or value == baseline.attributes.get(name):
            continue
        if value not in a.values:
            raise ValueError(f"{value!r} is not a value of {name}")
        items.append(f"{name}={value}")
    data["description"] = _with_tag(text, items)
    return raw


def _with_tag(text: str, items: list[str]) -> str:
    return "\n".join(filter(None, [text, "@tmt: " + "; ".join(items) if items else ""]))


def _threats(raw: dict):
    for d in raw.get("detail", {}).get("diagrams", []):
        for c in d.get("cells", []):
            yield from (c.get("data") or {}).get("threats") or []


def set_threat(raw: dict, key: str, state: str, priority: str, justification: str) -> dict:
    """Set TMT state, priority and justification on the threat with this threatsketch key or id."""
    if state not in STATES or priority not in PRIORITIES or not isinstance(justification, str):
        raise ValueError("bad state, priority or justification")
    found = [
        t
        for t in _threats(raw)
        if (isinstance(t.get("tdtm"), dict) and t["tdtm"].get("key") == key) or t.get("id") == key
    ]
    if not found:
        raise KeyError(f"no threat {key!r}")
    status, tmt = STATES[state]
    for t in found:
        t["status"], t["severity"], t["mitigation"] = status, priority, justification
        if tmt:
            t.setdefault("tdtm", {})["tmtState"] = tmt
        elif isinstance(t.get("tdtm"), dict):
            t["tdtm"].pop("tmtState", None)
    _, doc = load_raw(raw)
    merge(doc, [], packs=())  # recompute hasOpenThreats and the red outlines
    return raw


def import_tm7(data: bytes, title: str = "Imported model") -> dict:
    from .tm7 import parse_tm7

    raw, warnings = parse_tm7(bytes(data), title)
    return {"model": raw, "warnings": warnings}


def export_tm7(raw: dict) -> dict:
    from .tm7_export import export_tm7 as export

    text, warnings = export(raw)
    return {"text": text, "warnings": warnings}


def _resolved(raw: dict) -> Model:
    model, _ = load_raw(raw)
    resolve(model, template())
    return model


def report_html(raw: dict) -> str:
    return render(_resolved(raw), template())


def report_csv(raw: dict) -> str:
    return render_csv(_resolved(raw), template())
