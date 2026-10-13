"""Threat Dragon v2 JSON <-> internal model. SPEC section 2. PLAN task 1.1.

- `load(path) -> tuple[Model, Document]`: parse every diagram; identify cells by `data.type`
  (see `model.TD_TYPE_TO_KIND`), skip `tm.Text`; warn (in `Model.warnings`) on dangling flows.
- `Document` holds the original parsed JSON plus an index cell_id -> cell dict, so writes are
  patches to the original structure. Nothing the adapter does not understand is ever dropped.
- `save(doc, path)`: write JSON with the same indentation style Threat Dragon uses (2 spaces).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import TD_TYPE_TO_KIND, Diagram, Element, Kind, Model, Point, Rect, Threat


@dataclass
class Document:
    raw: dict
    cells: dict[str, dict] = field(default_factory=dict)  # cell_id -> cell dict inside raw


def _threat(t: dict) -> Threat:
    tdtm = t.get("tdtm")
    return Threat(
        title=t.get("title", ""),
        type=t.get("type", ""),
        status=t.get("status", ""),
        severity=t.get("severity", ""),
        description=t.get("description", ""),
        mitigation=t.get("mitigation", ""),
        id=t.get("id"),
        tdtm_key=tdtm.get("key") if isinstance(tdtm, dict) else None,
        raw=t,
    )


def _point(p: dict) -> Point | None:
    return Point(p["x"], p["y"]) if isinstance(p, dict) and "x" in p and "y" in p else None


def _element(cell: dict, diagram_id, kind: Kind, warn) -> Element | None:
    data = cell.get("data", {})
    e = Element(
        cell_id=cell["id"],
        diagram_id=diagram_id,
        kind=kind,
        name=data.get("name") or "",
        description=data.get("description") or "",
        out_of_scope=bool(data.get("outOfScope")),
        td_props={k: v for k, v in data.items() if k != "threats"},
        threats=[_threat(t) for t in data.get("threats") or []],
    )
    label = f"{kind.value} {e.name!r} ({e.cell_id})"
    if kind in (Kind.ACTOR, Kind.PROCESS, Kind.STORE, Kind.BOUNDARY_BOX):
        pos, size = cell.get("position"), cell.get("size")
        if not (pos and size):
            warn(f"{label} has no position/size; skipped")
            return None
        e.rect = Rect(pos["x"], pos["y"], size["width"], size["height"])
    elif kind is Kind.FLOW:
        e.source_id = (cell.get("source") or {}).get("cell")
        e.target_id = (cell.get("target") or {}).get("cell")
        e.points = [p for p in map(_point, cell.get("vertices") or []) if p]
    else:  # boundary curve: a free-standing line
        ends = [_point(cell.get("source")), _point(cell.get("target"))]
        if None in ends:
            warn(f"{label} is attached to a shape rather than drawn freely; skipped")
            return None
        mids = [p for p in map(_point, cell.get("vertices") or []) if p]
        e.points = [ends[0], *mids, ends[1]]
    return e


def load(path: str | Path) -> tuple[Model, Document]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    doc = Document(raw=raw)
    summary, detail = raw.get("summary", {}), raw.get("detail", {})
    model = Model(
        title=summary.get("title", ""),
        owner=summary.get("owner") or "",
        description=summary.get("description") or "",
        reviewer=detail.get("reviewer") or "",
        contributors=[c.get("name", "") for c in detail.get("contributors") or [] if c],
    )
    warn = model.warnings.append

    for d in raw.get("detail", {}).get("diagrams", []):
        diagram = Diagram(
            id=d.get("id"), title=d.get("title", ""), diagram_type=d.get("diagramType") or "STRIDE"
        )
        model.diagrams.append(diagram)
        for cell in d.get("cells", []):
            doc.cells[cell["id"]] = cell
            td_type = cell.get("data", {}).get("type")
            kind = TD_TYPE_TO_KIND.get(td_type)
            if kind is None:
                if td_type != "tm.Text":
                    warn(f"cell {cell['id']} has unknown type {td_type!r}; skipped")
                continue
            e = _element(cell, diagram.id, kind, warn)
            if e:
                diagram.elements[e.cell_id] = e

        for f in diagram.of_kind(Kind.FLOW):
            if f.source_id not in diagram.elements or f.target_id not in diagram.elements:
                warn(f"flow {f.name!r} ({f.cell_id}) is unconnected at one end; skipped")
                del diagram.elements[f.cell_id]
    return model, doc


def save(doc: Document, path: str | Path) -> None:
    Path(path).write_text(json.dumps(doc.raw, indent=2, ensure_ascii=False), encoding="utf-8")
