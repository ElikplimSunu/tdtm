"""Trust boundary geometry. SPEC section 5. PLAN task 1.4.

- `assign_zones(diagram)`: set `Element.zone` on every node to the innermost boundary box
  containing its centre (None = outer zone).
- `assign_crossings(diagram)`: set `Element.crosses` on every flow to the boundary cell ids
  (boxes, then curves, in diagram order) it crosses.
Pure geometry on `model.Point`/`model.Rect`; no Threat Dragon JSON in here.
"""

from __future__ import annotations

from itertools import pairwise

from .model import NODE_KINDS, Diagram, Element, Kind, Point


def _boxes_containing(diagram: Diagram, p: Point) -> list[Element]:
    return [b for b in diagram.of_kind(Kind.BOUNDARY_BOX) if b.rect.contains(p)]


def assign_zones(diagram: Diagram) -> None:
    for e in diagram.of_kind(*NODE_KINDS):
        boxes = _boxes_containing(diagram, e.rect.centre)
        e.zone = min(boxes, key=lambda b: b.rect.width * b.rect.height).cell_id if boxes else None


def _cross(o: Point, a: Point, b: Point) -> float:
    return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x)


def _segments_cross(p1: Point, p2: Point, q1: Point, q2: Point) -> bool:
    d1, d2 = _cross(q1, q2, p1), _cross(q1, q2, p2)
    if d1 == d2 == 0:
        return False  # collinear: running along a boundary is not crossing it
    return d1 * d2 <= 0 and _cross(p1, p2, q1) * _cross(p1, p2, q2) <= 0


def polylines_cross(a: list[Point], b: list[Point]) -> bool:
    return any(_segments_cross(p1, p2, q1, q2) for p1, p2 in pairwise(a) for q1, q2 in pairwise(b))


def flow_path(diagram: Diagram, flow: Element) -> list[Point]:
    src, tgt = diagram.elements[flow.source_id], diagram.elements[flow.target_id]
    return [src.rect.centre, *flow.points, tgt.rect.centre]


def assign_crossings(diagram: Diagram) -> None:
    # ponytail: curves are approximated by their control polyline (SPEC 5.2); Threat Dragon draws
    # them smooth, so a flow passing within a few pixels of a curve's bend can be misjudged.
    for f in diagram.of_kind(Kind.FLOW):
        src, tgt = diagram.elements[f.source_id], diagram.elements[f.target_id]
        path = flow_path(diagram, f)
        f.crosses = [
            b.cell_id
            for b in diagram.of_kind(Kind.BOUNDARY_BOX)
            if b.rect.contains(src.rect.centre) != b.rect.contains(tgt.rect.centre)
        ] + [
            c.cell_id
            for c in diagram.of_kind(Kind.BOUNDARY_CURVE)
            if polylines_cross(path, c.points)
        ]
