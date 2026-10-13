"""Draw a diagram as inline SVG from its own geometry, the way the report and analysis view show it.

Shapes as in TMT and the ThreatSketch canvas: actors are rectangles, processes circles, stores two
lines, boundaries dashed red; everything else in ink. Flows run edge to edge with an arrow,
straight through their vertices. Colours are the app's design tokens (app/src/app.css).
"""

from __future__ import annotations

import math
from html import escape

from .model import Diagram, Element, Kind, Point, Rect

PAD = 40
STYLE = """
.shape { fill: #fbfcfc; stroke: #1b2026; stroke-width: 1.5; }
.boundary { fill: none; stroke: #c0392f; stroke-width: 1.5; stroke-dasharray: 7 5; }
.flow { fill: none; stroke: #1b2026; stroke-width: 1.3; stroke-linejoin: round; }
text { font: 12px "IBM Plex Sans", system-ui, "Segoe UI", sans-serif; fill: #1b2026; }
text.boundary-label { fill: #c0392f; font-weight: 600; }
text.flow-label { font-size: 11px; paint-order: stroke; stroke: #fbfcfc; stroke-width: 4px; }
"""


def _edge_point(rect: Rect, towards: Point, ellipse: bool) -> Point:
    """Where a line from the centre of `rect` towards `towards` leaves the shape."""
    c = rect.centre
    dx, dy = towards.x - c.x, towards.y - c.y
    if dx == dy == 0:
        return c
    hw, hh = rect.width / 2, rect.height / 2
    if ellipse:
        t = 1 / math.hypot(dx / hw, dy / hh)
    else:
        t = min(hw / abs(dx) if dx else math.inf, hh / abs(dy) if dy else math.inf)
    t = min(t, 1.0)
    return Point(c.x + dx * t, c.y + dy * t)


def _flow_points(d: Diagram, f: Element) -> list[Point]:
    src, tgt = d.elements[f.source_id], d.elements[f.target_id]
    mids = f.points
    first = mids[0] if mids else tgt.rect.centre
    last = mids[-1] if mids else src.rect.centre
    start = _edge_point(src.rect, first, src.kind is Kind.PROCESS)
    end = _edge_point(tgt.rect, last, tgt.kind is Kind.PROCESS)
    return [start, *mids, end]


def _twins(d: Diagram, f: Element) -> tuple[int, int]:
    """This flow's place among the flows joining the same two shapes (by id), and their count."""
    pair = {f.source_id, f.target_id}
    twins = sorted(g.cell_id for g in d.of_kind(Kind.FLOW) if {g.source_id, g.target_id} == pair)
    return twins.index(f.cell_id), len(twins)


def _twin_shift(d: Diagram, f: Element) -> float:
    """How far to move a flow sideways so flows joining the same two shapes do not overlap."""
    i, n = _twins(d, f)
    return (i - (n - 1) / 2) * 16


def _label_at(d: Diagram, f: Element) -> float:
    """Where along a flow its name goes: staggered among flows joining the same two shapes, as
    the canvas does it, so their names do not sit on top of each other."""
    i, n = _twins(d, f)
    step = 0 if n < 2 else min(0.25, 0.6 / (n - 1))
    from_lo = 0.5 + (i - (n - 1) / 2) * step
    return from_lo if f.source_id == min(f.source_id, f.target_id) else 1 - from_lo


def _point_along(points: list[Point], t: float) -> Point:
    lengths = [math.dist((a.x, a.y), (b.x, b.y)) for a, b in zip(points, points[1:], strict=False)]
    left = sum(lengths) * t
    for (a, b), length in zip(zip(points, points[1:], strict=False), lengths, strict=True):
        if left <= length and length:
            k = left / length
            return Point(a.x + (b.x - a.x) * k, a.y + (b.y - a.y) * k)
        left -= length
    return points[-1]


def _side_by_side(d: Diagram, f: Element, points: list[Point], shift: float) -> list[Point]:
    """Move a straight flow `shift` across the line between its shapes' centres."""
    if not shift or len(points) != 2:
        return points
    lo, hi = sorted((f.source_id, f.target_id))  # one direction for every flow of the pair
    a, b = d.elements[lo].rect.centre, d.elements[hi].rect.centre
    length = math.hypot(b.x - a.x, b.y - a.y) or 1
    nx, ny = -(b.y - a.y) / length * shift, (b.x - a.x) / length * shift
    return [Point(p.x + nx, p.y + ny) for p in points]


def _elbow(d: Diagram, f: Element, shift: float) -> list[Point]:
    """An elbow line, as the canvas draws one: out of the facing sides, one bend each way.

    Flows sharing the two shapes are moved `shift` apart, the bend too, so they never cross.
    """
    lo, hi = sorted((f.source_id, f.target_id))
    a, b = d.elements[lo].rect, d.elements[hi].rect
    ca, cb = a.centre, b.centre
    if abs(cb.x - ca.x) / (a.width + b.width) >= abs(cb.y - ca.y) / (a.height + b.height):
        right = cb.x > ca.x
        sx, ex = (a.x + a.width, b.x) if right else (a.x, b.x + b.width)
        mx = (sx + ex) / 2 - shift * (1 if cb.y > ca.y else -1) * (1 if right else -1)
        pts = [Point(sx, ca.y + shift), Point(mx, ca.y + shift), Point(mx, cb.y + shift)]
        pts.append(Point(ex, cb.y + shift))
    else:
        down = cb.y > ca.y
        sy, ey = (a.y + a.height, b.y) if down else (a.y, b.y + b.height)
        my = (sy + ey) / 2 - shift * (1 if cb.x > ca.x else -1) * (1 if down else -1)
        pts = [Point(ca.x - shift, sy), Point(ca.x - shift, my), Point(cb.x - shift, my)]
        pts.append(Point(cb.x - shift, ey))
    return pts if f.source_id == lo else pts[::-1]


def _pts(points: list[Point]) -> str:
    return " ".join(f"{p.x:.1f},{p.y:.1f}" for p in points)


def render_svg(d: Diagram) -> str:
    xs, ys, parts = [], [], []
    for e in d.elements.values():
        if e.rect:
            xs += [e.rect.x, e.rect.x + e.rect.width]
            ys += [e.rect.y, e.rect.y + e.rect.height]
        for p in e.points:
            xs.append(p.x)
            ys.append(p.y)
    xs, ys = xs or [0.0], ys or [0.0]  # an empty diagram still gets a small canvas
    x0, y0 = min(xs) - PAD, min(ys) - PAD
    width, height = max(xs) - x0 + PAD, max(ys) - y0 + PAD

    for b in d.of_kind(Kind.BOUNDARY_BOX):
        r = b.rect
        parts.append(
            f'<rect class="boundary" x="{r.x}" y="{r.y}" width="{r.width}" height="{r.height}"'
            ' rx="6"/>'
        )
        parts.append(
            f'<text class="boundary-label" x="{r.x + 10}" y="{r.y + 18}">{escape(b.label)}</text>'
        )
    for c in d.of_kind(Kind.BOUNDARY_CURVE):
        parts.append(f'<polyline class="boundary" points="{_pts(c.points)}"/>')
        if c.name.strip():
            p = c.points[0]
            parts.append(
                f'<text class="boundary-label" x="{p.x + 6}" y="{p.y - 6}">{escape(c.label)}</text>'
            )
    for e in d.of_kind(Kind.ACTOR, Kind.PROCESS, Kind.STORE):
        r, c = e.rect, e.rect.centre
        if e.kind is Kind.ACTOR:
            parts.append(
                f'<rect class="shape" x="{r.x}" y="{r.y}" width="{r.width}" height="{r.height}"/>'
            )
        elif e.kind is Kind.PROCESS:
            parts.append(
                f'<ellipse class="shape" cx="{c.x}" cy="{c.y}" rx="{r.width / 2}"'
                f' ry="{r.height / 2}"/>'
            )
        else:
            for y in (r.y, r.y + r.height):
                parts.append(
                    f'<line class="shape" x1="{r.x}" y1="{y}" x2="{r.x + r.width}" y2="{y}"/>'
                )
        parts.append(f'<text x="{c.x}" y="{c.y + 4}" text-anchor="middle">{escape(e.label)}</text>')
    for f in d.of_kind(Kind.FLOW):
        shift = 0.0 if f.points else _twin_shift(d, f)
        if f.elbow and not f.points:
            pts = _elbow(d, f, shift)
        else:
            pts = _side_by_side(d, f, _flow_points(d, f), shift)
        parts.append(f'<polyline class="flow" points="{_pts(pts)}" marker-end="url(#arrow)"/>')
        mid = pts[len(pts) // 2] if f.points else _point_along(pts, _label_at(d, f))
        parts.append(
            f'<text class="flow-label" x="{mid.x:.1f}" y="{mid.y - 4:.1f}"'
            f' text-anchor="middle">{escape(f.label)}</text>'
        )

    markers = (
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9"'
        ' markerHeight="9" markerUnits="userSpaceOnUse" orient="auto">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#1b2026"/></marker>'
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x0:.0f} {y0:.0f} {width:.0f} '
        f'{height:.0f}" role="img" aria-label="Diagram: {escape(d.title)}">'
        f"<style>{STYLE}</style><defs>{markers}</defs>{''.join(parts)}</svg>"
    )
