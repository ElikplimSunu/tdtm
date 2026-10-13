from pathlib import Path

from threatsketch.diagram import render_svg
from threatsketch.td_adapter import load

FIXTURES = Path(__file__).parent / "fixtures"


def test_svg_draws_every_element():
    model, _ = load(Path(__file__).parent.parent / "examples" / "online-shop.json")
    svg = render_svg(model.diagrams[0])
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    for name in ("Customer", "Shop Web App", "Orders DB", "Payment Provider", "Shop backend"):
        assert f">{name}<" in svg
    assert svg.count('marker-end="url(#') == 7  # one arrow per flow
    assert "<ellipse" in svg  # processes are circles, like TMT and Threat Dragon


def test_svg_escapes_names_and_draws_in_tmt_style(tmp_path):
    import json
    import shutil

    path = tmp_path / "m.json"
    shutil.copy(FIXTURES / "golden" / "2-actor-process-curve.json", path)
    raw = json.loads(path.read_text())
    for c in raw["detail"]["diagrams"][0]["cells"]:
        if c["id"] == "user":
            c["data"]["name"] = "<b>User</b>"
        if c["id"] == "request":
            c["data"]["threats"] = [
                {
                    "title": "t",
                    "status": "Open",
                    "severity": "High",
                    "type": "Spoofing",
                    "description": "",
                    "mitigation": "",
                }
            ]
    path.write_text(json.dumps(raw))
    model, _ = load(path)
    svg = render_svg(model.diagrams[0])
    assert "<b>User" not in svg and "&lt;b&gt;User&lt;/b&gt;" in svg
    assert "open" not in svg  # red is for trust boundaries only, as on the canvas
    assert 'class="boundary"' in svg and "#c0392f" in svg
    assert "<polyline" in svg  # the boundary curve


def test_svg_of_an_empty_diagram_is_valid():
    from threatsketch.model import Diagram

    assert render_svg(Diagram(0, "empty")).startswith("<svg")


def test_flows_both_ways_between_two_shapes_do_not_overlap():
    from threatsketch.model import Diagram, Element, Kind, Rect

    d = Diagram(0, "two-way")
    for id_, x in (("a", 0), ("b", 300)):
        d.elements[id_] = Element(id_, 0, Kind.ACTOR, id_, rect=Rect(x, 0, 100, 60))
    for id_, s, t in (("f1", "a", "b"), ("f2", "b", "a")):
        d.elements[id_] = Element(id_, 0, Kind.FLOW, id_, source_id=s, target_id=t)
    svg = render_svg(d)
    lines = [p for p in svg.split("<") if p.startswith('polyline class="flow"')]
    assert len(lines) == 2 and lines[0] != lines[1]
    labels = [p for p in svg.split("<") if p.startswith('text class="flow-label"')]
    xs = [float(p.split(' x="')[1].split('"')[0]) for p in labels]
    assert abs(xs[0] - xs[1]) > 30  # their names sit apart along the lines


def test_elbow_flows_bend_at_right_angles_and_two_way_ones_stay_apart():
    from threatsketch.model import Diagram, Element, Kind, Rect

    d = Diagram(0, "elbows")
    d.elements["a"] = Element("a", 0, Kind.ACTOR, "a", rect=Rect(0, 0, 100, 60))
    d.elements["b"] = Element("b", 0, Kind.ACTOR, "b", rect=Rect(300, 100, 100, 60))
    for id_, s, t in (("f1", "a", "b"), ("f2", "b", "a")):
        d.elements[id_] = Element(id_, 0, Kind.FLOW, id_, source_id=s, target_id=t, elbow=True)
    lines = []
    for part in render_svg(d).split("<"):
        if part.startswith('polyline class="flow"'):
            pts = part.split('points="')[1].split('"')[0].split()
            lines.append([tuple(map(float, p.split(","))) for p in pts])
    assert len(lines) == 2
    for pts in lines:
        assert len(pts) == 4
        assert all(p[0] == q[0] or p[1] == q[1] for p, q in zip(pts, pts[1:], strict=False))
    assert set(lines[0]).isdisjoint(lines[1])
    assert lines[0][0][0] == 100 and lines[1][-1][0] == 100  # out of a's right side, back into it
