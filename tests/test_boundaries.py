from threatsketch.boundaries import assign_crossings, assign_zones
from threatsketch.model import Diagram, Element, Kind, Point, Rect


def node(cid, x, y, w=20, h=20, kind=Kind.PROCESS):
    return Element(cid, 0, kind, cid, rect=Rect(x, y, w, h))


def box(cid, x, y, w, h):
    return node(cid, x, y, w, h, Kind.BOUNDARY_BOX)


def flow(cid, src, tgt, *vertices):
    return Element(cid, 0, Kind.FLOW, cid, source_id=src, target_id=tgt, points=list(vertices))


def curve(cid, *points):
    return Element(cid, 0, Kind.BOUNDARY_CURVE, cid, points=[Point(*p) for p in points])


def diagram(*elements):
    d = Diagram(0, "t", elements={e.cell_id: e for e in elements})
    assign_zones(d)
    assign_crossings(d)
    return d.elements


def test_nested_boxes_give_innermost_zone():
    els = diagram(
        box("outer", 0, 0, 400, 400),
        box("inner", 50, 50, 100, 100),
        node("deep", 90, 90),
        node("shallow", 300, 300),
        node("out", 500, 500),
    )
    assert (els["deep"].zone, els["shallow"].zone, els["out"].zone) == ("inner", "outer", None)


def test_flow_crossing_boxes():
    els = diagram(
        box("outer", 0, 0, 400, 400),
        box("inner", 50, 50, 100, 100),
        node("deep", 90, 90),
        node("shallow", 300, 300),
        node("out", 500, 500),
        node("out2", 500, 0),
        flow("deep->out", "deep", "out"),
        flow("deep->shallow", "deep", "shallow"),
        flow("shallow->shallow", "shallow", "shallow"),
        flow("out->out2 through box", "out", "out2", Point(200, 200)),
    )
    assert els["deep->out"].crosses == ["outer", "inner"]
    assert els["deep->shallow"].crosses == ["inner"]
    assert els["shallow->shallow"].crosses == []
    assert els["out->out2 through box"].crosses == []  # enters and leaves: not a crossing


def test_flow_crossing_a_curve():
    els = diagram(
        node("a", 0, 0),
        node("b", 200, 0),
        node("c", 0, 200),
        curve("wall", (100, -50), (110, 50), (100, 300)),
        flow("a->b", "a", "b"),
        flow("a->c", "a", "c"),
        flow("a->c bent", "a", "c", Point(150, 100)),
    )
    assert els["a->b"].crosses == ["wall"]
    assert els["a->c"].crosses == []
    assert els["a->c bent"].crosses == ["wall"]


def test_flow_parallel_to_or_along_a_curve_does_not_cross():
    els = diagram(
        node("a", 0, 0),
        node("b", 200, 0),
        curve("parallel", (0, 50), (210, 50)),
        curve("collinear", (-50, 10), (300, 10)),
        curve("short", (300, -50), (300, 50)),
        flow("a->b", "a", "b"),
    )
    assert els["a->b"].crosses == []


def test_real_demo_model_crossings(fixtures):
    """Threat Dragon's demo model: 10 flows, 3 boundary curves (B1 Browser side, B2 queue side,
    B3 database side, in file order).

    Human check: AWAITING. Sent to the user on 2026-10-13 as a drawing of these crossings. Each
    decision has at least 39 px of clearance, and none changes when the curves are smoothed the
    way Threat Dragon draws them. Update this docstring with the user's answer.
    """
    from threatsketch.td_adapter import load

    model, _ = load(fixtures / "td" / "v2-threat-model.json")
    d = model.diagrams[0]
    assign_zones(d)
    assign_crossings(d)
    curves = [c.cell_id for c in d.of_kind(Kind.BOUNDARY_CURVE)]
    got = {
        f.name.replace("\n", " "): [curves.index(c) + 1 for c in f.crosses]
        for f in d.of_kind(Kind.FLOW)
    }
    assert got == {
        "Web Request": [1],
        "Web Response": [1],
        "Put Message": [2],
        "Message": [2],
        "Queries": [3],
        "Web App Query Results": [3],
        "Worker Queries": [3],
        "Worker Query Results": [3],
        "Read web app config": [],
        "Read worker config": [],
    }
