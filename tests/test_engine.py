import pytest

from tdtm.model import Diagram, Element, Kind, Model, Point, Rect
from tdtm.resolve import resolve
from tdtm.rules.engine import fill_placeholders, run_sdl
from tdtm.rules.tb7 import load_template

CSRF = "8404dcf5-bdd8-4902-abc2-3b6c967b0261"


@pytest.fixture(scope="module")
def t():
    return load_template()


def model(*, crossing=True, bidirectional=False, diagram_type="STRIDE", **scope):
    """User (actor) <-> App (process), optionally across a boundary curve."""
    user = Element("user", 0, Kind.ACTOR, "User", rect=Rect(0, 0, 20, 20))
    app = Element("app", 0, Kind.PROCESS, "App", rect=Rect(200, 0, 20, 20))
    flow = Element(
        "f", 0, Kind.FLOW, "Login", source_id="user", target_id="app",
        td_props={"isBidirectional": bidirectional},
    )  # fmt: skip
    user.out_of_scope = scope.get("user_oos", False)
    app.out_of_scope = scope.get("app_oos", False)
    flow.out_of_scope = scope.get("flow_oos", False)
    els = [user, app, flow]
    if crossing:
        els.append(
            Element("wall", 0, Kind.BOUNDARY_CURVE, "", points=[Point(100, -50), Point(100, 50)])
        )
    return Model("m", [Diagram(0, "d", diagram_type, {e.cell_id: e for e in els})])


def fired(t, m, **kw):
    assert resolve(m, t) == []
    return [(g.direction, g.rule_id) for g in run_sdl(m, t, **kw)]


FWD = ["S2", "S3", "T1", "R6", "I6", "D3", "D4", "E5", "E6", "E7", CSRF]  # template order


def test_actor_to_process_without_and_with_a_boundary(t):
    assert fired(t, model(crossing=False)) == [(None, "S3"), (None, "E5")]
    assert fired(t, model()) == [(None, r) for r in FWD]


def test_bidirectional_flows_are_two_interactions(t):
    got = fired(t, model(bidirectional=True))
    assert got == [("fwd", r) for r in FWD] + [("rev", r) for r in ["S8", "R7", "D4"]]


def test_titles_use_names_and_threats_attach_to_the_flow(t):
    m = model(bidirectional=True)
    assert resolve(m, t) == []
    gen = run_sdl(m, t)
    s3 = next(g for g in gen if g.rule_id == "S3")
    assert s3.title == "Spoofing the User External Entity (User → App)"
    assert "User may be spoofed" in s3.description
    assert (s3.cell_id, s3.category, s3.severity, s3.pack) == ("f", "S", "High", "sdl")
    assert s3.key == "sdl:S3:f:fwd"
    s8 = next(g for g in gen if g.rule_id == "S8")
    assert s8.title == "Spoofing of the User External Destination Entity (App → User)"


def test_placeholders_are_case_insensitive():
    names = {"source": "A", "target": "B", "flow": "F"}
    assert fill_placeholders(
        "{source.Name}/{SOURCE.name}/{target.NAME} via {flow.name}", names
    ) == ("A/A/B via F")


def test_legacy_rules_only_on_request(t):
    legacy = {"SU", "TU", "RU", "IU", "DU", "EU"}
    assert not legacy & {r for _, r in fired(t, model())}
    assert legacy <= {r for _, r in fired(t, model(), include_legacy=True)}


def test_out_of_scope(t):
    assert fired(t, model(flow_oos=True)) == []
    assert fired(t, model(user_oos=True, app_oos=True)) == []
    assert fired(t, model(user_oos=True)) == [(None, r) for r in FWD]


def test_non_stride_diagrams_are_skipped_with_a_warning(t):
    m = model(diagram_type="LINDDUN")
    assert fired(t, m) == []
    assert any("LINDDUN" in w for w in m.warnings)


def test_tags_change_the_outcome(t):
    m = model()
    m.diagrams[0].elements["f"].description = "@tmt: HTTPS"
    got = {r for _, r in fired(t, m)}
    assert "T1" not in got and "I6" not in got  # HTTPS provides confidentiality and integrity
    assert "S2" not in got  # HTTPS authenticates the destination
