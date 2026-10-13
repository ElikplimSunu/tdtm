import pytest

from threatsketch.model import Diagram, Element, Kind, Model, Rect
from threatsketch.resolve import resolve
from threatsketch.rules.tb7 import load_template


@pytest.fixture(scope="module")
def t():
    return load_template()


def el(kind, description="", **td_props):
    return Element("c", 0, kind, "Thing", description=description, td_props=td_props)


def run(t, e):
    elements = {e.cell_id: e}
    if e.kind is Kind.FLOW:
        e.source_id, e.target_id = "a", "b"
        for cid in "ab":
            elements[cid] = Element(cid, 0, Kind.PROCESS, cid, rect=Rect(0, 0, 10, 10))
    else:
        e.rect = Rect(0, 0, 10, 10)
    model = Model("m", [Diagram(0, "d", elements=elements)])
    errors = resolve(model, t)
    return e, errors, model.warnings


def test_process_defaults_and_web_application(t):
    e, errors, _ = run(t, el(Kind.PROCESS))
    assert (e.stencil, errors) == ("GE.P", [])
    assert (e.attributes["codeType"], e.attr_source["codeType"]) == ("Not Selected", "default")

    e, _, _ = run(t, el(Kind.PROCESS, isWebApplication=True))
    assert e.stencil == "SE.P.TMCore.WebApp"
    assert (e.attributes["codeType"], e.attr_source["codeType"]) == ("Unmanaged", "static")

    e, _, _ = run(t, el(Kind.PROCESS, "@tmt: Generic Process", isWebApplication=True))
    assert e.stencil == "GE.P"


def test_flow_properties_and_protocol(t):
    e, _, _ = run(t, el(Kind.FLOW, isEncrypted=True))
    assert e.stencil == "GE.DF"
    assert (e.attributes["providesConfidentiality"], e.attr_source["providesConfidentiality"]) == (
        "Yes",
        "TD",
    )
    assert e.attributes["providesIntegrity"] == "Yes"
    assert e.attributes["authenticatesDestination"] == "No"

    for protocol, stencil in [
        ("HTTPS", "SE.DF.TMCore.HTTPS"),
        ("HTTP/S", "SE.DF.TMCore.HTTPS"),
        ("http", "SE.DF.TMCore.HTTP"),
        ("IPsec", "SE.DF.TMCore.IPsec"),
        ("carrier pigeon", "GE.DF"),
        ("", "GE.DF"),
    ]:
        assert run(t, el(Kind.FLOW, protocol=protocol))[0].stencil == stencil, protocol

    e, _, _ = run(t, el(Kind.FLOW, protocol="HTTPS"))
    assert e.attr_source["providesConfidentiality"] == "static"


def test_store_and_actor_properties(t):
    e, _, _ = run(t, el(Kind.STORE, storesCredentials=True, isALog=True, isEncrypted=False))
    assert e.attributes["storesCredentials"] == "Yes" and e.attributes["storesLogData"] == "Yes"
    assert e.attributes["Encrypted"] == "No"  # false or missing leaves the default
    e, _, _ = run(t, el(Kind.ACTOR, providesAuthentication=True))
    assert (e.stencil, e.attributes["authenticatesItself"]) == ("GE.EI", "Yes")


def test_tags_beat_threat_dragon_properties(t):
    e, _, _ = run(t, el(Kind.STORE, "@tmt: storesCredentials=No", storesCredentials=True))
    assert (e.attributes["storesCredentials"], e.attr_source["storesCredentials"]) == ("No", "tag")


def test_static_values_beat_tags_with_a_warning(t):
    e, errors, warnings = run(t, el(Kind.PROCESS, "@tmt: codeType=Managed", isWebApplication=True))
    assert errors == []
    assert e.attributes["codeType"] == "Unmanaged"
    assert any("codeType" in w and "Web Application" in w for w in warnings)


def test_tag_errors_name_the_element(t):
    _, errors, _ = run(t, el(Kind.PROCESS, "@tmt: WebAp"))
    assert len(errors) == 1 and "Thing" in errors[0] and "Web Application" in errors[0]


def test_boundaries_get_stencils_and_demo_model_resolves(t, fixtures):
    from threatsketch.td_adapter import load

    model, _ = load(fixtures / "td" / "v2-threat-model.json")
    assert resolve(model, t) == []
    d = model.diagrams[0]
    assert {c.stencil for c in d.of_kind(Kind.BOUNDARY_CURVE)} == {"GE.TB.L"}
    web_request = d.elements["2d84bfae-f1ed-49e5-8542-10a02f4a1c57"]
    assert web_request.stencil == "SE.DF.TMCore.HTTPS" and web_request.crosses
