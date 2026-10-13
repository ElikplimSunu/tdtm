import pytest

from threatsketch.rules.tb7 import load_template


@pytest.fixture(scope="module")
def t():
    return load_template()


def test_counts(t):
    assert len(t.threat_types) == 47
    assert len(t.categories) == 7
    assert len([s for s in t.stencils if s.startswith("SE.")]) == 52
    assert {s for s in t.stencils if s.startswith("GE.")} == {
        "GE.P",
        "GE.EI",
        "GE.DS",
        "GE.DF",
        "GE.TB.L",
        "GE.TB.B",
        "GE.A",
    }


def test_parents_and_is_a(t):
    web = t.stencils["SE.P.TMCore.WebApp"]
    assert web.parent == "GE.P" and web.root == "GE.P" and web.name == "Web Application"
    assert t.stencils["GE.P"].root == "GE.P"
    assert t.is_a("SE.P.TMCore.WebApp", "GE.P")
    assert t.is_a("SE.P.TMCore.WebApp", "SE.P.TMCore.WebApp")
    assert t.is_a("SE.P.TMCore.WebApp", "ROOT")
    assert not t.is_a("SE.P.TMCore.WebApp", "GE.DS")
    assert not t.is_a("GE.P", "SE.P.TMCore.WebApp")
    assert not t.is_a("no.such.stencil", "GE.P")


def test_attributes_inherit_and_override(t):
    kernel = t.attributes_for("SE.P.TMCore.KernelThread")
    assert kernel["codeType"].values == ["Unmanaged"]
    assert kernel["codeType"].static and kernel["codeType"].default == "Unmanaged"
    assert kernel["hasInputSanitizers"].values == ["Not Selected", "Yes", "No"]
    assert not kernel["hasInputSanitizers"].static

    generic = t.attributes_for("GE.P")
    assert generic["codeType"].default == "Not Selected"
    assert generic["hasInputSanitizers"].display_name == "Sanitizes Input"

    cookie = t.attributes_for("SE.DS.TMCore.Cookie")
    assert cookie["HTTPOnly"].values == ["No", "Yes"]  # added by the stencil itself
    assert "storesCredentials" in cookie
    assert "HTTPOnly" not in t.attributes_for("GE.DS")

    flow = t.attributes_for("GE.DF")
    assert flow["54851a3b-65da-4902-b4e0-94ef015be735"].display_name == "Forgery Protection"
    assert flow["Cookies"].default == "Yes"


def test_categories(t):
    assert t.categories["S"] == "Spoofing"
    assert t.categories["I"] == "Information Disclosure"
    assert set(t.categories) == set("STRIDEA")


def test_threat_types(t):
    by_id = {tt.id: tt for tt in t.threat_types}
    s1 = by_id["S1"]
    assert s1.category == "S"
    assert s1.short_title == "Spoofing the {source.Name} Process"
    assert s1.include.startswith("source is")
    assert s1.description
    assert not s1.legacy
    assert sum(tt.legacy for tt in t.threat_types) == 6
    assert by_id["SU"].legacy and by_id["SU"].include == "source is 'ROOT'"
    assert sum(bool(tt.exclude) for tt in t.threat_types) == 11
    assert all(tt.priority is None for tt in t.threat_types)  # SDL leaves Priority empty
    assert t.default_priority == "High"  # ...so TMT uses the template-level first value
