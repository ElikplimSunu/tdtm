import pytest

from tdtm.model import Element, Kind
from tdtm.resolve import _resolve_element
from tdtm.rules.filters import Context, FilterSyntaxError, evaluate, parse
from tdtm.rules.tb7 import load_template


@pytest.fixture(scope="module")
def t():
    return load_template()


def resolved(t, kind, stencil=None, **attrs):
    e = Element(kind.value, 0, kind, kind.value)
    if stencil:
        e.description = f"@tmt: {stencil}"
    if attrs:
        e.description += "\n@tmt: " + "; ".join(f"{k}={v}" for k, v in attrs.items())
    errors = []
    _resolve_element(e, t, errors, errors.append)
    assert errors == []
    return e


def ctx(t, source=None, target=None, flow=None, crossed=()):
    return Context(
        template=t,
        source=source or resolved(t, Kind.PROCESS),
        flow=flow or resolved(t, Kind.FLOW),
        target=target or resolved(t, Kind.PROCESS),
        crossed=list(crossed),
    )


def check(text, c):
    return evaluate(parse(text), c)


def test_every_template_filter_parses(t):
    includes = [tt.include for tt in t.threat_types]
    excludes = [tt.exclude for tt in t.threat_types if tt.exclude]
    assert (len(includes), len(excludes)) == (47, 11)
    for text in includes + excludes:
        parse(text)


def test_is_matches_stencil_and_descendants(t):
    c = ctx(t, source=resolved(t, Kind.PROCESS, "WebApp"), target=resolved(t, Kind.STORE))
    assert check("source is 'SE.P.TMCore.WebApp'", c)
    assert check("source is 'GE.P'", c)  # descendant
    assert not check("source is 'GE.EI'", c)
    assert check("target is 'GE.DS'", c)
    assert not check("target is 'SE.DS.TMCore.SQL'", c)  # generic store is not SQL
    assert check("flow is 'GE.DF'", c)
    assert check("source is 'ROOT'", c) and check("target is 'ROOT'", c)


def test_crosses(t):
    c = ctx(t, crossed=["SE.TB.L.TMCore.Internet"])
    assert check("flow crosses 'GE.TB.L'", c)
    assert check("flow crosses 'SE.TB.L.TMCore.Internet'", c)
    assert not check("flow crosses 'GE.TB.B'", c)
    assert not check("flow crosses 'GE.TB.L'", ctx(t))


def test_attributes(t):
    c = ctx(t, flow=resolved(t, Kind.FLOW, "HTTPS"), target=resolved(t, Kind.PROCESS, "WebApp"))
    assert check("flow.providesConfidentiality is 'Yes'", c)  # static on HTTPS
    assert check("target.codeType is 'Unmanaged'", c)  # static on Web Application
    assert check("flow.authenticatesSource is 'Not Selected'", c)  # default
    assert not check("flow.authenticatesSource is 'Yes'", c)
    assert not check("source.internetClient is 'No'", c)  # attribute the stencil lacks
    c = ctx(t, flow=resolved(t, Kind.FLOW, **{"Forgery Protection": "None"}))
    assert check("flow.54851a3b-65da-4902-b4e0-94ef015be735 is 'None'", c)


def test_default_codetype_does_not_match_unmanaged(t):
    assert not check("target.codeType is 'Unmanaged'", ctx(t))
    assert check("target.codeType is 'Not Selected'", ctx(t))


def test_and_binds_tighter_than_or(t):
    c = ctx(t)  # process -> process over a generic flow
    yes, no = "source is 'GE.P'", "source is 'GE.DS'"
    assert check(f"{yes} or {no} and {no}", c)  # yes or (no and no)
    assert not check(f"({yes} or {no}) and {no}", c)
    assert check(f"{no} and {no} or {yes}", c)
    assert not check(f"{yes} and ({no} or {no})", c)


def test_keywords_are_case_insensitive(t):
    assert check("SOURCE IS 'GE.P' AND Flow Crosses 'GE.TB.L'", ctx(t, crossed=["GE.TB.L"]))


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "source is",
        "source is GE.P",
        "source is 'GE.P' and",
        "(source is 'GE.P'",
        "source is 'GE.P')",
        "source crosses 'GE.TB.L'",
        "elsewhere is 'GE.P'",
        "source is 'unterminated",
        "source is 'GE.P' source is 'GE.P'",
        "__import__('os')",
    ],
)
def test_syntax_errors(bad):
    with pytest.raises(FilterSyntaxError):
        parse(bad)
