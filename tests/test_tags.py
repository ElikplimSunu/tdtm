import pytest

from threatsketch.model import Kind
from threatsketch.rules.tb7 import load_template
from threatsketch.tags import parse_tags


@pytest.fixture(scope="module")
def t():
    return load_template()


@pytest.mark.parametrize(
    "tag", ["WebApp", "webapp", "SE.P.TMCore.WebApp", "web application", "Web  Application"]
)
def test_stencil_by_id_suffix_or_name(t, tag):
    r = parse_tags(f"@tmt: {tag}", Kind.PROCESS, t)
    assert (r.stencil, r.errors) == ("SE.P.TMCore.WebApp", [])


def test_stencil_key_form_and_other_kinds(t):
    assert parse_tags("@tmt: stencil=WebApp", Kind.PROCESS, t).stencil == "SE.P.TMCore.WebApp"
    assert parse_tags("@tmt: SQL Database", Kind.STORE, t).stencil == "SE.DS.TMCore.SQL"
    assert parse_tags("@tmt: HTTPS", Kind.FLOW, t).stencil == "SE.DF.TMCore.HTTPS"
    assert parse_tags("@tmt: Generic Process", Kind.PROCESS, t).stencil == "GE.P"
    assert parse_tags("@tmt: Internet Boundary", Kind.BOUNDARY_CURVE, t).stencil.startswith(
        "SE.TB.L."
    )


def test_attributes_by_name_or_display_name_with_canonical_values(t):
    r = parse_tags("@tmt: hasInputSanitizers=yes; Code Type = managed", Kind.PROCESS, t)
    assert r.errors == []
    assert r.attributes == {"hasInputSanitizers": "Yes", "codeType": "Managed"}
    r = parse_tags("@tmt: Forgery Protection=nonce", Kind.FLOW, t)
    assert r.attributes == {"54851a3b-65da-4902-b4e0-94ef015be735": "Nonce"}


def test_attributes_validated_against_the_tagged_stencil(t):
    assert parse_tags("@tmt: Cookies; HTTPOnly=Yes", Kind.STORE, t).errors == []
    r = parse_tags("@tmt: HTTPOnly=Yes", Kind.STORE, t)
    assert r.errors and "HTTPOnly" in r.errors[0]


def test_lines_combine_and_other_text_is_ignored(t):
    desc = (
        "Handles logins.\n  @TMT: WebApp\n"
        "text with @tmt: in the middle\n@tmt: hasOutputSanitizers=No;"
    )
    r = parse_tags(desc, Kind.PROCESS, t)
    assert r.errors == []
    assert (r.stencil, r.attributes) == ("SE.P.TMCore.WebApp", {"hasOutputSanitizers": "No"})
    assert parse_tags("no tags here", Kind.PROCESS, t) == parse_tags("", Kind.PROCESS, t)


def test_errors_suggest_fixes(t):
    [e] = parse_tags("@tmt: WebAp", Kind.PROCESS, t).errors
    assert "WebAp" in e and "Web Application" in e
    [e] = parse_tags("@tmt: hasInputSanitiser=Yes", Kind.PROCESS, t).errors
    assert "hasInputSanitizers" in e
    [e] = parse_tags("@tmt: hasInputSanitizers=Maybe", Kind.PROCESS, t).errors
    assert "Maybe" in e and "Not Selected, Yes, No" in e
    [e] = parse_tags("@tmt: SQL Database", Kind.PROCESS, t).errors
    assert "data store" in e
    [e] = parse_tags("@tmt: WebApp; Web Server", Kind.PROCESS, t).errors
    assert "more than one stencil" in e
