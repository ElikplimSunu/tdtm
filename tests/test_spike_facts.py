"""Facts about the external formats that the design in docs/SPEC.md depends on.

If one of these fails after updating a fixture or template, SPEC.md is out of date: fix SPEC first.
These read the raw files directly and do not use tdtm code.
"""

import json
import re
import xml.etree.ElementTree as ET
from collections import Counter

import pytest

from tdtm import DEFAULT_TEMPLATE

from .conftest import TD_MODELS

TB7 = ET.parse(str(DEFAULT_TEMPLATE)).getroot()


# --- Threat Dragon (SPEC 2) ---------------------------------------------------------------


@pytest.mark.parametrize("path", TD_MODELS, ids=lambda p: p.name)
def test_td_fixture_validates_against_v2_schema(path, td_schema_path):
    # SPEC 2.1: Threat Dragon itself writes `strokeDasharray: null`, which its schema rejects.
    # That is the only tolerated error; anything else is a real structural problem.
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    validator = jsonschema.validators.validator_for(schema)(schema)
    errors = [
        e
        for e in validator.iter_errors(json.loads(path.read_text()))
        if not (e.instance is None and list(e.absolute_path)[-1:] == ["strokeDasharray"])
    ]
    assert errors == [], [e.message for e in errors[:5]]


def test_td_cell_types_and_shapes(fixtures):
    seen = Counter()
    for path in TD_MODELS:
        for d in json.loads(path.read_text())["detail"]["diagrams"]:
            for c in d["cells"]:
                seen[(c["data"]["type"], c["shape"])] += 1
    types = {t for t, _ in seen}
    assert types <= {
        "tm.Actor",
        "tm.Process",
        "tm.Store",
        "tm.Flow",
        "tm.Boundary",
        "tm.BoundaryBox",
        "tm.Text",
    }
    # SPEC 2.2: shape is unreliable, a real file misspells it
    assert ("tm.Boundary", "trust-broundary-curve") in seen
    assert ("tm.BoundaryBox", "trust-boundary-box") in seen


def test_td_flows_reference_cells_and_curves_are_points(fixtures):
    m = json.loads((fixtures / "td" / "v2-threat-model.json").read_text())
    for c in m["detail"]["diagrams"][0]["cells"]:
        if c["data"]["type"] == "tm.Flow":
            assert "cell" in c["source"] and "cell" in c["target"]
        if c["data"]["type"] == "tm.Boundary":
            assert {"x", "y"} <= c["source"].keys() and {"x", "y"} <= c["target"].keys()


def test_td_schema_allows_extra_keys(td_schema_path):
    # SPEC 2.5: no additionalProperties:false anywhere, so a `tdtm` key validates
    def walk(o):
        if isinstance(o, dict):
            assert o.get("additionalProperties", True) is not False
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(json.loads(td_schema_path.read_text()))


# --- Microsoft template (SPEC 3) ----------------------------------------------------------


def test_template_is_sdl_core():
    m = TB7.find("Manifest")
    assert m.get("name") == "SDL TM Knowledge Base (Core)"


def test_template_counts():
    assert len(TB7.find("ThreatTypes")) == 47
    assert len(TB7.find("StandardElements")) == 52
    cats = {c.findtext("Id") for c in TB7.find("ThreatCategories")}
    assert cats == set("STRIDEA")


def test_stencil_parents():
    parents = {e.findtext("ID"): e.findtext("ParentElement") for e in TB7.find("StandardElements")}
    assert parents["SE.P.TMCore.WebApp"] == "GE.P"
    assert parents["SE.DF.TMCore.HTTPS"] == "GE.DF"


def test_filter_grammar_uses_only_known_words():
    words = Counter()
    for tt in TB7.find("ThreatTypes"):
        for tag in ("Include", "Exclude"):
            text = tt.findtext(f"GenerationFilters/{tag}") or ""
            text = re.sub(r"'[^']*'", "", text)  # drop string literals
            text = re.sub(r"\b(source|target|flow)\.[A-Za-z0-9-]+", "ATTR", text)
            words.update(re.findall(r"[A-Za-z]+", text))
    assert set(words) <= {"source", "target", "flow", "is", "crosses", "and", "or", "ATTR"}


def test_legacy_root_rules():
    legacy = [
        tt.findtext("Id")
        for tt in TB7.find("ThreatTypes")
        if "'ROOT'" in (tt.findtext("GenerationFilters/Include") or "")
    ]
    assert len(legacy) == 6


def test_title_placeholders():
    found = Counter()
    for tt in TB7.find("ThreatTypes"):
        found.update(re.findall(r"\{(\w+)\.(\w+)\}", ET.tostring(tt, encoding="unicode")))
    assert {(s.lower(), a.lower()) for s, a in found} == {
        ("source", "name"),
        ("target", "name"),
        ("flow", "name"),
    }


def test_stencil_inheritance_is_one_level():
    # SPEC 3.1: every SE's parent is a GE (no SE -> SE chains). An SE attribute is either a Static
    # single-value override of a parent attribute, or a new Dynamic attribute the parent lacks.
    generic = {e.findtext("ID"): e for e in TB7.find("GenericElements")}
    for e in generic.values():
        assert e.findtext("ParentElement") == "ROOT"
        assert all(a.findtext("Mode") == "Dynamic" for a in e.iter("Attribute"))
    added = set()
    for e in TB7.find("StandardElements"):
        parent = generic[e.findtext("ParentElement")]
        inherited = {a.findtext("Name") for a in parent.iter("Attribute")}
        for a in e.iter("Attribute"):
            name = a.findtext("Name")
            if a.findtext("Mode") == "Static":
                assert name in inherited and len(a.find("AttributeValues")) == 1
            else:
                assert name not in inherited and a.findtext("IsInherited") == "false"
                added.add((e.findtext("ID"), name))
    assert ("SE.P.TMCore.Modern", "internetClient") in added
    assert ("SE.DS.TMCore.Cookie", "HTTPOnly") in added


def test_threat_dragon_keeps_custom_keys(fixtures):
    # PLAN 0.2 [manual]: a human opens tests/fixtures/manual/custom-keys.json in Threat Dragon
    # desktop, moves Browser, edits the Web Request threat's mitigation, and saves the result as
    # custom-keys.saved.json. This test is the verdict (SPEC 2.5, 6.3).
    saved = fixtures / "manual" / "custom-keys.saved.json"
    if not saved.exists():
        pytest.skip("waiting for the manual Threat Dragon save (PLAN 0.2)")
    cells = {c["id"]: c for c in json.loads(saved.read_text())["detail"]["diagrams"][0]["cells"]}
    browser = cells["b394f9f7-07ca-42bc-b616-ad77c6fbfcce"]
    threat = cells["2d84bfae-f1ed-49e5-8542-10a02f4a1c57"]["data"]["threats"][0]
    assert "edited" in threat["mitigation"].lower(), "the threat edit did not happen"
    assert browser["data"].get("tdtm") == {"probe": "cell-data-key"}
    assert threat.get("tdtm", {}).get("probe") == "threat-key"
