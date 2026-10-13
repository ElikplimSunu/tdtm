"""The functions the ThreatSketch app calls (api.py): same results as the CLI, no files."""

import copy
import json
import shutil
from pathlib import Path

import pytest

from tdtm import api
from tdtm.cli import main

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
MODELS = [
    *sorted(p for p in (FIXTURES / "golden").glob("*.json") if ".expected" not in p.name),
    ROOT / "examples" / "online-shop.json",
]


def shop() -> dict:
    return json.loads((ROOT / "examples" / "online-shop.json").read_text())


def cell(raw, cell_id):
    return next(c for d in raw["detail"]["diagrams"] for c in d["cells"] if c["id"] == cell_id)


@pytest.mark.parametrize("path", MODELS, ids=lambda p: p.stem)
def test_analyze_equals_the_cli(path, tmp_path):
    copy_ = tmp_path / path.name
    shutil.copy(path, copy_)
    assert main(["analyze", str(copy_)]) == 0
    got = api.analyze(json.loads(path.read_text()))
    assert got["model"] == json.loads(copy_.read_text())
    assert got["warnings"] == []
    again = api.analyze(got["model"])
    assert again["counts"]["added"] == 0 and again["model"] == got["model"]


def test_analyze_lists_threats_and_resolved_elements():
    got = api.analyze(shop())
    assert len(got["threats"]) == 38 and got["counts"]["added"] == 38
    row = next(t for t in got["threats"] if t["title"] == "Spoofing the Customer External Entity")
    assert row["cell"] == "placeorder" and row["state"] == "Not Started"
    web = next(e for e in got["elements"].values() if e["stencilName"] == "Web Application")
    names = {a["name"]: a for a in web["attributes"]}
    assert names["codeType"] == {
        **names["codeType"],
        "value": "Unmanaged",
        "source": "static",
        "static": True,
    }  # fixed by the Web Application stencil
    assert got["elements"]["audit"]["attributes"][1]["source"] == "TD"  # Threat Dragon's "Is a Log"
    assert all(a["value"] in a["values"] for a in web["attributes"])


def test_set_threat_is_kept_by_the_next_analysis():
    raw = api.analyze(shop())["model"]
    key = next(t for t in api.analyze(raw)["threats"] if t["id"] == 1)["key"]
    api.set_threat(raw, key, "Needs Investigation", "Low", "Checking with the payments team.")
    got = api.analyze(raw)
    row = next(t for t in got["threats"] if t["key"] == key)
    assert (row["state"], row["priority"], row["justification"]) == (
        "Needs Investigation",
        "Low",
        "Checking with the payments team.",
    )
    assert got["counts"]["edited"] == 1
    api.set_threat(raw, key, "Mitigated", "Low", "Done.")
    row = next(t for t in api.analyze(raw)["threats"] if t["key"] == key)
    assert row["state"] == "Mitigated"
    with pytest.raises(ValueError):
        api.set_threat(raw, key, "Done", "Low", "")
    with pytest.raises(KeyError):
        api.set_threat(raw, "sdl:NOPE:x", "Mitigated", "Low", "")


def test_set_threat_restyles_the_cell():
    raw = api.analyze(shop())["model"]
    flow = cell(raw, "placeorder")
    assert flow["data"]["hasOpenThreats"] is True
    for t in flow["data"]["threats"]:
        api.set_threat(raw, t["tdtm"]["key"], "Not Applicable", "High", "n/a")
    assert flow["data"]["hasOpenThreats"] is False


def test_new_model_is_valid_threat_dragon(td_schema_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    raw = api.new_model("Shop")
    jsonschema.validate(raw, schema)
    assert api.analyze(raw)["threats"] == []


def test_palette_lists_tmt_stencils_per_kind():
    p = api.palette()
    assert p["process"][0] == {"id": "GE.P", "name": "Generic Process", "generic": True}
    assert any(s["name"] == "Web Application" for s in p["process"])
    assert any(s["name"] == "SQL Database" for s in p["store"])
    assert any(s["name"] == "HTTPS" for s in p["flow"])
    assert set(p) == {"actor", "process", "store", "flow", "boundary_box", "boundary_curve"}


def test_set_element_writes_a_minimal_hidden_tag():
    raw = shop()
    store = next(
        c for d in raw["detail"]["diagrams"] for c in d["cells"]
        if c["data"].get("type") == "tm.Store" and "@tmt" not in c["data"].get("description", "")
    )  # fmt: skip
    cid = store["id"]
    store["data"]["description"] = "Holds orders."
    before = len(api.analyze(copy.deepcopy(raw))["threats"])

    sql = next(s["id"] for s in api.palette()["store"] if s["name"] == "SQL Database")
    api.set_element(raw, cid, sql, {})
    assert store["data"]["description"] == "Holds orders.\n@tmt: SQL Database"
    got = api.analyze(copy.deepcopy(raw))
    assert got["elements"][cid]["stencilName"] == "SQL Database"
    assert len(got["threats"]) > before

    attrs = {a["name"]: a for a in got["elements"][cid]["attributes"]}
    free = next(a for a in attrs.values() if not a["static"] and len(a["values"]) > 1)
    other = next(v for v in free["values"] if v != free["value"])
    static = next((a for a in attrs.values() if a["static"]), None)
    choice = {free["name"]: other, **({static["name"]: "x"} if static else {})}
    api.set_element(raw, cid, sql, choice)
    assert store["data"]["description"] == (
        f"Holds orders.\n@tmt: SQL Database; {free['name']}={other}"
    )
    assert api.analyze(copy.deepcopy(raw))["elements"][cid]["attributes"] == [
        {**a, "value": other, "source": "tag"} if a["name"] == free["name"] else a
        for a in got["elements"][cid]["attributes"]
    ]

    api.set_element(raw, cid, "GE.DS", {})  # back to generic: the tag line goes
    assert store["data"]["description"] == "Holds orders."
    with pytest.raises(ValueError):
        api.set_element(raw, cid, "GE.P", {})
    assert store["data"]["description"] == "Holds orders."


def test_set_element_can_override_a_threat_dragon_property():
    raw = shop()
    web = next(
        c for d in raw["detail"]["diagrams"] for c in d["cells"]
        if c["data"].get("isWebApplication")
    )  # fmt: skip
    api.set_element(raw, web["id"], "GE.P", {})  # generic, despite the Web Application box
    assert web["data"]["description"].endswith("@tmt: Generic Process")
    got = api.analyze(raw)
    assert got["elements"][web["id"]]["stencil"] == "GE.P"


def test_tm7_import_export_and_reports():
    data = (FIXTURES / "tm7" / "small.tm7").read_bytes()
    from tdtm.tm7 import import_tm7

    imported = api.import_tm7(data, "small")
    assert (imported["model"], imported["warnings"]) == import_tm7(FIXTURES / "tm7" / "small.tm7")
    out = api.export_tm7(shop())
    assert "<ThreatModel" in out["text"][:400]
    raw = api.analyze(shop())["model"]
    html = api.report_html(raw)
    assert "Online shop" in html and "Threat Model Summary" in html
    assert api.report_csv(raw).startswith("Id,Title,Category,Diagram")
