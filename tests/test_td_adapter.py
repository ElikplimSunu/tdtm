import json

import pytest

from threatsketch.model import Kind, Point, Rect
from threatsketch.td_adapter import load, save

from .conftest import TD_MODELS


@pytest.mark.parametrize("path", TD_MODELS, ids=lambda p: p.name)
def test_round_trip_is_json_equal(path, tmp_path):
    _, doc = load(path)
    out = tmp_path / "out.json"
    save(doc, out)
    assert json.loads(out.read_text()) == json.loads(path.read_text())


def test_kinds_come_from_data_type_not_shape(fixtures):
    model, doc = load(fixtures / "td" / "v2-boundary-box.json")
    els = {cid: e for d in model.diagrams for cid, e in d.elements.items()}
    misspelled = [cid for cid, c in doc.cells.items() if c["shape"] == "trust-broundary-curve"]
    assert misspelled and all(els[cid].kind is Kind.BOUNDARY_CURVE for cid in misspelled)

    model, _ = load(fixtures / "td" / "v2-threat-model.json")
    kinds = {e.kind for e in model.diagrams[0].elements.values()}
    assert kinds == {Kind.ACTOR, Kind.PROCESS, Kind.STORE, Kind.FLOW, Kind.BOUNDARY_CURVE}


def test_element_fields(fixtures):
    model, _ = load(fixtures / "td" / "v2-threat-model.json")
    els = model.diagrams[0].elements
    browser = els["b394f9f7-07ca-42bc-b616-ad77c6fbfcce"]
    assert browser.kind is Kind.ACTOR and browser.name == "Browser"
    assert browser.rect == Rect(40, 29, 160, 80)
    assert browser.td_props["providesAuthentication"] is False

    flow = els["2d84bfae-f1ed-49e5-8542-10a02f4a1c57"]
    assert flow.source_id == "b394f9f7-07ca-42bc-b616-ad77c6fbfcce"
    assert flow.target_id in els
    assert flow.td_props["isEncrypted"] is True and flow.td_props["protocol"] == "HTTP/S"
    [threat] = flow.threats
    assert threat.status == "Mitigated" and threat.type == "Information disclosure"
    assert threat.raw["id"] == threat.id == "79cbaf10-e5a2-4fd6-9818-7f180a113938"
    assert threat.tdtm_key is None

    curve = els["0adc088b-ebb1-46be-af7b-36112c60c419"]
    assert curve.points == [Point(80, 220), Point(276, 149), Point(295, 51)]


def test_dangling_flows_are_skipped_with_a_warning(fixtures):
    model, doc = load(fixtures / "td" / "v2-boundary-box.json")
    dangling = [w for w in model.warnings if "unconnected" in w]
    assert len(dangling) == 5
    assert "63092af0-" in " ".join(dangling)
    all_ids = {cid for d in model.diagrams for cid in d.elements}
    assert not any(cid.startswith("63092af0") for cid in all_ids)
    assert any(cid.startswith("63092af0") for cid in doc.cells)  # still in the document


def test_text_cells_are_ignored_and_diagram_types_kept(fixtures):
    model, doc = load(fixtures / "td" / "v2-boundary-box.json")
    texts = [cid for cid, c in doc.cells.items() if c["data"]["type"] == "tm.Text"]
    all_ids = {cid for d in model.diagrams for cid in d.elements}
    assert texts and not set(texts) & all_ids
    assert [d.diagram_type for d in model.diagrams][:3] == ["STRIDE", "CIA", "LINDDUN"]


def test_document_cells_are_live_views_into_raw(fixtures, tmp_path):
    model, doc = load(fixtures / "td" / "v2-threat-model.json")
    cid = "b394f9f7-07ca-42bc-b616-ad77c6fbfcce"
    doc.cells[cid]["data"]["tdtm"] = {"key": "x"}
    save(doc, tmp_path / "m.json")
    saved = json.loads((tmp_path / "m.json").read_text())
    cell = next(c for c in saved["detail"]["diagrams"][0]["cells"] if c["id"] == cid)
    assert cell["data"]["tdtm"] == {"key": "x"}


def test_tdtm_key_is_read_from_threats(tmp_path, fixtures):
    raw = json.loads((fixtures / "td" / "v2-threat-model.json").read_text())
    cell = raw["detail"]["diagrams"][0]["cells"][0]
    cell["data"]["threats"][0]["tdtm"] = {"key": "sdl:S1:abc", "fingerprint": "f"}
    (tmp_path / "m.json").write_text(json.dumps(raw))
    model, _ = load(tmp_path / "m.json")
    assert model.diagrams[0].elements[cell["id"]].threats[0].tdtm_key == "sdl:S1:abc"
