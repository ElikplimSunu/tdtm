import json
import shutil

import pytest

from tdtm.merge import merge
from tdtm.resolve import resolve
from tdtm.rules.engine import run_sdl
from tdtm.rules.tb7 import load_template
from tdtm.td_adapter import load, save

TEMPLATE = load_template()


def analyze(path, **kw):
    """One tdtm run on `path`, in place. Returns the merge summary."""
    model, doc = load(path)
    assert resolve(model, TEMPLATE) == []
    summary = merge(doc, run_sdl(model, TEMPLATE), **kw)
    save(doc, path)
    return summary


def cells(path):
    raw = json.loads(path.read_text())
    return raw, {c["id"]: c for d in raw["detail"]["diagrams"] for c in d["cells"]}


@pytest.fixture
def golden(fixtures, tmp_path):
    def copy(name):
        dst = tmp_path / f"{name}.json"
        shutil.copy(fixtures / "golden" / f"{name}.json", dst)
        return dst

    return copy


def test_first_run_writes_threat_dragon_shaped_threats(golden, td_schema_path):
    path = golden("2-actor-process-curve")
    s = analyze(path)
    assert len(s.added) == 24 and not (s.refreshed or s.stale)
    raw, cs = cells(path)
    threats = cs["request"]["data"]["threats"]
    s3 = next(t for t in threats if t["tdtm"]["key"] == "sdl:S3:request")
    assert s3["title"] == "Spoofing the User External Entity"
    assert (s3["type"], s3["status"], s3["severity"], s3["modelType"]) == (
        "Spoofing",
        "Open",
        "TBD",
        "STRIDE",
    )
    assert (s3["new"], s3["score"], s3["mitigation"]) == (False, "", "")
    assert len(s3["id"]) == 36 and s3["tdtm"]["fingerprint"]
    assert sorted(t["number"] for c in cs.values() for t in c["data"].get("threats", [])) == list(
        range(1, 25)
    )
    assert raw["detail"]["threatTop"] == 24

    req = cs["request"]
    assert req["data"]["hasOpenThreats"] is True
    assert (req["attrs"]["line"]["stroke"], req["attrs"]["line"]["strokeWidth"]) == ("red", 2.5)
    assert cs["user"]["attrs"]["body"]["stroke"] == "#333333"  # actors carry no threats

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    assert list(jsonschema.validators.validator_for(schema)(schema).iter_errors(raw)) == []


def test_second_run_changes_nothing(golden):
    path = golden("4-tags")
    analyze(path)
    before = path.read_bytes()
    s = analyze(path)
    assert (s.added, s.refreshed, s.stale) == ([], [], [])
    assert len(s.unchanged) == 26
    assert path.read_bytes() == before


def test_human_edits_survive(golden):
    path = golden("2-actor-process-curve")
    analyze(path)
    raw, cs = cells(path)
    t = cs["request"]["data"]["threats"][0]
    t["mitigation"], t["status"] = "Use mutual TLS.", "Mitigated"
    path.write_text(json.dumps(raw))
    s = analyze(path)
    assert s.kept_edited == [t["tdtm"]["key"]]
    _, cs = cells(path)
    again = cs["request"]["data"]["threats"][0]
    assert (again["mitigation"], again["status"]) == ("Use mutual TLS.", "Mitigated")


def test_rules_that_stop_firing_go_stale_then_prune(golden):
    path = golden("4-tags")
    analyze(path)
    raw, cs = cells(path)
    cs["users"]["data"]["description"] = ""  # no longer a SQL database storing credentials
    lookup = cs["lookup"]["data"]["threats"]
    i24 = next(t for t in lookup if t["tdtm"]["key"] == "sdl:I24:lookup")
    i24["mitigation"] = "Hash with Argon2."  # a human edit: never stale-marked or pruned
    path.write_text(json.dumps(raw))

    s = analyze(path)
    assert s.stale == ["sdl:T7:lookup"] and s.kept_edited == ["sdl:I24:lookup"]
    _, cs = cells(path)
    titles = [t["title"] for t in cs["lookup"]["data"]["threats"]]
    assert "[stale] Potential SQL Injection Vulnerability for Users DB" in titles
    assert "Weak Credential Storage" in titles

    assert analyze(path).stale == []  # already marked: nothing new
    s = analyze(path, prune=True)
    assert s.pruned == ["sdl:T7:lookup"]
    _, cs = cells(path)
    keys = [t["tdtm"]["key"] for t in cs["lookup"]["data"]["threats"]]
    assert "sdl:T7:lookup" not in keys and "sdl:I24:lookup" in keys


def test_stale_threat_that_fires_again_is_restored(golden):
    path = golden("4-tags")
    analyze(path)
    raw, cs = cells(path)
    desc = cs["users"]["data"]["description"]
    cs["users"]["data"]["description"] = ""
    path.write_text(json.dumps(raw))
    analyze(path)
    raw, cs = cells(path)
    cs["users"]["data"]["description"] = desc
    path.write_text(json.dumps(raw))
    s = analyze(path)
    assert "sdl:T7:lookup" in s.refreshed
    _, cs = cells(path)
    assert not any(t["title"].startswith("[stale]") for t in cs["lookup"]["data"]["threats"])


def test_has_open_threats_follows_status(golden):
    path = golden("4-tags")
    analyze(path)
    raw, cs = cells(path)
    for t in cs["lookup"]["data"]["threats"]:
        t["status"] = "NotApplicable"
    cs["auditwrite"]["data"]["threats"][0]["status"] = "Mitigated"  # others still Open
    path.write_text(json.dumps(raw))
    analyze(path)
    _, cs = cells(path)
    assert cs["lookup"]["data"]["hasOpenThreats"] is False
    assert cs["lookup"]["attrs"]["line"] == {**cs["lookup"]["attrs"]["line"], "stroke": "#333333"}
    assert cs["lookup"]["attrs"]["line"]["strokeWidth"] == 1.5
    assert cs["auditwrite"]["data"]["hasOpenThreats"] is True
    assert cs["auditwrite"]["attrs"]["line"]["stroke"] == "red"


def test_threats_without_a_tdtm_key_are_never_touched(fixtures, tmp_path):
    path = tmp_path / "demo.json"
    shutil.copy(fixtures / "td" / "v2-threat-model.json", path)
    _, before = cells(path)
    human = {cid: c["data"].get("threats", []) for cid, c in before.items()}
    analyze(path)
    raw, after = cells(path)
    for cid, threats in human.items():
        assert after[cid]["data"].get("threats", [])[: len(threats)] == threats
    numbers = [
        t["number"] for c in after.values() for t in c["data"].get("threats", []) if "tdtm" in t
    ]
    assert min(numbers) == 51  # threatTop was 50
    assert raw["detail"]["threatTop"] == max(numbers)


def test_stripped_keys_do_not_duplicate(golden):
    path = golden("2-actor-process-curve")
    analyze(path)
    raw, cs = cells(path)
    for c in cs.values():
        for t in c["data"].get("threats", []):
            del t["tdtm"]  # as if Threat Dragon dropped our key
    path.write_text(json.dumps(raw))
    s = analyze(path)
    assert s.added == [] and len(s.kept_edited) == 24
    _, cs = cells(path)
    assert len(cs["request"]["data"]["threats"]) == 11


def test_sidecar_mode(golden):
    path = golden("2-actor-process-curve")
    sidecar = {}
    s = analyze(path, sidecar=sidecar)
    assert len(s.added) == 24 and len(sidecar) == 24
    _, cs = cells(path)
    assert not any("tdtm" in t for c in cs.values() for t in c["data"].get("threats", []))
    s = analyze(path, sidecar=sidecar)
    assert len(s.unchanged) == 24 and s.added == []


def test_merge_is_deterministic(golden, tmp_path):
    a, b = golden("1-webapp-db-box"), tmp_path / "copy.json"
    shutil.copy(a, b)
    analyze(a)
    analyze(b)
    assert a.read_bytes() == b.read_bytes()
