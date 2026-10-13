"""PLAN 4.2 (.tm7 import) and 3.4 (parity with real TMT output)."""

import csv
import json
import shutil
from pathlib import Path

import pytest

from tdtm.cli import main
from tdtm.tm7 import Tm7Error, import_tm7

FIXTURES = Path(__file__).parent / "fixtures"
SMALL = FIXTURES / "tm7" / "small.tm7"
PRIVATE = FIXTURES / "private"  # gitignored: real coursework models, never committed
ID = "00000000-0000-4000-8000-0000000000"  # + two digits, see the fixture generator


def cells_of(raw):
    return {c["id"]: c for d in raw["detail"]["diagrams"] for c in d["cells"]}


def test_import_builds_a_valid_threat_dragon_model(td_schema_path):
    raw, warnings = import_tm7(SMALL)
    assert warnings == []
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    assert list(jsonschema.validators.validator_for(schema)(schema).iter_errors(raw)) == []

    assert raw["summary"]["title"] == "Small shop" and raw["summary"]["owner"] == "Ama Mensah"
    assert raw["detail"]["reviewer"] == "Kofi Boateng"
    assert [c["name"] for c in raw["detail"]["contributors"]] == ["Ama Mensah", "Kofi Boateng"]
    [diagram] = raw["detail"]["diagrams"]
    assert (diagram["title"], diagram["diagramType"]) == ("Checkout flow", "STRIDE")

    c = cells_of(raw)
    customer, app, db, feed, zone = (c[ID + n] for n in ("10", "11", "12", "13", "14"))
    checkout, save = c[ID + "15"], c[ID + "16"]
    assert [x["data"]["type"] for x in (customer, app, db, zone, checkout)] == [
        "tm.Actor",
        "tm.Process",
        "tm.Store",
        "tm.BoundaryBox",
        "tm.Flow",
    ]
    assert app["data"]["name"] == "Shop Web App"
    assert app["position"] == {"x": 300, "y": 100} and app["size"] == {"width": 100, "height": 100}
    assert app["data"]["description"] == "@tmt: SE.P.TMCore.WebApp; hasInputSanitizers=Yes"
    assert db["data"]["description"] == "@tmt: storesCredentials=Yes"
    assert customer["data"]["description"] == ""
    assert save["data"]["description"] == "@tmt: SE.DF.TMCore.HTTPS"
    assert (feed["data"]["outOfScope"], feed["data"]["reasonOutOfScope"]) == (
        True,
        "Retired next year",
    )
    assert checkout["source"] == {"cell": ID + "10"} and checkout["target"] == {"cell": ID + "11"}
    assert checkout["vertices"] == [{"x": 220, "y": 140}]


def test_import_brings_tmt_threats_as_tracked_threats():
    raw, _ = import_tm7(SMALL)
    checkout = cells_of(raw)[ID + "15"]
    s3, t1 = checkout["data"]["threats"]
    assert s3["tdtm"]["key"] == f"sdl:S3:{ID}15"
    assert (s3["title"], s3["type"], s3["status"], s3["severity"], s3["number"]) == (
        "Spoofing the Customer External Entity",
        "Spoofing",
        "Open",
        "High",
        1,
    )
    assert (t1["status"], t1["mitigation"], t1["type"]) == (
        "Mitigated",
        "Input is validated on the server.",
        "Tampering",
    )
    assert raw["detail"]["threatTop"] == 2
    assert checkout["data"]["hasOpenThreats"] is True
    assert checkout["attrs"]["line"]["stroke"] == "red"


def test_analyze_after_import_keeps_tmt_work(tmp_path, capsys):
    out = tmp_path / "small.json"
    assert main(["import", str(SMALL), "--out", str(out)]) == 0
    assert main(["analyze", str(out)]) == 0
    summary = capsys.readouterr().out
    # S3 is untouched TMT output: tdtm generates the same threat. T1 was triaged in TMT: kept.
    # Checkout fires 12 rules (11 for actor -> process across a box, plus T13.1 for a web app
    # with input but not output sanitizing); Save order fires S7.1, I24 and D2.
    assert "13 added, 0 refreshed, 1 unchanged, 1 kept as you edited them" in summary
    t1 = next(t for t in cells_of(json.loads(out.read_text()))[ID + "15"]["data"]["threats"]
              if t["tdtm"]["key"].startswith("sdl:T1:"))  # fmt: skip
    assert t1["mitigation"] == "Input is validated on the server."


def test_import_command_will_not_overwrite(tmp_path, capsys):
    out = tmp_path / "m.json"
    out.write_text("{}")
    assert main(["import", str(SMALL), "--out", str(out)]) == 2
    assert "exists" in capsys.readouterr().err and out.read_text() == "{}"
    assert main(["import", str(SMALL), "--out", str(out), "--force"]) == 0
    shutil.copy(SMALL, tmp_path / "shop.tm7")
    assert main(["import", str(tmp_path / "shop.tm7")]) == 0  # default: same name, .json
    assert (tmp_path / "shop.json").exists()


def test_import_rejects_doctype(tmp_path):
    bad = tmp_path / "bad.tm7"
    bad.write_text('<!DOCTYPE x [<!ENTITY a "aaaa">]><ThreatModel>&a;</ThreatModel>')
    with pytest.raises(Tm7Error, match="DOCTYPE"):
        import_tm7(bad)


@pytest.mark.skipif(
    not (PRIVATE / "mobile-banking.tm7").exists(), reason="private TMT model absent"
)
def test_parity_with_real_tmt_output(tmp_path, capsys):
    """PLAN 3.4. A real model drawn in TMT 7.3 with the SDL template: 7 elements, a boundary box,
    12 flows, 54 generated threats, all untouched. tdtm must generate exactly the same threats."""
    path = tmp_path / "mb.json"
    assert main(["import", str(PRIVATE / "mobile-banking.tm7"), "--out", str(path)]) == 0
    assert main(["analyze", str(path)]) == 0
    assert "0 added, 0 refreshed, 54 unchanged, 0 kept" in capsys.readouterr().out

    raw = json.loads(path.read_text())
    flows = {c["id"]: c for c in cells_of(raw).values() if c["data"]["type"] == "tm.Flow"}
    ours = sorted(
        (flows[cid]["data"]["name"], t["title"], t["type"].lower(), t["severity"])
        for cid in flows
        for t in flows[cid]["data"]["threats"]
    )
    with open(PRIVATE / "mobile-banking.csv", newline="") as f:
        theirs = sorted(
            (r["Interaction"], r["Title"], r["Category"].lower(), r["Priority"])
            for r in csv.DictReader(f)
        )
    assert ours == theirs


def test_parity_fixture_stays_out_of_git():
    import subprocess

    shutil.which("git") or pytest.skip("git not available")
    probe = PRIVATE / "mobile-banking.tm7"
    r = subprocess.run(["git", "check-ignore", "-q", str(probe)], cwd=FIXTURES, check=False)
    assert r.returncode == 0, "tests/fixtures/private/ must stay gitignored"


TMT_CSV_HEADER = (
    "Id,Title,Category,Diagram,Interaction,Priority,State,Changed By,Description,"
    "Justification,Last Modified"
)


def test_report_csv_in_tmt_format(tmp_path):
    model, out = tmp_path / "small.json", tmp_path / "threats.csv"
    assert main(["import", str(SMALL), "--out", str(model)]) == 0
    assert main(["report", str(model), "--out", str(out)]) == 0
    data = out.read_bytes()
    assert data.startswith(TMT_CSV_HEADER.encode() + b"\r\n") and data.endswith(b"\r\n")
    rows = {r["Id"]: r for r in csv.DictReader(out.open(newline=""))}
    assert rows["1"] == {
        "Id": "1",
        "Title": "Spoofing the Customer External Entity",
        "Category": "Spoofing",
        "Diagram": "Checkout flow",
        "Interaction": "Checkout",
        "Priority": "High",
        "State": "Not Started",
        "Changed By": "",
        "Description": rows["1"]["Description"],
        "Justification": "",
        "Last Modified": "Generated",
    }
    assert (rows["2"]["State"], rows["2"]["Justification"], rows["2"]["Last Modified"]) == (
        "Mitigated",
        "Input is validated on the server.",
        "",
    )


@pytest.mark.skipif(
    not (PRIVATE / "mobile-banking.tm7").exists(), reason="private TMT model absent"
)
def test_csv_parity_with_tmt_export(tmp_path):
    """TMT's own CSV export of the real model, reproduced from Threat Dragon JSON: every row, every
    column (Id, Title, Category, Diagram, Interaction, Priority, State, ... Last Modified)."""
    model, out = tmp_path / "mb.json", tmp_path / "mb.csv"
    assert main(["import", str(PRIVATE / "mobile-banking.tm7"), "--out", str(model)]) == 0
    assert main(["report", str(model), "--out", str(out)]) == 0
    with out.open(newline="") as ours, (PRIVATE / "mobile-banking.csv").open(newline="") as theirs:
        assert sorted(csv.reader(ours)) == sorted(csv.reader(theirs))
