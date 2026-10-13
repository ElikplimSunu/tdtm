import json
import shutil
import sys

import pytest

from threatsketch.cli import main
from threatsketch.resolve import resolve
from threatsketch.rules.pytm_pack import PytmMissing, run_pytm
from threatsketch.rules.tb7 import load_template
from threatsketch.td_adapter import load


def resolved(path):
    model, _ = load(path)
    assert resolve(model, load_template()) == []
    return model


def test_findings_map_back_to_cells(fixtures):
    pytest.importorskip("pytm")
    model = resolved(fixtures / "golden" / "1-webapp-db-box.json")
    gen = run_pytm(model)
    assert {g.cell_id for g in gen} == {"webapp", "db", "query", "results"}
    assert all(g.pack == "pytm" and g.category in "STRIDE" for g in gen)
    assert {g.severity for g in gen} <= {"Low", "Medium", "High", "Critical"}
    assert len({g.key for g in gen}) == len(gen)
    assert run_pytm(model) == gen  # pytm's class-level state is reset between runs


def test_bidirectional_and_out_of_scope(fixtures, tmp_path):
    pytest.importorskip("pytm")
    raw = json.loads((fixtures / "golden" / "2-actor-process-curve.json").read_text())
    cells = {c["id"]: c for c in raw["detail"]["diagrams"][0]["cells"]}
    cells["request"]["data"]["isBidirectional"] = True
    cells["app"]["data"]["outOfScope"] = True
    (tmp_path / "m.json").write_text(json.dumps(raw))
    gen = run_pytm(resolved(tmp_path / "m.json"))
    assert {g.direction for g in gen if g.cell_id == "request"} == {"fwd", "rev"}
    assert not any(g.cell_id == "app" for g in gen)


def test_missing_pytm_is_a_clear_error(fixtures, monkeypatch, tmp_path, capsys):
    monkeypatch.setitem(sys.modules, "pytm", None)  # import pytm now raises ImportError
    model = resolved(fixtures / "golden" / "1-webapp-db-box.json")
    with pytest.raises(PytmMissing):
        run_pytm(model)
    shutil.copy(fixtures / "golden" / "1-webapp-db-box.json", tmp_path / "m.json")
    assert main(["analyze", str(tmp_path / "m.json"), "--pack", "pytm"]) == 2
    assert "uv sync --extra pytm" in capsys.readouterr().err


def test_packs_do_not_stale_each_other(fixtures, tmp_path, capsys):
    pytest.importorskip("pytm")
    path = tmp_path / "m.json"
    shutil.copy(fixtures / "golden" / "1-webapp-db-box.json", path)
    assert main(["analyze", str(path), "--pack", "all"]) == 0
    assert main(["analyze", str(path), "--pack", "sdl"]) == 0
    assert "0 newly stale" in capsys.readouterr().out.splitlines()[-2]
    raw = json.loads(path.read_text())
    keys = [t["tdtm"]["key"] for c in raw["detail"]["diagrams"][0]["cells"]
            for t in c["data"].get("threats", [])]  # fmt: skip
    assert any(k.startswith("pytm:") for k in keys) and any(k.startswith("sdl:") for k in keys)
