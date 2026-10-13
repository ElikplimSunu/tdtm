"""`threatsketch open`: one command from a model (or .tm7) to Threat Dragon, threats, reports."""

import json
import shutil
from pathlib import Path

import pytest

import threatsketch.cli as cli
import threatsketch.launcher as launcher
from threatsketch.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def stop_watching(monkeypatch):
    def stop(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)


def test_open_creates_a_blank_model(tmp_path, monkeypatch, capsys, td_schema_path):
    stop_watching(monkeypatch)
    path = tmp_path / "shop.json"
    assert main(["open", str(path), "--no-launch"]) == 0
    raw = json.loads(path.read_text())
    assert raw["summary"]["title"] == "shop"
    assert raw["detail"]["diagrams"][0]["diagramType"] == "STRIDE"
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    assert list(jsonschema.validators.validator_for(schema)(schema).iter_errors(raw)) == []
    assert "created" in capsys.readouterr().out


def test_open_analyzes_and_writes_reports(tmp_path, monkeypatch, capsys):
    stop_watching(monkeypatch)
    path = tmp_path / "m.json"
    shutil.copy(FIXTURES / "golden" / "2-actor-process-curve.json", path)
    assert main(["open", str(path), "--no-launch"]) == 0
    out = capsys.readouterr().out
    assert "24 added" in out
    assert "Spoofing the User External Entity" in (tmp_path / "m.report.html").read_text()
    assert (tmp_path / "m.csv").read_text().startswith("Id,Title,Category")


def test_open_imports_a_tm7_first(tmp_path, monkeypatch, capsys):
    stop_watching(monkeypatch)
    tm7 = tmp_path / "shop.tm7"
    shutil.copy(FIXTURES / "tm7" / "small.tm7", tm7)
    assert main(["open", str(tm7), "--no-launch"]) == 0
    assert (tmp_path / "shop.json").exists() and (tmp_path / "shop.csv").exists()
    assert "13 added" in capsys.readouterr().out
    # a second open reuses the .json (which may hold triage) instead of re-importing
    assert main(["open", str(tm7), "--no-launch"]) == 0
    assert "using existing" in capsys.readouterr().out


class FakeThreatDragon:
    """Stands in for the app: `open -a` appends to its log the way Threat Dragon 2.6.2 does."""

    def __init__(self, log: Path, running: bool):
        self.log, self.running, self.calls = log, running, []
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("[info] Electron log level is set to: debug\n")

    def run(self, cmd, **_kw):
        self.calls.append(cmd)
        with self.log.open("a") as f:
            if cmd[-1] == launcher.APP:  # launch without a file
                self.running = True
                f.write("[info]  Checking for update\n")  # main window exists from here on
            else:
                assert self.running, "a file sent to a Threat Dragon that is not running crashes it"
                f.write(f"[debug] {launcher.CONFIRMED}{cmd[-1]}\n")

        class Done:
            returncode = 0

        return Done()


@pytest.mark.parametrize("running", [False, True])
def test_launch_never_sends_a_file_before_the_window_exists(tmp_path, monkeypatch, running):
    fake = FakeThreatDragon(tmp_path / "Logs" / "main.log", running)
    monkeypatch.setattr(launcher, "LOG", fake.log)
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher.subprocess, "run", fake.run)
    monkeypatch.setattr(launcher, "installed", lambda: True)
    monkeypatch.setattr(launcher, "is_running", lambda: fake.running)
    sleeps = []
    monkeypatch.setattr(launcher.time, "sleep", sleeps.append)
    model = tmp_path / "m.json"
    assert launcher.open_in_threat_dragon(model) is True
    sent = [c for c in fake.calls if c[-1] == str(model)]
    assert len(sent) == 1
    assert (fake.calls[0][-1] == launcher.APP) is (not running)  # cold: launch empty first
    assert (launcher.LOAD_MARGIN in sleeps) is (not running)  # and let the page load


def test_launch_explains_when_threat_dragon_is_missing(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    monkeypatch.setattr(launcher, "installed", lambda: False)
    assert launcher.open_in_threat_dragon(tmp_path / "m.json") is False
    assert "brew install --cask threat-dragon" in capsys.readouterr().out
