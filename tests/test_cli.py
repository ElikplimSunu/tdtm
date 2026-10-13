import pytest

from tdtm import __version__
from tdtm.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_unimplemented_commands_say_where_to_look(capsys):
    assert main(["report", "x.json"]) == 1
    assert "PLAN.md" in capsys.readouterr().err


def test_inspect_demo_model(capsys, fixtures):
    assert main(["inspect", str(fixtures / "td" / "v2-threat-model.json")]) == 0
    out = capsys.readouterr().out
    assert "Main Request Data Flow" in out
    assert "flow 'Web Request': Browser -> Web Application" in out
    assert "SE.DF.TMCore.HTTPS (HTTPS)" in out
    assert "providesConfidentiality = Yes  [static]" in out
    assert "storesCredentials = Yes  [TD]" in out
    assert "codeType = Not Selected  [default]" in out
    assert "crosses: boundary curve 0adc088b" in out
    assert "zone: outer" in out


def test_inspect_reports_tag_errors_and_skipped_diagrams(capsys, fixtures, tmp_path):
    import json

    raw = json.loads((fixtures / "td" / "v2-boundary-box.json").read_text())
    raw["detail"]["diagrams"][0]["cells"][0]["data"]["description"] = "@tmt: Nonsense"
    (tmp_path / "m.json").write_text(json.dumps(raw))
    assert main(["inspect", str(tmp_path / "m.json")]) == 0
    captured = capsys.readouterr()
    assert "not analysed (CIA diagram)" in captured.out
    assert "unknown stencil 'Nonsense'" in captured.err
    assert "unconnected" in captured.err


def test_missing_model_is_exit_code_2(capsys, tmp_path):
    assert main(["inspect", str(tmp_path / "nope.json")]) == 2
    assert "nope.json" in capsys.readouterr().err
