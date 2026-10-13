import pytest

from threatsketch import __version__
from threatsketch.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert __version__ in capsys.readouterr().out


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


def tdtm_threats(path):
    import json

    raw = json.loads(path.read_text())
    cells = [c for d in raw["detail"]["diagrams"] for c in d["cells"]]
    return [t for c in cells for t in c["data"].get("threats", []) if "tdtm" in t]


@pytest.fixture
def model_copy(fixtures, tmp_path):
    import shutil

    path = tmp_path / "model.json"
    shutil.copy(fixtures / "golden" / "2-actor-process-curve.json", path)
    return path


def test_analyze_writes_threats_and_a_backup(model_copy, capsys):
    original = model_copy.read_bytes()
    assert main(["analyze", str(model_copy)]) == 0
    out = capsys.readouterr().out
    assert "24 added" in out
    assert model_copy.with_name("model.json.bak").read_bytes() == original
    assert len(tdtm_threats(model_copy)) == 24

    after = model_copy.read_bytes()
    assert main(["analyze", str(model_copy)]) == 0
    out = capsys.readouterr().out
    assert "0 added" in out and "24 unchanged" in out
    assert "no changes" in out and "wrote" not in out
    assert model_copy.read_bytes() == after
    assert model_copy.with_name("model.json.bak").read_bytes() == original  # backup kept


def test_analyze_dry_run_changes_nothing(model_copy, capsys):
    original = model_copy.read_bytes()
    assert main(["analyze", str(model_copy), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "+ flow 'Request' (User -> App): Spoofing the User External Entity" in out
    assert "dry run" in out
    assert model_copy.read_bytes() == original
    assert not model_copy.with_name("model.json.bak").exists()


def test_analyze_out_leaves_the_model_alone(model_copy, tmp_path):
    original = model_copy.read_bytes()
    assert main(["analyze", str(model_copy), "--out", str(tmp_path / "new.json")]) == 0
    assert model_copy.read_bytes() == original
    assert len(tdtm_threats(tmp_path / "new.json")) == 24
    assert not model_copy.with_name("model.json.bak").exists()


def test_analyze_strict_stops_on_tag_errors(model_copy, capsys):
    import json

    raw = json.loads(model_copy.read_text())
    raw["detail"]["diagrams"][0]["cells"][1]["data"]["description"] = "@tmt: Nonsense"
    model_copy.write_text(json.dumps(raw))
    original = model_copy.read_bytes()
    assert main(["analyze", str(model_copy), "--strict"]) == 3
    assert "Nonsense" in capsys.readouterr().err
    assert model_copy.read_bytes() == original
    assert main(["analyze", str(model_copy)]) == 0  # without --strict: warn and carry on


def test_analyze_sidecar(model_copy):
    assert main(["analyze", str(model_copy), "--sidecar"]) == 0
    assert tdtm_threats(model_copy) == []
    assert model_copy.with_name("model.tdtm.json").exists()
    before = model_copy.read_bytes()
    assert main(["analyze", str(model_copy), "--sidecar"]) == 0
    assert model_copy.read_bytes() == before


def test_stencils_lists_tags_for_a_kind(capsys):
    assert main(["stencils", "--kind", "process"]) == 0
    out = capsys.readouterr().out
    assert "Web Application" in out and "SE.P.TMCore.WebApp" in out
    assert "fixes codeType=Unmanaged" in out
    assert "hasInputSanitizers (Sanitizes Input): Not Selected*, Yes, No" in out
    assert "SQL Database" not in out
    assert main(["stencils", "--kind", "store"]) == 0
    out = capsys.readouterr().out
    assert "HTTPOnly (HTTPOnly): No*, Yes" in out and "only with Cookies" in out


def test_stencils_lists_every_kind_by_default(capsys):
    assert main(["stencils"]) == 0
    out = capsys.readouterr().out
    for word in ("actor", "process", "store", "flow", "boundary box", "boundary curve"):
        assert f"== {word}" in out


def test_coverage(capsys):
    assert main(["coverage"]) == 0
    out = capsys.readouterr().out
    td_alone, _, rest = out.partition("Need @tmt tags")
    assert "S3 " in td_alone and "T2 " in td_alone  # T2 via isWebApplication (codeType fixed)
    assert "T7 " in rest and "SQL Database" in rest
    assert "E3 " in rest and "Authorization Provider" in rest
    assert "I25 " in rest and "Machine Trust Boundary" in rest
    assert "T6 " in rest and "tag attributes so that" in rest  # authenticated, unencrypted flow
    assert "SU " not in td_alone and "Legacy" in out


def test_watch_reruns_on_change_but_not_on_its_own_write(tmp_path):
    from threatsketch.cli import watch

    path = tmp_path / "m.json"
    path.write_text("{}")
    runs = []

    def run():  # like analyze: rewrites the file it watches
        runs.append(path.read_text())
        path.write_text(path.read_text() + " ")

    def sleep(_):
        if len(sleeps) == 2:  # the user saves in Threat Dragon
            path.write_text('{"edited": 1}')
        sleeps.append(1)

    sleeps = []
    watch(path, run, interval=0, sleep=sleep, ticks=5)
    assert runs == ["{}", '{"edited": 1}']


def test_watch_flag_runs_analyze_until_interrupted(model_copy, monkeypatch, capsys):
    import threatsketch.cli as cli

    def stop(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)
    assert main(["analyze", str(model_copy), "--watch"]) == 0
    out = capsys.readouterr().out
    assert "24 added" in out and "watching" in out
