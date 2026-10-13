import json
import shutil

from threatsketch.cli import main
from threatsketch.report import render
from threatsketch.td_adapter import load


def analyzed(fixtures, tmp_path, name="2-actor-process-curve"):
    path = tmp_path / "m.json"
    shutil.copy(fixtures / "golden" / f"{name}.json", path)
    assert main(["analyze", str(path)]) == 0
    return path


def test_report_shape(fixtures, tmp_path):
    model, _ = load(analyzed(fixtures, tmp_path))
    html = render(model)
    assert html.startswith("<!doctype html>")
    assert "Threat Modeling Report" in html  # TMT's report title, above the model's name
    assert "<h1>Golden 2: actors and a process across a curve</h1>" in html
    assert "<h2>Threat Model Summary</h2>" in html
    assert "<b>24</b><span>Total</span>" in html and "<b>24</b><span>Not Started</span>" in html
    assert "<span>Mitigation Implemented</span>" in html  # TMT's summary wording
    assert "<svg" in html  # the diagram, drawn from the model
    assert "Interaction: Request" in html and "User → App" in html
    assert "<h4>Spoofing the User External Entity</h4>" in html
    assert 'class="state not-started"' in html and "Priority <b>High</b>" in html
    assert "Category <b>Spoofing</b>" in html
    assert "&lt;no mitigation provided&gt;" in html
    assert "SDL rule S3" in html


def test_report_is_one_self_contained_printable_file(fixtures, tmp_path):
    html = render(load(analyzed(fixtures, tmp_path))[0])
    assert html.count("@font-face") == 3 and "data:font/woff2;base64," in html
    assert "src:url(http" not in html and "<link" not in html  # nothing fetched
    assert "@page" in html and "Save as PDF" in html and "#print" in html


def test_report_names_crossed_boundaries():
    import json
    from pathlib import Path

    from threatsketch import api

    raw = api.analyze(
        json.loads((Path(__file__).parent.parent / "examples/online-shop.json").read_text())
    )
    html = api.report_html(raw["model"])
    assert 'Customer → Shop Web App · crosses <span class="crosses">Shop backend</span>' in html


def test_report_escapes_model_text(fixtures, tmp_path):
    path = analyzed(fixtures, tmp_path)
    raw = json.loads(path.read_text())
    cell = next(c for c in raw["detail"]["diagrams"][0]["cells"] if c["id"] == "request")
    cell["data"]["threats"][0]["description"] = "<script>alert(1)</script>"
    path.write_text(json.dumps(raw))
    html = render(load(path)[0])
    assert "<script>alert" not in html and "&lt;script&gt;" in html
    raw["summary"]["title"] = 'Shop "x" </style><script>alert(1)</script>'
    path.write_text(json.dumps(raw))
    html = render(load(path)[0])
    assert "<script>alert" not in html  # nor via the printed page footer


def test_report_includes_human_threats_on_elements(fixtures, tmp_path):
    model, _ = load(fixtures / "td" / "v2-threat-model.json")
    html = render(model)
    assert "Accessing DB credentials" in html  # a human threat on the Worker Config store
    assert "Worker Config" in html


def test_report_command(fixtures, tmp_path, capsys):
    path = analyzed(fixtures, tmp_path)
    out = tmp_path / "r.html"
    assert main(["report", str(path), "--out", str(out)]) == 0
    assert "Spoofing the User External Entity" in out.read_text()
    assert str(out) in capsys.readouterr().out
