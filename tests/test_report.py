import json
import shutil

from tdtm.cli import main
from tdtm.report import render
from tdtm.td_adapter import load


def analyzed(fixtures, tmp_path, name="2-actor-process-curve"):
    path = tmp_path / "m.json"
    shutil.copy(fixtures / "golden" / f"{name}.json", path)
    assert main(["analyze", str(path)]) == 0
    return path


def test_report_shape(fixtures, tmp_path):
    model, _ = load(analyzed(fixtures, tmp_path))
    html = render(model)
    assert html.startswith("<!doctype html>")
    assert "<h1>Threat Modeling Report</h1>" in html
    assert "Threat Model Name:</b> Golden 2: actors and a process across a curve" in html
    assert "Threat Model Summary:" in html and "Diagram Summary:" in html
    assert "<td>Not Started</td><td>24</td>" in html and "<td>Total</td><td>24</td>" in html
    assert "<svg" in html  # the diagram, drawn from the model
    assert "Interaction: Request" in html and "User → App" in html
    assert "Spoofing the User External Entity [State: Not Started] [Priority: High]" in html
    assert "Category:</b> Spoofing" in html
    assert "Justification:</b> &lt;no mitigation provided&gt;" in html
    assert "SDL rule S3" in html


def test_report_escapes_model_text(fixtures, tmp_path):
    path = analyzed(fixtures, tmp_path)
    raw = json.loads(path.read_text())
    cell = next(c for c in raw["detail"]["diagrams"][0]["cells"] if c["id"] == "request")
    cell["data"]["threats"][0]["description"] = "<script>alert(1)</script>"
    path.write_text(json.dumps(raw))
    html = render(load(path)[0])
    assert "<script>alert" not in html and "&lt;script&gt;" in html


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
