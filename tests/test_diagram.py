from pathlib import Path

from threatsketch.diagram import render_svg
from threatsketch.td_adapter import load

FIXTURES = Path(__file__).parent / "fixtures"


def test_svg_draws_every_element():
    model, _ = load(Path(__file__).parent.parent / "examples" / "online-shop.json")
    svg = render_svg(model.diagrams[0])
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    for name in ("Customer", "Shop Web App", "Orders DB", "Payment Provider", "Shop backend"):
        assert f">{name}<" in svg
    assert svg.count('marker-end="url(#') == 7  # one arrow per flow
    assert "<ellipse" in svg  # processes are circles, like TMT and Threat Dragon


def test_svg_escapes_names_and_draws_in_tmt_style(tmp_path):
    import json
    import shutil

    path = tmp_path / "m.json"
    shutil.copy(FIXTURES / "golden" / "2-actor-process-curve.json", path)
    raw = json.loads(path.read_text())
    for c in raw["detail"]["diagrams"][0]["cells"]:
        if c["id"] == "user":
            c["data"]["name"] = "<b>User</b>"
        if c["id"] == "request":
            c["data"]["threats"] = [
                {
                    "title": "t",
                    "status": "Open",
                    "severity": "High",
                    "type": "Spoofing",
                    "description": "",
                    "mitigation": "",
                }
            ]
    path.write_text(json.dumps(raw))
    model, _ = load(path)
    svg = render_svg(model.diagrams[0])
    assert "<b>User" not in svg and "&lt;b&gt;User&lt;/b&gt;" in svg
    assert "open" not in svg  # red is for trust boundaries only, as on the canvas
    assert 'class="boundary"' in svg and "#c0392f" in svg
    assert "<polyline" in svg  # the boundary curve


def test_svg_of_an_empty_diagram_is_valid():
    from threatsketch.model import Diagram

    assert render_svg(Diagram(0, "empty")).startswith("<svg")
