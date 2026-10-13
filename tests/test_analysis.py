"""The analysis view: TMT's Analysis View as a local page (read-only)."""

import http.client
import json
import shutil
from pathlib import Path

import pytest

from tdtm.analysis import serve, snapshot
from tdtm.cli import main
from tdtm.rules.tb7 import load_template

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def analyzed(tmp_path):
    path = tmp_path / "shop.json"
    shutil.copy(Path(__file__).parent.parent / "examples" / "online-shop.json", path)
    assert main(["analyze", str(path)]) == 0
    return path


def test_snapshot_lists_threats_like_tmt(analyzed):
    snap = snapshot(analyzed, load_template())
    assert snap["title"] == "Online shop" and len(snap["threats"]) == 38
    assert snap["diagrams"][0]["svg"].startswith("<svg")
    t = next(t for t in snap["threats"] if t["title"] == "Spoofing the Customer External Entity")
    assert t == {
        "key": t["key"],
        "id": 1,
        "diagram": "Online shop",
        "interaction": "Place order",
        "source": "Customer",
        "target": "Shop Web App",
        "state": "Not Started",
        "title": "Spoofing the Customer External Entity",
        "category": "Spoofing",
        "description": t["description"],
        "justification": "",
        "priority": "High",
        "generatedBy": "SDL rule S3",
    }
    assert snap["stamp"]


def get(port, path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("GET", path, skip_host=True)
    conn.putheader("Host", host or f"127.0.0.1:{port}")
    conn.endheaders()
    r = conn.getresponse()
    return r.status, r.getheader("Content-Type", ""), r.read()


def test_server_serves_page_and_data_to_this_machine_only(analyzed):
    server, url = serve(analyzed, load_template(), port=0)
    try:
        port = server.server_address[1]
        assert url == f"http://127.0.0.1:{port}/"
        status, ctype, body = get(port, "/")
        assert status == 200 and ctype.startswith("text/html")
        assert b"Threat List" in body and b"Threat Properties" in body
        status, ctype, body = get(port, "/api/model")
        assert status == 200 and ctype.startswith("application/json")
        assert len(json.loads(body)["threats"]) == 38
        assert get(port, "/", host="evil.example:80")[0] == 403  # DNS rebinding
        assert get(port, "/nope")[0] == 404
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/model", body=b"{}")
        assert conn.getresponse().status == 405  # read-only for now
    finally:
        server.shutdown()


def test_snapshot_follows_file_changes(analyzed):
    t = load_template()
    first = snapshot(analyzed, t)
    raw = json.loads(analyzed.read_text())
    flow = next(c for c in raw["detail"]["diagrams"][0]["cells"] if c["id"] == "placeorder")
    flow["data"]["threats"][0]["status"] = "Mitigated"
    flow["data"]["threats"][0]["mitigation"] = "MFA for customers"
    analyzed.write_text(json.dumps(raw))
    second = snapshot(analyzed, t)
    assert second["stamp"] != first["stamp"]
    t1 = next(x for x in second["threats"] if x["id"] == 1)
    assert (t1["state"], t1["justification"]) == ("Mitigated", "MFA for customers")


def test_view_command(analyzed, monkeypatch, capsys):
    import tdtm.cli as cli

    opened = []
    monkeypatch.setattr(cli.webbrowser, "open", opened.append)

    def stop(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)
    assert main(["view", str(analyzed)]) == 0
    out = capsys.readouterr().out
    assert "analysis view: http://127.0.0.1:" in out
    assert opened and opened[0].startswith("http://127.0.0.1:")


def test_open_starts_the_analysis_view(analyzed, monkeypatch, capsys):
    import tdtm.cli as cli

    monkeypatch.setattr(cli.webbrowser, "open", lambda _url: None)

    def stop(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)
    assert main(["open", str(analyzed), "--no-launch"]) == 0
    assert "analysis view: http://127.0.0.1:" in capsys.readouterr().out
    assert main(["open", str(analyzed), "--no-launch", "--no-view"]) == 0
    assert "analysis view" not in capsys.readouterr().out
