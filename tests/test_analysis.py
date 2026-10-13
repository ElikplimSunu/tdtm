"""The analysis view: TMT's Analysis View as a local page (read-only)."""

import http.client
import json
import shutil
from pathlib import Path

import pytest

from threatsketch.analysis import serve, snapshot
from threatsketch.cli import main
from threatsketch.rules.tb7 import load_template

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
        "cell": "placeorder",
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
        "changedBy": "",
        "lastModified": "Generated",
        "generatedBy": "SDL rule S3",
        "editable": True,
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
    import threatsketch.cli as cli

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
    import threatsketch.cli as cli

    monkeypatch.setattr(cli.webbrowser, "open", lambda _url: None)

    def stop(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", stop)
    assert main(["open", str(analyzed), "--no-launch"]) == 0
    assert "analysis view: http://127.0.0.1:" in capsys.readouterr().out
    assert main(["open", str(analyzed), "--no-launch", "--no-view"]) == 0
    assert "analysis view" not in capsys.readouterr().out


# --- editing from the analysis view, with the triage journal --------------------------------


def post(port, payload, token, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "Host": host or f"127.0.0.1:{port}"}
    if token is not None:
        headers["X-Tdtm-Token"] = token
    conn.request("POST", "/api/threat", body=body, headers=headers)
    r = conn.getresponse()
    return r.status, r.read()


def threat_by_number(path, number):
    raw = json.loads(path.read_text())
    for d in raw["detail"]["diagrams"]:
        for c in d["cells"]:
            for t in c["data"].get("threats", []):
                if t.get("number") == number:
                    return c, t


def test_editing_requires_this_page_and_writes_model_and_journal(analyzed):
    server, url = serve(analyzed, load_template(), port=0)
    try:
        port, token = server.server_address[1], server.token
        assert f'"{token}"' in get(port, "/")[2].decode()  # the page carries the token
        _, t = threat_by_number(analyzed, 1)
        edit = {"key": t["tdtm"]["key"], "state": "Mitigated", "priority": "Medium",
                "justification": "Customers sign in with MFA."}  # fmt: skip
        assert post(port, edit, token=None)[0] == 403  # another page cannot read the token
        assert post(port, edit, token="guess")[0] == 403
        assert post(port, edit, token, host="evil.example:80")[0] == 403
        assert post(port, {**edit, "state": "Done"}, token)[0] == 400
        assert post(port, {**edit, "key": "sdl:NOPE:x"}, token)[0] == 404
        assert post(port, edit, token)[0] == 200

        _, t = threat_by_number(analyzed, 1)
        assert (t["status"], t["severity"], t["mitigation"]) == (
            "Mitigated",
            "Medium",
            "Customers sign in with MFA.",
        )
        journal = json.loads(analyzed.with_suffix(".triage.json").read_text())
        assert journal[edit["key"]]["status"] == "Mitigated"

        needs = {**edit, "state": "Needs Investigation"}
        assert post(port, needs, token)[0] == 200
        _, t = threat_by_number(analyzed, 1)
        assert (t["status"], t["tdtm"]["tmtState"]) == ("Open", "Needs Investigation")
        assert snapshot(analyzed, load_template())["threats"][0]["state"] == "Needs Investigation"
    finally:
        server.shutdown()


def test_journal_survives_a_stale_save_from_threat_dragon(analyzed, capsys):
    stale = analyzed.read_text()  # what Threat Dragon still holds in memory
    server, _ = serve(analyzed, load_template(), port=0)
    try:
        _, t = threat_by_number(analyzed, 1)
        edit = {"key": t["tdtm"]["key"], "state": "Not Applicable", "priority": "Low",
                "justification": "No customer accounts."}  # fmt: skip
        assert post(server.server_address[1], edit, server.token)[0] == 200
    finally:
        server.shutdown()
    analyzed.write_text(stale)  # Threat Dragon saves its older copy over the edit
    assert main(["analyze", str(analyzed)]) == 0
    assert "1 restored from the analysis view" in capsys.readouterr().out
    c, t = threat_by_number(analyzed, 1)
    assert (t["status"], t["severity"], t["mitigation"]) == (
        "NotApplicable",
        "Low",
        "No customer accounts.",
    )


def test_an_edit_in_threat_dragon_beats_the_journal(analyzed):
    server, _ = serve(analyzed, load_template(), port=0)
    try:
        _, t = threat_by_number(analyzed, 1)
        edit = {"key": t["tdtm"]["key"], "state": "Mitigated", "priority": "High",
                "justification": "From the page."}  # fmt: skip
        assert post(server.server_address[1], edit, server.token)[0] == 200
    finally:
        server.shutdown()
    raw = json.loads(analyzed.read_text())
    _, t = threat_by_number(analyzed, 1)
    for d in raw["detail"]["diagrams"]:
        for c in d["cells"]:
            for x in c["data"].get("threats", []):
                if x.get("number") == 1:
                    x["status"], x["mitigation"] = "Open", "Changed my mind in Threat Dragon."
    analyzed.write_text(json.dumps(raw))
    assert main(["analyze", str(analyzed)]) == 0
    _, t = threat_by_number(analyzed, 1)
    assert (t["status"], t["mitigation"]) == ("Open", "Changed my mind in Threat Dragon.")
    journal = json.loads(analyzed.with_suffix(".triage.json").read_text())
    assert journal[t["tdtm"]["key"]]["mitigation"] == "Changed my mind in Threat Dragon."
