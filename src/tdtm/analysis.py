"""TMT's Analysis View as a local page: every threat in one grid, with filters and properties.

`snapshot(path, template) -> dict` reads the model fresh. `serve(path, template, port=0)` starts a
background HTTP server on 127.0.0.1 and returns `(server, url)`. Read-only: threats are edited in
Threat Dragon, and the page refreshes when the model file changes.

Safety: binds to 127.0.0.1 only, rejects any Host header but its own (DNS rebinding), answers GET
only, and the page puts model text into the DOM as text, never as HTML. The diagram SVG comes from
`diagram.render_svg`, which escapes every name.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .diagram import render_svg
from .model import Kind
from .report import generated_by, tmt_category, tmt_state
from .td_adapter import load


def snapshot(path: str | Path, template) -> dict:
    path = Path(path)
    st = path.stat()
    model, _ = load(path)
    threats = []
    for d in model.diagrams:
        for e in d.elements.values():
            src = d.elements[e.source_id].label if e.kind is Kind.FLOW else ""
            tgt = d.elements[e.target_id].label if e.kind is Kind.FLOW else ""
            for i, t in enumerate(e.threats):
                threats.append(
                    {
                        "key": t.tdtm_key or t.id or f"{e.cell_id}:{i}",
                        "id": t.raw.get("number"),
                        "diagram": d.title,
                        "interaction": e.label,
                        "source": src,
                        "target": tgt,
                        "state": tmt_state(t),
                        "title": t.title,
                        "category": tmt_category(t, template),
                        "description": t.description,
                        "justification": t.mitigation,
                        "priority": t.severity,
                        "generatedBy": generated_by(t),
                    }
                )
    return {
        "title": model.title,
        "stamp": f"{st.st_mtime_ns}-{st.st_size}",
        "diagrams": [{"title": d.title, "svg": render_svg(d)} for d in model.diagrams],
        "threats": threats,
    }


def serve(path: str | Path, template, port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    path = Path(path)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, ctype: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            port_ = self.server.server_address[1]
            if self.headers.get("Host") not in (f"127.0.0.1:{port_}", f"localhost:{port_}"):
                return self._send(403, "text/plain", b"forbidden")
            if self.path == "/":
                return self._send(200, "text/html; charset=utf-8", PAGE.encode())
            if self.path == "/api/model":
                try:
                    body = json.dumps(snapshot(path, template)).encode()
                except (OSError, ValueError, KeyError):  # mid-save: the page retries
                    return self._send(503, "text/plain", b"model not readable yet")
                return self._send(200, "application/json", body)
            self._send(404, "text/plain", b"not found")

        def do_POST(self) -> None:
            self._send(405, "text/plain", b"read-only")

        def log_message(self, *_args) -> None:  # keep the terminal for tdtm's own messages
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/"


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat List</title>
<style>
:root { --line: #c8c8c8; --head: #f0f0f0; --sel: #cce8ff; --muted: #5c5c5c; }
* { box-sizing: border-box; }
body { margin: 0; font: 13px/1.4 "Segoe UI", system-ui, -apple-system, sans-serif;
       color: #1b1b1b; background: #fff; }
header { display: flex; gap: 12px; align-items: baseline; padding: 10px 16px;
         background: #2b579a; color: #fff; }
header h1 { font-size: 16px; margin: 0; font-weight: 600; }
header .model { opacity: .9; }
header .status { margin-left: auto; opacity: .85; }
main { padding: 10px 16px 16px; }
details.diagram { border: 1px solid var(--line); margin-bottom: 10px; }
details.diagram summary { padding: 6px 10px; background: var(--head); cursor: pointer;
                          font-weight: 600; }
details.diagram svg { display: block; width: 100%; height: auto; max-height: 460px; }
.filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 6px 0; }
.filters select, .filters input { font: inherit; padding: 3px 6px; border: 1px solid var(--line);
                                  border-radius: 2px; background: #fff; }
.filters input { min-width: 200px; } .count { color: var(--muted); margin-left: auto; }
.grid { border: 1px solid var(--line); max-height: 46vh; overflow: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { border-bottom: 1px solid #e3e3e3; padding: 4px 8px; text-align: left;
         vertical-align: top; white-space: nowrap; }
th { position: sticky; top: 0; background: var(--head); font-weight: 600;
     border-bottom: 1px solid var(--line); }
td.wrap { white-space: normal; min-width: 220px; }
tbody tr { cursor: pointer; } tbody tr:hover { background: #f5f9ff; }
tbody tr.selected { background: var(--sel); }
.state { padding: 0 6px; border-radius: 9px; font-size: 12px; }
.s-not-started { background: #eeeeee; } .s-needs-investigation { background: #fde7b0; }
.s-mitigated { background: #cdeccf; } .s-not-applicable { background: #e6e9f2; }
section.props { border: 1px solid var(--line); margin-top: 10px; }
section.props h2 { margin: 0; padding: 6px 10px; background: var(--head); font-size: 13px; }
section.props dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px;
                   margin: 0; padding: 10px; }
section.props dt { color: var(--muted); } section.props dd { margin: 0; white-space: pre-wrap; }
.note { color: var(--muted); margin-top: 8px; }
</style></head>
<body>
<header><h1>Threat List</h1><span class="model" id="model"></span>
<span class="status" id="status">Loading...</span></header>
<main>
<div id="diagrams"></div>
<div class="filters">
  <select id="f-state" aria-label="State"></select>
  <select id="f-category" aria-label="Category"></select>
  <select id="f-priority" aria-label="Priority"></select>
  <input id="f-text" type="search" placeholder="Search title, description, interaction"
         aria-label="Search">
  <span class="count" id="count"></span>
</div>
<div class="grid"><table>
<thead><tr><th>ID</th><th>State</th><th>Title</th><th>Category</th><th>Interaction</th>
<th>Priority</th><th>Justification</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<section class="props"><h2>Threat Properties</h2><dl id="props"></dl></section>
<p class="note">Read-only. Change state, priority and justification (mitigation) in Threat Dragon;
this page updates when the model is saved.</p>
</main>
<script>
"use strict";
let data = null, selected = null;
const folded = new Set();
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
};
const slug = (s) => s.toLowerCase().replace(/[^a-z]+/g, "-");
const FILTERS = [["f-state", "state", "All states"], ["f-category", "category", "All categories"],
                 ["f-priority", "priority", "All priorities"]];

function fillFilters() {
  for (const [id, field, label] of FILTERS) {
    const sel = $(id), keep = sel.value;
    sel.replaceChildren(el("option", label));
    sel.firstChild.value = "";
    for (const v of [...new Set(data.threats.map((t) => t[field]))].sort()) {
      const o = el("option", v); o.value = v; sel.append(o);
    }
    sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
  }
}

function visible() {
  const q = $("f-text").value.trim().toLowerCase();
  return data.threats.filter((t) =>
    FILTERS.every(([id, field]) => !$(id).value || t[field] === $(id).value) &&
    (!q || [t.title, t.description, t.interaction, t.justification]
      .some((v) => (v || "").toLowerCase().includes(q))));
}

function renderRows() {
  const rows = visible(), body = $("rows");
  body.replaceChildren();
  for (const t of rows) {
    const tr = el("tr");
    if (t.key === selected) tr.className = "selected";
    tr.append(el("td", t.id ?? ""));
    const st = el("td"); st.append(el("span", t.state, "state s-" + slug(t.state))); tr.append(st);
    tr.append(el("td", t.title, "wrap"), el("td", t.category), el("td", t.interaction),
              el("td", t.priority), el("td", t.justification, "wrap"));
    tr.addEventListener("click", () => { selected = t.key; renderRows(); renderProps(); });
    body.append(tr);
  }
  $("count").textContent = rows.length + " of " + data.threats.length + " threats";
}

function renderProps() {
  const t = data.threats.find((x) => x.key === selected), dl = $("props");
  dl.replaceChildren();
  if (!t) { dl.append(el("dd", "Select a threat to see its properties.")); return; }
  const fields = [["Title", t.title], ["Category", t.category], ["State", t.state],
    ["Priority", t.priority], ["Interaction", t.interaction],
    ["Flow", t.source ? t.source + " \\u2192 " + t.target : ""], ["Description", t.description],
    ["Justification", t.justification || "<no mitigation provided>"],
    ["Diagram", t.diagram], ["Generated by", t.generatedBy || "a person"]];
  for (const [k, v] of fields) dl.append(el("dt", k), el("dd", v));
}

function render() {
  $("model").textContent = data.title;
  document.title = "Threat List: " + data.title;
  const box = $("diagrams");
  box.replaceChildren();
  for (const d of data.diagrams) {
    const det = el("details", null, "diagram");
    det.open = !folded.has(d.title);  // remember what the reader folded across refreshes
    det.addEventListener("toggle", () =>
      det.open ? folded.delete(d.title) : folded.add(d.title));
    det.append(el("summary", "Diagram: " + d.title));
    const holder = el("div");
    holder.innerHTML = d.svg;  // server-rendered, every name escaped (diagram.render_svg)
    det.append(holder);
    box.append(det);
  }
  fillFilters(); renderRows(); renderProps();
}

async function refresh() {
  try {
    const r = await fetch("/api/model", {cache: "no-store"});
    if (!r.ok) throw new Error(String(r.status));
    const d = await r.json();
    if (!data || d.stamp !== data.stamp) { data = d; render(); }
    $("status").textContent = "Up to date";
  } catch (e) {
    $("status").textContent = "Waiting for the model...";
  }
}
for (const [id] of FILTERS) $(id).addEventListener("change", renderRows);
$("f-text").addEventListener("input", renderRows);
refresh();
setInterval(refresh, 2000);
</script>
</body></html>
"""
