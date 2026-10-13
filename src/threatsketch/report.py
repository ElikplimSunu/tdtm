"""Self-contained HTML report in the shape of TMT's Full Report. SPEC section 9. PLAN task 3.2.

`render(model, template=None) -> str`: TMT's sections in TMT's order (model details, the Threat
Model Summary by TMT state, then per diagram its drawing, its summary and each interaction with its
threats: title, State, Priority, Category, Description, Justification), on a modern layout built
from the ThreatSketch design tokens. One file: fonts and the diagram are embedded, nothing is
fetched. It prints to A4 (page numbers, threats never split across pages), and its "Save as PDF"
button opens the print dialog; `#print` in the address opens it straight away. Every threat in the
model is reported, generated or not. All model text is escaped. [layout of the sections from
memory of TMT 7.3's report, not yet compared with a real one]

`render_csv(model, template) -> str` writes TMT's own CSV export format (same columns, category
names, state names and CRLF line endings), so a Threat Dragon model hands in like a TMT one.
"""

from __future__ import annotations

import base64
import csv
import io
import re
from datetime import datetime
from functools import cache
from html import escape
from importlib.resources import files

from . import __version__
from .diagram import render_svg
from .merge import STRIDE_TYPES, fingerprint
from .model import Diagram, Kind, Model, Threat

STATES = ["Not Started", "Needs Investigation", "Not Applicable", "Mitigated"]
OPEN = ("Not Started", "Needs Investigation")
STATE_CLASS = {s: s.lower().replace(" ", "-") for s in STATES}
CATEGORY_ORDER = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                  "Denial Of Service", "Elevation Of Privilege"]  # fmt: skip


@cache
def _fonts() -> str:
    """IBM Plex (OFL-1.1, data/fonts), embedded so the report needs nothing from the network."""
    faces = [("IBM Plex Sans", 400, "ibm-plex-sans-latin-400-normal.woff2"),
             ("IBM Plex Sans", 600, "ibm-plex-sans-latin-600-normal.woff2"),
             ("IBM Plex Mono", 400, "ibm-plex-mono-latin-400-normal.woff2")]  # fmt: skip
    out = []
    for family, weight, name in faces:
        data = base64.b64encode((files("threatsketch") / "data" / "fonts" / name).read_bytes())
        out.append(
            f"@font-face{{font-family:'{family}';font-weight:{weight};font-display:swap;"
            f"src:url(data:font/woff2;base64,{data.decode()}) format('woff2')}}"
        )
    return "\n".join(out)


CSS = (files("threatsketch") / "data" / "report.css").read_text(encoding="utf-8")
MARK = (files("threatsketch") / "data" / "mark.svg").read_text(encoding="utf-8")  # the app icon
PRINT_ON_OPEN = "if(location.hash==='#print')addEventListener('load',()=>setTimeout(print,300))"
TMT_STATE = {"Open": "Not Started", "NotApplicable": "Not Applicable"}  # others are the same


def tmt_state(t: Threat) -> str:
    """The state TMT would show. `Needs Investigation` has no Threat Dragon status, so it is kept
    in the threat's `tdtm` key (SPEC 13); everything else maps from the status."""
    meta = t.raw.get("tdtm")
    if isinstance(meta, dict) and meta.get("tmtState"):
        return meta["tmtState"]
    return TMT_STATE.get(t.status, t.status)


def tmt_time(stamp: str) -> str:
    """TMT's ModifiedAt (ISO 8601, 7-digit fractions, an offset) as TMT lists it: the stored wall
    time, "13/10/2026 9:56:59 pm" (SPEC 11).
    ponytail: TMT follows the Windows locale; this is the en-GB form a real TMT 7.3 showed. Pass a
    locale if models from other locales need their own form."""
    try:
        t = datetime.fromisoformat(stamp)
    except ValueError:
        return stamp
    return f"{t:%d/%m/%Y} {t.hour % 12 or 12}:{t:%M:%S} {'pm' if t.hour >= 12 else 'am'}"


def tmt_changed(t: Threat) -> tuple[str, str]:
    """(Changed By, Last Modified) as TMT lists them: "Generated" until the threat is triaged,
    then who (`MACHINE\\user`, from a `.tm7`) and when (TMT's ModifiedAt, or ours on triage)."""
    meta = t.raw.get("tdtm")
    if not isinstance(meta, dict):
        return "", ""
    if meta.get("fingerprint") == fingerprint(t.raw):
        return "", "Generated"
    keep = meta.get("tm7") or {}
    return keep.get("changedBy") or "", tmt_time(keep.get("modifiedAt") or "")


def tmt_category(t: Threat, template) -> str:
    letter = {name.lower(): k for k, name in STRIDE_TYPES.items()}.get(t.type.lower(), "")
    return template.categories.get(letter, t.type)


def generated_by(t: Threat) -> str:
    """'SDL rule S3' for threats threatsketch generated, else ''."""
    if not t.tdtm_key:
        return ""
    pack, rule = t.tdtm_key.split(":")[:2]
    return f"{pack.upper()} rule {rule}"


def _state(state: str) -> str:
    cls = STATE_CLASS.get(state, "not-started")
    return f'<span class="state {cls}"><span class="dot"></span>{escape(state)}</span>'


def _threat(t: Threat, template) -> str:
    state = tmt_state(t)
    number = t.raw.get("number")
    facts = [("Category", tmt_category(t, template)), ("Priority", t.severity or "TBD")]
    if generated_by(t):
        facts.append(("Generated by", generated_by(t)))
    just = (
        f'<p class="just"><span class="k">Justification</span>{escape(t.mitigation)}</p>'
        if t.mitigation
        else '<p class="just none"><span class="k">Justification</span>'
        "&lt;no mitigation provided&gt;</p>"
    )
    return (
        f'<article class="threat {STATE_CLASS.get(state, "")}">'
        f'<div class="th"><span class="id num">{"" if number is None else number}</span>'
        f"<h4>{escape(t.title)}</h4>{_state(state)}</div>"
        '<div class="facts">'
        + "".join(f"<span>{k} <b>{escape(str(v))}</b></span>" for k, v in facts)
        + f'</div><p class="desc">{escape(t.description)}</p>{just}</article>'
    )


def _counts(threats: list[Threat]) -> dict[str, int]:
    states = [tmt_state(t) for t in threats]
    return {s: states.count(s) for s in STATES}


def _summary(threats: list[Threat], template) -> str:
    """TMT's Threat Model Summary: counts by state, a bar of the same, and counts by category."""
    c = _counts(threats)
    total = len(threats)
    stats = [
        ("Total", total),
        *((s, c[s]) for s in STATES[:3]),
        ("Mitigation Implemented", c["Mitigated"]),
    ]
    bar = "".join(
        f'<i class="{STATE_CLASS[s]}-bg" style="width:{100 * n / total:.2f}%"></i>'
        for s, n in c.items()
        if n and total
    )
    legend = "".join(
        f'<span><i class="sw {STATE_CLASS[s]}-bg"></i>{escape(s)} <b class="num">{n}</b></span>'
        for s, n in c.items()
    )
    by_cat: dict[str, list[Threat]] = {}
    for t in threats:
        by_cat.setdefault(tmt_category(t, template), []).append(t)
    order = sorted(
        by_cat, key=lambda k: (CATEGORY_ORDER.index(k) if k in CATEGORY_ORDER else 99, k)
    )
    rows = "".join(
        f'<tr><td>{escape(k)}</td><td class="n num">{len(by_cat[k])}</td>'
        f'<td class="n num">{sum(tmt_state(t) in OPEN for t in by_cat[k])}</td></tr>'
        for k in order
    )
    table = (
        '<table><thead><tr><th>Category</th><th class="n">Threats</th><th class="n">Open</th></tr>'
        f"</thead><tbody>{rows}</tbody></table>"
        if rows
        else ""
    )
    return (
        '<div class="stats">'
        + "".join(f'<div class="stat"><b>{n}</b><span>{escape(k)}</span></div>' for k, n in stats)
        + f'</div><div class="bar">{bar}</div><div class="legend">{legend}</div>{table}'
    )


BOUNDARIES = "trust boundaries"

# Names an element gets when it is drawn (ThreatSketch, Threat Dragon); stencil names count too.
DEFAULT_NAMES = {"", "external interactor", "external actor", "actor", "process", "data store",
                 "store", "data flow", "flow"}  # fmt: skip


def review(model: Model, template) -> list[str]:
    """What a reader of the report would trip over, one plain-text line each; [] when ready."""
    defaults = DEFAULT_NAMES | {s.name.lower() for s in template.stencils.values()}
    parts = [e for d in model.diagrams for e in d.of_kind(Kind.ACTOR, Kind.PROCESS, Kind.STORE)]
    flows = [f for d in model.diagrams for f in d.of_kind(Kind.FLOW)]
    unnamed = [
        e for e in parts + flows if re.sub(r"[\s_-]*\d+$", "", e.name.strip()).lower() in defaults
    ]
    threats = [t for d in model.diagrams for e in d.elements.values() for t in e.threats]
    states = [tmt_state(t) for t in threats]
    notes = []
    if unnamed:
        examples = list(dict.fromkeys(e.label for e in unnamed))[:4]
        notes.append(
            f"{len(unnamed)} of {_n(len(parts + flows), 'element')} still "
            f"{'has' if len(unnamed) == 1 else 'have'} a default name ({', '.join(examples)}). "
            "Name each after the real thing, such as Web server, Orders database or Card details."
        )
    if not model.description.strip():
        notes.append("The model has no description. Say what the system is and what it is for.")
    if flows and not any(d.of_kind(Kind.BOUNDARY_BOX, Kind.BOUNDARY_CURVE) for d in model.diagrams):
        notes.append(
            "No trust boundary is drawn, so threats that apply only where data crosses one "
            "(such as between the Internet and your servers) cannot appear."
        )
    if (n := states.count("Not Started")) and threats:
        notes.append(
            f"{n} of {_n(len(threats), 'threat')} {'is' if n == 1 else 'are'} still Not Started. "
            "Triage each one as Mitigated, Not Applicable or Needs Investigation."
        )
    closed = [
        t
        for t, s in zip(threats, states, strict=True)
        if s in ("Mitigated", "Not Applicable") and not t.mitigation
    ]
    if closed:
        notes.append(
            f"{_n(len(closed), 'threat')} {'is' if len(closed) == 1 else 'are'} Mitigated or "
            "Not Applicable without a justification."
        )
    return notes


def _review(model: Model, template) -> str:
    notes = review(model, template)
    if not notes:
        return ""
    items = "".join(f"<li>{escape(n)}</li>" for n in notes)
    return f'<aside class="review"><h2>Review before sharing</h2><ul>{items}</ul></aside>'


def _n(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def _diagram(d: Diagram, template) -> list[str]:
    threats = [t for e in d.elements.values() for t in e.threats]
    c = _counts(threats)
    names = {e.cell_id: e.label for e in d.elements.values()}
    boxes = len(d.of_kind(Kind.BOUNDARY_BOX, Kind.BOUNDARY_CURVE))
    parts = [
        '<section class="diagram">',
        f"<h2>Diagram: {escape(d.title)}</h2>",
        f"<figure>{render_svg(d)}<figcaption>{escape(d.title)}: "
        f"{_n(len(d.of_kind(Kind.ACTOR, Kind.PROCESS, Kind.STORE)), 'element')}, "
        f"{_n(len(d.of_kind(Kind.FLOW)), 'data flow')}, {_n(boxes, 'trust boundary', BOUNDARIES)}"
        "</figcaption></figure>",
        '<div class="mini">'
        f"<span>Threats <b>{len(threats)}</b></span>"
        + "".join(f"<span>{escape(s)} <b>{n}</b></span>" for s, n in c.items())
        + "</div>",
    ]
    for f in d.of_kind(Kind.FLOW):
        if not f.threats:
            continue
        src, tgt = d.elements[f.source_id].label, d.elements[f.target_id].label
        crosses = ", ".join(names.get(b, "") for b in f.crosses)
        route = f"{escape(src)} → {escape(tgt)}"
        if crosses:
            route += f' · crosses <span class="crosses">{escape(crosses)}</span>'
        if f.out_of_scope:
            route += " · out of scope"
        parts.append(
            f'<section class="interaction"><header><h3>Interaction: {escape(f.label)}</h3>'
            f'<span class="route">{route}</span></header>'
            + "".join(_threat(t, template) for t in f.threats)
            + "</section>"
        )
    for e in d.elements.values():
        if e.kind is not Kind.FLOW and e.threats:
            parts.append(
                f'<section class="interaction"><header><h3>Element: {escape(e.label)}</h3></header>'
                + "".join(_threat(t, template) for t in e.threats)
                + "</section>"
            )
    parts.append("</section>")
    return parts


def render(model: Model, template=None) -> str:
    if template is None:
        from .rules.tb7 import load_template

        template = load_template()
    threats = [t for d in model.diagrams for e in d.elements.values() for t in e.threats]
    created = datetime.now()
    meta = [
        ("Owner", model.owner),
        ("Reviewer", model.reviewer),
        ("Contributors", ", ".join(model.contributors)),
        ("Assumptions", model.assumptions),
        ("External Dependencies", model.external_dependencies),
        ("Created", f"{created:%d %B %Y, %H:%M}"),
        ("Template", template.name or "SDL TM Knowledge Base"),
        ("Diagrams", str(len(model.diagrams))),
    ]
    title = escape(model.title or "Untitled threat model")
    # the title in the printed page footer: a CSS string, so no quotes, backslashes or markup
    footer = "".join(ch for ch in (model.title or "Threat model") if ch not in '"\\<>\n\r')
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}: Threat Modeling Report</title>",
        f'<style>{_fonts()}{CSS}@page{{@bottom-left{{content:"{footer}"}}}}</style>',
        f"<script>{PRINT_ON_OPEN}</script></head><body>",
        '<div class="toolbar"><button type="button" onclick="print()">Save as PDF</button></div>',
        '<main class="page">',
        '<header class="cover">',
        f'<div class="brandline">{MARK}<span>Threat Modeling Report</span></div>',
        f"<h1>{title}</h1>",
        f'<p class="lede">{escape(model.description)}</p>' if model.description else "",
        '<dl class="meta">'
        + "".join(f"<div><dt>{k}</dt><dd>{escape(v)}</dd></div>" for k, v in meta if v)
        + "</dl></header>",
        _review(model, template),
        "<h2>Threat Model Summary</h2>",
        _summary(threats, template),
    ]
    for d in model.diagrams:
        parts += _diagram(d, template)
    parts.append(
        f"<footer>Created on {created:%d/%m/%Y %H:%M} by ThreatSketch {__version__} from TMT's "
        f"{escape(template.name or 'SDL TM Knowledge Base')} template.</footer>"
        "</main></body></html>"
    )
    return "\n".join(p for p in parts if p) + "\n"


CSV_COLUMNS = [
    "Id",
    "Title",
    "Category",
    "Diagram",
    "Interaction",
    "Priority",
    "State",
    "Changed By",
    "Description",
    "Justification",
    "Last Modified",
]


def render_csv(model: Model, template) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for d in model.diagrams:
        for e in d.elements.values():
            for t in e.threats:
                changed_by, last_modified = tmt_changed(t)
                number = t.raw.get("number")
                w.writerow([
                    "" if number is None else number,
                    t.title,
                    tmt_category(t, template),
                    d.title,
                    e.label,
                    t.severity,
                    tmt_state(t),
                    changed_by,
                    t.description,
                    t.mitigation,
                    last_modified,
                ])  # fmt: skip
    return out.getvalue()
