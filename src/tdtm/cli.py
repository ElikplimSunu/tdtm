"""`tdtm` command line. SPEC section 8."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .model import Kind, Model
from .td_adapter import load, save

GUID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class UsageError(Exception):
    """A problem with the model or template the user pointed at (exit code 2)."""


def _load(args: argparse.Namespace):
    """Load and resolve. Returns (model, doc, template, tag errors)."""
    from .resolve import resolve

    template = _template(args)
    try:
        model, doc = load(args.model)
    except (OSError, ValueError, KeyError) as e:
        raise UsageError(f"cannot read model {args.model}: {e}") from e
    return model, doc, template, resolve(model, template)


def _report_problems(model: Model, errors: list[str]) -> None:
    for w in model.warnings:
        print(f"warning: {w}", file=sys.stderr)
    for e in errors:
        print(f"tag error: {e}", file=sys.stderr)


def cmd_inspect(args: argparse.Namespace) -> int:
    model, _, template, errors = _load(args)
    for d in model.diagrams:
        print(f"Diagram {d.id}: {d.title}")
        if d.diagram_type != "STRIDE":
            print(f"  not analysed ({d.diagram_type} diagram)\n")
            continue
        for e in d.elements.values():
            stencil = f"{e.stencil} ({template.stencils[e.stencil].name})"
            if e.kind is Kind.FLOW:
                src, tgt = d.elements[e.source_id].label, d.elements[e.target_id].label
                print(f"  flow {e.label!r}: {src} -> {tgt}  {stencil}")
                crossed = ", ".join(d.elements[b].label for b in e.crosses) or "none"
                print(f"    crosses: {crossed}")
            else:
                print(f"  {e.kind.value.replace('_', ' ')} {e.label!r}  {stencil}")
                if e.kind in (Kind.ACTOR, Kind.PROCESS, Kind.STORE):
                    print(f"    zone: {d.elements[e.zone].label if e.zone else 'outer'}")
            if e.out_of_scope:
                print("    out of scope")
            for name, value in e.attributes.items():
                shown = name
                if GUID.fullmatch(name):  # show GUID-named attributes by their display name
                    shown = f"{template.attributes_for(e.stencil)[name].display_name} ({name})"
                print(f"    {shown} = {value}  [{e.attr_source[name]}]")
        print()
    _report_problems(model, errors)
    return 0


def _where(cid: str, model: Model, doc) -> str:
    """Human description of the cell a threat lives on."""
    els = {c: e for d in model.diagrams for c, e in d.elements.items()}
    e = els.get(cid)
    if e and e.kind is Kind.FLOW:
        return f"flow {e.label!r} ({els[e.source_id].label} -> {els[e.target_id].label})"
    name = " ".join(doc.cells.get(cid, {}).get("data", {}).get("name", "").split())
    return f"cell {name or cid[:8]!r}"


def _stamp(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except FileNotFoundError:
        return None  # mid-save: some editors replace the file
    return st.st_mtime_ns, st.st_size


def watch(path: Path, run, *, interval: float = 1.0, sleep=None, ticks: int | None = None):
    """Call `run` now and whenever `path` changes. `run`'s own write does not count as a change."""
    # ponytail: stdlib polling once a second; fine for one file, no watcher dependency needed
    sleep = sleep or time.sleep  # looked up per call so tests can patch it
    run()
    last = _stamp(path)
    n = 0
    while ticks is None or n < ticks:
        sleep(interval)
        n += 1
        now = _stamp(path)
        if now is not None and now != last:
            run()
            last = _stamp(path)


def cmd_analyze(args: argparse.Namespace) -> int:
    if not args.watch:
        return _analyze_once(args)

    def run():
        try:
            _analyze_once(args)
        except UsageError as e:  # e.g. half-written file: report and keep watching
            print(f"tdtm: {e}", file=sys.stderr)

    print(f"watching {args.model}; press Ctrl-C to stop")
    try:
        watch(Path(args.model), run)
    except KeyboardInterrupt:
        print("stopped")
    return 0


def _analyze_once(args: argparse.Namespace) -> int:
    from .merge import merge
    from .rules.engine import run_sdl

    model, doc, template, errors = _load(args)
    if errors and args.strict:
        _report_problems(model, errors)
        print(
            "tdtm: tag errors; nothing written (drop --strict to continue anyway)", file=sys.stderr
        )
        return 3

    packs = ("sdl", "pytm") if args.pack == "all" else (args.pack,)
    generated = (
        run_sdl(model, template, include_legacy=args.include_legacy) if "sdl" in packs else []
    )
    if "pytm" in packs:
        from .rules.pytm_pack import PytmMissing, run_pytm

        try:
            generated += run_pytm(model)
        except PytmMissing as e:
            raise UsageError(str(e)) from e

    out = Path(args.out or args.model)
    sidecar_in, sidecar_out = (Path(p).with_suffix(".tdtm.json") for p in (args.model, out))
    sidecar = None
    if args.sidecar:
        sidecar = json.loads(sidecar_in.read_text()) if sidecar_in.exists() else {}

    titles = {g.key: g.title for g in generated}
    for c in doc.cells.values():  # titles of threats that may go stale or be pruned
        for t in c.get("data", {}).get("threats") or []:
            m = sidecar.get(t.get("id")) if sidecar is not None else t.get("tdtm")
            if isinstance(m, dict) and "key" in m:
                titles.setdefault(m["key"], t.get("title", ""))

    from . import journal

    before = json.dumps([doc.raw, sidecar], sort_keys=True)
    s = merge(doc, generated, packs=packs, prune=args.prune, sidecar=sidecar)
    triage, restored = journal.read(args.model) if sidecar is None else {}, 0
    if triage:  # re-apply analysis-view edits a stale Threat Dragon save overwrote (SPEC 13)
        restored, triage_changed = journal.apply(doc, triage)
        merge(doc, [], packs=())  # restyle after restored states
        if triage_changed and not args.dry_run:
            journal.write(args.model, triage)
    changed = json.dumps([doc.raw, sidecar], sort_keys=True) != before
    _report_problems(model, errors)
    if args.dry_run:
        for mark, keys in (("+", s.added), ("~", s.refreshed), ("!", s.stale), ("-", s.pruned)):
            for key in keys:
                print(f"{mark} {_where(key.split(':')[2], model, doc)}: {titles.get(key, key)}")
    print(
        f"{len(s.added)} added, {len(s.refreshed)} refreshed, {len(s.unchanged)} unchanged, "
        f"{len(s.kept_edited)} kept as you edited them, {len(s.stale)} newly stale, "
        f"{len(s.pruned)} pruned"
        + (f", {restored} restored from the analysis view" if restored else "")
        + (" (dry run: nothing written)" if args.dry_run else "")
    )
    if args.dry_run:
        return 0

    in_place = out.resolve() == Path(args.model).resolve()
    if in_place and not changed:  # keep the file, its timestamp and the previous .bak as they are
        print(f"no changes; {out} left as it was")
        return 0
    if in_place:
        shutil.copyfile(args.model, f"{args.model}.bak")
    save(doc, out)
    if sidecar is not None:
        sidecar_out.write_text(json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {out}")
    return 0


KIND_ORDER = [
    Kind.ACTOR,
    Kind.PROCESS,
    Kind.STORE,
    Kind.FLOW,
    Kind.BOUNDARY_BOX,
    Kind.BOUNDARY_CURVE,
]


def _template(args: argparse.Namespace):
    from .rules.tb7 import load_template

    try:
        return load_template(args.template)
    except (OSError, ET.ParseError) as e:
        raise UsageError(f"cannot read template: {e}") from e


def cmd_stencils(args: argparse.Namespace) -> int:
    from .model import KIND_ROOT

    template = _template(args)
    for kind in [Kind(args.kind)] if args.kind else KIND_ORDER:
        root = KIND_ROOT[kind]
        stencils = [s for s in template.stencils.values() if s.root == root]
        print(f"== {kind.value.replace('_', ' ')} (TMT {root})")
        print("Stencils (@tmt: <name or id>):")
        width = max(len(s.name) for s in stencils)
        for s in stencils:
            fixed = ", ".join(
                f"{a.name}={a.default}" for a in s.own_attributes.values() if a.static
            )
            print(f"  {s.name:<{width}}  {s.id}" + (f"  fixes {fixed}" if fixed else ""))
        print("Attributes (@tmt: <name>=<value>; * marks the default):")
        generic = template.attributes_for(root)
        for a in generic.values():
            print(f"  {a.name} ({a.display_name}): {', '.join(_starred(a))}")
        extra = [
            (s, a)
            for s in stencils
            for a in s.own_attributes.values()
            if not a.static and a.name not in generic
        ]
        for s, a in extra:
            print(f"  {a.name} ({a.display_name}): {', '.join(_starred(a))}  only with {s.name}")
        print()
    return 0


def _starred(a) -> list[str]:
    return [v + ("*" if i == 0 else "") for i, v in enumerate(a.values)]


def cmd_coverage(args: argparse.Namespace) -> int:
    from .coverage import coverage

    results = coverage(_template(args))
    legacy = [tt.id for tt, _, _ in results if tt.legacy]
    alone = [(tt, h) for tt, fires, h in results if fires and not tt.legacy]
    tagged = [(tt, h) for tt, fires, h in results if not fires and not tt.legacy]
    width = max(len(tt.id) for tt, _, _ in results if len(tt.id) < 10)
    for heading, rows in (
        ("Fire from Threat Dragon properties alone", alone),
        ("Need @tmt tags", tagged),
    ):
        print(f"{heading} ({len(rows)}):")
        for tt, hints in rows:
            print(f"  {tt.id:<{width}}  {tt.category}  {tt.short_title}")
            for hint in hints:
                print(f"  {'':<{width}}     {hint}")
        print()
    print(f"Legacy rules, skipped unless --include-legacy ({len(legacy)}): {', '.join(legacy)}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .report import render, render_csv

    try:
        model, _ = load(args.model)
    except (OSError, ValueError, KeyError) as e:
        raise UsageError(f"cannot read model {args.model}: {e}") from e
    if args.out.lower().endswith(".csv"):
        # newline="" keeps the CRLF line endings TMT's export uses
        Path(args.out).write_text(render_csv(model, _template(args)), encoding="utf-8", newline="")
    else:
        Path(args.out).write_text(render(model, _template(args)), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from .tm7 import Tm7Error, import_tm7

    out = Path(args.out or Path(args.model).with_suffix(".json"))
    if out.exists() and not args.force:
        raise UsageError(f"{out} exists; pass --out elsewhere or --force to overwrite it")
    try:
        raw, warnings = import_tm7(args.model)
    except (OSError, Tm7Error) as e:
        raise UsageError(str(e)) from e
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    out.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    threats = sum(
        len(c["data"].get("threats", [])) for d in raw["detail"]["diagrams"] for c in d["cells"]
    )
    print(f"wrote {out} ({len(raw['detail']['diagrams'])} diagrams, {threats} TMT threats)")
    return 0


def _blank_model(title: str) -> dict:
    diagram = {
        "id": 0,
        "title": "Main diagram",
        "diagramType": "STRIDE",
        "placeholder": "New STRIDE diagram description",
        "thumbnail": "./public/content/images/thumbnail.stride.jpg",
        "version": "2.6.2",
        "cells": [],
    }
    return {
        "version": "2.6.2",
        "summary": {"title": title, "owner": "", "description": "", "id": 0},
        "detail": {
            "contributors": [],
            "diagramTop": 1,
            "reviewer": "",
            "threatTop": 0,
            "diagrams": [diagram],
        },
    }


def _write_reports(model_path: Path, args: argparse.Namespace) -> None:
    from .report import render, render_csv

    model, _ = load(model_path)
    html, csv_path = model_path.with_suffix(".report.html"), model_path.with_suffix(".csv")
    html.write_text(render(model, _template(args)), encoding="utf-8")
    csv_path.write_text(render_csv(model, _template(args)), encoding="utf-8", newline="")
    print(f"reports: {html.name}, {csv_path.name}")


def _start_view(model: Path, args: argparse.Namespace, browser: bool):
    from .analysis import serve

    server, url = serve(model, _template(args), port=getattr(args, "port", 0) or 0)
    print(f"analysis view: {url}")
    if browser:
        webbrowser.open(url)
    return server


def cmd_view(args: argparse.Namespace) -> int:
    if not Path(args.model).exists():
        raise UsageError(f"{args.model} does not exist")
    server = _start_view(Path(args.model), args, browser=not args.no_browser)
    print("press Ctrl-C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.shutdown()
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    from .launcher import open_in_threat_dragon

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)  # show progress live even when piped

    model = Path(args.model)
    if model.suffix.lower() == ".tm7":
        target = model.with_suffix(".json")
        if target.exists():
            print(f"using existing {target.name} (it may hold your triage; delete it to re-import)")
        else:
            cmd_import(argparse.Namespace(model=str(model), out=str(target), force=False))
        model = target
    elif not model.exists():
        model.write_text(json.dumps(_blank_model(model.stem), indent=2), encoding="utf-8")
        print(f"created {model}: an empty STRIDE model to draw in")

    analyze = argparse.Namespace(
        model=str(model),
        pack=args.pack,
        template=args.template,
        include_legacy=False,
        dry_run=False,
        prune=False,
        out=None,
        sidecar=False,
        strict=False,
    )
    first = True

    def on_change():
        nonlocal first
        before = _stamp(model)
        try:
            _analyze_once(analyze)
            _write_reports(model, args)
        except UsageError as e:  # e.g. caught Threat Dragon mid-save: say so, keep watching
            print(f"tdtm: {e}", file=sys.stderr)
            return
        wrote = _stamp(model) != before
        if first:
            first = False
            if not args.no_launch:
                open_in_threat_dragon(model)
            if not args.no_view:
                servers.append(_start_view(model, args, browser=not args.no_launch))
            print(f"watching {model}: save in Threat Dragon and tdtm updates the threats")
            print("press Ctrl-C to stop")
        elif wrote and args.reload:
            open_in_threat_dragon(model)
        elif wrote:
            print(f"threats updated: reopen {model.name} in Threat Dragon to see them")

    servers = []
    try:
        watch(model, on_change)
    except KeyboardInterrupt:
        print("stopped")
    finally:
        for server in servers:
            server.shutdown()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .tm7_export import export_tm7

    out = Path(args.out or Path(args.model).with_suffix(".tm7"))
    if out.exists() and not args.force:
        raise UsageError(f"{out} exists; pass --out elsewhere or --force to overwrite it")
    try:
        raw = json.loads(Path(args.model).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise UsageError(f"cannot read model {args.model}: {e}") from e
    xml, warnings = export_tm7(raw, args.template)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    out.write_text(xml, encoding="utf-8")
    print(f"wrote {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tdtm", description="TMT-style threat generation for OWASP Threat Dragon models."
    )
    p.add_argument("--version", action="version", version=f"tdtm {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="generate threats and merge them into the model")
    a.add_argument("model")
    a.add_argument("--pack", choices=["sdl", "pytm", "all"], default="sdl")
    a.add_argument("--template", help="path to a .tb7 template (default: SDL TM Knowledge Base)")
    a.add_argument("--dry-run", action="store_true")
    a.add_argument("--prune", action="store_true")
    a.add_argument("--include-legacy", action="store_true")
    a.add_argument("--out", help="write here instead of overwriting MODEL")
    a.add_argument(
        "--sidecar",
        action="store_true",
        help="track generated threats in MODEL.tdtm.json instead of inside the model",
    )
    a.add_argument("--strict", action="store_true", help="exit with code 3 on @tmt tag errors")
    a.add_argument("--watch", action="store_true", help="re-run whenever MODEL changes")
    a.set_defaults(func=cmd_analyze)

    i = sub.add_parser("inspect", help="show resolved stencils, attributes, zones and crossings")
    i.add_argument("model")
    i.add_argument("--template", help="path to a .tb7 template (default: SDL TM Knowledge Base)")
    i.set_defaults(func=cmd_inspect)

    s = sub.add_parser("stencils", help="list valid @tmt stencils and attributes")
    s.add_argument("--kind", choices=[k.value for k in KIND_ORDER])
    s.add_argument("--template")
    s.set_defaults(func=cmd_stencils)

    r = sub.add_parser("report", help="write a TMT-style HTML report")
    r.add_argument("model")
    r.add_argument("--out", default="report.html", help="ending in .csv writes TMT's CSV format")
    r.add_argument("--template", help="for category names (default: SDL TM Knowledge Base)")
    r.set_defaults(func=cmd_report)

    o = sub.add_parser(
        "open",
        help="one command: create or import, add threats, write reports, open Threat Dragon, watch",
    )
    o.add_argument("model", help="a Threat Dragon .json (created if missing) or a TMT .tm7")
    o.add_argument("--pack", choices=["sdl", "pytm", "all"], default="sdl")
    o.add_argument("--template", help="path to a .tb7 template (default: SDL TM Knowledge Base)")
    o.add_argument(
        "--reload",
        action="store_true",
        help="after each update, reopen the model in Threat Dragon (it lands on the summary page)",
    )
    o.add_argument(
        "--no-launch", action="store_true", help="do not start Threat Dragon or the browser"
    )
    o.add_argument("--no-view", action="store_true", help="do not serve the analysis view")
    o.set_defaults(func=cmd_open)

    v = sub.add_parser("view", help="TMT-style analysis view of a model's threats, in the browser")
    v.add_argument("model")
    v.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free)")
    v.add_argument("--no-browser", action="store_true", help="only print the address")
    v.add_argument("--template", help="for category names (default: SDL TM Knowledge Base)")
    v.set_defaults(func=cmd_view)

    m = sub.add_parser("import", help="convert a Microsoft TMT .tm7 model to Threat Dragon JSON")
    m.add_argument("model", help="the .tm7 file")
    m.add_argument("--out", help="where to write (default: same name with .json)")
    m.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    m.set_defaults(func=cmd_import)

    x = sub.add_parser("export", help="write a Threat Dragon model as a Microsoft TMT .tm7 file")
    x.add_argument("model")
    x.add_argument("--out", help="where to write (default: same name with .tm7)")
    x.add_argument("--force", action="store_true", help="overwrite --out if it exists")
    x.add_argument("--template", help="path to a .tb7 template (default: SDL TM Knowledge Base)")
    x.set_defaults(func=cmd_export)

    c = sub.add_parser("coverage", help="which template rules can fire from TD properties alone")
    c.add_argument("--template")
    c.set_defaults(func=cmd_coverage)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except UsageError as e:
        print(f"tdtm: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
