"""`tdtm` command line. SPEC section 8. Subcommands are wired; their bodies land per PLAN."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from . import __version__
from .model import Kind, Model
from .td_adapter import load, save


def _not_yet(task: str):
    def run(_args: argparse.Namespace) -> int:
        print(f"not implemented yet (docs/PLAN.md {task})", file=sys.stderr)
        return 1

    return run


GUID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


class UsageError(Exception):
    """A problem with the model or template the user pointed at (exit code 2)."""


def _load(args: argparse.Namespace):
    """Load and resolve. Returns (model, doc, template, tag errors)."""
    from .resolve import resolve
    from .rules.tb7 import load_template

    try:
        template = load_template(getattr(args, "template", None))
    except (OSError, ET.ParseError) as e:
        raise UsageError(f"cannot read template: {e}") from e
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


def cmd_analyze(args: argparse.Namespace) -> int:
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
        from .rules.pytm_pack import run_pytm

        try:
            generated += run_pytm(model)
        except NotImplementedError:
            print("tdtm: the pytm pack is not implemented yet (docs/PLAN.md 4.1)", file=sys.stderr)
            return 1

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

    s = merge(doc, generated, packs=packs, prune=args.prune, sidecar=sidecar)
    _report_problems(model, errors)
    if args.dry_run:
        for mark, keys in (("+", s.added), ("~", s.refreshed), ("!", s.stale), ("-", s.pruned)):
            for key in keys:
                print(f"{mark} {_where(key.split(':')[2], model, doc)}: {titles.get(key, key)}")
    print(
        f"{len(s.added)} added, {len(s.refreshed)} refreshed, {len(s.unchanged)} unchanged, "
        f"{len(s.kept_edited)} kept as you edited them, {len(s.stale)} newly stale, "
        f"{len(s.pruned)} pruned" + (" (dry run: nothing written)" if args.dry_run else "")
    )
    if args.dry_run:
        return 0

    if out.resolve() == Path(args.model).resolve():
        shutil.copyfile(args.model, f"{args.model}.bak")
    save(doc, out)
    if sidecar is not None:
        sidecar_out.write_text(json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8")
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
    a.set_defaults(func=cmd_analyze)

    i = sub.add_parser("inspect", help="show resolved stencils, attributes, zones and crossings")
    i.add_argument("model")
    i.add_argument("--template", help="path to a .tb7 template (default: SDL TM Knowledge Base)")
    i.set_defaults(func=cmd_inspect)

    s = sub.add_parser("stencils", help="list valid @tmt stencils and attributes")
    s.add_argument("--kind")
    s.add_argument("--template")
    s.set_defaults(func=_not_yet("3.1"))

    r = sub.add_parser("report", help="write a TMT-style HTML report")
    r.add_argument("model")
    r.add_argument("--out", default="report.html")
    r.set_defaults(func=_not_yet("3.2"))

    c = sub.add_parser("coverage", help="which template rules can fire from TD properties alone")
    c.add_argument("--template")
    c.set_defaults(func=_not_yet("3.1"))
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
