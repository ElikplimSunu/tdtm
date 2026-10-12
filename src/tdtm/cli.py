"""`tdtm` command line. SPEC section 8. Subcommands are wired; their bodies land per PLAN."""

from __future__ import annotations

import argparse
import sys

from . import __version__


def _not_yet(task: str):
    def run(_args: argparse.Namespace) -> int:
        print(f"not implemented yet (docs/PLAN.md {task})", file=sys.stderr)
        return 1

    return run


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
    a.set_defaults(func=_not_yet("2.5"))

    i = sub.add_parser("inspect", help="show resolved stencils, attributes, zones and crossings")
    i.add_argument("model")
    i.set_defaults(func=_not_yet("1.6"))

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
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
