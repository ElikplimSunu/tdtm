"""`@tmt:` tags in element descriptions. SPEC section 4.3. PLAN task 1.3.

`parse_tags(description, kind, template) -> TagResult`: read every line starting with `@tmt:`
(case-insensitive, leading whitespace allowed). Bare tokens name a stencil; `key=value` pairs set
attributes; `;` separates items. Names and values match case- and space-insensitively and come back
in the template's spelling. Problems are collected as errors with suggestions, never raised.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from .model import KIND_ROOT, ROOT_NOUN, Kind

TAG_LINE = re.compile(r"^\s*@tmt:(.*)$", re.IGNORECASE | re.MULTILINE)


@dataclass
class TagResult:
    stencil: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return "".join(s.split()).lower()


def _suggest(word: str, choices: dict[str, str]) -> str:
    """choices: normalised key -> how to show it."""
    close = difflib.get_close_matches(_norm(word), choices, n=1, cutoff=0.6)
    return f"; did you mean {choices[close[0]]}?" if close else ""


def stencil_index(template, root: str | None = None) -> dict[str, str]:
    """Normalised ID, ID suffix and name -> stencil ID, for stencils under `root` (or all)."""
    index = {}
    for s in template.stencils.values():
        if root is None or s.root == root:
            for key in (s.id, s.id.rsplit(".", 1)[-1], s.name):
                index[_norm(key)] = s.id
    return index


def _find_stencil(token: str, kind: Kind, template, errors: list[str]) -> str | None:
    root = KIND_ROOT[kind]
    found = stencil_index(template, root).get(_norm(token))
    if found:
        return found
    elsewhere = stencil_index(template).get(_norm(token))
    if elsewhere:
        s = template.stencils[elsewhere]
        errors.append(
            f"stencil {token!r} ({s.name}) is a {ROOT_NOUN.get(s.root, s.root)} stencil, "
            f"but this element is a {ROOT_NOUN[root]}"
        )
        return None
    shown = {
        _norm(k): f"{template.stencils[sid].name!r} ({sid})"
        for k, sid in stencil_index(template, root).items()
    }
    errors.append(f"unknown stencil {token!r}{_suggest(token, shown)}")
    return None


def parse_tags(description: str, kind: Kind, template) -> TagResult:
    r = TagResult()
    items = [
        item.strip()
        for line in TAG_LINE.findall(description or "")
        for item in line.split(";")
        if item.strip()
    ]
    stencil_tokens, pairs = [], []
    for item in items:
        key, eq, value = (part.strip() for part in item.partition("="))
        if not eq:
            stencil_tokens.append(item)
        elif _norm(key) == "stencil":
            stencil_tokens.append(value)
        else:
            pairs.append((key, value))

    if len(stencil_tokens) > 1:
        r.errors.append(f"more than one stencil given: {', '.join(stencil_tokens)}")
    elif stencil_tokens:
        r.stencil = _find_stencil(stencil_tokens[0], kind, template, r.errors)

    attrs = template.attributes_for(r.stencil or KIND_ROOT[kind])
    by_key = {_norm(k): a for a in attrs.values() for k in (a.name, a.display_name)}
    for key, value in pairs:
        a = by_key.get(_norm(key))
        if a is None:
            shown = {_norm(k): f"{a.name!r} ({a.display_name})" for k, a in by_key.items()}
            r.errors.append(f"unknown attribute {key!r}{_suggest(key, shown)}")
            continue
        match = next((v for v in a.values if _norm(v) == _norm(value)), None)
        if match is None:
            r.errors.append(
                f"{value!r} is not a value of {a.name} ({a.display_name}); "
                f"allowed: {', '.join(a.values)}"
            )
        else:
            r.attributes[a.name] = match
    return r
