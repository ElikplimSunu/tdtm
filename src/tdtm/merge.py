"""Merge generated threats into a Threat Dragon document. SPEC section 6. PLAN task 2.4.

`merge(doc, generated, *, packs=("sdl",), prune=False, sidecar=None) -> MergeSummary`

- A threat is tdtm-owned when it carries a `tdtm` key (inline mode) or its id is in `sidecar`
  (sidecar mode, SPEC 6.3: pass the dict, save it beside the model). A threat with neither is
  human-written and never touched, unless its id is one tdtm would have generated: then it is
  ours with the key stripped, kept as if edited so re-runs never duplicate it.
- An owned threat whose fields no longer match its fingerprint was edited by a human: never
  overwritten, never marked stale, never pruned.
- Owned threats whose rule stopped firing (for a pack in `packs`) get a `[stale] ` title prefix,
  or are removed with `prune`.
- Every cell holding owned threats gets `data.hasOpenThreats` and its outline recomputed the way
  Threat Dragon does (SPEC 2.4), since Threat Dragon does not restyle on load.
- Deterministic: same inputs give byte-identical output.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from . import __version__
from .model import GeneratedThreat

NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/ElikplimSunu/tdtm")  # frozen: IDs
STRIDE_TYPES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
    "A": "Abuse",  # no SDL rule uses it; kept as-is (SPEC 6.4)
}
FINGERPRINT_FIELDS = ("title", "type", "severity", "status", "description", "mitigation")
STALE = "[stale] "
OUTLINE = {  # data.type -> attrs parts Threat Dragon styles for open threats
    "tm.Actor": ("body",),
    "tm.Process": ("body",),
    "tm.Store": ("topLine", "bottomLine"),
    "tm.Flow": ("line",),
}


@dataclass
class MergeSummary:
    added: list[str] = field(default_factory=list)
    refreshed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    kept_edited: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)
    pruned: list[str] = field(default_factory=list)


def fingerprint(t: dict) -> str:
    return hashlib.sha1(
        "|".join(str(t.get(f, "")) for f in FINGERPRINT_FIELDS).encode()
    ).hexdigest()


def threat_id(key: str) -> str:
    return str(uuid.uuid5(NAMESPACE, key))


def _text(g: GeneratedThreat) -> dict:
    return {
        "title": g.title,
        "severity": g.severity,
        "type": STRIDE_TYPES.get(g.category, g.category),
        "description": g.description,
        "mitigation": g.mitigation,
    }


def merge(
    doc,
    generated: list[GeneratedThreat],
    *,
    packs: tuple[str, ...] = ("sdl",),
    prune: bool = False,
    sidecar: dict | None = None,
) -> MergeSummary:
    s = MergeSummary()

    def meta(t: dict) -> dict | None:
        m = sidecar.get(t.get("id")) if sidecar is not None else t.get("tdtm")
        return m if isinstance(m, dict) and "key" in m else None

    def stamp(t: dict, key: str) -> None:
        m = {"key": key, "fingerprint": fingerprint(t), "version": __version__}
        if sidecar is None:  # keep anything else under `tdtm`, e.g. what `tdtm import` kept
            t["tdtm"] = {**(t.get("tdtm") if isinstance(t.get("tdtm"), dict) else {}), **m}
        else:
            sidecar[t["id"]] = m

    detail = doc.raw.setdefault("detail", {})
    numbers = [
        t["number"]
        for c in doc.cells.values()
        for t in c.get("data", {}).get("threats") or []
        if isinstance(t.get("number"), int)
    ]
    top = start = max([int(detail.get("threatTop") or 0), *numbers])

    by_cell: dict[str, list[GeneratedThreat]] = {}
    for g in generated:
        by_cell.setdefault(g.cell_id, []).append(g)

    for cid, cell in doc.cells.items():
        data = cell.get("data", {})
        threats = data.get("threats") or []
        gens = by_cell.get(cid, [])
        owned = {meta(t)["key"]: t for t in threats if meta(t)}
        if not gens and not owned:
            continue
        threats = data.setdefault("threats", [])
        by_id = {t.get("id"): t for t in threats}

        for g in gens:
            t = owned.pop(g.key, None)
            if t is None and by_id.get(threat_id(g.key)) is not None:
                s.kept_edited.append(g.key)  # ours, but our key was stripped: treat as edited
            elif t is None:
                top += 1
                t = {"id": threat_id(g.key), "title": g.title, "status": "Open"}
                t.update(_text(g))
                t.update(modelType="STRIDE", new=False, number=top, score="")
                stamp(t, g.key)
                threats.append(t)
                s.added.append(g.key)
            elif fingerprint(t) != meta(t)["fingerprint"]:
                s.kept_edited.append(g.key)
            elif all(t.get(k) == v for k, v in _text(g).items()):
                s.unchanged.append(g.key)
            else:
                t.update(_text(g))  # also drops a [stale] prefix
                stamp(t, g.key)
                s.refreshed.append(g.key)

        for key, t in owned.items():  # owned threats whose rule did not fire this run
            if key.split(":", 1)[0] not in packs:
                continue
            if fingerprint(t) != meta(t)["fingerprint"]:
                s.kept_edited.append(key)
            elif prune:
                threats.remove(t)
                if sidecar is not None:
                    sidecar.pop(t.get("id"), None)
                s.pruned.append(key)
            elif not t["title"].startswith(STALE):
                t["title"] = STALE + t["title"]
                stamp(t, key)
                s.stale.append(key)

        is_open = any(str(t.get("status", "")).lower() == "open" for t in threats)
        data["hasOpenThreats"] = is_open
        for part in OUTLINE.get(data.get("type"), ()):
            a = cell.setdefault("attrs", {}).setdefault(part, {})
            a["stroke"], a["strokeWidth"] = ("red", 2.5) if is_open else ("#333333", 1.5)

    if top > start:
        detail["threatTop"] = top
    return s
