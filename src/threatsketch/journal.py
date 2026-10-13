"""The triage journal: analysis-view edits, kept beside the model in `<model>.triage.json`.

Threat Dragon keeps its own copy of the model in memory, so saving there can overwrite edits made
in the analysis view. Each analyze run re-applies the journal (SPEC 13):

- a threat back in the state it was generated in (fingerprint intact) gets the journal's values;
- a threat that differs from both was changed in Threat Dragon: that change wins and is written
  into the journal.

Known limit: deliberately setting a threat back to exactly its generated values in Threat Dragon
looks like a stale save, so the journal re-applies the older edit.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .merge import fingerprint

FIELDS = ("status", "severity", "mitigation", "tmtState")


def path_for(model_path: str | Path) -> Path:
    return Path(model_path).with_suffix(".triage.json")


def read(model_path: str | Path) -> dict:
    p = path_for(model_path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def write(model_path: str | Path, journal: dict) -> None:
    text = json.dumps(journal, indent=2, sort_keys=True, ensure_ascii=False)
    path_for(model_path).write_text(text, encoding="utf-8")


def values(t: dict) -> dict:
    meta = t.get("tdtm") if isinstance(t.get("tdtm"), dict) else {}
    return {
        "status": t.get("status", ""),
        "severity": t.get("severity", ""),
        "mitigation": t.get("mitigation", ""),
        "tmtState": meta.get("tmtState", ""),
    }


def set_values(t: dict, v: dict) -> None:
    t["status"], t["severity"], t["mitigation"] = v["status"], v["severity"], v["mitigation"]
    meta = t.setdefault("tdtm", {})
    if v.get("tmtState"):
        meta["tmtState"] = v["tmtState"]
    else:
        meta.pop("tmtState", None)


def entry(v: dict) -> dict:
    return {**{k: v.get(k, "") for k in FIELDS}, "at": datetime.now(UTC).isoformat()}


def apply(doc, journal: dict) -> tuple[int, bool]:
    """Re-apply journal entries to `doc`. Returns (threats restored, journal changed)."""
    restored, changed = 0, False
    for cell in doc.cells.values():
        for t in cell.get("data", {}).get("threats") or []:
            meta = t.get("tdtm") if isinstance(t.get("tdtm"), dict) else {}
            key = meta.get("key")
            if key not in journal:
                continue
            current = values(t)
            wanted = {k: journal[key].get(k, "") for k in FIELDS}
            if current == wanted:
                continue
            if meta.get("fingerprint") == fingerprint(t):  # as generated: a stale save
                set_values(t, wanted)
                restored += 1
            else:  # changed in Threat Dragon since: that wins
                journal[key] = entry(current)
                changed = True
    return restored, changed
