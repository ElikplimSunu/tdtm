"""Threat Dragon v2 JSON <-> internal model. SPEC section 2. PLAN task 1.1.

Contract:
- `load(path) -> tuple[Model, Document]`: parse every diagram; identify cells by `data.type`
  (see `model.TD_TYPE_TO_KIND`), skip `tm.Text`; warn (in `Model.warnings`) on dangling flows.
- `Document` holds the original parsed JSON plus an index cell_id -> cell dict, so writes are
  patches to the original structure. Nothing the adapter does not understand is ever dropped.
- `save(doc, path)`: write JSON with the same indentation style Threat Dragon uses (2 spaces).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .model import Model


@dataclass
class Document:
    raw: dict
    cells: dict[str, dict] = field(default_factory=dict)  # cell_id -> cell dict inside raw


def load(path: str | Path) -> tuple[Model, Document]:
    raise NotImplementedError("PLAN 1.1")


def save(doc: Document, path: str | Path) -> None:
    raise NotImplementedError("PLAN 1.1")
