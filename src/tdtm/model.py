"""Internal model. Everything converts to and from these types (SPEC sections 2-6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Kind(StrEnum):
    ACTOR = "actor"
    PROCESS = "process"
    STORE = "store"
    FLOW = "flow"
    BOUNDARY_BOX = "boundary_box"
    BOUNDARY_CURVE = "boundary_curve"


# Threat Dragon data.type -> Kind. Identify cells by data.type, never by shape (SPEC 2.2).
TD_TYPE_TO_KIND: dict[str, Kind] = {
    "tm.Actor": Kind.ACTOR,
    "tm.Process": Kind.PROCESS,
    "tm.Store": Kind.STORE,
    "tm.Flow": Kind.FLOW,
    "tm.BoundaryBox": Kind.BOUNDARY_BOX,
    "tm.Boundary": Kind.BOUNDARY_CURVE,
}

NODE_KINDS = {Kind.ACTOR, Kind.PROCESS, Kind.STORE}


@dataclass(frozen=True)
class Point:
    x: float
    y: float


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    width: float
    height: float

    @property
    def centre(self) -> Point:
        return Point(self.x + self.width / 2, self.y + self.height / 2)

    def contains(self, p: Point) -> bool:
        return self.x <= p.x <= self.x + self.width and self.y <= p.y <= self.y + self.height


@dataclass
class Threat:
    """A threat as stored on a Threat Dragon cell. `raw` keeps every original key."""

    title: str
    type: str
    status: str
    severity: str
    description: str
    mitigation: str
    id: str | None = None
    tdtm_key: str | None = None  # set only on threats tdtm generated (SPEC 6.1)
    raw: dict = field(default_factory=dict)


@dataclass
class Element:
    """A node (actor/process/store), boundary, or flow in one diagram."""

    cell_id: str
    diagram_id: int | str
    kind: Kind
    name: str
    description: str = ""
    out_of_scope: bool = False
    td_props: dict = field(default_factory=dict)  # TD-specific properties, e.g. isEncrypted
    threats: list[Threat] = field(default_factory=list)

    # nodes and boxes
    rect: Rect | None = None
    # flows and curves
    source_id: str | None = None  # flows: connected cell ids
    target_id: str | None = None
    points: list[Point] = field(default_factory=list)  # curves: source, vertices..., target

    # filled in by later stages
    stencil: str | None = None  # TMT stencil ID, e.g. "SE.P.TMCore.WebApp"
    attributes: dict[str, str] = field(default_factory=dict)  # effective TMT attributes
    zone: str | None = None  # innermost boundary box cell id, None = outer zone
    crosses: list[str] = field(default_factory=list)  # flows: boundary cell ids crossed


@dataclass
class Diagram:
    id: int | str
    title: str
    diagram_type: str = "STRIDE"  # only STRIDE diagrams get generated threats (SPEC 2.1)
    elements: dict[str, Element] = field(default_factory=dict)

    def of_kind(self, *kinds: Kind) -> list[Element]:
        return [e for e in self.elements.values() if e.kind in kinds]


@dataclass
class Model:
    title: str
    diagrams: list[Diagram] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class GeneratedThreat:
    """Output of a rule pack, before merging into the document."""

    pack: str  # "sdl", "pytm"
    rule_id: str  # e.g. "S1"
    cell_id: str  # cell the threat attaches to (the flow, for TMT interactions)
    direction: str | None  # "fwd"/"rev" for bidirectional flows, else None
    category: str  # TMT category letter or pack-native category
    title: str
    description: str
    severity: str = "TBD"
    mitigation: str = ""

    @property
    def key(self) -> str:
        parts = [self.pack, self.rule_id, self.cell_id]
        if self.direction:
            parts.append(self.direction)
        return ":".join(parts)
