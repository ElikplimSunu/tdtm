"""Parse Microsoft TMT `.tb7` templates. SPEC section 3. PLAN task 1.2.

- `load_template(path=DEFAULT_TEMPLATE) -> Template` using xml.etree (stdlib).
- `Template.stencils`: ID -> Stencil, generic (GE.*) and standard (SE.*) elements.
- `Template.is_a(stencil_id, ancestor_id)` walks the parent chain; 'ROOT' matches all.
- `Template.attributes_for(stencil_id)`: the parent's attributes, plus the stencil's own new ones,
  with its static overrides applied (SPEC 3.1).
- `Template.categories`: letter -> name. `Template.threat_types`: in file order.
- `Template.default_priority`: first value of the template-level Priority list ("High" in SDL),
  which TMT gives every threat whose type sets no priority (SPEC 6.4)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from pathlib import Path

ROOT = "ROOT"


@dataclass(frozen=True)
class Attribute:
    name: str
    display_name: str
    values: list[str]
    static: bool  # Mode=Static: fixed by the stencil, the single value always applies

    @property
    def default(self) -> str:
        return self.values[0]  # SPEC 3.1: first value is the default [assumed]


@dataclass
class Stencil:
    id: str
    name: str
    parent: str
    root: str = ""  # the GE.* ancestor, or itself for a GE
    image: str = ""  # base64 PNG; inherited from the parent when the stencil has none
    image_location: str = ""  # TMT's ImageLocation, e.g. "Centered on stencil"
    own_attributes: dict[str, Attribute] = field(default_factory=dict)


@dataclass(frozen=True)
class ThreatType:
    id: str
    short_title: str
    category: str
    description: str
    include: str
    exclude: str
    priority: str | None

    @property
    def legacy(self) -> bool:
        return self.include.strip() == f"source is '{ROOT}'"  # SPEC 3.3: migrated from V3


@dataclass
class Template:
    name: str
    stencils: dict[str, Stencil]
    categories: dict[str, str]
    threat_types: list[ThreatType]
    default_priority: str | None = None

    def is_a(self, stencil_id: str, ancestor_id: str) -> bool:
        if ancestor_id == ROOT:
            return True
        while stencil_id in self.stencils:
            if stencil_id == ancestor_id:
                return True
            stencil_id = self.stencils[stencil_id].parent
        return False

    def attributes_for(self, stencil_id: str) -> dict[str, Attribute]:
        s = self.stencils[stencil_id]
        attrs = dict(self.attributes_for(s.parent)) if s.parent in self.stencils else {}
        for name, a in s.own_attributes.items():
            # a static override keeps the parent's display name; a new attribute is taken whole
            attrs[name] = (
                replace(attrs[name], values=a.values, static=True)
                if a.static and name in attrs
                else a
            )
        return attrs


def _text(el: ET.Element, path: str) -> str:
    return (el.findtext(path) or "").strip()


def _attribute(el: ET.Element) -> Attribute:
    return Attribute(
        name=_text(el, "Name"),
        display_name=_text(el, "DisplayName"),
        values=[(v.text or "").strip() for v in el.findall("AttributeValues/Value")],
        static=_text(el, "Mode") == "Static",
    )


def _metadatum(tt: ET.Element, name: str) -> str | None:
    """First value of the named ThreatMetaDatum under `tt` (a ThreatType or ThreatMetaData)."""
    for m in tt.findall("PropertiesMetaData/ThreatMetaDatum"):
        if _text(m, "Name") == name:
            return _text(m, "Values/Value") or None
    return None


def load_template(path: str | Path | None = None) -> Template:
    if path is None:
        from .. import DEFAULT_TEMPLATE

        path = DEFAULT_TEMPLATE
    root = ET.parse(str(path)).getroot()

    stencils: dict[str, Stencil] = {}
    for section in ("GenericElements", "StandardElements"):
        for el in root.findall(f"{section}/ElementType"):
            s = Stencil(
                id=_text(el, "ID"),
                name=_text(el, "Name"),
                parent=_text(el, "ParentElement"),
                image=_text(el, "Image"),
                image_location=_text(el, "ImageLocation"),
            )
            s.own_attributes = {
                a.name: a for a in map(_attribute, el.findall("Attributes/Attribute"))
            }
            stencils[s.id] = s
    for s in stencils.values():
        s.root = s.id
        while stencils.get(s.root) and stencils[s.root].parent in stencils:
            s.root = stencils[s.root].parent
        parent = stencils.get(s.parent)
        while parent and not (s.image and s.image_location):
            s.image, s.image_location = (
                s.image or parent.image,
                s.image_location or parent.image_location,
            )
            parent = stencils.get(parent.parent)

    return Template(
        name=root.find("Manifest").get("name", ""),
        stencils=stencils,
        categories={
            _text(c, "Id"): _text(c, "Name")
            for c in root.findall("ThreatCategories/ThreatCategory")
        },
        threat_types=[
            ThreatType(
                id=_text(tt, "Id"),
                short_title=_text(tt, "ShortTitle"),
                category=_text(tt, "Category"),
                description=_text(tt, "Description"),
                include=_text(tt, "GenerationFilters/Include"),
                exclude=_text(tt, "GenerationFilters/Exclude"),
                priority=_metadatum(tt, "Priority"),
            )
            for tt in root.findall("ThreatTypes/ThreatType")
        ],
        default_priority=_metadatum(root.find("ThreatMetaData"), "Priority"),
    )
