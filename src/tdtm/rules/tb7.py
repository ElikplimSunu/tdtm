"""Parse Microsoft TMT `.tb7` templates. SPEC section 3. PLAN task 1.2.

Contract:
- `load_template(path=DEFAULT_TEMPLATE) -> Template` using xml.etree (stdlib).
- `Template.stencils`: ID -> Stencil(id, name, parent, kind_root, attributes, static_overrides).
  Include generic (GE.*) and standard (SE.*) elements.
- `Template.is_a(stencil_id, ancestor_id) -> bool` walks the parent chain; 'ROOT' matches all.
- `Template.attributes_for(stencil_id)`: inherited attributes with their allowed values and default.
- `Template.categories`: letter -> name. `Template.threat_types`: list of ThreatType(id,
  short_title, category, description, include, exclude, legacy) where legacy = migrated-from-V3.
"""

from __future__ import annotations


def load_template(path=None):
    raise NotImplementedError("PLAN 1.2")
