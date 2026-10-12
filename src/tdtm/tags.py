"""`@tmt:` tags in element descriptions. SPEC section 4.3. PLAN task 1.3.

Contract:
- `parse_tags(description, kind, template) -> TagResult`: read every line starting with `@tmt:`
  (case-insensitive, leading whitespace allowed). Bare tokens name a stencil; `key=value` pairs set
  attributes; `;` separates items. Validate against the template; collect errors with
  "did you mean" suggestions (difflib) rather than raising.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TagResult:
    stencil: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def parse_tags(description: str, kind, template) -> TagResult:
    raise NotImplementedError("PLAN 1.3")
