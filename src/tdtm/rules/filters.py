"""TMT generation-filter expressions. SPEC sections 3.4 and 3.5. PLAN task 2.1.

Never eval. Tokenize -> recursive-descent parse into an AST -> evaluate by walking it against an
interaction context (source element, flow element, target element, template).

Contract:
- `parse(text) -> Node` raises `FilterSyntaxError` with the position on bad input.
- `evaluate(node, ctx) -> bool`.
"""

from __future__ import annotations


class FilterSyntaxError(ValueError):
    pass


def parse(text: str):
    raise NotImplementedError("PLAN 2.1")


def evaluate(node, ctx) -> bool:
    raise NotImplementedError("PLAN 2.1")
