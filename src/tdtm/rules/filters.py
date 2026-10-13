"""TMT generation-filter expressions. SPEC sections 3.4 and 3.5. PLAN task 2.1.

Never eval. Tokenize -> recursive-descent parse into an AST -> evaluate by walking it against an
interaction context (source element, flow element, target element, template).

    expr    := and ("or" and)*
    and     := atom ("and" atom)*
    atom    := "(" expr ")" | subject "is" STRING | "flow" "crosses" STRING
             | subject "." ATTR "is" STRING
    subject := "source" | "target" | "flow"

`parse(text) -> Node` raises `FilterSyntaxError` with the position on bad input.
`evaluate(node, ctx) -> bool`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import Element

SUBJECTS = ("source", "target", "flow")
TOKEN = re.compile(r"\s*(?:(?P<str>'[^']*')|(?P<word>[A-Za-z0-9_-]+)|(?P<sym>[().])|(?P<bad>\S))")


class FilterSyntaxError(ValueError):
    pass


@dataclass(frozen=True)
class Or:
    items: tuple


@dataclass(frozen=True)
class And:
    items: tuple


@dataclass(frozen=True)
class Is:
    subject: str
    stencil: str


@dataclass(frozen=True)
class Crosses:
    stencil: str


@dataclass(frozen=True)
class AttrIs:
    subject: str
    attr: str
    value: str


@dataclass
class Context:
    template: object
    source: Element
    flow: Element
    target: Element
    crossed: list[str]  # stencil ids of the boundaries the flow crosses


def _tokenize(text: str) -> list[tuple[str, str, int]]:
    """-> [(kind, value, position)]; kind is 'str', 'word' (lowercased) or a symbol."""
    tokens, pos = [], 0
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break  # only trailing whitespace left
        start = m.start(m.lastgroup)
        if m.lastgroup == "bad":
            if m.group("bad") == "'":
                raise FilterSyntaxError(f"unterminated string at {start}: {text!r}")
            raise FilterSyntaxError(f"unexpected {m.group('bad')!r} at {start}: {text!r}")
        value = m.group(m.lastgroup)
        if m.lastgroup == "str":
            tokens.append(("str", value[1:-1], start))
        elif m.lastgroup == "word":
            tokens.append(("word", value, start))
        else:
            tokens.append((value, value, start))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, text: str):
        self.text, self.tokens, self.i = text, _tokenize(text), 0

    def error(self, expected: str):
        if self.i < len(self.tokens):
            _, value, pos = self.tokens[self.i]
            raise FilterSyntaxError(f"expected {expected} at {pos}, got {value!r}: {self.text!r}")
        raise FilterSyntaxError(f"expected {expected} at end: {self.text!r}")

    def peek_word(self) -> str | None:
        if self.i < len(self.tokens) and self.tokens[self.i][0] == "word":
            return self.tokens[self.i][1].lower()
        return None

    def take(self, kind: str, expected: str, word: str | None = None) -> str:
        if self.i < len(self.tokens):
            k, value, _ = self.tokens[self.i]
            if k == kind and (word is None or value.lower() == word):
                self.i += 1
                return value
        self.error(expected)

    def parse(self):
        node = self.expr()
        if self.i < len(self.tokens):
            self.error("'and', 'or' or end")
        return node

    def expr(self):
        items = [self.conj()]
        while self.peek_word() == "or":
            self.i += 1
            items.append(self.conj())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def conj(self):
        items = [self.atom()]
        while self.peek_word() == "and":
            self.i += 1
            items.append(self.atom())
        return items[0] if len(items) == 1 else And(tuple(items))

    def atom(self):
        if self.i < len(self.tokens) and self.tokens[self.i][0] == "(":
            self.i += 1
            node = self.expr()
            self.take(")", "')'")
            return node
        subject = self.take("word", "source, target or flow").lower()
        if subject not in SUBJECTS:
            self.i -= 1
            self.error("source, target or flow")
        if self.i < len(self.tokens) and self.tokens[self.i][0] == ".":
            self.i += 1
            attr = self.take("word", "an attribute name")
            self.take("word", "'is'", "is")
            return AttrIs(subject, attr, self.take("str", "a quoted value"))
        if subject == "flow" and self.peek_word() == "crosses":
            self.i += 1
            return Crosses(self.take("str", "a quoted stencil id"))
        self.take("word", "'is'" + (" or 'crosses'" if subject == "flow" else ""), "is")
        return Is(subject, self.take("str", "a quoted stencil id"))


def parse(text: str):
    return _Parser(text).parse()


def evaluate(node, ctx: Context) -> bool:
    match node:
        case Or(items):
            return any(evaluate(n, ctx) for n in items)
        case And(items):
            return all(evaluate(n, ctx) for n in items)
        case Is(subject, stencil):
            return ctx.template.is_a(getattr(ctx, subject).stencil, stencil)
        case Crosses(stencil):
            return any(ctx.template.is_a(b, stencil) for b in ctx.crossed)
        case AttrIs(subject, attr, value):
            actual = getattr(ctx, subject).attributes.get(attr)
            return actual is not None and actual.casefold() == value.casefold()
    raise TypeError(f"not a filter node: {node!r}")
