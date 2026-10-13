"""PLAN 2.3: engine output must equal the hand-derived firings in tests/fixtures/golden/."""

import json
from pathlib import Path

import pytest

from tdtm.resolve import resolve
from tdtm.rules.engine import run_sdl
from tdtm.rules.tb7 import load_template
from tdtm.td_adapter import load

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = sorted(  # private/ is gitignored: models from coursework, run only where present
    p
    for folder in ("golden", "private")
    for p in (FIXTURES / folder).glob("*.json")
    if not p.name.endswith(".expected.json") and p.with_name(p.stem + ".expected.json").exists()
)


@pytest.mark.parametrize("path", GOLDEN, ids=lambda p: p.stem)
def test_golden(path, td_schema_path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(td_schema_path.read_text())
    errors = list(jsonschema.validators.validator_for(schema)(schema).iter_errors(
        json.loads(path.read_text())
    ))  # fmt: skip
    assert errors == [], [e.message for e in errors]

    template = load_template()
    model, _ = load(path)
    assert resolve(model, template) == []
    assert model.warnings == []
    got = sorted(
        ({"flow": g.cell_id, "direction": g.direction, "rule": g.rule_id}
         for g in run_sdl(model, template)),
        key=lambda x: (x["flow"], x["direction"] or "", x["rule"]),
    )  # fmt: skip
    expected = json.loads(path.with_name(path.stem + ".expected.json").read_text())
    missing = [e for e in expected if e not in got]
    extra = [g for g in got if g not in expected]
    assert (missing, extra) == ([], [])
