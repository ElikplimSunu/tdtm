from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
TD_MODELS = sorted((FIXTURES / "td").glob("*.json"))


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def td_schema_path() -> Path:
    return FIXTURES / "schema" / "threat-dragon-v2.schema.json"
