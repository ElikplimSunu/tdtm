"""One version for the app and the command, written the same everywhere (scripts/bump.py)."""

import json
import re
import tomllib
from pathlib import Path

from threatsketch import __version__

ROOT = Path(__file__).parent.parent


def test_every_version_source_agrees():
    app = ROOT / "app"
    cargo = tomllib.loads((app / "src-tauri/Cargo.toml").read_text())["package"]["version"]
    tauri = json.loads((app / "src-tauri/tauri.conf.json").read_text())["version"]
    lock = json.loads((app / "package-lock.json").read_text())
    assert json.loads((app / "package.json").read_text())["version"] == __version__
    assert lock["version"] == lock["packages"][""]["version"] == __version__
    assert cargo == __version__
    assert tauri == "../package.json"  # Tauri reads the app's package.json
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?", __version__)


def test_changelog_has_an_unreleased_section_or_this_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    assert "## [Unreleased]" in text
    assert f"## [{__version__}]" in text or "## [Unreleased]" in text
