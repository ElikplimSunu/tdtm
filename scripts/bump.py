"""Set the version of the app and the command everywhere it is written, and date the changelog.

Usage: uv run python scripts/bump.py 0.3.1

One version covers the whole repository (semantic versioning: MAJOR.MINOR.PATCH). This moves the
changelog's "Unreleased" section under the new version. Then commit, tag vX.Y.Z and push the tag:
the release workflow builds and publishes everything.
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$")


def sub(path: Path, pattern: str, repl: str) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if n != 1:
        sys.exit(f"bump: no match for {pattern!r} in {path}")
    path.write_text(new, encoding="utf-8")


def main(version: str) -> None:
    if not SEMVER.match(version):
        sys.exit(f"bump: {version!r} is not a semantic version like 1.2.3")
    sub(
        ROOT / "src/threatsketch/__init__.py", r'^__version__ = ".*"$', f'__version__ = "{version}"'
    )
    sub(ROOT / "app/src-tauri/Cargo.toml", r'^version = ".*"$', f'version = "{version}"')
    lock = ROOT / "app/src-tauri/Cargo.lock"
    if lock.exists():
        sub(lock, r'(name = "threatsketch"\nversion = )".*"', rf'\1"{version}"')
    for name in ("package.json", "package-lock.json"):
        path = ROOT / "app" / name
        data = json.loads(path.read_text(encoding="utf-8"))
        data["version"] = version
        if "packages" in data:
            data["packages"][""]["version"] = version
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    today = datetime.date.today().isoformat()
    dated = f"## [Unreleased]\n\n## [{version}] - {today}"
    sub(ROOT / "CHANGELOG.md", r"^## \[Unreleased\]$", dated)
    print(f"version {version}: now commit, tag v{version} and push the tag")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
