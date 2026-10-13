"""Open a model in the Threat Dragon desktop app (macOS). Used by `tdtm open`.

Threat Dragon 2.6.2 crashes with a main-process error dialog when macOS hands it a file before its
window has loaded (`menu.js openModelRequest` uses a window set only on `did-finish-load`), which
is what `open -a App file` does on a cold start. So on a cold start: launch it empty, wait for its
log to show startup, give the page time to load, then send the file, and check its log that it
accepted it. Facts from td.vue/src at ff27a5e; see SPEC 12.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

APP = "Threat-Dragon-ng"
LOG = Path.home() / "Library" / "Logs" / "Threat Dragon" / "main.log"
STARTED = "Checking for update"  # logged when the window is created, before its page loads
CONFIRMED = "Open model confirmation from renderer for file name: "  # not translated
# ponytail: fixed wait for the page to load after STARTED; a slower Mac may need more. Nothing in
# Threat Dragon's log marks the moment, so raise this if a cold start shows the error dialog.
LOAD_MARGIN = 4.0


def installed() -> bool:
    return subprocess.run(["open", "-Ra", APP], capture_output=True).returncode == 0


def is_running() -> bool:
    cmd = ["pgrep", "-f", f"{APP}.app/Contents/MacOS"]
    return subprocess.run(cmd, capture_output=True).returncode == 0


def _log_size() -> int:
    try:
        return LOG.stat().st_size
    except FileNotFoundError:
        return 0


def _wait_for(text: str, since: int, timeout: float) -> bool:
    """True once `text` appears in Threat Dragon's log after byte offset `since`."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            with LOG.open("rb") as f:
                f.seek(since)
                if text in f.read().decode("utf-8", "replace"):
                    return True
        except FileNotFoundError:
            pass
        if time.monotonic() > deadline:
            return False
        time.sleep(0.25)


def open_in_threat_dragon(path: Path) -> bool:
    """Show `path` in Threat Dragon. Returns False (after saying what to do) if it could not."""
    target = str(Path(path).absolute())
    manual = f"open {target} in Threat Dragon yourself (File > Open Model)"
    if sys.platform != "darwin":
        print(f"tdtm only drives Threat Dragon on macOS: {manual}")
        return False
    if not installed():
        print(f"Threat Dragon is not installed: brew install --cask threat-dragon, then {manual}")
        return False
    if not is_running():
        since = _log_size()
        subprocess.run(["open", "-a", APP], capture_output=True)
        if not _wait_for(STARTED, since, 60):
            print(f"Threat Dragon did not start in time: {manual}")
            return False
        time.sleep(LOAD_MARGIN)
    since = _log_size()
    subprocess.run(["open", "-a", APP, target], capture_output=True)
    if _wait_for(CONFIRMED + target, since, 10):
        return True
    print(f"Threat Dragon has not opened the model (did it ask about unsaved changes?): {manual}")
    return False
