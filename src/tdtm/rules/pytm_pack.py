"""Optional pytm rule pack. SPEC section 7.2. PLAN task 4.1.

Import pytm lazily inside `run_pytm` so the core works without the extra installed; raise a clear
error telling the user to `uv sync --extra pytm` if it is missing.
"""

from __future__ import annotations


def run_pytm(model):
    raise NotImplementedError("PLAN 4.1")
