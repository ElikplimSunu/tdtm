"""tdtm: Microsoft TMT-style threat generation for OWASP Threat Dragon models."""

from importlib.resources import files

__version__ = "0.3.0"

DEFAULT_TEMPLATE = files("tdtm") / "data" / "templates" / "default.tb7"
