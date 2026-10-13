"""threatsketch: Microsoft TMT-style threat generation for OWASP Threat Dragon models."""

from importlib.resources import files

__version__ = "0.3.0"

DEFAULT_TEMPLATE = files("threatsketch") / "data" / "templates" / "default.tb7"
