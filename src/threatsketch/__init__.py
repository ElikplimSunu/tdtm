"""ThreatSketch: Microsoft TMT-style threat generation for data-flow diagrams."""

from importlib.resources import files

__version__ = "0.5.0"

DEFAULT_TEMPLATE = files("threatsketch") / "data" / "templates" / "default.tb7"
