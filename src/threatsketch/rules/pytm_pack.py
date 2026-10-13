"""Optional pytm rule pack. SPEC section 7.2. PLAN task 4.1.

`run_pytm(model) -> list[GeneratedThreat]`.

pytm is imported lazily so the core works without the extra installed. pytm evaluates its threat
conditions with `eval`; we only ever let it load its own bundled threat library, never a file
from the user (CLAUDE.md rule 1).

Mapping (SPEC 7.2): actor -> Actor, process -> Process (Server if `isWebApplication`), store ->
Datastore, flow -> Dataflow (two for a bidirectional flow).
"""

from __future__ import annotations

import re

from ..model import GeneratedThreat, Kind, Model

# pytm's library has no STRIDE field; this is threatsketch's reading of each SID prefix (SPEC 7.2).
CATEGORY_BY_PREFIX = {
    "INP": "T",  # input validation and injection
    "SC": "T",  # script injection, XSS
    "API": "T",
    "LB": "T",  # API manipulation
    "LLM": "T",  # prompt injection, poisoning
    "AC": "E",  # access control, privilege abuse
    "AA": "S",  # authentication abuse, principal spoofing
    "CR": "S",  # session sidejacking, credential forging, password attacks
    "DS": "I",  # excavation, footprinting
    "DE": "I",  # interception, sniffing
    "DR": "I",  # unprotected sensitive data
    "HA": "I",  # reverse engineering, fingerprinting, path traversal
    "DO": "D",  # flooding, resource exhaustion
}
SEVERITY = {
    "Very High": "Critical",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Very Low": "Low",
}


class PytmMissing(RuntimeError):
    pass


def run_pytm(model: Model) -> list[GeneratedThreat]:
    try:
        from pytm import TM, Actor, Dataflow, Datastore, Process, Server
    except ImportError as e:
        raise PytmMissing("the pytm pack needs pytm: run `uv sync --extra pytm`") from e

    out: list[GeneratedThreat] = []
    for d in model.diagrams:
        if d.diagram_type != "STRIDE":
            continue
        TM.reset()  # pytm keeps elements and threats in class-level state
        tm = TM(d.title or "diagram", description=model.title or "Threat Dragon model")
        where: dict[int, tuple[str, str | None]] = {}  # id(pytm object) -> (cell id, direction)

        # ponytail: no Boundary objects; no condition in pytm 1.4.0's library reads inBoundary.
        # Map zones (SPEC 5) to Boundary/inBoundary if a later pytm version starts using them.
        nodes = {}
        for e in d.of_kind(Kind.ACTOR, Kind.PROCESS, Kind.STORE):
            if e.kind is Kind.ACTOR:
                obj = Actor(e.label)
            elif e.kind is Kind.PROCESS:
                obj = (Server if e.td_props.get("isWebApplication") else Process)(e.label)
            else:
                obj = Datastore(e.label)
                obj.storesLogData = bool(e.td_props.get("isALog"))
                obj.storesSensitiveData = bool(e.td_props.get("storesCredentials"))
                obj.controls.isEncryptedAtRest = bool(e.td_props.get("isEncrypted"))
            obj.inScope = not e.out_of_scope
            nodes[e.cell_id] = obj
            where[id(obj)] = (e.cell_id, None)

        for f in d.of_kind(Kind.FLOW):
            ends = [(f.source_id, f.target_id, None)]
            if f.td_props.get("isBidirectional"):
                ends = [(f.source_id, f.target_id, "fwd"), (f.target_id, f.source_id, "rev")]
            for src, tgt, direction in ends:
                flow = Dataflow(nodes[src], nodes[tgt], f.label)
                flow.protocol = str(f.td_props.get("protocol") or "")
                flow.controls.isEncrypted = bool(f.td_props.get("isEncrypted"))
                flow.inScope = not f.out_of_scope
                where[id(flow)] = (f.cell_id, direction)

        tm.resolve()
        for finding in tm.findings:
            cell_id, direction = where[id(finding.element)]
            prefix = re.sub(r"\d+$", "", finding.threat_id)
            out.append(
                GeneratedThreat(
                    pack="pytm",
                    rule_id=finding.threat_id,
                    cell_id=cell_id,
                    direction=direction,
                    category=CATEGORY_BY_PREFIX.get(prefix, "T"),
                    title=finding.description,
                    description=finding.details or finding.description,
                    severity=SEVERITY.get(finding.severity, "TBD"),
                    mitigation=finding.mitigations or "",
                )
            )
    TM.reset()
    return out
