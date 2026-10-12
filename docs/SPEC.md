# tdtm design spec

Status markers used below:
- **[confirmed]** checked against real files on 2026-10-12 (and locked in by `tests/test_spike_facts.py` where possible)
- **[verify]** believed true, not yet checked; the PLAN task that depends on it must check it first

## 1. Goal and scope

Given a Threat Dragon v2 model, generate the threats Microsoft TMT would generate for the same
diagram using the SDL TM Knowledge Base template, write them into the model so Threat Dragon shows
them, and produce a TMT-style report. Re-running must be safe.

Out of scope for v1: editing inside the Threat Dragon UI, a graphical template editor, Azure and
Medical Device templates (the parser should not preclude them), `.tm7` import/export (Phase 3).

## 2. Threat Dragon v2 file format

Source: `tests/fixtures/td/*.json` (from OWASP/threat-dragon `ThreatDragonModels/`) and
`tests/fixtures/schema/threat-dragon-v2.schema.json`.

### 2.1 Top level [confirmed]

```json
{
  "version": "2.0",
  "summary": {"title": "...", "owner": "...", "description": "...", "id": 0},
  "detail": {
    "contributors": [], "reviewer": "", "threatTop": 0, "diagramTop": 0,
    "diagrams": [
      {"id": 0, "title": "...", "diagramType": "STRIDE", "version": "...", "thumbnail": "...",
       "cells": [ ... ]}
    ]
  }
}
```

Schema conformance: Threat Dragon's own sample files fail its v2 schema in exactly one way: cell
`attrs.*.strokeDasharray` is `null` where the schema says string. Threat Dragon only warns on load.
tdtm's "output validates" checks use the same tolerance (see `test_spike_facts.py`) and must not
introduce any other error. Fixture `version` values seen: `"2.0"`, `"2.1.3"`; accept any `2.x`.

Process every diagram. `threatTop` is a counter Threat Dragon uses for threat `number`s; when
adding threats, increment it and assign `number` the way the UI does. **[verify]** in td.vue source.

### 2.2 Cells [confirmed]

Identify cell kind by `data.type`, **not** `shape`. A real fixture contains the misspelled shape
`trust-broundary-curve`.

| data.type | shape | kind | geometry |
|---|---|---|---|
| `tm.Actor` | `actor` | node | `position{x,y}`, `size{width,height}` |
| `tm.Process` | `process` | node | same |
| `tm.Store` | `store` | node | same |
| `tm.BoundaryBox` | `trust-boundary-box` | node (container) | same; a rectangle |
| `tm.Text` | `td-text-block` | ignore | |
| `tm.Flow` | `flow` | edge | `source{cell}` and `target{cell}`, optional `vertices[]` |
| `tm.Boundary` | `trust-boundary-curve` | edge (line) | `source{x,y}`, `target{x,y}`, optional `vertices[]`, `connector: "smooth"` |

A flow's `source`/`target` can be a bare point `{x,y}` when it is dangling. Treat dangling flows as
"unconnected": skip them and emit a warning.

### 2.3 Element properties [confirmed in samples; full list **[verify]** against schema]

Common `data`: `name`, `description`, `outOfScope`, `reasonOutOfScope`, `isTrustBoundary`,
`hasOpenThreats`, `threats[]`.

| kind | properties |
|---|---|
| actor | `providesAuthentication` |
| process | `privilegeLevel`, `isWebApplication`, `handlesCardPayment`, `handlesGoodsOrServices` |
| store | `isALog`, `storesCredentials`, `isEncrypted`, `isSigned`, `storesInventory` |
| flow | `protocol`, `isEncrypted`, `isPublicNetwork`, `isBidirectional` |

Out-of-scope elements (`outOfScope: true`) get no generated threats, and interactions where both
ends are out of scope are skipped. **[verify]** what TMT does with out-of-scope elements and match it.

### 2.4 Threats [confirmed]

Schema-required: `title`, `type`, `status`, `severity`, `description`, `mitigation`.
Optional: `modelType`, `number`, `score`, `threatId`. Samples also carry `id` (a UUID).
Preserve whatever keys exist.

- `type` (STRIDE diagrams): sample strings are `"Information disclosure"`, `"Denial of service"`.
  Full set **[verify]** in td.vue (expected: Spoofing, Tampering, Repudiation, Information
  disclosure, Denial of service, Elevation of privilege).
- `severity`: `TBD | Low | Medium | High | Critical`.
- `status`: `NotApplicable | Open | Mitigated` plus treatment outcomes. Exact stored strings **[verify]**.
- After changing threats, recompute `data.hasOpenThreats` on the cell. Threat Dragon colours
  elements red from this flag.

### 2.5 Custom keys

The v2 schema has no `additionalProperties: false`, so extra keys validate. **[verify, manual]**:
whether the Threat Dragon desktop app keeps unknown keys in `data` and in threat objects after
you edit and re-save. The design does not depend on it (see section 4), but `merge.py` stores
provenance on each generated threat in a `tdtm` key. If the UI strips it, merge falls back to the
sidecar file (section 6.3).

## 3. Microsoft template (`.tb7`) format [confirmed]

File: `src/tdtm/data/templates/default.tb7`, the root `<KnowledgeBase>`, manifest
name `SDL TM Knowledge Base (Core)`, version `4.1.0.11`. This is the template TMT users pick as
"SDL TM Knowledge Base", and the one tdtm must match.

Children: `Manifest`, `ThreatMetaData`, `GenericElements`, `StandardElements`,
`ThreatCategories`, `ThreatTypes`.

### 3.1 Elements

Generic element IDs and their attributes:

| ID | meaning | attributes (`<Attribute><Name>`) |
|---|---|---|
| `GE.P` | process | codeType, runningAs, Isolation, acceptsInputFrom, implementsAuthenticationScheme, implementsCustomAuthorizationMechanism, implementsCommunicationProtocol, hasInputSanitizers, hasOutputSanitizers |
| `GE.EI` | external interactor | authenticatesItself, type, MS |
| `GE.DS` | data store | storesCredentials, storesLogData, Encrypted, Signed, AccessType, RemoveableStorage, Backup, shared, storeType |
| `GE.DF` | data flow | channel, authenticatesSource, authenticatesDestination, providesConfidentiality, providesIntegrity, XMLenc, Cookies, SOAP, REST, RSS, JSON, `54851a3b-65da-4902-b4e0-94ef015be735` (displayed as "Forgery Protection") |
| `GE.TB.L` | line trust boundary | none |
| `GE.TB.B` | border trust boundary | none |
| `GE.A` | annotation | none |

Each attribute has a `DisplayName` and a list of `AttributeValues`. tdtm treats the **first value
as the default**. That matches the file's shape (most lists start with `Not Selected` or `No`) but
is **[assumed]**: only TMT itself can confirm it (PLAN 3.4). Exceptions worth knowing: `Cookies`
defaults to `Yes`, `authenticatesItself` to `Not Applicable`. Attribute names can be GUIDs.

`StandardElements` are stencils with a `ParentElement` (52 total): 15 under GE.P (e.g. Web
Application `SE.P.TMCore.WebApp`, Web Server, Browser Client, Thick Client, Win32 Service),
9 under GE.EI (Browser, Human User, External Web Service, ...), 10 under GE.DS (SQL Database,
Cloud Storage, Cookies, ...), 10 under GE.DF (HTTP, HTTPS, IPsec, ...), 4 under GE.TB.L
(Internet Boundary, Machine Trust Boundary, ...), 4 under GE.TB.B (CorpNet Trust Boundary, ...).
Inheritance is **one level** [confirmed, `test_stencil_inheritance_is_one_level`]: every SE's
parent is a GE, every GE's parent is `ROOT`. All GE attributes are `Mode=Dynamic` (user-selectable).
An SE attribute is either
- a `Mode=Static` override of a parent attribute with exactly one value, fixed for that stencil
  (Kernel Thread and Web Application force `codeType=Unmanaged`; HTTPS forces
  `providesConfidentiality`, `providesIntegrity` and `authenticatesDestination` to `Yes`), or
- a new `Mode=Dynamic` attribute the parent lacks (`IsInherited=false`), e.g. Windows Store app
  capabilities on `SE.P.TMCore.Modern`, `HTTPOnly` on Cookies, sandbox types on browser boundaries.

So a stencil's attributes are: its GE's attributes, plus its own new ones, with its Static
overrides applied. One rule tests `source.internetClient`, which only `SE.P.TMCore.Modern` has;
on any other source that test is false (3.5: unknown attribute, no match).

### 3.2 Threat categories

`S` Spoofing, `T` Tampering, `R` Repudiation, `I` Information Disclosure, `D` Denial Of Service,
`E` Elevation Of Privilege, `A` Abuse. No threat type in default.tb7 uses `A`.

### 3.3 Threat types

47 `ThreatType`s. Fields: `GenerationFilters{Include, Exclude}`, `Id` (e.g. `S1`, `T7`),
`ShortTitle`, `Category`, `Description`, `PropertiesMetaData`.

- `ShortTitle` and `Description` are templates with placeholders `{source.Name}`,
  `{target.Name}`, `{flow.Name}`. Placeholder case varies (`{source.name}` appears twice), so
  substitute case-insensitively. Example: `S1` title `Spoofing the {source.Name} Process`.
- 6 threat types have Include `source is 'ROOT'` and Description `Threat was migrated from V3.`
  These are legacy catch-alls. Default: **skip** them (flag `--include-legacy` to keep).
  **[verify, manual]** whether TMT 7.3 shows them for SDL models.
- 11 threat types have a non-empty Exclude.

### 3.4 Filter grammar [confirmed by scanning all 47 rules]

```
expr    := or
or      := and ("or" and)*
and     := atom ("and" atom)*
atom    := "(" expr ")" | test
test    := subject "is" STRING            # type test: element type or any descendant stencil
         | "flow" "crosses" STRING        # flow crosses a boundary of this type (or descendant)
         | subject "." ATTR "is" STRING   # attribute equality
subject := "source" | "target" | "flow"
STRING  := single-quoted
ATTR    := [A-Za-z0-9-]+                  # can be a GUID
```

Only `is`, `crosses`, `and`, `or`, parentheses occur. No `not`. Keywords are lowercase in the
file; parse case-insensitively anyway. `'ROOT'` matches any element.

Examples from default.tb7:

```
source is 'GE.P' and (target is 'GE.P' or target is 'GE.DS') and (flow crosses 'GE.TB.L' or flow crosses 'GE.TB.B')
source is 'GE.P' and target is 'GE.P' and target.codeType is 'Unmanaged'
EXCLUDE: (flow.providesConfidentiality is 'Yes' and flow.providesIntegrity is 'Yes')
```

### 3.5 Evaluation semantics

TMT generates threats per **interaction** = one data flow with its source and target. For each
flow F (source S, target T) and each threat type R:
`fires = eval(R.Include, S, F, T) and not eval(R.Exclude, S, F, T)` (empty Exclude = false).

- `x is 'ID'`: x's stencil is ID or descends from ID.
- `x.attr is 'V'`: x's effective attribute value equals V, where effective value =
  explicit tag value, else stencil static override, else attribute default. Unknown attr → no match.
- `flow crosses 'ID'`: the flow crosses at least one boundary whose stencil is or descends from ID.

Bidirectional TD flows (`isBidirectional: true`) are evaluated in both directions **[verify]**
what TMT does; TMT has no bidirectional flows, so two interactions is the faithful mapping.

Each firing produces one threat on the flow cell (the interaction). Title and description come
from the templates with names substituted.

## 4. Mapping Threat Dragon to TMT stencils

### 4.1 Default stencil by kind

| TD kind | default stencil | notes |
|---|---|---|
| actor | `GE.EI` | |
| process | `GE.P` (`SE.P.TMCore.WebApp` if `isWebApplication`) | |
| store | `GE.DS` | |
| flow | `GE.DF` | |
| boundary box | `GE.TB.B` | |
| boundary curve | `GE.TB.L` | |

### 4.2 Default attribute values from TD properties

| TD property | TMT attribute | mapping |
|---|---|---|
| flow.isEncrypted | providesConfidentiality, providesIntegrity | true → Yes |
| actor.providesAuthentication | authenticatesItself | true → Yes |
| store.storesCredentials | storesCredentials | true → Yes |
| store.isALog | storesLogData | true → Yes |
| store.isEncrypted | Encrypted | true → Yes |
| store.isSigned | Signed | true → Yes |
| flow.protocol | stencil hint | "HTTPS"/"HTTP/S" → `SE.DF.TMCore.HTTPS`; "HTTP" → `SE.DF.TMCore.HTTP` [confirmed IDs] |

TD false or missing properties do not set anything; the TMT default applies.

### 4.3 `@tmt` tags (the escape hatch for everything else)

Any line in an element's `description` that starts with `@tmt:` is parsed. Tags override
4.1 and 4.2.

```
@tmt: WebApp
@tmt: hasInputSanitizers=No; codeType=Managed
@tmt: stencil=SE.P.TMCore.WebApp; hasInputSanitizers=Yes
```

- A bare token is a stencil: matched against stencil ID, the ID suffix after the last dot,
  or Name, case- and space-insensitive (`WebApp`, `web application`, `SE.P.TMCore.WebApp`).
- `key=value` pairs set attributes. Keys match attribute `Name` or `DisplayName`
  (case/space-insensitive). Values must match one of the attribute's `AttributeValues`
  (case-insensitive) or it is an error.
- Unknown stencil/attribute/value is an error with a "did you mean" suggestion, not a silent skip.
- The description field is used because Threat Dragon is guaranteed to keep it. `tdtm stencils`
  lists every valid stencil and attribute so users can copy tags.

## 5. Boundaries

### 5.1 Membership

- An element is inside a boundary box if its centre point is inside the box rectangle. Boxes can
  nest; an element's zone is the innermost box containing it. No box → the implicit outer zone.
- A boundary box is a TMT border boundary (`GE.TB.B`).

### 5.2 Crossing

A flow crosses:
- a **box** if exactly one of its endpoints' centres is inside the box;
- a **curve** if the flow's polyline (source centre → vertices → target centre) intersects the
  curve's polyline (source → vertices → target). Threat Dragon draws curves with
  `connector: "smooth"`; approximate the curve by its control polyline, and expose
  `--curve-samples N` to subdivide a Catmull-Rom spline through the points if the polyline
  approximation proves wrong on real diagrams **[verify]**.

Flows that enter and leave the same box (both ends outside) do not cross it.

## 6. Merge

### 6.1 Identity

Each generated threat gets `tdtm: {"key": "<pack>:<rule-id>:<cell-id>[:<direction>]",
"fingerprint": "<sha1 of title|type|severity|status|description|mitigation as written>",
"version": "<tdtm version>"}` and a deterministic `id` = UUIDv5(namespace, key).

### 6.2 Re-run rules

For each cell, compare generated keys G with existing tdtm-owned threats E (existing threats with a
`tdtm.key`; threats without one are human-written and never touched):

| case | action |
|---|---|
| key in G and not in E | append new threat |
| key in G and E, fingerprint unchanged | refresh text (template wording may have changed) |
| key in G and E, fingerprint changed | the human edited it: leave untouched |
| key in E and not in G | do not delete; prefix title with `[stale] ` unless the human edited it; `--prune` removes unedited stale threats |

### 6.3 Sidecar fallback

If Threat Dragon strips the `tdtm` key (2.5), write `<model>.tdtm.json` beside the model mapping
threat `id` → `{key, fingerprint}`. Detect at load: a threat whose `id` is in the sidecar is
tdtm-owned. The adapter must work in both modes. Choose per the Phase 0 manual result.

### 6.4 Defaults for new threats

`status: "Open"`, `severity`: from rule pack (SDL template has empty Priority → `"TBD"`;
pytm severity maps directly), `modelType: "STRIDE"`, `mitigation`: pack text or `""`,
`type`: category mapped to TD STRIDE strings (Abuse → keep `"Abuse"`, flag in report).

## 7. Rule packs

### 7.1 `sdl` (default)

Compiled from `default.tb7` at runtime (fast enough; cache optional). `--template PATH` loads another
`.tb7`; nothing in the evaluator should be SDL-specific.

### 7.2 `pytm` (optional extra)

pytm **1.4.0** is installed via the `pytm` extra. Note: 1.4.0 classes are pydantic models
(`TM.model_dump` etc.), so README examples written for older versions may not apply. Build
`TM`, `Actor`, `Process`/`Server`, `Datastore`, `Dataflow`, `Boundary` objects from the model,
set `inBoundary` from section 5, call `tm.resolve()`, read findings. **[verify]** the exact 1.4.0 API
and how findings link back to elements (by name or uuid). pytm only knows boundaries by
membership, so its crossing rules follow from `inBoundary` on each end.

## 8. CLI

```
tdtm analyze MODEL [--pack sdl|pytm|all] [--template PATH] [--dry-run] [--prune]
                   [--include-legacy] [--out PATH]   # default: overwrite MODEL after writing MODEL.bak
tdtm inspect MODEL        # elements, resolved stencils/attributes, zones, crossings (debug view)
tdtm stencils [--kind process|store|...]   # valid @tmt stencils and attributes with allowed values
tdtm report MODEL [--out report.html]       # TMT-style HTML report from what is in the model
tdtm coverage [--template PATH]             # which rules can fire from TD props alone vs need tags
```

Exit codes: 0 ok, 1 usage error, 2 model/template error, 3 tag errors (with `--strict`).

## 9. Report

Single self-contained HTML file. Sections like TMT's report: summary counts by category/status,
diagram list, then per interaction: interaction name (`source → target`), each threat with
category, title, description, justification (= mitigation), priority (= severity), state (= status).

## 10. Testing strategy

- Unit tests per module, fixtures in `tests/fixtures/`.
- Golden test: `tests/fixtures/golden/` holds hand-built TD models with expected rule firings
  derived by reading the tb7 filters by hand.
- **Parity test [manual]:** someone on Windows draws the same model in TMT with the SDL template,
  exports the report, and we diff threat IDs/titles per interaction. This is the real
  acceptance test for "super similar to TMT".
