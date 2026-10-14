# ThreatSketch design spec

Status markers used below:
- **[confirmed]** checked against real files on 2026-10-12 (and locked in by `tests/test_spike_facts.py` where possible)
- **[verify]** believed true, not yet checked; the PLAN task that depends on it must check it first
- **[assumed]** cannot be checked without running TMT on Windows; left to the parity test (PLAN 3.4)

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
ThreatSketch's "output validates" checks use the same tolerance (see `test_spike_facts.py`) and must not
introduce any other error. Fixture `version` values seen: `"2.0"`, `"2.1.3"`; accept any `2.x`.

Load every diagram, but generate threats only on diagrams whose `diagramType` is `STRIDE` (or
absent). TMT's threats are STRIDE; a fixture also holds CIA, LINDDUN, DIE, PLOT4ai and Generic
diagrams, whose threat-type lists differ, so writing STRIDE threats there would be wrong. Those
diagrams are skipped with a warning and round-trip untouched.

`threatTop` is the counter behind threat `number`s [confirmed in td.vue 2.6.2,
`components/GraphMeta.vue:167-171`, `ThreatSuggestDialog.vue:193-209`]: a new threat gets
`number = threatTop + 1`, then `threatTop` is incremented. Numbers are never reused. A model with
no `threatTop` is given 100 when Threat Dragon opens it. ThreatSketch does the same per new threat,
starting from `max(threatTop or 0, highest existing number)` so it never duplicates a number.

Source facts in this section come from OWASP/threat-dragon commit `ff27a5e` (2.6.2), `td.vue/src`,
read in `vendor/threat-dragon` (gitignored).

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

A flow's `source`/`target` can be a bare point `{x,y}` when it is dangling (5 such flows in
`v2-boundary-box.json`). Treat dangling flows as unconnected: skip them and emit a warning. A
boundary curve whose ends are attached to cells (`{cell}` rather than `{x,y}`) has no fixed
geometry; skip it with a warning (none seen in fixtures).

### 2.3 Element properties [confirmed, `service/entity/default-properties.js`]

Common `data`: `type`, `name`, `description`, `outOfScope`, `reasonOutOfScope`, `isTrustBoundary`,
`hasOpenThreats`, `threats[]`.

| kind | properties |
|---|---|
| actor | `providesAuthentication` |
| process | `privilegeLevel`, `isWebApplication`, `handlesCardPayment`, `handlesGoodsOrServices` |
| store | `isALog`, `storesCredentials`, `isEncrypted`, `isSigned`, `storesInventory` |
| flow | `protocol`, `isEncrypted`, `isPublicNetwork`, `isBidirectional`, `trustBoundaryIds` |
| boundary box / curve | `crossingFlows`, `containedElements` (no `threats`) |
| text | `name` only |

`trustBoundaryIds`, `crossingFlows` and `containedElements` are recomputed by Threat Dragon on
every save; ThreatSketch ignores them (section 5). `isBidirectional: true` is drawn as a `block` marker on
`attrs.line.sourceMarker`.

Out of scope: Threat Dragon hides the add-threat button on out-of-scope cells and draws them
dashed. ThreatSketch skips an interaction when the flow is out of scope or both its ends are. What TMT
does is **[assumed]** to be similar; only TMT can confirm (PLAN 3.4).

### 2.4 Threats [confirmed]

Stored at `cell.data.threats[]` in every real file. (The v2 schema declares `threats` on the cell
itself, not inside `data`; the files disagree with the schema and the files win.)
Schema-required: `title`, `type`, `status`, `severity`, `description`, `mitigation`.
Optional: `modelType`, `number`, `score`, `threatId`. Samples also carry `id` (a UUID).
Preserve whatever keys exist.

- `type` (STRIDE): the stored value is the display string in the UI's language at creation time,
  not an i18n key. English: `Spoofing`, `Tampering`, `Repudiation`, `Information disclosure`,
  `Denial of service`, `Elevation of privilege` (`i18n/en.json:429-434`). Threat Dragon's UI
  offers only some types per kind (actor S,R; store T,R,I,D; flow T,I,D; process all), but keeps
  any stored type (`ThreatEditDialog.vue:300`). TMT attaches threats of every category to the
  flow, so ThreatSketch writes e.g. a Spoofing threat on a flow; Threat Dragon shows it.
- `severity`: `TBD | Low | Medium | High | Critical`; new threats get `TBD`.
- `status`: `NotApplicable | Open | Mitigated | Accepted | Transferred | Avoided | Eliminated`
  (`service/threats/status.js`); new threats get `Open`.
- New threat object (`service/threats/index.js:125-137`): `id` (uuid v4), `title`, `status`,
  `severity`, `type`, `description`, `mitigation`, `modelType` (`STRIDE`), `new` (false once
  applied), `number`, `score` (`""`). No `threatId` in practice.
- `hasOpenThreats` = some threat's `status` equals `Open` case-insensitively
  (`threats/index.js:140-141`).
- **Red outlines are stored, not computed on load** (`service/x6/graph/data-changed.js:48-66`;
  x6 adds cells silently on `fromJSON`). After changing threats ThreatSketch must set both
  `data.hasOpenThreats` and the stroke attrs, or the element opens black:
  open → `stroke: "red"`, `strokeWidth: 2.5`; otherwise `stroke: "#333333"`, `strokeWidth: 1.5`.
  Attr paths: actor and process `body`; store `topLine` and `bottomLine`; flow `line`.
  Boundaries and text have no threat styling.

### 2.5 Custom keys

The v2 schema has no `additionalProperties: false`, so extra keys validate. Reading the source,
Threat Dragon keeps unknown keys (high confidence): the threat editor edits a copy and writes back
field by field onto the existing object (`ThreatEditDialog.vue:393,455-470`), x6 deep-merges cell
`data` and `toJSON` deep-clones all props, and save spreads the diagram. A save does strip attrs
equal to shape defaults, drop `angle: 0`, rewrite `diagram.version` and recompute the boundary
keys, so a byte-equal round trip through Threat Dragon is not expected. **[verify, manual]**
(PLAN 0.2): confirm by editing and re-saving in the desktop app. The design does not depend on it (see section 4), but `merge.py` stores
provenance on each generated threat in a `tdtm` key. If the UI strips it, merge falls back to the
sidecar file (section 6.3).

## 3. Microsoft template (`.tb7`) format [confirmed]

File: `src/threatsketch/data/templates/default.tb7`, the root `<KnowledgeBase>`, manifest
name `SDL TM Knowledge Base (Core)`, version `4.1.0.11`. This is the template TMT users pick as
"SDL TM Knowledge Base", and the one ThreatSketch must match.

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

Each attribute has a `DisplayName` and a list of `AttributeValues`. The **first value is the
default** [confirmed against TMT 7.3, section 10]: a `.tm7` stores each selection as a
`SelectedIndex` into that list, untouched elements have index 0, and TMT's generated threats are
exactly the ones those first values predict. Exceptions worth knowing: `Cookies` defaults to
`Yes`, `authenticatesItself` to `Not Applicable`. Attribute names can be GUIDs.

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
  [confirmed: TMT 7.3 generated none of them across 12 interactions, section 10.]
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
- `x.attr is 'V'`: x's effective attribute value equals V, where effective value = the stencil's
  static value, else the `@tmt` tag value, else the value derived from a Threat Dragon property
  (4.2), else the attribute default. A static value cannot be changed in TMT, so a tag that
  disagrees with one is ignored with a warning. Values compare case-insensitively. Unknown attr
  → no match.
- `flow crosses 'ID'`: the flow crosses at least one boundary whose stencil is or descends from ID.

Bidirectional TD flows (`isBidirectional: true`) are evaluated in both directions **[assumed]**; TMT has no bidirectional flows, so two interactions is the faithful mapping.

Each firing produces one threat on the flow cell (the interaction). Title and description come
from the templates with names substituted.

## 4. Mapping Threat Dragon to TMT stencils

### 4.1 Default stencil by kind

| TD kind | default stencil | notes |
|---|---|---|
| actor | `GE.EI` | |
| process | `GE.P` (`SE.P.TMCore.WebApp` if `isWebApplication`) | |
| store | `GE.DS` | |
| flow | `GE.DF`, or the flow stencil named by `protocol` | `protocol` is matched like a tag against data-flow stencil names (`HTTPS`, `IPsec`, `SMB`, ...); `HTTP/S` counts as `HTTPS` |
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
| flow.protocol | stencil (4.1) | e.g. "HTTPS"/"HTTP/S" → `SE.DF.TMCore.HTTPS`, "HTTP" → `SE.DF.TMCore.HTTP` |

TD false or missing properties do not set anything; the TMT default applies.

### 4.2a What Threat Dragon alone can reach

`threatsketch coverage` tries every element Threat Dragon's own properties can express (4.1, 4.2) in
every source, flow, target and crossing combination. With default.tb7, **30 of the 41 non-legacy
rules** can fire without tags. The other 11 need `@tmt`: T3, T4, I26 (process implements a
protocol or authentication scheme), I2 (custom authorization), T7, T8 (SQL Database), T11, T12
(XML or JSON payload), I25 (Machine Trust Boundary), E3 (Authorization Provider), and T6, which
needs an authenticated flow without both confidentiality and integrity. Threat Dragon's settings
only give authentication together with encryption (HTTPS, IPsec), so T6 needs a tag such as
`@tmt: authenticatesSource=Yes` on an ordinary flow.

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
- Attribute keys are checked against the tagged stencil's attributes, or the kind's generic
  element's when no stencil is tagged (so `HTTPOnly` needs `@tmt: Cookies` on the same element).
- A stencil from the wrong kind (`@tmt: SQL Database` on a process) is an error naming both kinds.
- Unknown stencil/attribute/value is an error with a "did you mean" suggestion, not a silent skip.
- The description field is used because Threat Dragon is guaranteed to keep it. `threatsketch stencils`
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
  approximation proves wrong on real diagrams (it held on the demo model; see below).

Flows that enter and leave the same box (both ends outside) do not cross it. A flow running
along a curve (collinear) does not cross it.

On Threat Dragon's demo model every crossing decision has at least 39 px of clearance and none
changes when the curves are smoothed, so the polyline approximation holds there and
`--curve-samples` is not implemented (add it if a real diagram is misjudged).

Threat Dragon 2.6 computes its own `containedElements`/`crossingFlows`/`trustBoundaryIds` on
save (`service/diagram/boundary-utils.js`): an element is inside only if its whole box is inside,
and curves are judged by their bounding box. ThreatSketch does not read those keys: TMT treats a line
boundary as a line, which a bounding box cannot model.

## 6. Merge

### 6.1 Identity

Each generated threat gets `tdtm: {"key": "<pack>:<rule-id>:<cell-id>[:<direction>]",
"fingerprint": "<sha1 of title|type|severity|status|description|mitigation as written>",
"version": "<ThreatSketch version>"}` and a deterministic `id` = UUIDv5(namespace, key), where namespace =
UUIDv5(URL, `https://github.com/ElikplimSunu/tdtm`). The fingerprint is re-stamped whenever ThreatSketch
itself rewrites the threat (refresh, `[stale]` prefix), so only human changes break it.

### 6.2 Re-run rules

For each cell, compare generated keys G with existing ThreatSketch-owned threats E (existing threats with a
`tdtm.key`; threats without one are human-written and never touched):

| case | action |
|---|---|
| key in G and not in E | append new threat |
| key in G and E, fingerprint unchanged | refresh text (template wording may have changed) |
| key in G and E, fingerprint changed | the human edited it: leave untouched |
| key in E and not in G | do not delete; prefix title with `[stale] ` unless the human edited it; `--prune` removes unedited stale threats |
| key in G, no E, but a threat on the cell has `id` = UUIDv5(key) | ours with the `tdtm` key stripped: treat as edited, never duplicate it |

Staleness only applies to keys of the packs run this time, so `--pack pytm` never marks `sdl`
threats stale. A stale threat whose rule fires again is refreshed, which removes the prefix.

After merging, every cell holding ThreatSketch-owned threats gets `hasOpenThreats` and its outline attrs
recomputed with Threat Dragon's rule (2.4). `threatTop` is written only when threats were added.

### 6.3 Sidecar fallback

If Threat Dragon strips the `tdtm` key (2.5), write `<model>.tdtm.json` beside the model mapping
threat `id` → `{key, fingerprint}`. Detect at load: a threat whose `id` is in the sidecar is
ThreatSketch-owned. Both modes are implemented: `merge(..., sidecar=dict)` uses the sidecar. Inline is
the default because the source reading (2.5) says Threat Dragon keeps unknown keys; PLAN 0.2
confirms by hand. Either way the `id` fallback in 6.2 prevents duplicates.

### 6.4 Defaults for new threats

`status: "Open"`, `severity`: the threat type's own Priority, else the first value of the
template-level Priority list (`ThreatMetaData`: `High, Medium, Low` in SDL, so `"High"`), else
`"TBD"`. [confirmed against TMT 7.3: all 54 untouched threats in a real model have priority
High.] pytm severity maps directly, `modelType: "STRIDE"`, `mitigation`: pack text or `""`,
`type`: category mapped to TD STRIDE strings (Abuse → keep `"Abuse"`, flag in report),
`new: false`, `number`: `threatTop + 1` per threat in output order, `score: ""`. Threats on a
bidirectional flow get `(source → target)` appended to the title, since both directions land on
the same cell.

## 7. Rule packs

### 7.1 `sdl` (default)

Compiled from `default.tb7` at runtime (fast enough; cache optional). `--template PATH` loads another
`.tb7`; nothing in the evaluator should be SDL-specific.

### 7.2 `pytm` (optional extra)

pytm **1.4.0** is installed via the `pytm` extra (CI installs it; works on Python 3.11 and 3.14).
Confirmed API: `TM.reset()` first (elements and threats live in class-level state), build
`TM(name, description=...)` and `Actor`/`Process`/`Server`/`Datastore`/`Dataflow(src, dst, name)`
objects, call `tm.resolve()`, read `tm.findings`. Each finding has `element` (the pytm object, so
threatsketch maps back by object identity, not by name), `threat_id` (e.g. `INP03`), `description` (short),
`details`, `severity`, `mitigations`. Findings attach to nodes as well as flows.

Mapping: actor → `Actor`; process → `Process`, or `Server` if `isWebApplication`; store →
`Datastore` with `storesLogData` (isALog), `storesSensitiveData` (storesCredentials),
`controls.isEncryptedAtRest` (isEncrypted); flow → `Dataflow` with `protocol` and
`controls.isEncrypted`, two Dataflows for a bidirectional flow; `outOfScope` → `inScope = False`.

Boundaries are not mapped: no condition in pytm 1.4.0's threat library reads `inBoundary`, so
they would change nothing. Map zones (section 5) if a later pytm uses them.

pytm has no STRIDE field. ThreatSketch maps the SID prefix (`rules/pytm_pack.py CATEGORY_BY_PREFIX`):
INP, SC, API, LB, LLM → Tampering; AC → Elevation of privilege; AA, CR → Spoofing; DS, DE, DR, HA
→ Information disclosure; DO → Denial of service. This is ThreatSketch's judgement, not pytm's. Severity:
Very High → Critical, Very Low → Low, others unchanged.

pytm evaluates its conditions with `eval`; ThreatSketch only lets it load its bundled library.

## 8. CLI

```
threatsketch analyze MODEL [--pack sdl|pytm|all] [--template PATH] [--dry-run] [--prune]
                   [--include-legacy] [--out PATH]   # default: overwrite MODEL after writing MODEL.bak
                   [--sidecar]   # tracking data in MODEL.tdtm.json instead of in the threats (6.3)
                   [--strict]    # exit 3 on @tmt tag errors, write nothing
                   [--watch]     # re-run whenever MODEL changes (polls once a second)
threatsketch inspect MODEL [--template PATH]   # elements, stencils/attributes, zones, crossings
threatsketch stencils [--kind process|store|...]   # valid @tmt stencils and attributes with allowed values
threatsketch report MODEL [--out report.html]       # TMT-style HTML report from what is in the model
threatsketch coverage [--template PATH]             # which rules can fire from TD props alone vs need tags
```

Exit codes: 0 ok, 1 usage error, 2 model/template error, 3 tag errors (with `--strict`).

## 9. Report

`threatsketch report MODEL` (and the app's Report and Export) writes one self-contained HTML file
with TMT's Full Report sections in TMT's order: model details (name, owner, reviewer,
contributors, description, template), the Threat Model Summary by TMT state (Not Started, Needs
Investigation, Not Applicable, Mitigation Implemented, with the total) plus counts by STRIDE
category, then per diagram an SVG drawing of it (`diagram.py`, from the model's own geometry, in
TMT's style: ink lines, red dashed boundaries), and each interaction that has threats, with its
route and the boundaries it crosses: title, state, category, priority, rule, description and
justification (`<no mitigation provided>` when empty). Threats people attached to other elements
follow under `Element:`. Styles are `data/report.css`; IBM Plex is embedded from `data/fonts`, so
nothing is fetched. It prints to A4 with page numbers and never splits a threat across pages; the
"Save as PDF" button and `#print` open the print dialog (PDF is the browser's, no PDF library).
**[approximate]**: the section order is from memory of TMT 7.3's report; compare with a real TMT
report and adjust.

### 9a. CSV export

`threatsketch report MODEL --out NAME.csv` writes TMT's CSV export exactly: columns `Id, Title, Category,
Diagram, Interaction, Priority, State, Changed By, Description, Justification, Last Modified`,
CRLF line endings, no byte-order mark. Category uses the template's names (`Denial Of Service`);
State maps Open → `Not Started`, NotApplicable → `Not Applicable`; Last Modified is `Generated` for
an untouched ThreatSketch threat, else empty. [confirmed: reproduces a real TMT 7.3 export row for row,
for models whose threats are all untouched.] Changed By and Last Modified of a threat triaged in TMT
come from its `.tm7` (`ChangedBy`, `ModifiedAt`) [unverified: no TMT CSV with a triaged threat seen].

## 10. Testing strategy

- Unit tests per module, fixtures in `tests/fixtures/`.
- Golden test: `tests/fixtures/golden/` holds hand-built TD models with expected rule firings
  derived by reading the tb7 filters by hand.
- **Parity test:** a model drawn in TMT, imported with `threatsketch import`, must give exactly TMT's
  threats. `test_tm7.py::test_parity_with_real_tmt_output` runs on any model in
  `tests/fixtures/private/` (gitignored: real coursework, never committed) and skips otherwise.

Parity result, 2026-10-13. A real TMT 7.3 model built with SDL TM Knowledge Base 4.1.0.11 (the
same template ThreatSketch bundles): 4 external interactors and processes, 3 data stores, one boundary box,
12 flows, 54 generated threats, none edited. ThreatSketch produces **the same 54 threats**: identical rule
IDs per flow, identical titles and descriptions, identical category and priority, matching TMT's
own CSV export row for row; `threatsketch analyze` on the imported model reports 0 added, 54 unchanged.
This confirms: box crossings, actor/process/store rules, attribute defaults (3.1), legacy rules
skipped (3.3), placeholder substitution, default priority High (6.4).

Not exercised by that model, so still checked only against hand-derived golden models: boundary
curves, nested boxes, `@tmt` tags and non-default attributes, encrypted or HTTPS flows,
out-of-scope elements, bidirectional flows.

## 11. `.tm7` import

`threatsketch import MODEL.tm7 [--out PATH] [--force]` writes Threat Dragon JSON (default: same name,
`.json`; never overwrites without `--force`). Format facts from a real TMT 7.3 file
(`Version` 4.3), read by local element name so namespaces do not matter:

- Root `ThreatModel`: `DrawingSurfaceList`, `MetaInformation`, `ThreatInstances`,
  `KnowledgeBase` (the whole template, embedded, with its own element names), `Version`.
- Each `DrawingSurfaceModel` (title in `Header`) has `Borders` (shapes and boundary boxes:
  `Left`, `Top`, `Width`, `Height`) and `Lines` (flows and line boundaries: `SourceGuid`,
  `TargetGuid`, `SourceX/Y`, `TargetX/Y`, one middle `HandleX/Y`). Each element has
  `GenericTypeId` (GE.P ...), `TypeId` (the stencil), `Guid`, and `Properties`: the name
  (`StringDisplayAttribute` with DisplayName `Name`), out of scope (Boolean, Name
  `71f3d9aa-...`), reason (`752473b6-...`), and one `ListDisplayAttribute` per attribute with the
  allowed values and a `SelectedIndex`. `StaticListDisplayAttribute` holds fixed stencil values.
  Flows and boundaries also have `Dataflow Order` (String, Name `15ccd509-...`): "0" by default,
  numbered 1, 2, ... in a second real TMT 7.3 model. Import keeps a non-zero value under
  `tdtm.tm7.dataflowOrder`; export writes it back.
- `ThreatInstances`: per threat `TypeId` (rule), `FlowGuid`, `SourceGuid`, `TargetGuid`, `Id`,
  `State` (`AutoGenerated` until touched), `Priority`, `StateInformation` (justification),
  `ModifiedAt` (`0001-01-01` until touched), and `Properties` with `Title`,
  `UserThreatCategory` (e.g. "Denial Of Service"), `UserThreatDescription`.

Triage in TMT 7.3 sets `ChangedBy` to `MACHINE\user` and `ModifiedAt` to the time, ISO 8601 with
7-digit fractions and an offset (`2026-10-13T22:39:44.6125953+00:00`). The threat list, Threat
Properties and the CSV show both; the time as `13/10/2026 9:56:59 pm` (en-GB Windows; TMT follows
the Windows locale). Import keeps them under `tdtm.tm7`; triage here stamps `modifiedAt`.

TMT 7.3 keeps a threat's justification as the `StateInformation` entry of its `Properties`
(after `UserThreatDescription`), with the `StateInformation` element nil; import reads either, and
export writes it where the file had it (the property for new triage). `Notes` holds `<Note>`
elements with `AddedBy`, `Date`, `Id`, `Message`; import keeps them in `tdtm.tm7.notes`.
`ThreatGenerationEnabled` false is kept. TMT's own sample model has a boundary without its
`Trust Boundary Area` header and a diagram `Name` attribute with an empty key; both are kept.

TMT lists and exports a threat stored with `Id` 0 as the highest `Id` + 1 (a real model: 0 among
1..241 is 242 in TMT's CSV) and the file keeps 0. Import numbers it the same way and keeps the 0
under `tdtm.tm7.id` for export. [unverified: the reference model has one Id 0 threat; with
several, import numbers them highest + 1, + 2, ... in file order; TMT's own numbering not seen.]
Dataflow Order "" is read as the default and exported as "0" [unverified: no TMT file seen with
an empty value].

Mapping: GUIDs become cell ids, so a TMT threat and ThreatSketch's threat for the same rule and flow share
the key `sdl:<rule>:<flow guid>`. Non-generic stencil and every non-zero `SelectedIndex` become an
`@tmt:` line. TMT's middle handle becomes one flow vertex (approximation; TMT draws a curve).
TMT threats become ThreatSketch-tracked threats; untouched ones get a normal fingerprint so `analyze`
treats them as its own, triaged ones a fingerprint that never matches, so they are kept as edits.
State `Mitigated`/`NotApplicable` map across, everything else is `Open`.

Unverified (no example in the sample files): line boundaries (`GE.TB.L`), annotations (`GE.A`,
skipped with a warning), user-added custom threats. Multiple drawing surfaces: a second real
model has two and exports back unchanged. A `.tm7` with a
DOCTYPE or entity declarations is refused: TMT never writes one, and it is the usual XML attack.

## 12. `threatsketch open` and driving Threat Dragon (macOS)

`threatsketch open MODEL [--reload] [--no-launch] [--pack ...] [--template ...]`: create a blank STRIDE
model if MODEL is missing, or import a `.tm7` to `<stem>.json` (reusing an existing `.json`, which
may hold triage); analyze; write `<stem>.report.html` and `<stem>.csv`; open it in Threat Dragon;
then watch and repeat on every save.

Threat Dragon 2.6.2 facts (td.vue/src at ff27a5e, and its log at
`~/Library/Logs/Threat Dragon/main.log`), checked on a real install:
- `open -a Threat-Dragon-ng FILE` reaches the app as macOS `open-file`. When the app is running
  and its page has loaded, it opens FILE (if nothing is unsaved; otherwise it asks) and logs
  `Open model confirmation from renderer for file name: FILE`. [confirmed]
- On a cold start the same command crashes with a main-process `TypeError ... 'webContents'`
  dialog: the menu module only gets its window on `did-finish-load`. [confirmed, observed]
  So ThreatSketch launches the app empty, waits for `Checking for update` in the log (window created),
  waits `LOAD_MARGIN` (4 s) more for the page, then sends the file. No log line marks page load,
  so the margin is a calibrated guess. [confirmed once on an Intel Mac running Threat Dragon 2.6.2: no dialog, the
  model opened]
- An opened model lands on the model summary page, not the diagram. Because a reload while the
  user has unsaved edits makes Threat Dragon ask to discard them, automatic reload after each update
  is opt-in (`--reload`); by default ThreatSketch prints a reminder to reopen.

## 13. Analysis view

`threatsketch view MODEL [--port N] [--no-browser]`, also started by `threatsketch open` (unless `--no-view`):
TMT's Analysis View as a local web page. Diagram drawings (foldable), a grid of every threat
(ID, State, Title, Category, Interaction, Priority, Justification) with filters by state,
category and priority and a text search, and a Threat Properties panel for the selected row.
The page polls `/api/model` every 2 s and redraws when the file's mtime and size change.

**Editing.** For threats ThreatSketch generated, the properties panel sets State (TMT's four: Not
Started, Needs Investigation, Not Applicable, Mitigated), Priority and Justification.
`POST /api/threat` writes them into the model (status, severity, mitigation; Needs Investigation
is status Open plus `tdtm.tmtState`), restyles the outlines, saves atomically, and records the
values in the **triage journal** `<model>.triage.json`. Threats people wrote in Threat Dragon are
read-only here.

The journal exists because Threat Dragon keeps its own copy of the model in memory: saving there
can overwrite page edits. Every analyze run re-applies it (`journal.py`): a threat back in its
generated state (fingerprint intact) gets the journal's values; a threat that differs from both was
changed in Threat Dragon, which wins and updates the journal. Known limit: setting a threat back
to exactly its generated values in Threat Dragon looks like a stale save, so the older edit
returns. Sidecar mode does not use the journal.

Safety: `ThreadingHTTPServer` bound to 127.0.0.1; any Host header other than its own is refused
(DNS rebinding). A change needs `X-Tdtm-Token`, a random value embedded in the page that other
origins cannot read, and a custom header cannot cross origins without a preflight this server
never answers. Bodies over 100 kB are refused and every field is validated. Model text reaches the
DOM through `textContent` only; the one `innerHTML` is the server-rendered SVG, in which
`diagram.py` escapes every name. Model writes are atomic (temp file, then rename).

## 14. `.tm7` export

`threatsketch export MODEL.json [--out MODEL.tm7] [--force] [--template PATH]` writes a TMT file. TMT reads
`.tm7` with .NET's DataContractSerializer, which is strict about element names, order and
namespaces, so `tm7_export.py` writes the exact text shape of a real TMT 7.3 file (section 11),
including `z:Id` numbering and per-element namespace declarations.

- **KnowledgeBase**: transcribed from the `.tb7` at export time. Rules found by diffing against a
  real file: fields in alphabetical order with `IsExtension false` first; `ID`/`ParentElement`/
  `Image` become `Id`/`ParentId`/`ImageSource`; `Behavior`, `Shape`, `ImageStream` are always nil;
  `AvailableToBaseModels` empty; one `StencilConstraint` (Any/Any) per element; attribute `Id`,
  `IsInherited`, `IsOverrided` and metadatum `Description` dropped; `Include`/`Exclude` swapped;
  `ThreatMetaData` children in the default (Model) namespace; a field the `.tb7` lacks is written
  nil, an empty one empty; metadatum `Values` become `b:string` items (nil, empty or text).
- **Elements**: properties are rebuilt from the template and the element's resolved stencil and
  attributes (tags and Threat Dragon properties), `SelectedIndex` = position of the effective value.
  A standard stencil gets "Predefined Static Attributes", then "Configurable Attributes", then
  "As <generic name>" with the generic's dynamic attributes.
- **TMT-only details** kept by `threatsketch import` under `tdtm.tm7` (model, cell and threat level) are
  written back: diagram GUID and zoom, flow anchor points, ports and handle, threat order,
  ModifiedAt, ChangedBy. Without them they are derived: anchors where the flow meets the shape,
  ports from the side, handle from the middle vertex or midpoint, `0001-01-01` timestamps.
- Non-GUID cell ids get deterministic UUIDv5 GUIDs. A bidirectional flow becomes two connectors
  (TMT has none). Only STRIDE diagrams are exported. Threats without an `sdl` key (written by
  people in Threat Dragon) and `[stale]` threats are left out with a warning.

[confirmed] Import then export of a real TMT 7.3 model gives canonically identical XML (845,896
characters), also after an `analyze` run (`test_export_reproduces_the_real_tmt_file_exactly`).
**[unverified]**: TMT opening a model drawn in Threat Dragon and exported; line boundaries
(`LineBoundary`); where a stencil's own dynamic attributes go in its property list.
