# TMT parity plan

Goal: ThreatSketch behaves like Microsoft Threat Modeling Tool 7.3, on every platform: TMT's
features, panes, views, shapes, threat list, report and templates. PLAN.md already names TMT as
"the visual standard".

The app's visual design (blueprint blue, IBM Plex, the de-AI rules) is kept in the functional
PRs. Restyling it after TMT (palette, font, chrome) is a separate, optional PR (phase 8) the
maintainer can take or leave.

The engine is not the problem. A real TMT model (University Mobile Banking App, 2 diagrams)
imports and analyses to the same 232 threats TMT lists. Almost all the work is in `app/`, plus
some import/export fidelity in `src/threatsketch/`.

## How we work

- **Fork and PRs.** Fork `ElikplimSunu/threatsketch` to `josetseph/threatsketch`. Remotes:
  `origin` = fork, `upstream` = ElikplimSunu. One branch per phase below, each a PR to upstream
  `main`. Upstream merges several PRs a day, so keep PRs small and rebase often.
- **New UI uses the existing tokens** in `app/src/app.css`, so phase 8 can restyle everything
  by changing tokens, not components.
- **Upstream's rules still apply:** tests first; facts learned about the file formats go into
  `docs/SPEC.md` in the same commit; CI green; note changes under *Unreleased* in CHANGELOG.md.
- **TMT is the reference, checked by hand.** For every phase, capture the TMT side (screenshots,
  `.tm7`, report HTML, CSV) on Windows and keep it in `tests/fixtures/private/` (not in git) or
  `temp/`. Anything not personal goes into `tests/fixtures/` as a golden file.
- **The reference model** is `temp/New Threat Model.tm7` with TMT's screenshots and `m.html`
  (TMT's Full Report) beside it.

## Gaps found (ThreatSketch 0.5.0 vs TMT 7.3, same model)

| Area | TMT | ThreatSketch now |
|---|---|---|
| Window | Menu bar, icon toolbar, docked panes (Stencils, Properties, Threat List, Threat Properties, Messages, Notes) | Web-app header, fixed three-column layout |
| Views | Design view and Analysis view | One combined view |
| Shapes | TMT stencil icons inside each shape; data store drawn as two full-width lines with an icon; names wrap inside the shape | No icons; long names spill out of the shape |
| Flow labels | Boxed labels with an icon, draggable | Plain text on the line |
| Threat list columns | ID, Diagram, Changed By, Last Modified, State, Title, Category, Description, Justification, Interaction, Priority; filter on every column | ID, State, Title, Category, Interaction, Priority; three filters |
| Threat properties | Pane under the list; title, category, description, justification all editable | Right-hand panel; only state, priority, justification |
| Footer | "Export Csv"; "232 Threats Displayed, 232 Total" | Counts in the status bar |
| Model properties | Name, Owner, Reviewer, Contributors, Description, Assumptions, External Dependencies | No Assumptions or External Dependencies; imported name becomes the file name ("m") |
| Report | Full Report numbered per interaction, "Mitigation Implemented", "Total Migrated" | Redesigned report (close, not identical) |
| Templates | Template editor; apply a different template to a model | Built-in SDL template only |
| Font | Segoe UI | IBM Plex |

## TMT 7.3 reference (from screenshots in `temp/reference/`)

TMT 7.3.51110.1. What the window offers, as the target for phase 2:

- **File**: New Model (Ctrl+N), Open (Ctrl+O), Save (Ctrl+S), Save As, Apply Template…, Threat
  Model Information…, Close Model, Exit.
- **Edit**: Undo (Ctrl+Z), Redo (Ctrl+Y), Copy (Ctrl+C), Cut (Ctrl+X), Paste (Ctrl+V).
- **View**: Design View, Analysis View, Zoom In (Ctrl++), Zoom Out (Ctrl+-), then one item per
  pane: Stencils, Messages, Notes, Threat List, Threat Properties, Element Properties (each
  "(Pinned)" when docked), Reset Window Layout.
- **Settings**: Enable / Disable Threat Generation (stored in the `.tm7` as
  `ThreatGenerationEnabled`), Options.
- **Diagram**: Add New Diagram, Delete Diagram, then one item per diagram to switch to it.
- **Reports**: Create Full Report… (a "Custom Threat Properties" step listing extra threat
  properties to include, then a save dialog for `.htm`), Create Custom Report… (check boxes for
  Not Started, Needs Investigation, Not Applicable, Mitigated, and Include Migrated Threats).
- **Help**: Getting Started Guide, Microsoft SDL, Report an Issue…, About.
- **DiagramReader**: Read Full Diagram (Ctrl+R). A paged text reading of each diagram for screen
  readers: "Source name *A* type *Stencil* is connected to name *B* type *Stencil* using name
  *Flow* type *Flow stencil*." for every flow, then each boundary and the elements it contains,
  then "There is 1 more diagram to read out". PREVIOUS / NEXT / OK.
- **Toolbar** (left to right): Open, Save; Design View, Analysis View; Add Diagram, Delete
  Diagram; Copy, Cut, Paste; Undo, Redo; Zoom In, Zoom Out; Notes.
- **Threat List** pane: the eleven columns, each header with a filter drop-down; "Export Csv"
  button and "232 Threats Displayed, 232 Total" under it; Last Modified reads "Generated" for
  untouched threats. **Threat Properties** pane: "No threats are selected" when empty; tabbed
  with **Notes** ("Add New Note"; columns Id, Note, Date, Added By; tab title "Notes - no
  entries"). A status line at the very bottom ("Saved threats to Csv file …").
- **Start page**: Threat Model: Create A Model, Open A Model, Getting Started Guide; Template For
  New Models (Azure Threat Model Template 1.0.0.33, SDL TM Knowledge Base (Core) 4.1.0.11, Medical
  Device Model 4.1.0.417, plus Browse…); Recently Opened Models; Threat Modeling Workflow (4
  steps). Template: Create New Template, Open Template; Template Workflow (5 steps).
- **Flow labels** are always the green box with the flow stencil's icon, in Design view too, in
  a fresh sample model: it is TMT's style, not a threat state.
- **Threat IDs**: a threat stored with Id 0 is listed and exported as the highest Id + 1 (242 in
  the reference model); the file keeps 0.

## Phases

Each task lists how we know it's done. **[TMT]** means it needs a check against TMT on Windows.

### Phase 0: Setup

- [x] **0.1** Fork, set remotes, branch `tmt-parity-0`. Done when: `git remote -v` shows both.
- [x] **0.2 [TMT] Reference pack**: menus, reports, start page, Notes, DiagramReader; summed up
  above. Still to capture: Analysis view, the Stencils and Element Properties panes, right-click
  menus (canvas, element, flow, boundary, threat row), Options, Threat Model Information, the
  template editor.

### Phase 1: Engine and import fidelity (Python; small, easy-to-accept PRs)

- [x] **1.1 Threat IDs.** TMT's IDs come through, gaps included; Id 0 shows as the highest + 1,
  as TMT does. TMT's own CSV of the reference model now matches row for row.
- [x] **1.2 Model properties.** Assumptions and External Dependencies edited in the app, in the
  report, kept in `.tm7`. (TMT's model name may be empty; the file name stands in, as before.)
- [x] **1.2b Dataflow Order** written back on export (found by the reference model's round trip).
- [x] **1.3 Geometry.** Checked: positions and sizes come through exactly (shapes TMT placed 4px
  apart are 4px apart). What looked like overlaps is how shapes are drawn: phase 3.
- [ ] **1.4 Threat fields.** Changed By and Last Modified are listed (as TMT's CSV: "Generated"
  until triaged). **[TMT]** Does TMT show a date in Last Modified for a triaged threat? Edited
  title/description/category, threats added by hand; round-trip through `.json` and `.tm7`.
- [x] **1.5 Stencil icons.** `api.palette()` gives each stencil's icon (a data URL; inherited from
  the parent when missing) and where TMT puts it (`iconAt`: center, lower-right, before-label).
- [ ] **1.6 Notes** (the `.tm7`'s `Notes`: Id, text, date, added by): import, export, keep in
  `.json`.
- [ ] **1.7 Threat generation on/off** (`ThreatGenerationEnabled`): honoured by analyze, kept.
- [ ] **1.8 Messages.** The validation messages TMT shows in the Messages pane (e.g. flow with no
  source) **[TMT]**: list them, then generate them in the engine.

### Phase 2: The TMT window (structure and behaviour, in the current visual style)

- [x] **2.1 Menu bar**: File, Edit, View, Diagram, Reports, Help with TMT's items and shortcuts.
  Settings and DiagramReader join when 1.7 and 2.7 exist; File > Apply Template with 6.3. On the desktop app, use native menus (Tauri) on macOS; in-window elsewhere.
- [x] **2.2 Icon toolbar** with TMT's buttons and order (Save stays the primary button; Notes
  joins with 1.6).
- [ ] **2.3 Docking panes**: Stencils, Properties, Threat List, Threat Properties, Messages,
  Notes; pin/unpin, close, reopen from View, tabbed at the bottom as in TMT. Layout remembered.
- [x] **2.4 Design view / Analysis view** switch, showing the panes TMT shows in each; View toggles
  each pane. *Left for 2.3: docking, resizing every pane, remembering the layout.*
- [ ] **2.5 Start page** like TMT's (Create a model, Open a model, recent files, templates).
- [ ] **2.6 Threat Model Information** dialog (File menu): the model properties.
- [ ] **2.7 DiagramReader**: Read Full Diagram (Ctrl+R), the paged text reading above. Built from
  the engine's resolved stencils, so it also helps screen-reader users.

### Phase 3: Canvas

- [ ] **3.1 Shapes** for every stencil: TMT's outline, size and icon (from 1.5). Stores as two
  lines. Generic elements vs specific stencils look as in TMT. *Done: icons, word wrapping. Left:
  icons in the report's diagram; sizes and fades checked side by side* **[TMT]**.
- [ ] **3.2 Boundaries**: border boundaries (red dashed box, label at top left) and line
  boundaries (curved red dashed line with a handle).
- [ ] **3.3 Flows**: a curve with one draggable handle, as TMT draws them; arrowheads; two-way
  flows; drawing a flow from the stencil's Data Flow item as well as from the + handles.
- [ ] **3.4 Flow labels**: TMT's green box with the flow stencil's icon *(done)*, draggable
  apart from the line.
- [ ] **3.5 Interaction**: selection look, multi-select, grid, zoom levels, copy/paste,
  right-click menus, delete, undo/redo; all as TMT.
- [ ] **3.6 Pixel check**: the reference model in TMT and in ThreatSketch at the same zoom, side
  by side. Done when: differences are listed and accepted **[TMT]**.

### Phase 4: Threat list and triage

- [x] **4.1 Columns**: all eleven of TMT's, resizable, sorted by clicking the header. *Not
  reorderable yet.*
- [x] **4.2 Filters**: a drop-down filter on every column header, as TMT.
- [ ] **4.3 Threat Properties pane** under the list: every field editable as in TMT; Notes tab
  beside it (1.6).
- [ ] **4.4 Add/remove threats by hand** (if TMT 7.3 allows it **[TMT]**); multi-select rows to
  change state or priority at once.
- [x] **4.5 Footer**: Export Csv button; "N Threats Displayed, N Total".
- [ ] **4.6 Analysis view links**: selecting a threat highlights its interaction on the canvas;
  selecting an interaction filters the list, as TMT does.

### Phase 5: Reports

- [ ] **5.1 Full Report** identical in structure and wording to TMT's (`temp/m.html` is the
  golden file): summary by state, per-diagram summary, threats numbered per interaction,
  "Mitigation Implemented", "Total Migrated". Done when: a text diff against `m.html` shows only
  the creation date.
- [ ] **5.2 Create Full Report** (custom threat properties step) and **Create Custom Report**
  (choose states, include migrated). Keep PDF export.
- [ ] **5.3 CSV** stays identical (already tested).

### Phase 6: Templates

- [ ] **6.1 `.tb7` writer** in the engine (the reader exists in `rules/tb7.py`). Done when:
  `default.tb7` reads and writes back unchanged.
- [ ] **6.2 Template editor**: stencils and their properties, threat categories, threat types
  with their include/exclude rules, as in TMT's editor **[TMT]**.
- [ ] **6.3 Open a model with a different template / apply a template** to an existing model.
- [ ] **6.4 Other Microsoft templates** (Azure, Medical Device) from the same repo, if licences
  allow.

### Phase 7: Finish

- [ ] **7.1** README tour and screenshots redone (`scripts/screenshots.mjs` needs the menus and
  Analysis view); `app/README.md` design rules rewritten for the
  TMT look; `docs/coming-from-tmt.md` updated.
- [ ] **7.2** E2E tests for each new pane and menu; the private reference model as an e2e test.
- [ ] **7.3** Desktop builds checked on macOS, Windows and Linux.

### Phase 8: TMT visual style (separate, optional PR)

- [ ] **8.1 Design tokens.** TMT's palette, sizes and font: Segoe UI where installed, falling
  back to Selawik (Microsoft's open Segoe UI substitute). Offered as a theme or a replacement,
  whichever the maintainer prefers. Done when: side-by-side screenshots of the empty window
  match **[TMT]**.

## Order and size

Phase 1 first: it's small, clearly correct, and makes later screenshots meaningful. Then 3 (the
shapes, what people notice first), 2, 4, then 5, then 6 (the largest, the least used). Phase 8
whenever the maintainer wants it. Phases 2–4 rework most of `app/src/` (about 2,000 lines today).

## Open questions

1. Desktop menus: native macOS menu bar, or TMT's in-window menu everywhere?
2. Can TMT 7.3 add threats by hand? **[TMT]**
3. Do we also match TMT's file name (`.tm7`) as the default save format, or keep Threat Dragon
   `.json` as the native one with `.tm7` as export?
