# Changelog

One version covers the app and the command-line tool. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The threat list has TMT's eleven columns in TMT's order (ID, Diagram, Changed By, Last Modified,
  State, Title, Category, Description, Justification, Interaction, Priority), resizable, each
  with a filter drop-down of its values, as in TMT. Below it, as in TMT: Export Csv and
  "N Threats Displayed, M Total". The column filters replace the category and priority menus.

- TMT's menu bar: File, Edit, View, Diagram, Reports and Help, with TMT's items and shortcuts.
  New, Open, Export and Report moved into it (exports under File and Reports, as in TMT). File
  also has Save As, Threat Model Information and Close Model; Help links to TMT's and the SDL's
  pages.
- TMT's toolbar, in TMT's order: Open; Design and Analysis view; add and delete diagram; copy,
  cut, paste; undo, redo; zoom.
- Design and Analysis views, as in TMT: Design shows the stencils, Analysis the threat list. View
  shows or hides each pane; selecting a threat, or the threat count, opens the Analysis view.
- Cut (Ctrl+X), and Ctrl+N, Ctrl+Shift+S and Ctrl+plus/minus for new, save as and zoom.

- TMT's stencil icons, from the template: faded inside processes (centred), interactors and data
  stores (lower right), before each trust boundary's name, and in the stencil list.
- Flow names in TMT's pale green box with the flow stencil's icon before the name.

- Assumptions and External Dependencies, TMT's two other model fields: edited in the model's
  properties, shown in the report, and kept through `.tm7` import and export.

### Changed

- Names wrap inside their shape between words, as in TMT, instead of breaking mid-word or
  running past the edge. Trust boundary names are no longer bold, as in TMT.

### Fixed

- A threat TMT stored with Id 0 now shows as TMT shows it, the highest Id + 1, in the list, the
  report and the CSV. A real TMT model's CSV now matches TMT's own export row for row.
- A `.tm7` export kept each flow's TMT Dataflow Order at 0; it now writes back the number TMT gave
  it, so a real TMT model exports back unchanged.

## [0.5.1] - 2026-10-14

### Fixed

- Selecting a second threat on the same data flow kept the first threat's priority and
  justification in the triage form, and changing the second threat's state saved them onto it.
- An edit could be lost from the saved file: saving, exporting or editing the model's title while
  the threat engine was still working let the engine's older copy of the model replace the newer
  one. Results computed from an older model are now recomputed instead.

## [0.5.0] - 2026-10-13

### Added

- Elbow lines: a data flow can be curved, as in TMT, or an elbow line that goes round shapes
  (Line, in the flow's properties). New flows use the style chosen last. The report draws both.
- A "Review before sharing" list, in the app and at the top of the report, that names what a
  reader would trip over: elements still carrying a default name, no description, no trust
  boundary, threats not triaged, and threats closed without a justification.

### Changed

- A data flow stays on the side of the shape it was drawn from and dropped on, and leaves and
  enters square to that side. Flows that share a side are spaced apart, so two flows between the
  same shapes, one each way, no longer draw on top of each other (in the report too).
- Shapes added from the stencil list are placed further apart, and the canvas scrolls to them.
- Flows that share a side bow apart in the middle, as in TMT, and flows between the same two
  shapes carry their names at different points, so the names stay readable.
- The example model uses the new layout; the README screenshots and example PDF are new.

### Fixed

- A "+" under a data flow could not be clicked.
- Selecting a level data flow (or a threat on one) no longer scrolls the canvas.
- `threatsketch report` now shows which trust boundaries each flow crosses, as the app does.

## [0.4.0] - 2026-10-13

### Added

- Export the threat report as a PDF (Export > Threat report (PDF), or Save as PDF in the report).

### Changed

- The threat report is redesigned: TMT's sections in TMT's order on a clean, printable layout
  with a summary by state and by STRIDE category, the diagram in TMT's style, the trust boundaries
  each flow crosses, and A4 pages with page numbers. Fonts are embedded; the file needs nothing
  from the network.

## [0.3.1] - 2026-10-13

### Fixed

- Selecting a second threat on the same data flow cleared the selection instead of showing it.
- The threat report now says it was created by ThreatSketch.

## [0.3.0] - 2026-10-13

### Added

- **ThreatSketch**, a threat-modelling app in the style of Microsoft TMT, in the browser and as
  a desktop app for macOS, Windows and Linux. Draw a data-flow diagram with TMT's stencils and
  get the SDL template's threats as you draw; connect elements by dragging or clicking the **+**
  on each side; set TMT properties; triage with TMT's states; export a report, a CSV or a `.tm7`.
  Opens Threat Dragon `.json` and TMT `.tm7` files. Works offline. Desktop copies update
  themselves.
- `threatsketch.api`: the engine as plain functions over dicts, which ThreatSketch runs in the browser.
- `python -m threatsketch`.
- Install channels: Homebrew cask (`elikplimsunu/tap/threatsketch`), PyPI, GitHub Releases, the web.

## [0.2.0] - 2026-10-13

### Added

- `threatsketch open`: create or import a model, add threats, write reports, open Threat Dragon and the
  analysis view, and update on every save.
- Analysis view (`threatsketch view`) with editing, kept safe by a triage journal.
- `.tm7` export, TMT-style HTML report, TMT's CSV export format.
- An example model and a guide for people coming from TMT.

### Changed

- Generated threats default to priority High, as in TMT.

## [0.1.0] - 2026-10-12

### Added

- `threatsketch analyze`: TMT's SDL threat rules applied to OWASP Threat Dragon models, merged without
  overwriting human edits; `inspect`, `stencils`, `coverage`, `report`, `import` (`.tm7`), and an
  optional OWASP pytm rule pack.
