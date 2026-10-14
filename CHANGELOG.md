# Changelog

One version covers the app and the command-line tool. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-10-14

Most of this release is TMT parity work by @josetseph, reviewed and finished here.

### Added

- **TMT's layout, as an option.** TMT's menu bar (File, Edit, View, Diagram, Reports, Help, with
  TMT's items and shortcuts), its toolbar in TMT's order, and Design and Analysis views. Switch
  with the layout button in the header or View > TMT layout; the choice is remembered. The default
  layout is unchanged: every pane in view, so threats appear as you draw.
- **TMT's stencil icons** on the canvas and in the stencil list, and flow names in TMT's pale green
  box with the flow stencil's icon.
- **TMT's threat list columns**: ID, Diagram, Changed by, Last modified, State, Title, Category,
  Description, Justification, Interaction, Priority, resizable, each with a filter of its values,
  and Export CSV with "N threats displayed, M total" below. Columns with nothing to show yet (one
  diagram, nothing triaged) stay out of the way.
- **Editing a threat's title, category and description**, as in TMT's Threat Properties. Later
  analyses keep the edits, and `.tm7` exports carry them.
- **Last modified**: when a threat was triaged, in the list, the CSV and `.tm7` exports.
- **TMT's Notes pane**: notes about the model, kept through `.tm7` import and export.
- **Assumptions and External Dependencies**, TMT's other two model fields, in the model's
  properties, the report and `.tm7` files.
- Cut, Close model, Save as, and (desktop app) Cmd/Ctrl+N and zoom shortcuts.

### Changed

- Element properties are grouped as in TMT: predefined static attributes, then configurable ones.
- Names wrap inside their shape between words, as in TMT. Trust boundary names are not bold.

### Fixed

- `.tm7` imports from TMT 7.3 lost justifications: TMT keeps them in the threat's properties.
  Justifications and notes now round-trip exactly, line breaks included.
- A `.tm7` export wrote every flow's Dataflow Order as 0, and the model's original name and
  contributors even after they were edited. A real TMT model now exports back unchanged, and
  edits are exported.
- A threat TMT stored with Id 0 is numbered as TMT numbers it, so TMT's CSV matches row for row.

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
