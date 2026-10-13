# Changelog

One version covers tdtm and ThreatSketch. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-10-13

### Added

- **ThreatSketch**, a threat-modelling app in the style of Microsoft TMT, in the browser and as
  a desktop app for macOS, Windows and Linux. Draw a data-flow diagram with TMT's stencils and
  get the SDL template's threats as you draw; connect elements by dragging or clicking the **+**
  on each side; set TMT properties; triage with TMT's states; export a report, a CSV or a `.tm7`.
  Opens Threat Dragon `.json` and TMT `.tm7` files. Works offline. Desktop copies update
  themselves.
- `tdtm.api`: the engine as plain functions over dicts, which ThreatSketch runs in the browser.
- `python -m tdtm`.
- Install channels: Homebrew cask (`elikplimsunu/tap/threatsketch`), PyPI, GitHub Releases, the web.

## [0.2.0] - 2026-10-13

### Added

- `tdtm open`: create or import a model, add threats, write reports, open Threat Dragon and the
  analysis view, and update on every save.
- Analysis view (`tdtm view`) with editing, kept safe by a triage journal.
- `.tm7` export, TMT-style HTML report, TMT's CSV export format.
- An example model and a guide for people coming from TMT.

### Changed

- Generated threats default to priority High, as in TMT.

## [0.1.0] - 2026-10-12

### Added

- `tdtm analyze`: TMT's SDL threat rules applied to OWASP Threat Dragon models, merged without
  overwriting human edits; `inspect`, `stencils`, `coverage`, `report`, `import` (`.tm7`), and an
  optional OWASP pytm rule pack.
