# Third-party notices

## Microsoft Threat Modeling Templates

`src/threatsketch/data/templates/default.tb7` comes from https://github.com/microsoft/threat-modeling-templates
and is used under the MIT License. Copyright (c) Microsoft Corporation. The full licence text is in
`src/threatsketch/data/templates/LICENSE-microsoft-templates`.

## OWASP Threat Dragon

The files under `tests/fixtures/td/` and `tests/fixtures/schema/` come from
https://github.com/OWASP/threat-dragon (commit e538d78817dfdf9de7c403016471105486588e04) and are
used under the Apache License 2.0, http://www.apache.org/licenses/LICENSE-2.0.
`tests/fixtures/td/v2-boundary-box.json` was renamed from `ThreatDragonModels/test/test-reports.json`.

## OWASP pytm (optional dependency, not vendored)

https://github.com/OWASP/pytm, MIT License. Its threat library includes CAPEC material under
MITRE's CAPEC licence.

## ThreatSketch app (`app/`)

The app is built from these packages, bundled into its web build (not vendored in this repo):

- **AntV X6** and its plugins (`@antv/x6`, `@antv/x6-plugin-*`), https://github.com/antvis/X6,
  MIT License. Copyright (c) 2021-2023 Alipay.inc.
- **Pyodide**, https://github.com/pyodide/pyodide, Mozilla Public License 2.0. The Pyodide runtime
  files (`pyodide.mjs`, `pyodide.asm.*`, `python_stdlib.zip`, `pyodide-lock.json`) are copied
  unmodified into the build; they include CPython (PSF License).
- **Svelte**, https://github.com/sveltejs/svelte, MIT License.
- **Tauri** and its plugins (dialog, fs, opener, process, updater), https://github.com/tauri-apps,
  MIT or Apache License 2.0, in the desktop app, with the Rust crates they depend on
  (`app/src-tauri/Cargo.lock` lists them; each is MIT and/or Apache-2.0 or similarly permissive).

`app/src/lib/shapes.ts` transcribes the diagram shape definitions and default cell properties of
OWASP Threat Dragon 2.6.2 (`td.vue/src/service/x6/shapes/` and
`td.vue/src/service/entity/default-properties.js`), Apache License 2.0, so that Threat Dragon files
open in ThreatSketch and files saved by ThreatSketch open in Threat Dragon. Changes: the shapes
are restyled after Microsoft TMT's stencils, and connection points are moved outside each shape.
