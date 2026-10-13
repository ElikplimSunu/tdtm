# ThreatSketch

A TMT-style threat-modelling app: draw a data-flow diagram, get Microsoft TMT's STRIDE threats as
you draw. Svelte 5 + TypeScript + Vite, AntV X6 for the canvas, and tdtm's Python engine running
unchanged in the browser through Pyodide. The same build runs as a website (installable, works
offline) and inside a Tauri 2 desktop app.

## Commands

```bash
npm install
npm run dev            # http://localhost:5173 (builds the engine first, see below)
npm run build          # production build in dist/
npm run check          # svelte-check (TypeScript)
npx vitest run         # unit tests (tests/unit)
npx playwright test    # end-to-end tests against the production build, in Chrome
npm run tauri build -- --bundles app,dmg   # macOS desktop app and installer
node scripts/screenshots.mjs ../docs/img   # screenshots of a running dev server
```

`npm run dev` and `npm run build` run `scripts/prepare-engine.mjs` first. It builds tdtm's wheel
from this repository with `uv` into `public/engine/tdtm.whl`, and copies the Pyodide runtime into
`public/pyodide/`. Both folders are generated and ignored by git.

`BASE=/tdtm/ npm run build` builds for a sub-path (GitHub Pages serves the repo at `/tdtm/`).

## How it fits together

```
src/
  App.svelte              layout, files, menus; owns the editor
  components/             Palette (TMT stencils), Properties, ThreatList, Icon
  engine/worker.ts        Pyodide + tdtm in a Web Worker; calls tdtm.api functions by name
  engine/client.ts        promise wrapper around the worker
  lib/editor.ts           the X6 canvas, and keeping it in step with the model
  lib/sync.ts             canvas <-> Threat Dragon JSON, without losing anything
  lib/shapes.ts           diagram shapes (Threat Dragon's names, TMT's look)
  lib/files.ts            open and save: desktop dialogs, File System Access API, downloads
src-tauri/                the desktop app (file associations, native dialogs)
```

- **The model is the source of truth.** It is a Threat Dragon v2 JSON document, the same file
  tdtm and Threat Dragon read. The canvas holds a copy of each cell without its threats and
  without Threat Dragon's red outline styles. When the canvas changes, only the values that
  changed are written back (`sync.ts`), so unknown keys and everything the canvas never showed
  survive. A model opened and saved without edits is identical to what `tdtm analyze` writes;
  an end-to-end test checks this.
- **The engine does all threat work.** After every change (debounced), the editor sends the model
  to the worker, which runs `tdtm.api.analyze`: tdtm's own resolve, rule engine and merge. The
  answer comes back with the threat rows and each element's resolved TMT stencil and attributes.
  Edits made while the engine was busy are kept and trigger another run.
- **TMT stencils and attributes** are stored as a hidden `@tmt:` line in the element's description
  (`api.set_element`), so the CLI and Threat Dragon read the same file. The description field
  hides that line.
- **Connecting.** Each actor, process and store has a "+" just outside each side (an X6 port).
  Dragging one draws a flow; clicking one (`node:magnet:click`) links to the nearest element on
  that side, or adds a process there. Flows attach to the shape, not to the port.
- **Offline.** `vite-plugin-pwa` precaches the app and the engine (~14 MB) on the first visit.
  The desktop app does not need it and disables it.

## Testing notes

- Each e2e test boots its own Python engine, so the suite runs three workers at a time.
- `window.threatsketch.editor` is exposed for tests and the browser console.
- The last e2e test opens a private TMT model (`tests/fixtures/private/`, not in git) and is
  skipped where it is missing.
