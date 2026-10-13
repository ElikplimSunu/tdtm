# Build plan

Work top to bottom. One task per commit. Tick the box when its acceptance criteria pass.
**[manual]** tasks need a human; write precise instructions for them and stop.

## Phase 0: Spike (settle the [verify] items in SPEC.md)

- [x] **0.1 Threat Dragon details from source.** Clone OWASP/threat-dragon (sparse: `td.vue/src`)
  into `vendor/` (gitignored). Find and record in SPEC 2.3/2.4: full property list per kind,
  exact STRIDE `type` strings, exact `status` strings, how `number`/`threatTop` are assigned.
  *Done when:* every [verify] in SPEC 2.x is either confirmed or corrected.
- [ ] **0.2 [manual] Does Threat Dragon keep custom keys?** Human: open
  `tests/fixtures/manual/custom-keys.json` (create it: v2 sample with a `tdtm` key on one threat
  and on one cell's `data`) in Threat Dragon desktop 2.6.x, move one element, edit one threat's
  mitigation, save. Commit the saved file as `tests/fixtures/manual/custom-keys.saved.json`.
  *Done when:* SPEC 2.5 says kept or stripped, and SPEC 6.3 names the merge mode.
- [x] **0.3 Stencil hierarchy depth + defaults.** Using `rules/tb7.py` once 1.2 exists, or a
  throwaway script now, confirm SPEC 3.1 [verify] items (multi-level inheritance, first value
  is default).
  *Result:* one level, confirmed. First-value default cannot be confirmed without TMT; recorded as
  assumed in SPEC 3.1 and left to 3.4.

## Phase 1: Core (no rules yet)

- [x] **1.1 `td_adapter`: load/save.** `load(path) -> (Model, Document)` and
  `save(Document, path)`. The document keeps the raw JSON; edits are patches.
  *Done when:* round-trip test on every fixture gives equal JSON; dangling flows warn;
  kinds come from `data.type`; misspelled-shape fixture loads.
- [x] **1.2 `rules/tb7`: parse templates.** Elements with parent chain, attributes with
  values/defaults/static overrides, categories, threat types with raw filter strings.
  *Done when:* tests assert 47 threat types, 7 categories, 52 stencils, `SE.P.TMCore.WebApp`
  parent is `GE.P`, Kernel Thread static `codeType=Unmanaged`.
- [x] **1.3 `tags`: parse `@tmt` lines** against a loaded template (SPEC 4.3).
  *Done when:* stencil by ID/suffix/name; attrs by name/display name; bad values produce errors
  with suggestions; non-tag description text is ignored.
- [ ] **1.4 `boundaries`: zones and crossings** (SPEC 5).
  *Done when:* tests cover nested boxes, flow leaving a box, flow crossing a curve, flow parallel to
  a curve, and the real `v2-threat-model.json` (3 curves) gives crossings a human agrees with.
  Record that human check in the test docstring.
- [x] **1.5 Resolve effective stencil + attributes per element** (SPEC 3.5 precedence, 4.1, 4.2).
- [x] **1.6 `tdtm inspect`.** Prints each element: kind, stencil, effective attributes (marking
  source: tag/TD/static/default), zone; each flow: source → target, crossed boundaries.

## Phase 2: SDL rule pack (the main feature)

- [x] **2.1 `rules/filters`: tokenizer, parser, evaluator** (SPEC 3.4/3.5). No eval.
  *Done when:* all 47 Include and 11 Exclude strings in default.tb7 parse; hand-written truth-table
  tests for `is`, descendant `is`, `crosses`, attributes, `ROOT`, precedence of and/or.
- [x] **2.2 `rules/engine`: run a template over a model.** Per flow (both directions if
  bidirectional), title/description placeholder substitution, skip legacy ROOT rules by default.
- [x] **2.3 Golden models.** In `tests/fixtures/golden/`, hand-build 4 small TD models
  (web app + DB across a box; actor → process across a curve; unencrypted vs encrypted flow;
  `@tmt` tags changing the outcome). Expected firings are worked out by reading the filters by
  hand and written into `*.expected.json`. Engine output must match exactly.
- [x] **2.4 `merge`** (SPEC 6), in whichever mode 0.2 chose.
  *Done when:* running twice changes nothing; editing a generated threat's mitigation then
  re-running keeps the edit; deleting a tag makes threats `[stale]`; `--prune` removes unedited
  stale ones; `hasOpenThreats` is correct; output validates against the v2 schema.
- [x] **2.5 `tdtm analyze`** wired end to end, with `--dry-run` printing a diff summary and a
  `.bak` written before overwriting.
- [ ] **2.6 [manual] Smoke test in Threat Dragon.** Human: run `tdtm analyze` on a model drawn in
  Threat Dragon, reopen it, confirm threats appear on flows and elements turn red. Screenshot to
  `docs/img/`.

## Phase 3: Make it pleasant

- [x] **3.1 `tdtm stencils` and `tdtm coverage`.**
- [x] **3.2 `tdtm report`** HTML (SPEC 9).
- [x] **3.3 `tdtm analyze --watch`**: re-run when the model file changes (stdlib polling, no deps).
- [ ] **3.4 [manual, optional: needs Windows] TMT parity test.** *Partly done 2026-10-13:* a
  real TMT 7.3 model (private, gitignored) imports and gives exactly TMT's 54 threats; see SPEC
  10. Still open for the golden models, which cover curves, tags and encryption. Someone on Windows draws `tests/fixtures/golden/*`
  in TMT 7.3 with SDL TM Knowledge Base, generates the report, and the reports go into
  `tests/fixtures/parity/`. Write a test diffing per-interaction threat IDs. Fix differences or
  document them in SPEC.

## Phase 4: Optional

- [x] **4.1 pytm pack** (SPEC 7.2) behind `--pack pytm`.
- [x] **4.2 `.tm7` import** to Threat Dragon JSON (prior art: Part-IO/TMT2Cairis `TMTRead.py`).
- [ ] **4.3 `.tm7` export** so Windows users can open models in TMT (strict DataContract XML).
- [ ] **4.4 Azure template** support via `--template`.
