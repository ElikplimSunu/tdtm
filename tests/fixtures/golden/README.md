# Golden models (PLAN 2.3)

Each case is a pair:

- `<name>.json`: a small Threat Dragon v2 model (draw it in Threat Dragon or write it by hand).
- `<name>.expected.json`: the SDL rule firings worked out by hand from the filters in
  `default.tb7`, as a sorted list of `{"flow": "<cell id>", "direction": null|"fwd"|"rev", "rule": "S1"}`.

Write the expected file *before* running the engine, by reading the filters. If the engine
disagrees, decide which is wrong and say why in the commit message.

These same diagrams are what a Windows user redraws in TMT for the parity test (PLAN 3.4).

## The four cases

| model | what it exercises | firings |
|---|---|---|
| `1-webapp-db-box` | Threat Dragon's `isWebApplication` (Web Application stencil), a boundary box, flows both ways | 19 |
| `2-actor-process-curve` | external actors across a line boundary; `providesAuthentication` removes S3 | 24 |
| `3-encryption` | the same interaction plain, with `isEncrypted`, and with `protocol: HTTPS` | 28 |
| `4-tags` | `@tmt` stencils and attributes: Machine Trust Boundary, SQL Database, HTTP + JSON, unmanaged code | 26 |

All expected files were derived by hand from the filters before the engine first ran on these
models, and the engine matched all 97 firings on its first run.
