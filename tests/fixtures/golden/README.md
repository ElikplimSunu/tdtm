# Golden models (PLAN 2.3)

Each case is a pair:

- `<name>.json`: a small Threat Dragon v2 model (draw it in Threat Dragon or write it by hand).
- `<name>.expected.json`: the SDL rule firings worked out by hand from the filters in
  `default.tb7`, as a sorted list of `{"flow": "<cell id>", "direction": null|"fwd"|"rev", "rule": "S1"}`.

Write the expected file *before* running the engine, by reading the filters. If the engine
disagrees, decide which is wrong and say why in the commit message.

These same diagrams are what a Windows user redraws in TMT for the parity test (PLAN 3.4).
