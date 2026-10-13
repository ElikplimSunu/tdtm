# tdtm

[![CI](https://github.com/ElikplimSunu/tdtm/actions/workflows/ci.yml/badge.svg)](https://github.com/ElikplimSunu/tdtm/actions/workflows/ci.yml)

Automatic STRIDE threat generation for [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
models, using the same rules as Microsoft's Threat Modeling Tool (TMT). Draw on macOS or Linux, get
the threat list TMT would give you on Windows.

> **Status: early development.** All commands work. On a real model built in TMT 7.3, tdtm
> produces exactly the same 54 threats as TMT (same rules, titles and priorities). Diagrams with
> curves, tags or encryption are checked against hand-worked examples only so far. Progress is
> tracked in [docs/PLAN.md](docs/PLAN.md).

## Why

TMT's best feature is rule-driven threat generation. Every data flow in the diagram is checked
against the rules in a template, including which trust boundaries the flow crosses. TMT only runs
on Windows.

Threat Dragon runs everywhere and draws the same kind of diagram. It suggests threats one element
at a time and does not look at trust-boundary crossings.

tdtm bridges the two without modifying either. You draw in Threat Dragon. tdtm applies TMT's
**SDL TM Knowledge Base** template and writes the threats back into your model file.

## How it works

```
Threat Dragon: draw the diagram, save model.json
      |
tdtm analyze model.json
  1. read the Threat Dragon v2 JSON
  2. find the trust boundary each element sits in, and the boundaries each flow crosses
  3. read optional @tmt tags from element descriptions (TMT stencils and attributes)
  4. evaluate every TMT threat rule against every data flow
  5. merge the generated threats into the model, keeping anything you edited
      |
Threat Dragon: reopen model.json and triage the threats
```

tdtm follows these rules:

- **Your file loses nothing.** Unknown keys, positions and styling survive a read and write.
- **Re-running is safe.** Generated threats have stable IDs. A threat you edited is never
  overwritten. A threat whose rule stops firing is marked `[stale]`, not deleted. A `.bak` copy is
  written before the model is overwritten.
- **No `eval`.** Template filters go through tdtm's own parser. Nothing from a template or model
  is ever executed.
- **No runtime dependencies.** The core uses only the Python standard library.

## Install

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/). There is no PyPI release yet.

```bash
git clone https://github.com/ElikplimSunu/tdtm.git
cd tdtm
uv sync
uv run tdtm --help
```

## Usage

```bash
uv run tdtm analyze model.json            # add threats to the model, keeping a .bak copy
uv run tdtm analyze model.json --dry-run  # show what would change
uv run tdtm analyze model.json --prune    # also remove generated threats whose rule stopped firing
uv run tdtm analyze model.json --pack all # also OWASP pytm's threats (needs `uv sync --extra pytm`)
uv run tdtm inspect model.json            # how each element was read: stencil, attributes, zone
uv run tdtm stencils --kind process       # valid @tmt stencils and attributes
uv run tdtm report model.json             # TMT-style HTML report
uv run tdtm report model.json --out threats.csv  # TMT's own CSV export format
uv run tdtm coverage                      # which rules need @tmt tags to fire
uv run tdtm import model.tm7              # convert a TMT model, keeping TMT's threats and triage
```

Re-running is safe: threats you edited in Threat Dragon keep your changes, and threats whose rule no
longer fires are marked `[stale]` rather than deleted. Only STRIDE diagrams get threats.

### Working alongside Threat Dragon

Threat Dragon does not notice when a file changes on disk. After tdtm writes the model, close and
reopen it in Threat Dragon before you triage, otherwise Threat Dragon's next save overwrites the
new threats with its older copy. `tdtm analyze model.json --watch` re-runs every time you save, so
the loop is: draw, save, reopen, triage.

### Telling tdtm what an element really is

Threat Dragon has five generic shapes. TMT has 52 specific stencils, each with attributes the rules
test. tdtm maps Threat Dragon's own properties where it can: an encrypted flow provides
confidentiality and integrity, and a process marked as a web application becomes TMT's Web
Application.

For everything else, add a line starting with `@tmt:` to the element's description:

```
@tmt: WebApp; hasInputSanitizers=Yes
@tmt: SQL Database; storesCredentials=Yes
@tmt: HTTPS
```

A bare word names a stencil, by ID, short ID or name, in any case. `key=value` sets an attribute.
A typo is reported as an error with a suggestion, never silently ignored. `tdtm stencils` lists
every valid value. Tags live in the description because Threat Dragon always keeps that field.

### Trust boundaries

Draw them as usual. An element is inside a boundary box when its centre is inside the box. A flow
crosses a box when exactly one of its ends is inside, and crosses a boundary curve when the two
lines intersect. Boxes become TMT border boundaries; curves become line boundaries.

## Documentation

- [docs/SPEC.md](docs/SPEC.md): design, file format facts, rule semantics, merge behaviour.
- [docs/PLAN.md](docs/PLAN.md): roadmap and task list with acceptance criteria.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
uv sync --extra pytm   # optional OWASP pytm rule pack (`--pack pytm`); CI installs it
```

Work follows `docs/PLAN.md` from top to bottom, one task per commit. Tests come first, written from
the task's acceptance criteria. A task that teaches something new about the file formats updates
`docs/SPEC.md` in the same commit.

## Contributing

Issues and pull requests are welcome. The most valuable help needs a Windows machine: the real
acceptance test is drawing the four small diagrams in `tests/fixtures/golden/` in TMT 7.3 with the
SDL TM Knowledge Base template and comparing its threat report with tdtm's expected output (PLAN
task 3.4). If you can run TMT, please open an issue.

## License

MIT, see [LICENSE](LICENSE). Bundled third-party material:

- `src/tdtm/data/templates/default.tb7`: Microsoft
  [threat-modeling-templates](https://github.com/microsoft/threat-modeling-templates), MIT.
- `tests/fixtures/td/` and `tests/fixtures/schema/`: sample models and the v2 JSON schema from
  [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon), Apache-2.0.

Details in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). tdtm is not affiliated with Microsoft
or OWASP.
