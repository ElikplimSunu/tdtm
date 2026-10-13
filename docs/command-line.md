# The `threatsketch` command

The engine behind the ThreatSketch app, as a command. It adds TMT's threats to
[OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) models, so you can draw in
Threat Dragon instead of the app.

`threatsketch open examples/online-shop.json` adds 38 threats to the example model and opens it in
Threat Dragon. Flows that carry open threats are outlined in red:

![The example model in Threat Dragon after `threatsketch open`: every data flow carries generated threats and is outlined in red](img/threat-dragon-diagram.jpg)

Select a flow to see its threats, with the same titles and categories TMT would give them:

![Threat Dragon showing the generated threats on the Place order flow: Spoofing the Customer External Entity, Cross Site Scripting, Potential Data Repudiation](img/threat-dragon-threats.jpg)

`threatsketch open` also serves an analysis view in your browser, like TMT's Analysis View, and keeps a
TMT-style report next to the model.

## Why

TMT's best feature is rule-driven threat generation. Every data flow in the diagram is checked
against the rules in a template, including which trust boundaries the flow crosses. TMT only runs
on Windows.

Threat Dragon runs everywhere and draws the same kind of diagram. It suggests threats one element
at a time and does not look at trust-boundary crossings.

The command bridges the two without modifying either. You draw in Threat Dragon; it applies TMT's
**SDL TM Knowledge Base** template and writes the threats back into your model file.

## How it works

```
Threat Dragon: draw the diagram, save model.json
      |
threatsketch analyze model.json
  1. read the Threat Dragon v2 JSON
  2. find the trust boundary each element sits in, and the boundaries each flow crosses
  3. read optional @tmt tags from element descriptions (TMT stencils and attributes)
  4. evaluate every TMT threat rule against every data flow
  5. merge the generated threats into the model, keeping anything you edited
      |
Threat Dragon: reopen model.json and triage the threats
```

It follows these rules:

- **Your file loses nothing.** Unknown keys, positions and styling survive a read and write.
- **Re-running is safe.** Generated threats have stable IDs. A threat you edited is never
  overwritten. A threat whose rule stops firing is marked `[stale]`, not deleted. A `.bak` copy is
  written before the model is overwritten.
- **No `eval`.** Template filters go through ThreatSketch's own parser. Nothing from a template or model
  is ever executed.
- **No runtime dependencies.** The core uses only the Python standard library.

## Quick start on a Mac

Install once:

```bash
brew install --cask threat-dragon
uv tool install threatsketch                   # or: pipx install threatsketch
```

Then one command per model:

```bash
threatsketch open model.json      # or model.tm7 to start from a TMT model
```

It creates `model.json` if it does not exist (or converts the `.tm7`, keeping TMT's threats and
your triage), adds the threats TMT would generate, writes `model.report.html` (TMT-style report)
and `model.csv` (TMT's CSV export format) next to it, opens it in Threat Dragon and the
analysis view in your browser, and keeps watching. Draw and save in Threat Dragon; each save updates the threats and both reports. When new
threats arrive, reopen the model in Threat Dragon (File > Open Recent) to see them, or start with
`--reload` to have that done for you. Ctrl-C stops watching.

The same steps one at a time: `threatsketch import`, `threatsketch analyze`, `threatsketch report` (see Usage).

To try it on the example: `threatsketch open examples/online-shop.json` from a clone of this repo.
To update it later: `uv tool upgrade threatsketch`.

## Install for development

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/ElikplimSunu/threatsketch.git
cd threatsketch
uv sync
uv run threatsketch --help
```

## Usage

```bash
uv run threatsketch analyze model.json            # add threats to the model, keeping a .bak copy
uv run threatsketch analyze model.json --dry-run  # show what would change
uv run threatsketch analyze model.json --prune    # also remove generated threats whose rule stopped firing
uv run threatsketch analyze model.json --pack all # also OWASP pytm's threats (needs `uv sync --extra pytm`)
uv run threatsketch inspect model.json            # how each element was read: stencil, attributes, zone
uv run threatsketch stencils --kind process       # valid @tmt stencils and attributes
uv run threatsketch report model.json             # TMT-style HTML report
uv run threatsketch report model.json --out threats.csv  # TMT's own CSV export format
uv run threatsketch coverage                      # which rules need @tmt tags to fire
uv run threatsketch import model.tm7              # convert a TMT model, keeping TMT's threats and triage
uv run threatsketch export model.json             # write a TMT .tm7 you can open in TMT or hand in
uv run threatsketch open model.json               # all of the above, opened in Threat Dragon and kept updated
uv run threatsketch view model.json               # just the analysis view (TMT's threat grid) in the browser
```

Re-running is safe: threats you edited in Threat Dragon keep your changes, and threats whose rule no
longer fires are marked `[stale]` rather than deleted. Only STRIDE diagrams get threats.

### Working alongside Threat Dragon

Threat Dragon does not notice when a file changes on disk. After ThreatSketch writes the model, close and
reopen it in Threat Dragon before you triage, otherwise Threat Dragon's next save overwrites the
new threats with its older copy. `threatsketch analyze model.json --watch` re-runs every time you save, so
the loop is: draw, save, reopen, triage.

### Telling ThreatSketch what an element really is

Threat Dragon has five generic shapes. TMT has 52 specific stencils, each with attributes the rules
test. ThreatSketch maps Threat Dragon's own properties where it can: an encrypted flow provides
confidentiality and integrity, and a process marked as a web application becomes TMT's Web
Application.

For everything else, add a line starting with `@tmt:` to the element's description:

```
@tmt: WebApp; hasInputSanitizers=Yes
@tmt: SQL Database; storesCredentials=Yes
@tmt: HTTPS
```

A bare word names a stencil, by ID, short ID or name, in any case. `key=value` sets an attribute.
A typo is reported as an error with a suggestion, never silently ignored. `threatsketch stencils` lists
every valid value. Tags live in the description because Threat Dragon always keeps that field.

### Trust boundaries

Draw them as usual. An element is inside a boundary box when its centre is inside the box. A flow
crosses a box when exactly one of its ends is inside, and crosses a boundary curve when the two
lines intersect. Boxes become TMT border boundaries; curves become line boundaries.
