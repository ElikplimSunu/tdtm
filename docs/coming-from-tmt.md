# Coming from Microsoft TMT

If you know Microsoft's Threat Modeling Tool (TMT), you already know ThreatSketch. The diagram is
the same kind of data-flow diagram, drawn the way TMT draws it. The rules are TMT's own
**SDL TM Knowledge Base** template, and the threats come out with the same titles, categories
and priorities. On a real model built in TMT 7.3, tdtm (the engine inside ThreatSketch) produced
exactly the same 54 threats as TMT, and its CSV export matched TMT's row for row.

## Doing in ThreatSketch what you did in TMT

| In TMT | In ThreatSketch |
|---|---|
| File > New, choose *SDL TM Knowledge Base* | **New threat model** (the SDL template is built in) |
| File > Open a `.tm7` | **Open**, pick the `.tm7`: its diagram, threats and your triage come along |
| Stencils pane | **Stencils** on the left, with the same groups and names; drag one onto the canvas or click it |
| Draw a data flow | Hover an element: a **+** appears on each side. Drag it to the other element, or click it to link the nearest element on that side |
| Trust Border Boundary / Trust Line Boundary | **Trust border boundaries** (a box) and **Trust line boundaries** (a line) in the stencils |
| Properties pane (Name, Out Of Scope, Sanitizes Input ...) | **Properties** on the right: name, stencil, out of scope, and every TMT property of the stencil. Properties the stencil fixes are shown locked |
| Switch to Analysis View | Not needed: the **threat list** below the diagram updates as you draw |
| Filter the threat list | The state filters, category and priority menus, and search above the list |
| Change State, Priority, Justification | Select the threat; set them on the right |
| Reports > Create Full Report | **Report** (opens it) or **Export > Threat report** |
| Export the threat list to CSV | **Export > Threat list**, in TMT's own CSV columns |
| Save as `.tm7` | **Export > Microsoft TMT model** |
| Save | **Save** (⌘S). Models are saved as Threat Dragon `.json`, which OWASP Threat Dragon opens too |

## A first model, step by step

1. **New threat model**, then give it a title on the right.
2. In the stencils, click **Human User**, **Web Application** and **SQL Database**. Name each one
   on the right as you add it: *Customer*, *Shop*, *Orders*.
3. Hover *Customer* and click the **+** on the side facing *Shop*: a data flow joins them. Do the
   same from *Shop* to *Orders*, and back the other way for the replies.
4. Drag a **Generic Trust Border Boundary** onto the canvas and resize it from its corners so it
   holds *Shop* and *Orders* but not *Customer*.
5. The threat list fills in as you go. Select a threat, set its state, priority and
   justification on the right.
6. **Save**, then **Export** the report, the CSV or a `.tm7` to hand in.

## The same words

ThreatSketch uses TMT's words everywhere: states (Not Started, Needs Investigation, Not
Applicable, Mitigated), priorities, categories, interactions, justification. Saved files use
Threat Dragon's format underneath, where a state is stored as a status (Open, Mitigated,
NotApplicable) and Needs Investigation is kept alongside it.

## Differences to know about

- **Threat numbers** differ from TMT's for models drawn here. Titles, categories, descriptions
  and priorities do not.
- **Threats live on data flows**, as in TMT. Threats someone added to an element in Threat Dragon
  are shown and reported, but cannot be exported to `.tm7`.
- **Not yet compared with TMT:** boundary lines, non-default TMT properties, encrypted or HTTPS
  flows, out-of-scope elements and two-way flows. They are checked against worked examples and
  the rules are TMT's own, but nobody has put the same diagram through TMT yet. If you can,
  please open an issue with the result.
- **Check with your lecturer** if a course asks for TMT specifically: the threats match, but the
  screenshots will show ThreatSketch.

# Using Threat Dragon and the tdtm command instead

If you prefer to draw in [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/), the
`tdtm` command adds the same threats to its files.

## Set up once

```bash
brew install --cask threat-dragon
uv tool install git+https://github.com/ElikplimSunu/threatsketch
```

Then, for every model:

```bash
tdtm open mymodel.json     # a new model is created if the file does not exist
tdtm open mymodel.tm7      # or start from a TMT file: its threats and your triage come along
```

`tdtm open` opens the model in Threat Dragon and the analysis view in your browser, and keeps both
up to date every time you save.

## Doing with Threat Dragon and tdtm what you did in TMT

| In TMT | With Threat Dragon and tdtm |
|---|---|
| New model, choose *SDL TM Knowledge Base* | `tdtm open mymodel.json` (the SDL template is built in) |
| Open a `.tm7` | `tdtm open mymodel.tm7` (or `tdtm import mymodel.tm7`) |
| External Interactor, Process, Data Store, Data Flow | Threat Dragon toolbar: **Actor**, **Process**, **Store**, **Data Flow** |
| Trust Border Boundary (a box) | **Trust Boundary** box |
| Trust Line Boundary (a line) | **Trust Boundary** curve |
| A specific stencil (Web Application, SQL Database, HTTPS ...) | the Threat Dragon option where one exists (a process's *Web Application* box, a flow's *Protocol*), otherwise a line `@tmt: SQL Database` in the element's description |
| Element properties (Authenticates Itself, Sanitizes Input ...) | the matching Threat Dragon checkbox where one exists (*Provides Authentication*, *Encrypted*, *Stores Credentials*, *Is a Log*, *Signed*), otherwise `@tmt: hasInputSanitizers=Yes` |
| Out Of Scope | the *Out of Scope* checkbox |
| Switch to Analysis View | save in Threat Dragon: tdtm adds the threats and the analysis view in your browser updates |
| Filter the threat list | the analysis view's state, category and priority filters and search box |
| Change State, Priority, Justification | in the analysis view: select the threat, set State, Priority, Justification, Save. Or in Threat Dragon: select the flow, open the threat, set *Status*, *Severity*, *Mitigations* |
| Reports > Create Full Report | `mymodel.report.html`, written next to the model on every save |
| Export the threat list to CSV | `mymodel.csv`, in TMT's own CSV format, written on every save |
| Save as `.tm7` | `tdtm export mymodel.json` |

`tdtm stencils` lists every stencil and property a `@tmt:` line can use, with the allowed values.
`tdtm coverage` shows which rules can only fire with a tag (for example the SQL injection rules
need `@tmt: SQL Database` on the store).

## The same words, different names

| TMT | Threat Dragon |
|---|---|
| State: Not Started | Status: Open |
| State: Mitigated | Status: Mitigated |
| State: Not Applicable | Status: NotApplicable |
| Priority | Severity |
| Justification | Mitigations |
| Interaction | the data flow the threat is on |

The report, the CSV and the analysis view use TMT's words.

## A first model, step by step

1. `tdtm open shop.json`. Threat Dragon opens on an empty model; open its diagram.
2. Draw a **Customer** (Actor), a **Shop Web App** (Process) and an **Orders DB** (Store). Tick
   *Web Application* on the process. In the store's description, write `@tmt: SQL Database`.
3. Connect them with **Data Flows** both ways, then draw a **Trust Boundary** box around the web app
   and the database, leaving the customer outside.
4. Save. The terminal reports the new threats, and the analysis view in your browser lists them.
5. Reopen the model in Threat Dragon (File > Open Recent) to see the threats on the flows, outlined
   in red, and triage them: status, severity, mitigations. Save again.
6. Hand in `shop.report.html`, `shop.csv`, or `tdtm export shop.json` for a `.tm7`.

`examples/online-shop.json` in this repository is a finished version of this model.

![The example model in Threat Dragon with tdtm's threats](img/threat-dragon-diagram.jpg)

## Differences to know about (Threat Dragon)

- **Reopen after an update.** Threat Dragon does not notice that a file changed on disk. After
  tdtm adds threats, reopen the model before you edit; if you save Threat Dragon's older copy, tdtm
  adds the threats again but your own changes in that copy win. `tdtm open --reload` reopens for
  you, which also takes Threat Dragon back to the model's summary page.
- **No "Needs Investigation" state** in Threat Dragon. Set it in the analysis view (or bring it
  in from a `.tm7`): the analysis view, report, CSV and export show it, while Threat Dragon itself
  shows such threats as Open.
- **Edits in the analysis view** are kept in `mymodel.triage.json` next to the model, so they
  survive Threat Dragon saving an older copy. A later change to the same threat in Threat Dragon
  wins.
- **Threat numbers** differ from TMT's for models drawn in Threat Dragon. Titles, categories,
  descriptions and priorities do not.
- **Threats on elements.** Threat Dragon also lets you add threats to an actor, process or store;
  TMT only has threats on interactions. tdtm reports them, but cannot export them to `.tm7`.
- **Not yet compared with TMT:** boundary curves, tagged elements, encrypted or HTTPS flows,
  out-of-scope elements and two-way flows. They are checked against worked examples, and the
  rules are TMT's own, but nobody has put the same diagram through TMT yet. If you can, please
  open an issue with the result.
- **Check with your lecturer** if a course asks for TMT specifically: the threats match, but the
  screenshots will show Threat Dragon.
