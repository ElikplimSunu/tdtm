# tdtm

Microsoft TMT-style automatic threat generation for [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) models, so you can do TMT-style threat modelling on a Mac.

Draw your data-flow diagram in Threat Dragon, save it, run `tdtm analyze model.json`, and reopen
the file: each data flow now carries the STRIDE threats Microsoft's Threat Modeling Tool would
generate with the **SDL TM Knowledge Base** template, ready to triage in Threat Dragon.

> Status: scaffold. See `docs/PLAN.md` for what is built and what is next.

## Use

```bash
uv sync
uv run tdtm analyze path/to/model.json      # adds threats; keeps a .bak
uv run tdtm inspect path/to/model.json      # see how elements were interpreted
uv run tdtm stencils --kind process         # tags you can put in descriptions
uv run tdtm report path/to/model.json       # TMT-style HTML report
```

### Telling tdtm what an element really is

Threat Dragon has five generic shapes; TMT has 52 specific stencils with attributes. Put a line
starting with `@tmt:` in an element's description:

```
@tmt: WebApp; hasInputSanitizers=Yes
@tmt: SQL Database; storesCredentials=Yes
@tmt: HTTPS
```

## Develop

This repo is set up for Claude Code. Start with `CLAUDE.md`, then run `/next-task`.

```bash
uv sync && uv run pytest -q
```

## Credits

- Threat rules and stencils: Microsoft `threat-modeling-templates` (MIT).
- Test fixtures and schema: OWASP Threat Dragon (Apache-2.0).
- See `THIRD_PARTY_NOTICES.md`.
