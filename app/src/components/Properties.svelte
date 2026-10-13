<script lang="ts">
  // The properties pane: the model, the selected element (with TMT's stencil properties), or the
  // selected threat (TMT state, priority, justification).
  import { tick } from "svelte";
  import { KIND_NAMES, type Kind } from "../lib/shapes";
  import { visibleDescription, withTags } from "../lib/sync";
  import { PRIORITIES, STATES, type ElementInfo, type Model, type Palette, type ThreatRow } from "../lib/types";
  import Icon from "./Icon.svelte";

  type Props = {
    model: Model | null;
    cell: { id: string; kind: Kind; data: Record<string, any> } | null;
    info: ElementInfo | undefined;
    threat: ThreatRow | null;
    cellThreats: ThreatRow[];
    palette: Palette | null;
    names: Record<string, string>;
    focusName: number;
    onmodel: (field: string, value: string) => void;
    onupdate: (id: string, change: Record<string, any>) => void;
    onstencil: (id: string, stencil: string, attributes: Record<string, string>) => void;
    onthreat: (key: string, state: string, priority: string, justification: string) => void;
    onselectthreat: (key: string) => void;
    onshowcell: (id: string) => void;
    ondelete: () => void;
  };
  let p: Props = $props();

  let nameInput: HTMLInputElement | undefined = $state();
  let name = $state("");
  let description = $state("");
  let reason = $state("");
  let justification = $state("");
  let tstate = $state("");
  let priority = $state("");
  let lastId = "";

  $effect(() => {
    const id = p.cell?.id ?? p.threat?.key ?? "";
    if (id === lastId) return;
    lastId = id;
    name = p.cell?.data?.name ?? "";
    description = visibleDescription(p.cell?.data?.description);
    reason = p.cell?.data?.reasonOutOfScope ?? "";
    justification = p.threat?.justification ?? "";
    tstate = p.threat?.state ?? "";
    priority = p.threat?.priority ?? "";
  });

  $effect(() => {
    if (p.focusName) tick().then(() => { nameInput?.focus(); nameInput?.select(); });
  });

  const STENCIL_KEY: Partial<Record<Kind, keyof Palette>> = {
    actor: "actor", process: "process", store: "store", flow: "flow", boundary_box: "boundary_box", boundary_curve: "boundary_curve",
  };
  const stencils = $derived(p.cell && p.palette && STENCIL_KEY[p.cell.kind] ? p.palette[STENCIL_KEY[p.cell.kind]!] : []);
  const hasThreats = $derived(p.cell && ["actor", "process", "store", "flow"].includes(p.cell.kind));
  const isBoundary = $derived(p.cell && (p.cell.kind === "boundary_box" || p.cell.kind === "boundary_curve"));

  function commitName() {
    if (p.cell && name !== p.cell.data.name) p.onupdate(p.cell.id, { name });
  }
  function commitDescription() {
    if (!p.cell) return;
    const full = withTags(description, p.cell.data.description);
    if (full !== (p.cell.data.description ?? "")) p.onupdate(p.cell.id, { description: full });
  }
  function setStencil(id: string) {
    if (p.cell) p.onstencil(p.cell.id, id, {});
  }
  function setAttribute(attr: string, value: string) {
    if (!p.cell || !p.info) return;
    const values = Object.fromEntries(p.info.attributes.map((a) => [a.name, a.value]));
    p.onstencil(p.cell.id, p.info.stencil, { ...values, [attr]: value });
  }
  // The form keeps its own values, so a quick second change never sends a stale first one.
  function triage() {
    const t = p.threat;
    if (!t) return;
    if (tstate === t.state && priority === t.priority && justification === t.justification) return;
    p.onthreat(t.key, tstate, priority, justification);
  }
  const cls = (s: string) => `state-${s.replaceAll(" ", "-")}`;
  const sourceNote: Record<string, string> = { static: "set by the stencil", TD: "from a Threat Dragon option", tag: "", default: "" };
  const enter = (e: KeyboardEvent) => e.key === "Enter" && (e.target as HTMLElement).blur();
</script>

<aside class="props" aria-label="Properties">
  {#if p.threat}
    {@const t = p.threat}
    <header>
      <div class="kind">{["Threat " + (t.id ?? ""), t.category, t.generatedBy].filter(Boolean).join(" · ")}</div>
      <h2>{t.title}</h2>
    </header>
    <div class="body">
      <button class="link" onclick={() => p.onshowcell(t.cell)}>
        <Icon name="target" size={14} />
        <span>{t.source ? `${t.source} → ${t.target}` : t.interaction}</span>
        <span class="muted">· {t.interaction}</span>
      </button>

      <div class="grid2">
        <label class="field">
          <span>State</span>
          <select class="input" bind:value={tstate} onchange={triage} data-testid="threat-state">
            {#each STATES as s}<option>{s}</option>{/each}
          </select>
        </label>
        <label class="field">
          <span>Priority</span>
          <select class="input" bind:value={priority} onchange={triage} data-testid="threat-priority">
            {#each PRIORITIES as s}<option>{s}</option>{/each}
          </select>
        </label>
      </div>
      <label class="field">
        <span>Justification</span>
        <textarea class="input" rows="4" placeholder="How is this mitigated, or why does it not apply?" bind:value={justification}
          onblur={triage} data-testid="threat-justification"></textarea>
      </label>
      <div class="field">
        <span>Description</span>
        <p class="desc">{t.description}</p>
      </div>
    </div>
  {:else if p.cell}
    {@const c = p.cell}
    <header>
      <div class="kind">{[KIND_NAMES[c.kind], p.info?.stencilName].filter(Boolean).join(" · ")}</div>
      <h2>{c.data.name || KIND_NAMES[c.kind]}</h2>
    </header>
    <div class="body">
      <label class="field">
        <span>Name</span>
        <input class="input" bind:this={nameInput} bind:value={name} onblur={commitName} onkeydown={enter} data-testid="element-name" />
      </label>
      {#if stencils.length > 1}
        <label class="field">
          <span>Stencil</span>
          <select class="input" value={p.info?.stencil} onchange={(e) => setStencil(e.currentTarget.value)} data-testid="element-stencil">
            {#each stencils as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
          </select>
        </label>
      {/if}
      {#if c.kind !== "text"}
        <label class="field">
          <span>Description</span>
          <textarea class="input" rows="3" bind:value={description} onblur={commitDescription}></textarea>
        </label>
      {/if}
      {#if hasThreats}
        {#if c.kind === "flow"}
          <label class="check">
            <input type="checkbox" checked={!!c.data.isBidirectional} onchange={(e) => p.onupdate(c.id, { isBidirectional: e.currentTarget.checked })} />
            Two-way flow
          </label>
        {/if}
        <label class="check">
          <input type="checkbox" checked={!!c.data.outOfScope} onchange={(e) => p.onupdate(c.id, { outOfScope: e.currentTarget.checked })} />
          Out of scope
        </label>
        {#if c.data.outOfScope}
          <label class="field">
            <span>Reason for out of scope</span>
            <textarea class="input" rows="2" bind:value={reason} onblur={() => p.onupdate(c.id, { reasonOutOfScope: reason })}></textarea>
          </label>
        {/if}
      {/if}

      {#if p.info && (p.info.crosses.length || p.info.zone)}
        <div class="field">
          <span>{c.kind === "flow" ? "Crosses" : "Inside"}</span>
          <div class="tags">
            {#each c.kind === "flow" ? p.info.crosses : [p.info.zone] as b}
              <span class="boundary">{p.names[b ?? ""] || "Trust boundary"}</span>
            {/each}
          </div>
        </div>
      {/if}

      {#if p.info && p.info.attributes.length && !isBoundary}
        <div class="section">TMT properties</div>
        {#each p.info.attributes as a (a.name)}
          <label class="attr">
            <span class="aname" title={a.name}>{a.label}</span>
            {#if a.static}
              <span class="fixed" title="Fixed by the {p.info.stencilName} stencil"><Icon name="lock" size={12} />{a.value}</span>
            {:else}
              <select class="input compact" value={a.value} onchange={(e) => setAttribute(a.name, e.currentTarget.value)}>
                {#each a.values as v}<option>{v}</option>{/each}
              </select>
            {/if}
            {#if sourceNote[a.source]}<span class="src">{sourceNote[a.source]}</span>{/if}
          </label>
        {/each}
      {/if}

      {#if hasThreats}
        <div class="section">Threats <span class="num muted">{p.cellThreats.length}</span></div>
        {#if p.cellThreats.length}
          <ul class="mini">
            {#each p.cellThreats as t (t.key)}
              <li><button onclick={() => p.onselectthreat(t.key)}><span class="state {cls(t.state)}"><span class="dot"></span></span><span class="tt">{t.title}</span></button></li>
            {/each}
          </ul>
        {:else}
          <p class="muted small">{c.kind === "flow" ? "None for this flow." : "Threats are listed on the data flows that touch this element, as in TMT."}</p>
        {/if}
      {/if}
      <button class="btn danger" onclick={p.ondelete}><Icon name="trash" size={14} /> Delete</button>
    </div>
  {:else if p.model}
    <header>
      <div class="kind">Threat model</div>
      <h2>{p.model.summary.title || "Untitled"}</h2>
    </header>
    <div class="body">
      <label class="field"><span>Title</span>
        <input class="input" value={p.model.summary.title} onchange={(e) => p.onmodel("title", e.currentTarget.value)} data-testid="model-title" /></label>
      <div class="grid2">
        <label class="field"><span>Owner</span>
          <input class="input" value={p.model.summary.owner ?? ""} onchange={(e) => p.onmodel("owner", e.currentTarget.value)} /></label>
        <label class="field"><span>Reviewer</span>
          <input class="input" value={p.model.detail.reviewer ?? ""} onchange={(e) => p.onmodel("reviewer", e.currentTarget.value)} /></label>
      </div>
      <label class="field"><span>Contributors</span>
        <input class="input" placeholder="Comma-separated" value={(p.model.detail.contributors ?? []).map((c: any) => c.name).join(", ")}
          onchange={(e) => p.onmodel("contributors", e.currentTarget.value)} /></label>
      <label class="field"><span>Description</span>
        <textarea class="input" rows="4" value={p.model.summary.description ?? ""} onchange={(e) => p.onmodel("description", e.currentTarget.value)}></textarea></label>
      <p class="muted small hint">Select an element to edit it, or a threat in the list to triage it.</p>
    </div>
  {/if}
</aside>

<style>
  .props { display: flex; flex-direction: column; min-height: 0; background: var(--panel); border-left: 1px solid var(--border); overflow: auto; }
  header { padding: var(--s-4) var(--s-4) var(--s-3); border-bottom: 1px solid var(--border); }
  .kind { font-size: var(--fs-small); color: var(--muted); }
  h2 { margin: var(--s-1) 0 0; font-size: var(--fs-h2); font-weight: 600; line-height: 1.35; overflow-wrap: anywhere; }
  .small { font-size: var(--fs-small); }
  .body { padding: var(--s-4) var(--s-4) var(--s-6); }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--s-3); }
  .link { display: flex; align-items: center; gap: var(--s-2); width: 100%; margin: 0 0 var(--s-4); padding: 6px var(--s-2); border: 1px solid var(--border-strong); border-radius: var(--r-1); background: none; text-align: left; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .link:hover { border-color: var(--accent); color: var(--accent-text); }
  .desc { margin: 0; white-space: pre-wrap; line-height: 1.55; }
  .section { margin: var(--s-6) 0 var(--s-2); padding-top: var(--s-4); border-top: 1px solid var(--border); font-size: var(--fs-small); font-weight: 600; color: var(--muted); }
  .attr { display: grid; grid-template-columns: 1fr 1fr; gap: 2px var(--s-3); align-items: center; margin-bottom: var(--s-1); }
  .aname { font-size: var(--fs-small); overflow: hidden; text-overflow: ellipsis; }
  .input.compact { min-height: 26px; height: 26px; padding: 0 6px; font-size: var(--fs-small); }
  .fixed { display: inline-flex; align-items: center; gap: var(--s-1); font-size: var(--fs-small); color: var(--muted); }
  .src { grid-column: 2; font-size: var(--fs-caption); color: var(--muted); }
  .tags { display: flex; flex-wrap: wrap; gap: var(--s-1) var(--s-3); }
  /* trust boundaries are named in TMT's red, underlined dashed like the boundary itself */
  .boundary { color: var(--danger); font-weight: 500; border-bottom: 1.5px dashed currentColor; }
  .mini { list-style: none; margin: 0 0 var(--s-3); padding: 0; }
  .mini button { display: flex; align-items: center; gap: var(--s-2); width: 100%; height: 28px; padding: 0 var(--s-1); border: 0; border-radius: var(--r-1); background: none; text-align: left; }
  .mini button:hover { background: var(--hover); }
  .tt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .danger { margin-top: var(--s-2); color: var(--danger); }
  .danger:hover:not(:disabled) { background: var(--danger-bg); }
  .hint { margin-top: var(--s-5); }
</style>
