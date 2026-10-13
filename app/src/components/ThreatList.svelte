<script lang="ts">
  // TMT's Analysis View threat list: its eleven columns, a filter drop-down on every column header,
  // sorting by header, resizable columns, "Export Csv" and "N Threats Displayed, M Total" below.
  import { STATES, type ThreatRow } from "../lib/types";
  import Icon from "./Icon.svelte";

  let {
    threats,
    selected,
    onselect,
    onexport,
    loading,
  }: { threats: ThreatRow[]; selected: string | null; onselect: (key: string) => void; onexport: () => void; loading: boolean } = $props();

  type Col = "id" | "diagram" | "changedBy" | "lastModified" | "state" | "title" | "category" | "description" | "justification" | "interaction" | "priority";
  // TMT's columns, in its order, at roughly its widths
  const COLS: { col: Col; label: string; width: number }[] = [
    { col: "id", label: "ID", width: 76 },
    { col: "diagram", label: "Diagram", width: 150 },
    { col: "changedBy", label: "Changed By", width: 110 },
    { col: "lastModified", label: "Last Modified", width: 120 },
    { col: "state", label: "State", width: 170 },
    { col: "title", label: "Title", width: 280 },
    { col: "category", label: "Category", width: 160 },
    { col: "description", label: "Description", width: 320 },
    { col: "justification", label: "Justification", width: 200 },
    { col: "interaction", label: "Interaction", width: 220 },
    { col: "priority", label: "Priority", width: 90 },
  ];
  let widths = $state(Object.fromEntries(COLS.map((c) => [c.col, c.width])) as Record<Col, number>);
  const template = $derived(COLS.map((c) => `${widths[c.col]}px`).join(" "));

  let filter = $state<string>("All");
  let query = $state("");
  let sort = $state<{ col: Col; dir: 1 | -1 }>({ col: "id", dir: 1 });
  // per column: the values hidden by its filter drop-down (empty: show all)
  let hidden = $state<Partial<Record<Col, string[]>>>({});
  let openFilter = $state<Col | null>(null);

  const text = (t: ThreatRow, col: Col) => String(t[col] ?? "");
  const counts = $derived(Object.fromEntries(STATES.map((s) => [s, threats.filter((t) => t.state === s).length])));
  const values = (col: Col) => [...new Set(threats.map((t) => text(t, col)))].sort((a, b) => (col === "id" ? Number(a) - Number(b) : a.localeCompare(b)));

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const rows = threats.filter(
      (t) =>
        (filter === "All" || t.state === filter) &&
        COLS.every(({ col }) => !hidden[col]?.includes(text(t, col))) &&
        (!q || `${t.id} ${t.title} ${t.category} ${t.priority} ${t.state} ${t.interaction} ${t.source} ${t.target} ${t.description} ${t.justification}`.toLowerCase().includes(q)),
    );
    const { col, dir } = sort;
    return rows.sort((a, b) => {
      const x = a[col] ?? "", y = b[col] ?? "";
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * dir;
    });
  });

  const sortBy = (col: Col) => (sort = { col, dir: sort.col === col ? (-sort.dir as 1 | -1) : 1 });
  const SHORT: Record<string, string> = { "Needs Investigation": "Investigating" }; // full name in the tooltip
  const cls = (s: string) => `state-${s.replaceAll(" ", "-")}`;

  function toggle(col: Col, value: string) {
    const h = hidden[col] ?? [];
    hidden[col] = h.includes(value) ? h.filter((v) => v !== value) : [...h, value];
  }
  const filtered = (col: Col) => !!hidden[col]?.length;

  function keys(e: KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = shown.findIndex((t) => t.key === selected);
    const next = shown[Math.max(0, Math.min(shown.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) onselect(next.key);
  }

  function resize(e: PointerEvent, col: Col) {
    e.preventDefault();
    e.stopPropagation();
    const start = e.clientX, w = widths[col];
    const move = (m: PointerEvent) => (widths[col] = Math.max(40, w + m.clientX - start));
    const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }
</script>

<section class="threats" aria-label="Threat list">
  <div class="bar">
    <div class="title">Threat list</div>
    <div class="filters" role="tablist" aria-label="Filter by state">
      <button role="tab" class="seg" class:on={filter === "All"} aria-selected={filter === "All"} onclick={() => (filter = "All")}>
        All <b class="num">{threats.length}</b>
      </button>
      {#each STATES as s}
        <button role="tab" class="seg" title={s} class:on={filter === s} aria-selected={filter === s} onclick={() => (filter = s)}>
          <span class="state {cls(s)}"><span class="dot"></span></span><span class="lbl">{SHORT[s] ?? s}</span> <b class="num">{counts[s]}</b>
        </button>
      {/each}
    </div>
    <div class="spacer"></div>
    {#if Object.values(hidden).some((h) => h?.length)}
      <button class="btn small" onclick={() => (hidden = {})}>Clear column filters</button>
    {/if}
    <label class="search">
      <Icon name="search" size={14} />
      <input placeholder="Search threats" bind:value={query} aria-label="Search threats" />
    </label>
  </div>

  <div class="table" tabindex="0" role="grid" aria-rowcount={shown.length} onkeydown={keys}>
    <div class="row headrow" role="row" style="grid-template-columns: {template}">
      {#if openFilter}
        <!-- in the header's stacking context, under its drop-down: a click outside closes it -->
        <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
        <div class="scrim" onclick={() => (openFilter = null)}></div>
      {/if}
      {#each COLS as { col, label }}
        <div class="h" role="columnheader" aria-sort={sort.col === col ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
          <button class="sort" onclick={() => sortBy(col)}>
            {label}{#if sort.col === col}<span class="arrow">{sort.dir === 1 ? "↑" : "↓"}</span>{/if}
          </button>
          <button class="funnel" class:on={filtered(col)} aria-label={`Filter ${label}`} aria-haspopup="menu" aria-expanded={openFilter === col}
            onclick={() => (openFilter = openFilter === col ? null : col)}><Icon name="chevron" size={12} /></button>
          <!-- svelte-ignore a11y_no_static_element_interactions -->
          <span class="grip" onpointerdown={(e) => resize(e, col)} title="Drag to resize"></span>
          {#if openFilter === col}
            <div class="pop" role="menu" aria-label={`Filter ${label}`}>
              <div class="popbar">
                <button class="link" onclick={() => (hidden[col] = [])}>Select all</button>
                <button class="link" onclick={() => (hidden[col] = values(col))}>Clear</button>
              </div>
              <div class="vals">
                {#each values(col) as v}
                  <label class="val">
                    <input type="checkbox" checked={!hidden[col]?.includes(v)} onchange={() => toggle(col, v)} />
                    <span>{v || "(blank)"}</span>
                  </label>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      {/each}
    </div>
    {#each shown as t (t.key)}
      <div
        class="row"
        class:sel={t.key === selected}
        style="grid-template-columns: {template}"
        role="row"
        tabindex="-1"
        aria-selected={t.key === selected}
        data-testid="threat-row"
        onclick={() => onselect(t.key)}
        onkeydown={(e) => e.key === "Enter" && onselect(t.key)}
      >
        <div class="cell c-id num">{t.id ?? ""}</div>
        <div class="cell muted" title={t.diagram}>{t.diagram}</div>
        <div class="cell muted">{t.changedBy}</div>
        <div class="cell muted">{t.lastModified}</div>
        <div class="cell"><span class="state {cls(t.state)}"><span class="dot"></span>{t.state}</span></div>
        <div class="cell" title={t.title}>{t.title}</div>
        <div class="cell muted">{t.category}</div>
        <div class="cell muted" title={t.description}>{t.description}</div>
        <div class="cell muted" title={t.justification}>{t.justification}</div>
        <div class="cell muted" title={t.source ? `${t.source} → ${t.target}` : ""}>{t.interaction}</div>
        <div class="cell muted">{t.priority}</div>
      </div>
    {:else}
      <div class="empty">
        {#if loading}
          Starting the threat engine…
        {:else if threats.length}
          No threats match these filters.
        {:else}
          No threats yet. Draw elements and connect them with data flows: threats appear here as you draw.
        {/if}
      </div>
    {/each}
  </div>

  <div class="foot">
    <button class="btn small" onclick={onexport}>Export Csv</button>
    <span data-testid="threats-displayed">{shown.length} Threats Displayed, {threats.length} Total</span>
  </div>
</section>
<svelte:window onkeydown={(e) => { if (e.key === "Escape") openFilter = null; }} />

<style>
  .threats { container-type: inline-size; display: flex; flex-direction: column; min-height: 0; height: 100%; background: var(--panel); }
  .bar { display: flex; align-items: center; gap: var(--s-2); padding: var(--s-2) var(--s-3); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .title { font-weight: 600; margin-right: var(--s-2); }
  .filters { display: flex; gap: 2px; padding: 2px; border-radius: var(--r-1); background: var(--panel-2); border: 1px solid var(--border); }
  .seg { display: inline-flex; align-items: center; gap: 6px; height: 22px; padding: 0 var(--s-2); border: 0; border-radius: 2px; background: none; color: var(--muted); font-size: var(--fs-small); white-space: nowrap; }
  .seg b { font-weight: 500; color: var(--text); }
  .seg:hover { color: var(--text); }
  .seg.on { background: var(--panel); color: var(--text); box-shadow: 0 0 0 1px var(--border-strong); }
  .spacer { flex: 1; }
  .btn.small { height: 26px; padding: 0 var(--s-2); font-size: var(--fs-small); }
  .search { display: flex; align-items: center; gap: 6px; height: 26px; padding: 0 var(--s-2); border: 1px solid var(--border-strong); border-radius: var(--r-1); color: var(--faint); width: 180px; }
  .search:focus-within { border-color: var(--accent); box-shadow: var(--focus); }
  .search input { border: 0; outline: 0; background: transparent; width: 100%; font-size: var(--fs-small); color: var(--text); }
  .table { flex: 1; overflow: auto; outline: none; }
  .row { display: grid; width: max-content; min-width: 100%; align-items: center; min-height: 32px; border-bottom: 1px solid var(--border); cursor: pointer; }
  .row:not(.headrow):hover { background: var(--panel-2); }
  .row.sel { background: var(--accent-soft); box-shadow: inset 2px 0 0 var(--accent); }
  .headrow { position: sticky; top: 0; z-index: 2; background: var(--panel); min-height: 28px; cursor: default; border-bottom-color: var(--border-strong); }
  .cell { padding: 0 var(--s-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted { color: var(--muted); }
  .h { position: relative; display: flex; align-items: center; height: 28px; min-width: 0; padding-left: var(--s-3); }
  .sort { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; border: 0; background: none; padding: 0; text-align: left; font-size: var(--fs-small); font-weight: 500; color: var(--muted); }
  .sort:hover { color: var(--text); }
  .arrow { margin-left: var(--s-1); }
  .funnel { display: grid; place-items: center; width: 20px; height: 20px; margin-right: 6px; border: 0; border-radius: var(--r-1); background: none; color: var(--faint); }
  .funnel:hover { background: var(--hover); color: var(--text); }
  .funnel.on { color: var(--accent-text); background: var(--accent-soft); }
  .grip { position: absolute; right: 0; top: 4px; bottom: 4px; width: 5px; cursor: col-resize; border-right: 1px solid var(--border); }
  .grip:hover { border-right: 2px solid var(--accent); }
  .scrim { position: fixed; inset: 0; z-index: 20; }
  .pop { position: absolute; left: 0; top: 28px; z-index: 21; width: 260px; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); box-shadow: var(--shadow-pop); font-weight: 400; }
  .popbar { display: flex; gap: var(--s-3); padding: var(--s-2) var(--s-3); border-bottom: 1px solid var(--border); }
  .link { border: 0; background: none; padding: 0; color: var(--accent-text); font-size: var(--fs-small); }
  .vals { max-height: 240px; overflow: auto; padding: var(--s-1) 0; }
  .val { display: flex; align-items: center; gap: var(--s-2); padding: 3px var(--s-3); font-size: var(--fs-small); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .val:hover { background: var(--hover); }
  .foot { display: flex; align-items: center; gap: var(--s-4); padding: var(--s-1) var(--s-3); border-top: 1px solid var(--border); font-size: var(--fs-small); color: var(--muted); }
  @container (max-width: 1080px) { .seg .lbl { display: none; } .search { width: 150px; } }
  .empty { padding: var(--s-6) var(--s-4); color: var(--muted); }
</style>
