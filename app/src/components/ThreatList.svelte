<script lang="ts">
  // TMT's Analysis View threat list: every threat, filterable, one click to triage.
  import { STATES, type ThreatRow } from "../lib/types";
  import Icon from "./Icon.svelte";

  let {
    threats,
    selected,
    onselect,
    loading,
  }: { threats: ThreatRow[]; selected: string | null; onselect: (key: string) => void; loading: boolean } = $props();

  let filter = $state<string>("All");
  let category = $state("All");
  let priority = $state("All");
  let query = $state("");
  let sort = $state<{ col: keyof ThreatRow; dir: 1 | -1 }>({ col: "id", dir: 1 });

  const counts = $derived(Object.fromEntries(STATES.map((s) => [s, threats.filter((t) => t.state === s).length])));
  const categories = $derived([...new Set(threats.map((t) => t.category))].sort());
  const priorities = $derived([...new Set(threats.map((t) => t.priority))]);

  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const rows = threats.filter(
      (t) =>
        (filter === "All" || t.state === filter) &&
        (category === "All" || t.category === category) &&
        (priority === "All" || t.priority === priority) &&
        (!q || `${t.id} ${t.title} ${t.category} ${t.priority} ${t.state} ${t.interaction} ${t.source} ${t.target} ${t.description}`.toLowerCase().includes(q)),
    );
    const { col, dir } = sort;
    return rows.sort((a, b) => {
      const x = a[col] ?? "", y = b[col] ?? "";
      return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * dir;
    });
  });

  const sortBy = (col: keyof ThreatRow) => (sort = { col, dir: sort.col === col ? (-sort.dir as 1 | -1) : 1 });
  const SHORT: Record<string, string> = { "Needs Investigation": "Investigating" }; // full name in the tooltip
  const cls = (s: string) => `state-${s.replaceAll(" ", "-")}`;

  function keys(e: KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const i = shown.findIndex((t) => t.key === selected);
    const next = shown[Math.max(0, Math.min(shown.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) onselect(next.key);
  }

  const COLS: [keyof ThreatRow, string][] = [
    ["id", "ID"], ["state", "State"], ["title", "Title"], ["category", "Category"], ["interaction", "Interaction"], ["priority", "Priority"],
  ];
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
    <select class="input small" bind:value={category} aria-label="Category">
      <option value="All">Any category</option>
      {#each categories as c}<option>{c}</option>{/each}
    </select>
    <select class="input small" bind:value={priority} aria-label="Priority">
      <option value="All">Any priority</option>
      {#each priorities as p}<option>{p}</option>{/each}
    </select>
    <label class="search">
      <Icon name="search" size={14} />
      <input placeholder="Search threats" bind:value={query} aria-label="Search threats" />
    </label>
  </div>

  <div class="table" tabindex="0" role="grid" aria-rowcount={shown.length} onkeydown={keys}>
    <div class="row headrow" role="row">
      {#each COLS as [col, label]}
        <button role="columnheader" class="cell h c-{col}" onclick={() => sortBy(col)}>
          {label}{#if sort.col === col}<span class="arrow">{sort.dir === 1 ? "↑" : "↓"}</span>{/if}
        </button>
      {/each}
    </div>
    {#each shown as t (t.key)}
      <div
        class="row"
        class:sel={t.key === selected}
        role="row"
        tabindex="-1"
        aria-selected={t.key === selected}
        data-testid="threat-row"
        onclick={() => onselect(t.key)}
        onkeydown={(e) => e.key === "Enter" && onselect(t.key)}
      >
        <div class="cell c-id num">{t.id ?? ""}</div>
        <div class="cell c-state"><span class="state {cls(t.state)}"><span class="dot"></span>{t.state}</span></div>
        <div class="cell c-title" title={t.title}>{t.title}</div>
        <div class="cell c-category">{t.category}</div>
        <div class="cell c-interaction" title={t.source ? `${t.source} → ${t.target}` : ""}>{t.interaction}</div>
        <div class="cell c-priority">{t.priority}</div>
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
</section>

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
  .input.small { width: 132px; height: 26px; min-height: 26px; padding: 0 var(--s-2); font-size: var(--fs-small); }
  .search { display: flex; align-items: center; gap: 6px; height: 26px; padding: 0 var(--s-2); border: 1px solid var(--border-strong); border-radius: var(--r-1); color: var(--faint); width: 180px; }
  .search:focus-within { border-color: var(--accent); box-shadow: var(--focus); }
  .search input { border: 0; outline: 0; background: transparent; width: 100%; font-size: var(--fs-small); color: var(--text); }
  .table { flex: 1; overflow: auto; outline: none; }
  .row { display: grid; grid-template-columns: 56px 168px minmax(240px, 3fr) 152px minmax(140px, 1.4fr) 80px; align-items: center; min-height: 32px; border-bottom: 1px solid var(--border); cursor: pointer; }
  .row:not(.headrow):hover { background: var(--panel-2); }
  .row.sel { background: var(--accent-soft); box-shadow: inset 2px 0 0 var(--accent); }
  .headrow { position: sticky; top: 0; z-index: 1; background: var(--panel); min-height: 28px; cursor: default; border-bottom-color: var(--border-strong); }
  .cell { padding: 0 var(--s-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .h { border: 0; background: none; text-align: left; height: 28px; font-size: var(--fs-small); font-weight: 500; color: var(--muted); }
  .h:hover { color: var(--text); }
  .arrow { margin-left: var(--s-1); }
  .c-id { color: var(--muted); font-size: var(--fs-small); }
  .c-category, .c-interaction, .c-priority { color: var(--muted); }
  @container (max-width: 1080px) { .seg .lbl { display: none; } .search { width: 150px; } }
  @container (max-width: 700px) { .bar .input.small { display: none; } }
  .empty { padding: var(--s-6) var(--s-4); color: var(--muted); }
</style>
