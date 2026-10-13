<script lang="ts">
  // TMT's stencils, from the SDL template: drag one onto the canvas, or click to add it.
  import type { Palette, Stencil } from "../lib/types";
  import type { Kind } from "../lib/shapes";
  import Icon from "./Icon.svelte";

  let { palette, onadd }: { palette: Palette | null; onadd: (kind: Kind, stencil: string | null) => void } = $props();

  const SECTIONS: { kind: Kind; key: keyof Palette | null; title: string }[] = [
    { kind: "actor", key: "actor", title: "External interactors" },
    { kind: "process", key: "process", title: "Processes" },
    { kind: "store", key: "store", title: "Data stores" },
    { kind: "flow", key: "flow", title: "Data flows" },
    { kind: "boundary_box", key: "boundary_box", title: "Trust border boundaries" },
    { kind: "boundary_curve", key: "boundary_curve", title: "Trust line boundaries" },
  ];

  let query = $state("");
  let open = $state<Record<string, boolean>>({ actor: true, process: true, store: true, flow: false, boundary_box: true, boundary_curve: false });

  const items = (key: keyof Palette | null): Stencil[] => {
    const list = key && palette ? palette[key] : [];
    const q = query.trim().toLowerCase();
    return q ? list.filter((s) => s.name.toLowerCase().includes(q)) : list;
  };

  function drag(e: DragEvent, kind: Kind, s: Stencil) {
    e.dataTransfer?.setData("application/x-threatsketch", JSON.stringify({ kind, stencil: s.generic ? null : s.id }));
    if (e.dataTransfer) e.dataTransfer.effectAllowed = "copy";
  }
</script>

<aside class="palette" aria-label="Stencils">
  <div class="head">
    <div class="title">Stencils</div>
    <label class="search">
      <Icon name="search" size={14} />
      <input placeholder="Search stencils" bind:value={query} aria-label="Search stencils" />
    </label>
  </div>
  <div class="list">
    {#if !palette}
      <p class="muted pad">Loading the SDL template…</p>
    {:else}
      {#each SECTIONS as sec (sec.kind)}
        {@const list = items(sec.key)}
        {#if list.length}
          <section>
            <button class="sec" onclick={() => (open[sec.kind] = !open[sec.kind])} aria-expanded={open[sec.kind] || !!query}>
              <span class="chev" class:closed={!(open[sec.kind] || query)}><Icon name="chevron" size={14} /></span>
              {sec.title}
              <span class="count">{list.length}</span>
            </button>
            {#if open[sec.kind] || query}
              <div class="items">
                {#each list as s (s.id)}
                  <button
                    class="item"
                    class:generic={s.generic}
                    draggable="true"
                    ondragstart={(e) => drag(e, sec.kind, s)}
                    onclick={() => onadd(sec.kind, s.generic ? null : s.id)}
                    title={`${s.name}: drag onto the canvas, or click to add`}
                  >
                    <span class="glyph"><Icon name={sec.kind} size={16} /></span>
                    <span class="name">{s.name}</span>
                  </button>
                {/each}
              </div>
            {/if}
          </section>
        {/if}
      {/each}
      <section>
        <div class="items">
          <button class="item" draggable="true" ondragstart={(e) => drag(e, "text", { id: "", name: "Note", generic: true })} onclick={() => onadd("text", null)}>
            <span class="glyph"><Icon name="text" size={16} /></span><span class="name">Note</span>
          </button>
        </div>
      </section>
    {/if}
  </div>
  <div class="tip">
    Hover an element and drag a <b class="plus">+</b> to draw a data flow; click it to link the nearest element on that side.
  </div>
</aside>

<style>
  .palette { display: flex; flex-direction: column; min-height: 0; background: var(--panel); border-right: 1px solid var(--border); }
  .head { padding: var(--s-3) var(--s-3) var(--s-2); }
  .title { font-weight: 600; margin-bottom: var(--s-2); }
  .search { display: flex; align-items: center; gap: var(--s-2); height: 28px; padding: 0 var(--s-2); border: 1px solid var(--border-strong); border-radius: var(--r-1); color: var(--faint); background: var(--panel); }
  .search:focus-within { border-color: var(--accent); box-shadow: var(--focus); }
  .search input { border: 0; outline: 0; background: transparent; width: 100%; color: var(--text); }
  .list { flex: 1; overflow: auto; padding: 0 var(--s-2) var(--s-3); }
  .pad { padding: var(--s-2); }
  .sec { display: flex; align-items: center; gap: var(--s-1); width: 100%; padding: var(--s-3) var(--s-1) var(--s-1); border: 0; background: none; font-size: var(--fs-small); font-weight: 600; color: var(--muted); }
  .sec:hover { color: var(--text); }
  .chev { display: inline-flex; transition: transform 0.12s; }
  .chev.closed { transform: rotate(-90deg); }
  .count { margin-left: auto; font: var(--fs-caption) var(--mono); color: var(--faint); }
  .items { display: grid; }
  .item { display: flex; align-items: center; gap: var(--s-2); width: 100%; height: 28px; padding: 0 var(--s-2); border: 0; border-radius: var(--r-1); background: none; text-align: left; cursor: grab; color: var(--text); }
  .item:hover { background: var(--hover); }
  .item:active { cursor: grabbing; }
  .item.generic .name { font-weight: 500; }
  .glyph { display: grid; place-items: center; width: 20px; color: var(--muted); }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tip { padding: var(--s-2) var(--s-3) var(--s-3); border-top: 1px solid var(--border); font-size: var(--fs-small); color: var(--muted); }
  .plus { font-weight: 600; color: var(--accent-text); }
</style>
