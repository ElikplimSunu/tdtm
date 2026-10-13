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
                    <span class="glyph"><Icon name={sec.kind} size={18} /></span>
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
            <span class="glyph"><Icon name="text" size={18} /></span><span class="name">Note</span>
          </button>
        </div>
      </section>
    {/if}
  </div>
  <div class="tip">
    Hover an element and drag a <b class="plus">+</b> to draw a data flow, or click it to link the nearest element.
  </div>
</aside>

<style>
  .palette { display: flex; flex-direction: column; min-height: 0; background: var(--panel); border-right: 1px solid var(--border); }
  .head { padding: 12px 12px 8px; border-bottom: 1px solid var(--border); }
  .title { font-weight: 600; margin-bottom: 8px; }
  .search { display: flex; align-items: center; gap: 6px; height: 30px; padding: 0 8px; border: 1px solid var(--border-strong); border-radius: 6px; color: var(--faint); background: var(--panel); }
  .search:focus-within { border-color: var(--accent); box-shadow: var(--focus); }
  .search input { border: 0; outline: 0; background: transparent; width: 100%; color: var(--text); }
  .list { flex: 1; overflow: auto; padding: 6px 6px 12px; }
  .pad { padding: 8px; }
  .sec { display: flex; align-items: center; gap: 4px; width: 100%; padding: 8px 6px 4px; border: 0; background: none; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; text-transform: uppercase; color: var(--muted); }
  .sec:hover { color: var(--text); }
  .chev { display: inline-flex; transition: transform 0.12s; }
  .chev.closed { transform: rotate(-90deg); }
  .count { margin-left: auto; font-weight: 500; color: var(--faint); }
  .items { display: grid; gap: 1px; }
  .item { display: flex; align-items: center; gap: 10px; width: 100%; padding: 6px 8px; border: 0; border-radius: 6px; background: none; text-align: left; cursor: grab; }
  .item:hover { background: var(--hover); }
  .item:active { cursor: grabbing; }
  .item.generic .name { font-weight: 600; }
  .glyph { display: grid; place-items: center; width: 28px; height: 24px; border-radius: 5px; background: var(--panel-2); border: 1px solid var(--border); color: var(--text); }
  .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tip { padding: 10px 12px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }
  .plus { display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: 50%; background: var(--accent); color: #fff; font-size: 12px; line-height: 1; }
</style>
