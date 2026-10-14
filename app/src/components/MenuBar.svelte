<script lang="ts" module>
  // `checked` makes an item a check box, or with `radio` one of a set (a view, a diagram)
  export type MenuItem = { label: string; shortcut?: string; action: () => void; disabled?: boolean; checked?: boolean; radio?: boolean } | "-";
  export type Menu = { label: string; items: MenuItem[] };
</script>

<script lang="ts">
  // TMT's menu bar: click a menu to open it; while one is open, pointing at another opens that one.
  // Arrow keys move through the items and across menus; Escape closes.
  let { menus }: { menus: Menu[] } = $props();
  let open = $state<number | null>(null);
  let bar: HTMLElement | undefined = $state();
  let tops: HTMLButtonElement[] = $state([]);

  function items() {
    return [...(bar?.querySelectorAll<HTMLButtonElement>(".dropdown button:not(:disabled)") ?? [])];
  }

  function keydown(e: KeyboardEvent) {
    if (open === null) return;
    const list = items(), at = list.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") { tops[open]?.focus(); open = null; e.preventDefault(); } // back to the menu's title
    else if (e.key === "ArrowDown") { list[(at + 1) % list.length]?.focus(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { list[at < 0 ? list.length - 1 : (at - 1 + list.length) % list.length]?.focus(); e.preventDefault(); }
    else if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      open = (open + (e.key === "ArrowRight" ? 1 : menus.length - 1)) % menus.length;
      queueMicrotask(() => items()[0]?.focus());
      e.preventDefault();
    }
  }

  function run(item: Exclude<MenuItem, "-">) {
    open = null;
    item.action();
  }
</script>

<svelte:window onkeydown={keydown} />

<div class="menubar" role="menubar" tabindex="-1" aria-label="Menu" bind:this={bar}>
  {#each menus as menu, i}
    <div class="menu">
      <button role="menuitem" class="top" class:on={open === i} aria-haspopup="menu" aria-expanded={open === i} bind:this={tops[i]}
        onclick={() => (open = open === i ? null : i)}
        onpointerenter={() => { if (open !== null) open = i; }}>{menu.label}</button>
      {#if open === i}
        <div class="dropdown" role="menu" aria-label={menu.label}>
          {#each menu.items as item}
            {#if item === "-"}
              <div class="sep" role="separator"></div>
            {:else}
              <button role={item.checked === undefined ? "menuitem" : item.radio ? "menuitemradio" : "menuitemcheckbox"}
                aria-checked={item.checked === undefined ? undefined : item.checked} disabled={item.disabled} onclick={() => run(item)}>
                <span class="check" aria-hidden="true">{item.checked ? "✓" : ""}</span>
                <span class="label">{item.label}</span>
                <span class="kbd">{item.shortcut ?? ""}</span>
              </button>
            {/if}
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</div>
{#if open !== null}
  <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
  <div class="scrim" onclick={() => (open = null)}></div>
{/if}

<style>
  .menubar { position: relative; z-index: 22; display: flex; align-items: center; gap: 1px; } /* above the scrim: pointing at another menu opens it */
  .menu { position: relative; }
  .top { height: 28px; padding: 0 var(--s-2); border: 0; border-radius: var(--r-1); background: none; color: var(--text); }
  .top:hover, .top.on { background: var(--hover); }
  .scrim { position: fixed; inset: 0; z-index: 20; }
  .dropdown { position: absolute; left: 0; top: 30px; z-index: 21; min-width: 248px; padding: var(--s-1); background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); box-shadow: var(--shadow-pop); }
  .dropdown button { display: grid; grid-template-columns: 16px 1fr auto; align-items: center; gap: var(--s-2); width: 100%; height: 28px; padding: 0 var(--s-2); border: 0; border-radius: var(--r-1); background: none; text-align: left; color: var(--text); white-space: nowrap; }
  .dropdown button:hover:not(:disabled), .dropdown button:focus-visible { background: var(--hover); outline: none; }
  .dropdown button:disabled { color: var(--faint); }
  .check { color: var(--text); font-weight: 600; }
  .kbd { font: var(--fs-caption) var(--mono); color: var(--muted); }
  .sep { height: 1px; margin: var(--s-1) 0; background: var(--border); }
</style>
