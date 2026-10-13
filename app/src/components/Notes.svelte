<script lang="ts" module>
  export type Note = { Id: string; Message: string; Date: string; AddedBy: string };
</script>

<script lang="ts">
  // TMT's Notes pane: notes about the whole model, kept in the .tm7 (Id, Note, Date, Added By).
  let { notes, onchange }: { notes: Note[]; onchange: (notes: Note[]) => void } = $props();

  // as TMT's Notes pane shows it: "13/10/2026 10:35 pm"
  const when = (iso: string) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const two = (n: number) => String(n).padStart(2, "0");
    const h = d.getHours();
    return `${two(d.getDate())}/${two(d.getMonth() + 1)}/${d.getFullYear()} ${h % 12 || 12}:${two(d.getMinutes())} ${h < 12 ? "am" : "pm"}`;
  };

  function add() {
    const id = String(Math.max(0, ...notes.map((n) => Number(n.Id) || 0)) + 1);
    onchange([...notes, { Id: id, Message: "", Date: new Date().toISOString(), AddedBy: "" }]);
    queueMicrotask(() => document.querySelector<HTMLInputElement>(`[data-note="${id}"]`)?.focus());
  }
  function edit(id: string, message: string) {
    if (notes.find((n) => n.Id === id)?.Message === message) return;
    onchange(notes.map((n) => (n.Id === id ? { ...n, Message: message } : n)));
  }
  const remove = (id: string) => onchange(notes.filter((n) => n.Id !== id));
</script>

<section class="notes" aria-label="Notes">
  <div class="bar"><button class="btn small" onclick={add}>Add New Note</button></div>
  <div class="table" role="table" aria-label="Notes">
    <div class="row head" role="row">
      <span role="columnheader">Id</span><span role="columnheader">Note</span><span role="columnheader">Date</span>
      <span role="columnheader">Added By</span><span></span>
    </div>
    {#each notes as n (n.Id)}
      <div class="row" role="row" data-testid="note-row">
        <span class="num muted" role="cell">{n.Id}</span>
        <input class="input" data-note={n.Id} value={n.Message} aria-label={`Note ${n.Id}`}
          onblur={(e) => edit(n.Id, e.currentTarget.value)} onkeydown={(e) => e.key === "Enter" && e.currentTarget.blur()} />
        <span class="muted" role="cell">{when(n.Date)}</span>
        <span class="muted" role="cell">{n.AddedBy}</span>
        <button class="btn small" onclick={() => remove(n.Id)} aria-label={`Delete note ${n.Id}`}>Delete</button>
      </div>
    {:else}
      <div class="empty">No notes. Notes are for the whole model and are kept in .tm7 files, as in TMT.</div>
    {/each}
  </div>
</section>

<style>
  .notes { display: flex; flex-direction: column; min-height: 0; height: 100%; background: var(--panel); }
  .bar { padding: var(--s-2) var(--s-3); border-bottom: 1px solid var(--border); }
  .btn.small { height: 26px; padding: 0 var(--s-2); font-size: var(--fs-small); }
  .table { flex: 1; overflow: auto; }
  .row { display: grid; grid-template-columns: 48px minmax(240px, 1fr) 180px 160px 72px; align-items: center; gap: var(--s-2); min-height: 34px; padding: 0 var(--s-3); border-bottom: 1px solid var(--border); }
  .head { position: sticky; top: 0; background: var(--panel); min-height: 28px; font-size: var(--fs-small); font-weight: 500; color: var(--muted); border-bottom-color: var(--border-strong); }
  .row .input { height: 26px; min-height: 26px; }
  .muted { color: var(--muted); font-size: var(--fs-small); }
  .empty { padding: var(--s-5) var(--s-3); color: var(--muted); }
</style>
