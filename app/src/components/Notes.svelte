<script lang="ts" module>
  export type Note = { Id: string; Message: string; Date: string; AddedBy: string | null };
</script>

<script lang="ts">
  // TMT's Notes pane: notes about the whole model, kept in the .tm7 (Id, Note, Date, Added By).
  let { notes, onchange }: { notes: Note[]; onchange: (notes: Note[]) => void } = $props();

  // in the viewer's own date format, as TMT follows the Windows locale
  const when = (iso: string) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
  };

  /** Now, as local time with its offset, as triage stamps it (TMT writes local times). */
  function now() {
    const d = new Date(), off = -d.getTimezoneOffset();
    const two = (n: number) => String(Math.trunc(Math.abs(n))).padStart(2, "0");
    return `${new Date(d.getTime() + off * 60_000).toISOString().slice(0, -1)}${off < 0 ? "-" : "+"}${two(off / 60)}:${two(off % 60)}`;
  }

  function add() {
    const id = String(Math.max(0, ...notes.map((n) => Number(n.Id) || 0)) + 1);
    onchange([...notes, { Id: id, Message: "", Date: now(), AddedBy: "" }]);
    queueMicrotask(() => document.querySelector<HTMLTextAreaElement>(`[data-note="${id}"]`)?.focus());
  }
  function edit(id: string, message: string) {
    if (notes.find((n) => n.Id === id)?.Message === message) return;
    onchange(notes.map((n) => (n.Id === id ? { ...n, Message: message } : n)));
  }
  const remove = (id: string) => onchange(notes.filter((n) => n.Id !== id));
</script>

<section class="notes" aria-label="Notes">
  <div class="bar"><button class="btn small" onclick={add}>Add new note</button></div>
  <div class="table" role="table" aria-label="Notes">
    <div class="row head" role="row">
      <span role="columnheader">Id</span><span role="columnheader">Note</span><span role="columnheader">Date</span>
      <span role="columnheader">Added by</span><span></span>
    </div>
    {#each notes as n (n.Id)}
      <div class="row" role="row" data-testid="note-row">
        <span class="num muted" role="cell">{n.Id}</span>
        <!-- a note can run to several lines (TMT's do): Enter is a new line; Cmd/Ctrl+Enter or leaving saves -->
        <textarea class="input" data-note={n.Id} value={n.Message} aria-label={`Note ${n.Id}`} rows={Math.min(6, Math.max(1, n.Message.split("\n").length))}
          onblur={(e) => edit(n.Id, e.currentTarget.value)} onkeydown={(e) => e.key === "Enter" && (e.metaKey || e.ctrlKey) && e.currentTarget.blur()}></textarea>
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
  .row .input { min-height: 26px; height: auto; padding-top: 3px; padding-bottom: 3px; resize: vertical; line-height: 1.4; }
  .muted { color: var(--muted); font-size: var(--fs-small); }
  .empty { padding: var(--s-5) var(--s-3); color: var(--muted); }
</style>
