<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "./components/Icon.svelte";
  import Palette from "./components/Palette.svelte";
  import Properties from "./components/Properties.svelte";
  import ThreatList from "./components/ThreatList.svelte";
  import { engine, type EngineState } from "./engine/client";
  import { Editor } from "./lib/editor";
  import * as files from "./lib/files";
  import type { Kind } from "./lib/shapes";
  import type { AnalyzeResult, Model, Palette as PaletteT } from "./lib/types";

  let canvas: HTMLDivElement | undefined = $state();
  let editor: Editor | null = null;

  let engineState = $state<EngineState>(engine.state);
  let palette = $state.raw<PaletteT | null>(null);
  let model = $state.raw<Model | null>(null);
  let analysis = $state.raw<AnalyzeResult | null>(null);
  let version = $state(0); // bumped whenever the model changes underneath, to refresh what derives from it
  let selectedCell = $state<string | null>(null);
  let selectedThreat = $state<string | null>(null);
  let diagram = $state(0);
  let fileName = $state("");
  let handle: files.Handle | undefined;
  let dirty = $state(false);
  let focusName = $state(0);
  let notice = $state<{ text: string; tone: "info" | "error" } | null>(null);
  let exportOpen = $state(false);
  let threatHeight = $state(280);
  let draft = $state.raw(files.loadDraft());
  let dropping = $state(false);
  let renaming = $state<number | null>(null);
  let theme = $state<string>(readTheme());
  let fromThreat = false;

  onMount(() => {
    const off = engine.onState(async (s) => {
      engineState = s;
      if (s.status === "ready" && !palette) palette = await engine.palette();
    });
    const keys = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); if (model) save(e.shiftKey); }
      if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); open(); }
    };
    const leave = (e: BeforeUnloadEvent) => { if (dirty) e.preventDefault(); };
    if (files.isDesktop) selftest();
    files.onOpenedFiles(async (opened) => { if (await confirmDiscard()) await openBytes(opened[0]); });
    // installed web app: files opened with ThreatSketch from Finder or Explorer arrive here
    (window as any).launchQueue?.setConsumer(async (params: { files: FileSystemFileHandle[] }) => {
      const h = params.files[0];
      if (!h) return;
      const f = await h.getFile();
      await openBytes({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()), handle: /\.json$/i.test(f.name) ? h : undefined });
    });
    window.addEventListener("keydown", keys);
    window.addEventListener("beforeunload", leave);
    return () => { off(); window.removeEventListener("keydown", keys); window.removeEventListener("beforeunload", leave); };
  });

  /** Desktop smoke test (see src-tauri/src/lib.rs): open the example, report, quit. */
  async function selftest() {
    const { invoke } = await import("@tauri-apps/api/core");
    if (!(await invoke<boolean>("selftest_mode"))) return;
    const started = performance.now();
    const report: Record<string, unknown> = { ua: navigator.userAgent };
    try {
      await new Promise<void>((ok, fail) => engine.onState((s) => (s.status === "ready" ? ok() : s.status === "failed" ? fail(new Error(s.error)) : null)));
      report.engineMs = Math.round(performance.now() - started);
      report.phases = (engine.state as any).phases;
      const t = performance.now();
      const m = await fetch(`${import.meta.env.BASE_URL}examples/online-shop.json`).then((r) => r.json());
      const r = await engine.analyze(m);
      report.analyzeMs = Math.round(performance.now() - t);
      report.threats = r.threats.length;
      await load(m, "online-shop.json");
      await new Promise((r) => setTimeout(r, 500));
      report.cells = editor?.graph.getCellCount();
      report.drawn = document.querySelectorAll(".x6-node, .x6-edge").length;
    } catch (e: any) {
      report.error = String(e?.message ?? e);
    }
    await invoke("selftest_report", { report: JSON.stringify(report) });
  }

  function ensureEditor() {
    if (editor || !canvas) return editor;
    editor = new Editor(canvas, {
      analysed: (r) => {
        analysis = r;
        if (r.counts.added || r.counts.refreshed || r.counts.stale) dirty = true; // new threats to save
        model = editor!.model;
        version++;
        files.saveDraft({ model: editor!.model, name: fileName });
      },
      selected: (id) => {
        selectedCell = id;
        if (!fromThreat) selectedThreat = null;
        fromThreat = false;
      },
      changed: () => { dirty = true; version++; },
      failed: (m) => say(m, "error"),
      edit: () => focusName++,
    });
    (window as any).threatsketch = { editor }; // for automated tests and the browser console
    return editor;
  }

  function say(text: string, tone: "info" | "error" = "info") {
    notice = { text, tone };
    setTimeout(() => { if (notice?.text === text) notice = null; }, tone === "error" ? 8000 : 4000);
  }

  // --- files -------------------------------------------------------------------------------

  async function load(next: Model, name: string, h?: files.Handle) {
    try {
      await show(next, name, h);
    } catch (e: any) {
      say(`Could not open ${name || "the model"}: ${e?.message ?? e}`, "error");
      throw e;
    }
  }

  async function show(next: Model, name: string, h?: files.Handle) {
    if (!next?.detail?.diagrams?.length) throw new Error("This file is not a threat model (no diagrams found).");
    model = next;
    fileName = name;
    handle = h;
    analysis = null;
    selectedCell = selectedThreat = null;
    diagram = 0;
    await Promise.resolve(); // let the canvas mount
    ensureEditor()!.open(next);
    dirty = false;
    version++;
  }

  async function openBytes(o: files.Opened) {
    try {
      if (/\.tm7$/i.test(o.name)) {
        const r = await engine.importTm7(o.bytes, files.baseName(o.name));
        await load(r.model, `${files.baseName(o.name)}.json`);
        dirty = true;
        say(`Imported ${o.name} from Microsoft TMT${r.warnings.length ? ` (${r.warnings.length} notes)` : ""}. Save to keep it as a .json model.`);
      } else {
        await load(JSON.parse(new TextDecoder().decode(o.bytes)), o.name, o.handle);
      }
    } catch (e: any) {
      if (!notice) say(`Could not open ${o.name}: ${e?.message ?? e}`, "error");
    }
  }

  async function confirmDiscard() {
    return !dirty || files.ask("You have unsaved changes. Discard them?");
  }

  async function open() {
    if (!(await confirmDiscard())) return;
    const o = await files.pickFile().catch((e) => { say(String(e?.message ?? e), "error"); return null; });
    if (o) await openBytes(o);
  }

  async function newModel() {
    if (!(await confirmDiscard())) return;
    const m = await engine.newModel("Untitled threat model");
    await load(m, "");
    focusTitle();
  }

  async function example() {
    if (!(await confirmDiscard())) return;
    const m = await fetch(`${import.meta.env.BASE_URL}examples/online-shop.json`).then((r) => r.json());
    await load(m, "online-shop.json");
  }

  async function restore() {
    if (!draft) return;
    await load(draft.model, draft.name);
    dirty = true;
  }

  function focusTitle() {
    setTimeout(() => document.querySelector<HTMLInputElement>("[data-testid=model-title]")?.select(), 50);
  }

  const baseName = () => files.baseName(fileName) || (model?.summary.title || "threat-model").replace(/[^\w.-]+/g, "-");

  async function save(as = false) {
    if (!editor) return;
    const text = JSON.stringify(editor.snapshot(), null, 2);
    try {
      const used = await files.saveText(text, `${baseName()}.json`, "application/json", as ? undefined : handle);
      if (used) { handle = used; fileName = files.handleName(used); }
      else if (!files.canSaveInPlace) fileName ||= `${baseName()}.json`;
      else if (!handle) return; // cancelled
      dirty = false;
      files.clearDraft();
      say(files.canSaveInPlace ? `Saved ${fileName}` : `Downloaded ${baseName()}.json`);
    } catch (e: any) {
      say(`Could not save: ${e?.message ?? e}`, "error");
    }
  }

  async function exportAs(kind: "json" | "tm7" | "csv" | "html") {
    exportOpen = false;
    if (!editor) return;
    const m = editor.snapshot();
    try {
      if (kind === "json") await files.saveText(JSON.stringify(m, null, 2), `${baseName()}.json`, "application/json");
      if (kind === "tm7") {
        const r = await engine.exportTm7(m);
        await files.saveText(r.text, `${baseName()}.tm7`, "application/xml");
        if (r.warnings.length) say(`Exported for TMT with ${r.warnings.length} notes: ${r.warnings[0]}`);
      }
      if (kind === "csv") await files.saveText(await engine.reportCsv(m), `${baseName()}.csv`, "text/csv");
      if (kind === "html") await files.saveText(await engine.reportHtml(m), `${baseName()}.report.html`, "text/html");
    } catch (e: any) {
      say(`Export failed: ${e?.message ?? e}`, "error");
    }
  }

  async function report() {
    if (!editor) return;
    try {
      await files.showHtml(await engine.reportHtml(editor.snapshot()), `${baseName()}.report.html`);
    } catch (e: any) {
      say(`Could not show the report: ${e?.message ?? e}`, "error");
    }
  }

  // --- editing -----------------------------------------------------------------------------

  function add(kind: Kind, stencil: string | null, at?: { x: number; y: number }) {
    if (!editor) return;
    editor.add(kind, stencil, at);
    focusName++;
  }

  function dropOnCanvas(e: DragEvent) {
    dropping = false;
    const payload = e.dataTransfer?.getData("application/x-threatsketch");
    if (payload && editor) {
      e.preventDefault();
      const { kind, stencil } = JSON.parse(payload);
      add(kind, stencil, editor.clientToLocal(e.clientX, e.clientY));
    }
  }

  async function dropFile(e: DragEvent) {
    const file = e.dataTransfer?.files?.[0];
    dropping = false;
    if (!file) return;
    e.preventDefault();
    if (await confirmDiscard()) await openBytes(await files.readFile(file));
  }

  function selectThreat(key: string) {
    selectedThreat = key;
    const t = analysis?.threats.find((x) => x.key === key);
    if (!t || !editor) return;
    const d = editor.model.detail.diagrams.findIndex((dg) => dg.cells.some((c) => c.id === t.cell));
    if (d >= 0 && d !== diagram) switchDiagram(d);
    fromThreat = true;
    editor.select(t.cell);
    if (selectedCell !== t.cell) fromThreat = false;
    selectedCell = t.cell;
  }

  function showCell(id: string) {
    selectedThreat = null;
    editor?.select(id);
  }

  function updateModel(field: string, value: string) {
    if (!editor) return;
    const m = editor.model;
    if (field === "title" || field === "owner" || field === "description") m.summary[field] = value;
    else if (field === "reviewer") m.detail.reviewer = value;
    else if (field === "contributors") m.detail.contributors = value.split(",").map((n) => n.trim()).filter(Boolean).map((name) => ({ name }));
    model = { ...m } as Model; // new reference for the header; the editor keeps the same object
    editor.model = m;
    dirty = true;
    files.saveDraft({ model: m, name: fileName });
  }

  // --- diagrams ----------------------------------------------------------------------------

  function switchDiagram(i: number) {
    if (!editor) return;
    editor.loadDiagram(i);
    diagram = i;
    selectedCell = null;
    version++;
  }

  function addDiagram() {
    if (!editor) return;
    const m = editor.snapshot();
    const ids = m.detail.diagrams.map((d) => Number(d.id)).filter((n) => !Number.isNaN(n));
    const id = ids.length ? Math.max(...ids) + 1 : 0;
    m.detail.diagrams.push({
      id, title: `Diagram ${m.detail.diagrams.length + 1}`, diagramType: "STRIDE",
      placeholder: "New STRIDE diagram description", thumbnail: "./public/content/images/thumbnail.stride.jpg",
      version: m.version ?? "2.6.2", cells: [],
    });
    m.detail.diagramTop = (m.detail.diagramTop ?? 0) + 1;
    switchDiagram(m.detail.diagrams.length - 1);
    dirty = true;
  }

  function renameDiagram(i: number, title: string) {
    renaming = null;
    if (!editor || !title.trim()) return;
    editor.model.detail.diagrams[i].title = title.trim();
    dirty = true;
    version++;
    editor.analyse();
  }

  async function deleteDiagram(i: number) {
    if (!editor || editor.model.detail.diagrams.length < 2) return;
    if (!(await files.ask(`Delete the diagram "${editor.model.detail.diagrams[i].title}" and its threats?`))) return;
    editor.snapshot();
    editor.model.detail.diagrams.splice(i, 1);
    switchDiagram(Math.max(0, i - 1));
    editor.analyse();
    dirty = true;
  }

  // --- derived -----------------------------------------------------------------------------

  const cell = $derived.by(() => {
    version;
    if (!selectedCell || !editor) return null;
    const data = editor.dataOf(selectedCell);
    const kind = editor.kindOf(selectedCell);
    return data && kind ? { id: selectedCell, kind, data } : null;
  });
  const threat = $derived(analysis?.threats.find((t) => t.key === selectedThreat) ?? null);
  const cellThreats = $derived(analysis?.threats.filter((t) => t.cell === selectedCell) ?? []);
  const names = $derived.by(() => {
    version;
    const out: Record<string, string> = {};
    for (const d of model?.detail.diagrams ?? []) for (const c of d.cells) out[c.id] = c.data?.name ?? "";
    return out;
  });
  const diagrams = $derived.by(() => { version; return model?.detail.diagrams.map((d) => d.title) ?? []; });
  const empty = $derived.by(() => { version; return !!model && !(model.detail.diagrams[diagram]?.cells.length); });
  const open_ = $derived(analysis?.threats.filter((t) => t.state === "Not Started" || t.state === "Needs Investigation").length ?? 0);
  const warnings = $derived(analysis?.warnings ?? []);

  // --- layout ------------------------------------------------------------------------------

  function resize(e: PointerEvent) {
    const start = e.clientY, h = threatHeight;
    const move = (m: PointerEvent) => (threatHeight = Math.min(window.innerHeight - 220, Math.max(120, h + start - m.clientY)));
    const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  function readTheme() {
    try { return localStorage.getItem("threatsketch:theme") ?? "auto"; } catch { return "auto"; }
  }
  function toggleTheme() {
    const dark = theme === "dark" || (theme === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
    theme = dark ? "light" : "dark";
    try { localStorage.setItem("threatsketch:theme", theme); } catch { /* not kept */ }
  }
  $effect(() => {
    if (theme === "auto") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
  });
</script>

<svelte:window
  ondragover={(e) => { if (e.dataTransfer?.types.includes("Files")) { e.preventDefault(); dropping = true; } }}
  ondragleave={(e) => { if (!e.relatedTarget) dropping = false; }}
  ondrop={dropFile}
/>

<div class="app" class:has-model={!!model} style="--threats: {threatHeight}px">
  <header class="top">
    <div class="brand">
      <img class="mark" src="{import.meta.env.BASE_URL}favicon.svg" alt="" width="26" height="26" />
      <span class="name">ThreatSketch</span>
    </div>
    {#if model}
      <div class="doc">
        <button class="doctitle" onclick={() => { editor?.graph.cleanSelection(); selectedThreat = null; focusTitle(); }} title="Model properties">
          {model.summary.title || "Untitled threat model"}
        </button>
        <span class="file">{fileName || "not saved yet"}{#if dirty}<span class="dirty" title="Unsaved changes">•</span>{/if}</span>
      </div>
      <div class="tools">
        <button class="btn icon" onclick={() => editor?.undo()} title="Undo (⌘Z)" aria-label="Undo"><Icon name="undo" /></button>
        <button class="btn icon" onclick={() => editor?.redo()} title="Redo (⇧⌘Z)" aria-label="Redo"><Icon name="redo" /></button>
      </div>
    {/if}
    <div class="actions">
      <button class="btn icon" onclick={toggleTheme} title="Light or dark" aria-label="Toggle theme"><Icon name={theme === "dark" ? "sun" : "moon"} /></button>
      {#if model}
        <button class="btn" onclick={newModel}><Icon name="new" />New</button>
        <button class="btn" onclick={open}><Icon name="open" />Open</button>
        <div class="menu">
          <button class="btn" onclick={() => (exportOpen = !exportOpen)} aria-expanded={exportOpen} aria-haspopup="menu"><Icon name="export" />Export</button>
          {#if exportOpen}
            <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
            <div class="scrim" onclick={() => (exportOpen = false)}></div>
            <div class="dropdown" role="menu">
              <button role="menuitem" onclick={() => exportAs("tm7")}><b>Microsoft TMT model</b><span>.tm7, opens in TMT 7</span></button>
              <button role="menuitem" onclick={() => exportAs("html")}><b>Threat report</b><span>.html, TMT's Full Report layout</span></button>
              <button role="menuitem" onclick={() => exportAs("csv")}><b>Threat list</b><span>.csv, TMT's export columns</span></button>
              <button role="menuitem" onclick={() => exportAs("json")}><b>Save a copy</b><span>.json, opens in Threat Dragon too</span></button>
            </div>
          {/if}
        </div>
        <button class="btn outline" onclick={report}><Icon name="report" />Report</button>
        <button class="btn primary" onclick={() => save()} title="Save (⌘S)"><Icon name="save" />Save</button>
      {/if}
    </div>
  </header>

  {#if model}
    <Palette {palette} onadd={(k, s) => add(k, s)} />
  {/if}

  <main class="stage" class:hidden={!model}>
    <div class="tabs" role="tablist" aria-label="Diagrams">
      {#each diagrams as title, i}
        {#if renaming === i}
          <!-- svelte-ignore a11y_autofocus -->
          <input class="tabedit" value={title} autofocus
            onblur={(e) => renameDiagram(i, e.currentTarget.value)}
            onkeydown={(e) => { if (e.key === "Enter") e.currentTarget.blur(); if (e.key === "Escape") renaming = null; }} />
        {:else}
          <button role="tab" class="tab" class:on={i === diagram} aria-selected={i === diagram}
            onclick={() => switchDiagram(i)} ondblclick={() => (renaming = i)} title="Double-click to rename">
            {title}
            {#if diagrams.length > 1 && i === diagram}
              <span class="x" role="button" tabindex="-1" aria-label="Delete diagram"
                onclick={(e) => { e.stopPropagation(); deleteDiagram(i); }} onkeydown={() => {}}><Icon name="close" size={12} /></span>
            {/if}
          </button>
        {/if}
      {/each}
      <button class="tab add" onclick={addDiagram} title="New diagram" aria-label="New diagram"><Icon name="plus" size={14} /></button>
    </div>
    <div class="canvaswrap" role="application" aria-label="Diagram canvas"
      ondragover={(e) => { if (e.dataTransfer?.types.includes("application/x-threatsketch")) { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; } }}
      ondrop={dropOnCanvas}>
      <div class="canvas" bind:this={canvas}></div>
      {#if empty}
        <div class="hint">
          <b>Start your diagram</b>
          <span>Drag a stencil from the left, or click one to add it. Then hover an element and drag its <i>+</i> to draw a data flow.</span>
        </div>
      {/if}
      <div class="zoom">
        <button class="btn icon" onclick={() => editor?.zoom(-0.1)} aria-label="Zoom out" title="Zoom out (⌘ scroll)"><Icon name="zoomout" /></button>
        <button class="btn icon" onclick={() => editor?.fit()} aria-label="Fit to screen" title="Fit to screen"><Icon name="fit" /></button>
        <button class="btn icon" onclick={() => editor?.zoom(0.1)} aria-label="Zoom in" title="Zoom in (⌘ scroll)"><Icon name="zoomin" /></button>
      </div>
    </div>
  </main>

  {#if model}
    <section class="threatpane">
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="resizer" onpointerdown={resize} title="Drag to resize"></div>
      <ThreatList threats={analysis?.threats ?? []} selected={selectedThreat} onselect={selectThreat} loading={engineState.status === "loading"} />
    </section>
  {/if}

  {#if model}
    <Properties
      {model} {cell} {threat} {cellThreats} {palette} {names} {focusName}
      info={selectedCell ? analysis?.elements[selectedCell] : undefined}
      onmodel={updateModel}
      onupdate={(id, change) => editor?.update(id, change)}
      onstencil={(id, s, a) => editor?.setElement(id, s, a)}
      onthreat={(key, s, pr, j) => editor?.setThreat(key, s, pr, j)}
      onselectthreat={selectThreat}
      onshowcell={showCell}
      ondelete={() => editor?.removeSelected()}
    />
  {/if}

  <footer class="status">
    <span class="engine {engineState.status}" data-testid="engine-status">
      <span class="pulse"></span>
      {#if engineState.status === "loading"}Starting the threat engine…
      {:else if engineState.status === "ready"}SDL TM Knowledge Base · tdtm {engineState.version}
      {:else}Threat engine failed: {engineState.error}{/if}
    </span>
    {#if analysis}
      <span data-testid="threat-count">{analysis.threats.length} threats</span>
      <span>{open_} open</span>
    {/if}
    {#if warnings.length}
      <span class="warn" title={warnings.join("\n")}><Icon name="warning" size={13} />{warnings.length} {warnings.length === 1 ? "note" : "notes"}</span>
    {/if}
    <span class="grow"></span>
    {#if model}<span class="muted">{dirty ? "Unsaved changes (a draft is kept in this browser)" : "All changes saved"}</span>{/if}
  </footer>

  {#if !model}
    <div class="welcome">
      <div class="card">
        <img class="bigmark" src="{import.meta.env.BASE_URL}favicon.svg" alt="" width="64" height="64" />
        <h1>ThreatSketch</h1>
        <p class="lede">Draw a data-flow diagram and get Microsoft TMT's STRIDE threats as you draw, from the same SDL TM Knowledge Base template TMT uses.</p>
        <div class="start">
          <button class="btn primary big" onclick={newModel}><Icon name="new" />New threat model</button>
          <button class="btn outline big" onclick={open}><Icon name="open" />Open a file…</button>
        </div>
        <button class="btn example" onclick={example}>Or explore an example: an online shop with 38 threats →</button>
        {#if draft}
          <button class="restore" onclick={restore}>
            <b>Restore unsaved work</b>
            <span>{draft.model?.summary?.title || "Untitled"} · {new Date(draft.at).toLocaleString()}</span>
          </button>
        {/if}
        <p class="fine">Opens Threat Dragon <code>.json</code> and Microsoft TMT <code>.tm7</code> files, or drop one here. Your models never leave this computer.</p>
      </div>
    </div>
  {/if}

  {#if dropping}
    <div class="dropzone"><div>Drop a <b>.json</b> or <b>.tm7</b> model to open it</div></div>
  {/if}
  {#if notice}
    <div class="toast {notice.tone}" role="status">{notice.text}<button class="btn icon" onclick={() => (notice = null)} aria-label="Dismiss"><Icon name="close" size={14} /></button></div>
  {/if}
</div>

<style>
  .app {
    height: 100%;
    display: grid;
    grid-template-columns: 248px minmax(0, 1fr) 320px;
    grid-template-rows: 52px minmax(0, 1fr) var(--threats) 28px;
    grid-template-areas: "top top top" "pal stage props" "threats threats props" "status status status";
  }
  .app:not(.has-model) { grid-template-rows: 52px minmax(0, 1fr) 0 28px; grid-template-areas: "top top top" "stage stage stage" "threats threats threats" "status status status"; }
  .app > :global(.palette) { grid-area: pal; }
  .app > :global(.props) { grid-area: props; }
  .top { grid-area: top; display: flex; align-items: center; gap: 12px; padding: 0 12px; background: var(--panel); border-bottom: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 650; letter-spacing: -0.01em; padding-right: 12px; border-right: 1px solid var(--border); height: 28px; }
  .mark { display: block; width: 28px; height: 28px; }
  .doc { display: flex; flex-direction: column; min-width: 0; }
  .doctitle { border: 0; background: none; padding: 0; font-weight: 600; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 360px; }
  .doctitle:hover { color: var(--accent-text); }
  .file { font-size: 11px; color: var(--muted); }
  .dirty { color: var(--accent); margin-left: 4px; font-size: 16px; line-height: 0; vertical-align: -2px; }
  .tools { display: flex; gap: 2px; margin-left: 8px; }
  .actions { margin-left: auto; display: flex; align-items: center; gap: 6px; }
  .menu { position: relative; }
  .scrim { position: fixed; inset: 0; z-index: 20; }
  .dropdown { position: absolute; right: 0; top: 36px; z-index: 21; width: 270px; padding: 6px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow-lg); }
  .dropdown button { display: grid; width: 100%; padding: 8px 10px; border: 0; border-radius: 6px; background: none; text-align: left; }
  .dropdown button:hover { background: var(--hover); }
  .dropdown b { font-weight: 600; }
  .dropdown span { font-size: 12px; color: var(--muted); }

  .stage { grid-area: stage; display: grid; grid-template-rows: 38px minmax(0, 1fr); min-height: 0; min-width: 0; }
  .stage.hidden { visibility: hidden; }
  .tabs { display: flex; align-items: flex-end; gap: 2px; padding: 0 8px; background: var(--panel-2); border-bottom: 1px solid var(--border); overflow-x: auto; }
  .tab { display: inline-flex; align-items: center; gap: 6px; height: 30px; padding: 0 12px; border: 1px solid transparent; border-bottom: 0; border-radius: 7px 7px 0 0; background: none; color: var(--muted); white-space: nowrap; }
  .tab:hover { color: var(--text); }
  .tab.on { background: var(--canvas); border-color: var(--border); color: var(--text); font-weight: 600; margin-bottom: -1px; height: 31px; }
  .tab.add { padding: 0 8px; }
  .x { display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: 4px; color: var(--muted); }
  .x:hover { background: var(--hover); color: var(--text); }
  .tabedit { height: 26px; margin-bottom: 2px; padding: 0 8px; border: 1px solid var(--accent); border-radius: 6px; background: var(--panel); outline: none; box-shadow: var(--focus); }
  .canvaswrap { position: relative; min-height: 0; }
  .canvas { position: absolute; inset: 0; }
  .hint { position: absolute; left: 50%; top: 42%; transform: translate(-50%, -50%); display: grid; gap: 6px; max-width: 380px; padding: 18px 22px; text-align: center; border: 1.5px dashed var(--border-strong); border-radius: 12px; color: var(--muted); background: var(--panel); pointer-events: none; }
  .hint b { color: var(--text); font-size: 14px; }
  .hint i { display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: 50%; background: var(--accent); color: #fff; font-style: normal; font-size: 12px; line-height: 1; }
  .zoom { position: absolute; right: 14px; bottom: 14px; display: flex; gap: 2px; padding: 3px; background: var(--panel); border: 1px solid var(--border); border-radius: 9px; box-shadow: var(--shadow); }
  .threatpane { grid-area: threats; position: relative; min-height: 0; border-top: 1px solid var(--border); }
  .resizer { position: absolute; left: 0; right: 0; top: -4px; height: 8px; z-index: 5; cursor: row-resize; }
  .resizer:hover { background: linear-gradient(transparent 3px, var(--accent) 3px, var(--accent) 5px, transparent 5px); }

  .status { grid-area: status; display: flex; align-items: center; gap: 16px; padding: 0 12px; font-size: 12px; color: var(--muted); background: var(--panel); border-top: 1px solid var(--border); }
  .engine { display: inline-flex; align-items: center; gap: 7px; }
  .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--faint); }
  .engine.ready .pulse { background: var(--s-ok); }
  .engine.loading .pulse { background: var(--s-inv); animation: blink 1s ease-in-out infinite; }
  .engine.failed { color: var(--s-new); }
  .engine.failed .pulse { background: var(--s-new); }
  @keyframes blink { 50% { opacity: 0.3; } }
  .warn { display: inline-flex; align-items: center; gap: 5px; color: var(--s-inv); cursor: help; }
  .grow { flex: 1; }

  .welcome { position: fixed; inset: 52px 0 28px; display: grid; place-items: center; padding: 24px; background:
    radial-gradient(circle at 1px 1px, var(--border-strong) 1px, transparent 0) 0 0 / 22px 22px, var(--bg); }
  .card { width: min(560px, 100%); padding: 36px 36px 28px; background: var(--panel); border: 1px solid var(--border); border-radius: 16px; box-shadow: var(--shadow-lg); text-align: center; }
  .bigmark { display: inline-block; width: 68px; height: 68px; }
  h1 { margin: 14px 0 6px; font-size: 26px; letter-spacing: -0.02em; }
  .lede { margin: 0 auto 22px; max-width: 440px; color: var(--muted); font-size: 14px; line-height: 1.55; }
  .start { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
  .big { height: 40px; padding: 0 16px; font-size: 14px; border-radius: 8px; }
  .example { margin-top: 14px; color: var(--accent-text); }
  .restore { display: grid; gap: 2px; width: 100%; margin-top: 18px; padding: 10px 14px; border: 1px solid var(--border); border-radius: 10px; background: var(--panel-2); text-align: left; }
  .restore:hover { border-color: var(--accent); }
  .restore span { font-size: 12px; color: var(--muted); }
  .fine { margin: 22px 0 0; font-size: 12px; color: var(--faint); }
  .fine code { font: 11px var(--mono); }

  .dropzone { position: fixed; inset: 0; z-index: 40; display: grid; place-items: center; background: rgba(79, 107, 237, 0.12); border: 3px dashed var(--accent); pointer-events: none; font-size: 16px; }
  .dropzone div { padding: 14px 22px; background: var(--panel); border-radius: 10px; box-shadow: var(--shadow-lg); }
  .toast { position: fixed; left: 50%; bottom: 44px; transform: translateX(-50%); z-index: 50; display: flex; align-items: center; gap: 8px; max-width: min(640px, 90vw); padding: 8px 8px 8px 14px; background: #1d2433; color: #fff; border-radius: 10px; box-shadow: var(--shadow-lg); }
  .toast.error { background: #b42318; }
  .toast .btn { color: #fff; }
  .toast .btn:hover { background: rgba(255, 255, 255, 0.12); }
</style>
