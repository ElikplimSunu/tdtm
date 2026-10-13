<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "./components/Icon.svelte";
  import Palette from "./components/Palette.svelte";
  import Properties from "./components/Properties.svelte";
  import ThreatList from "./components/ThreatList.svelte";
  import { engine, type EngineState } from "./engine/client";
  import { Editor } from "./lib/editor";
  import * as files from "./lib/files";
  import * as updates from "./lib/updates";
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
  const MOD = /Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl+";
  let update = $state.raw<updates.Update | null>(null);

  onMount(() => {
    const off = engine.onState(async (s) => {
      engineState = s;
      if (s.status === "ready" && !palette) {
        palette = await engine.palette();
        editor?.setPalette(palette);
      }
    });
    const keys = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "s") { e.preventDefault(); if (model) save(e.shiftKey); }
      if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); open(); }
    };
    const leave = (e: BeforeUnloadEvent) => { if (dirty) e.preventDefault(); };
    if (files.isDesktop) selftest().then((testing) => { if (!testing) updates.checkDesktop().then((u) => (update = u)); });
    updates.watchWeb((u) => (update = u));
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
    const mode = await invoke<string>("selftest_mode");
    if (!mode) return false;
    if (mode === "update") {
      const u = await updates.checkDesktop();
      if (u) { await u.apply(); return true; } // restarts into the new version, which reports
    }
    const started = performance.now();
    const { getVersion } = await import("@tauri-apps/api/app");
    const report: Record<string, unknown> = { ua: navigator.userAgent, version: await getVersion() };
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
    return true;
  }

  async function applyUpdate() {
    if (!update) return;
    if (dirty && editor) files.saveDraft({ model: editor.snapshot(), name: fileName }); // offered again after the restart
    dirty = false;
    try {
      await update.apply();
    } catch (e: any) {
      say(`The update could not be installed: ${e?.message ?? e}`, "error");
    }
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
        selectedThreat = null; // selectThreat sets it again after selecting the flow
      },
      changed: () => { dirty = true; version++; },
      failed: (m) => say(m, "error"),
      edit: () => focusName++,
    });
    if (palette) editor.setPalette(palette);
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

  async function exportAs(kind: "json" | "tm7" | "csv" | "html" | "pdf") {
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
      if (kind === "pdf") {
        // the browser's own PDF: the report opens with its print dialog, where Save as PDF is a choice
        const autoPrint = "<" + "script>addEventListener('load',()=>setTimeout(print,300))<" + "/script>";
        const html = (await engine.reportHtml(m)).replace("</" + "head>", autoPrint + "</" + "head>");
        await files.showHtml(html, `${baseName()}.report.html`);
      }
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
    const t = analysis?.threats.find((x) => x.key === key);
    if (t && editor) {
      const d = editor.model.detail.diagrams.findIndex((dg) => dg.cells.some((c) => c.id === t.cell));
      if (d >= 0 && d !== diagram) switchDiagram(d);
      editor.select(t.cell); // fires "selected", which clears the threat; set it after
      selectedCell = t.cell;
    }
    selectedThreat = key;
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
    else if (field === "Assumptions" || field === "ExternalDependencies") {
      // TMT-only fields; tm7 export and the report read them here (SPEC 11)
      const tdtm = ((m as any).tdtm ??= {});
      ((tdtm.tm7 ??= {}).meta ??= {})[field] = value;
    } else if (field === "contributors") m.detail.contributors = value.split(",").map((n) => n.trim()).filter(Boolean).map((name) => ({ name }));
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
    return data && kind ? { id: selectedCell, kind, data, line: editor.lineStyleOf(selectedCell) } : null;
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
      <img class="mark" src="{import.meta.env.BASE_URL}favicon.svg" alt="" width="22" height="22" />
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
        <button class="btn icon" onclick={() => editor?.undo()} title={`Undo (${MOD}Z)`} aria-label="Undo"><Icon name="undo" /></button>
        <button class="btn icon" onclick={() => editor?.redo()} title={`Redo (${MOD}Shift+Z)`} aria-label="Redo"><Icon name="redo" /></button>
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
              <button role="menuitem" onclick={() => exportAs("pdf")}><b>Threat report (PDF)</b><span>opens the print dialog: choose Save as PDF</span></button>
              <button role="menuitem" onclick={() => exportAs("html")}><b>Threat report</b><span>.html, TMT's Full Report layout</span></button>
              <button role="menuitem" onclick={() => exportAs("csv")}><b>Threat list</b><span>.csv, TMT's export columns</span></button>
              <button role="menuitem" onclick={() => exportAs("json")}><b>Save a copy</b><span>.json, opens in Threat Dragon too</span></button>
            </div>
          {/if}
        </div>
        <button class="btn outline" onclick={report}><Icon name="report" />Report</button>
        <button class="btn primary" onclick={() => save()} title={`Save (${MOD}S)`}><Icon name="save" />Save</button>
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
          <b>Empty diagram</b>
          <span>Click or drag a stencil from the left. Hover an element and drag its <i>+</i> to draw a data flow.</span>
        </div>
      {/if}
      <div class="zoom">
        <button class="btn icon" onclick={() => editor?.zoom(-0.1)} aria-label="Zoom out" title={`Zoom out (${MOD}scroll)`}><Icon name="zoomout" /></button>
        <button class="btn icon" onclick={() => editor?.fit()} aria-label="Fit to screen" title="Fit to screen"><Icon name="fit" /></button>
        <button class="btn icon" onclick={() => editor?.zoom(0.1)} aria-label="Zoom in" title={`Zoom in (${MOD}scroll)`}><Icon name="zoomin" /></button>
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
      {model} {cell} {threat} {cellThreats} {palette} {names} {focusName} review={analysis?.review ?? []}
      info={selectedCell ? analysis?.elements[selectedCell] : undefined}
      onmodel={updateModel}
      onupdate={(id, change) => editor?.update(id, change)}
      online={(id, style) => { editor?.setLineStyle(id, style); version++; }}
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
      {:else if engineState.status === "ready"}SDL TM Knowledge Base · engine {engineState.version}
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
      <div class="start">
        <h1>ThreatSketch</h1>
        <p class="lede">Data-flow diagrams, threat-modelled with Microsoft TMT's SDL rules.</p>
        <h2>Start</h2>
        <button class="row" onclick={newModel}><Icon name="new" /><span>New threat model</span></button>
        <button class="row" onclick={open}><Icon name="open" /><span>Open a file…</span><span class="kbd">{MOD}O</span></button>
        <button class="row" onclick={example}><Icon name="report" /><span>Open the example</span><span class="hint2">online shop, 38 threats</span></button>
        {#if draft}
          <h2>Unsaved work</h2>
          <button class="row" onclick={restore}>
            <Icon name="undo" /><span>Restore unsaved work</span>
            <span class="hint2">{draft.model?.summary?.title || "Untitled"}, {new Date(draft.at).toLocaleString()}</span>
          </button>
        {/if}
        <p class="fine">Opens Threat Dragon <code>.json</code> and Microsoft TMT <code>.tm7</code> files; you can also drop one here. Models stay on this computer.</p>
      </div>
    </div>
  {/if}

  {#if dropping}
    <div class="dropzone"><div>Drop a <b>.json</b> or <b>.tm7</b> model to open it</div></div>
  {/if}
  {#if update}
    <div class="update" role="status">
      <span>{update.version ? `ThreatSketch ${update.version} is available.` : "A new version of ThreatSketch is ready."}</span>
      <button class="btn primary" onclick={applyUpdate}>{files.isDesktop ? "Install and restart" : "Reload"}</button>
      <button class="btn icon" onclick={() => (update = null)} aria-label="Later"><Icon name="close" size={14} /></button>
    </div>
  {/if}
  {#if notice}
    <div class="toast {notice.tone}" role="status">{notice.text}<button class="btn icon" onclick={() => (notice = null)} aria-label="Dismiss"><Icon name="close" size={14} /></button></div>
  {/if}
</div>

<style>
  .app {
    height: 100%;
    display: grid;
    grid-template-columns: 240px minmax(0, 1fr) 320px;
    grid-template-rows: 48px minmax(0, 1fr) var(--threats) 28px;
    grid-template-areas: "top top top" "pal stage props" "threats threats props" "status status status";
  }
  .app:not(.has-model) { grid-template-rows: 48px minmax(0, 1fr) 0 28px; grid-template-areas: "top top top" "stage stage stage" "threats threats threats" "status status status"; }
  .app > :global(.palette) { grid-area: pal; }
  .app > :global(.props) { grid-area: props; }

  .top { grid-area: top; display: flex; align-items: center; gap: var(--s-3); padding: 0 var(--s-3); background: var(--panel); border-bottom: 1px solid var(--border); }
  .brand { display: flex; align-items: center; gap: var(--s-2); font-weight: 600; padding-right: var(--s-3); height: 24px; }
  .has-model .brand { border-right: 1px solid var(--border); }
  .mark { display: block; width: 22px; height: 22px; }
  .doc { display: flex; flex-direction: column; min-width: 0; line-height: 1.3; }
  .doctitle { border: 0; background: none; padding: 0; font-weight: 500; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 360px; }
  .doctitle:hover { color: var(--accent-text); }
  .file { font-size: var(--fs-caption); color: var(--muted); }
  .dirty { color: var(--accent); margin-left: var(--s-1); }
  .tools { display: flex; gap: 2px; margin-left: var(--s-2); }
  .actions { margin-left: auto; display: flex; align-items: center; gap: var(--s-1); }
  .menu { position: relative; }
  .scrim { position: fixed; inset: 0; z-index: 20; }
  .dropdown { position: absolute; right: 0; top: 32px; z-index: 21; width: 264px; padding: var(--s-1); background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); box-shadow: var(--shadow-pop); }
  .dropdown button { display: grid; width: 100%; padding: 6px var(--s-2); border: 0; border-radius: var(--r-1); background: none; text-align: left; }
  .dropdown button:hover { background: var(--hover); }
  .dropdown b { font-weight: 500; }
  .dropdown span { font-size: var(--fs-small); color: var(--muted); }

  .stage { grid-area: stage; display: grid; grid-template-rows: 32px minmax(0, 1fr); min-height: 0; min-width: 0; }
  .stage.hidden { visibility: hidden; }
  .tabs { display: flex; align-items: flex-end; gap: 2px; padding: 0 var(--s-2); background: var(--panel-2); border-bottom: 1px solid var(--border); overflow-x: auto; }
  .tab { display: inline-flex; align-items: center; gap: var(--s-1); height: 28px; padding: 0 var(--s-3); border: 1px solid transparent; border-bottom: 0; border-radius: var(--r-1) var(--r-1) 0 0; background: none; color: var(--muted); white-space: nowrap; }
  .tab:hover { color: var(--text); }
  .tab.on { background: var(--canvas); border-color: var(--border); color: var(--text); font-weight: 500; margin-bottom: -1px; height: 29px; }
  .tab.add { padding: 0 var(--s-2); }
  .x { display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: var(--r-1); color: var(--muted); }
  .x:hover { background: var(--hover); color: var(--text); }
  .tabedit { height: 24px; margin-bottom: 2px; padding: 0 var(--s-2); border: 1px solid var(--accent); border-radius: var(--r-1); background: var(--panel); outline: none; box-shadow: var(--focus); }
  .canvaswrap { position: relative; min-height: 0; }
  .canvas { position: absolute; inset: 0; }
  .hint { position: absolute; left: var(--s-6); top: var(--s-5); display: grid; gap: var(--s-1); max-width: 340px; color: var(--muted); pointer-events: none; }
  .hint b { color: var(--text); font-weight: 600; font-size: var(--fs-h3); }
  .hint i { font-style: normal; font-weight: 600; color: var(--accent-text); }
  .zoom { position: absolute; right: var(--s-3); bottom: var(--s-3); display: flex; gap: 2px; padding: 2px; background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); }

  .threatpane { grid-area: threats; position: relative; min-height: 0; border-top: 1px solid var(--border-strong); }
  .resizer { position: absolute; left: 0; right: 0; top: -4px; height: 8px; z-index: 5; cursor: row-resize; }
  .resizer:hover { background: linear-gradient(transparent 3px, var(--accent) 3px, var(--accent) 5px, transparent 5px); }

  .status { grid-area: status; display: flex; align-items: center; gap: var(--s-4); padding: 0 var(--s-3); font-size: var(--fs-small); color: var(--muted); background: var(--panel); border-top: 1px solid var(--border); }
  .engine { display: inline-flex; align-items: center; gap: var(--s-2); }
  .pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--faint); }
  .engine.ready .pulse { background: var(--st-ok); }
  .engine.failed { color: var(--danger); }
  .engine.failed .pulse { background: var(--danger); }
  .warn { display: inline-flex; align-items: center; gap: var(--s-1); color: var(--st-inv); cursor: help; }
  .grow { flex: 1; }

  .welcome { position: fixed; inset: 48px 0 28px; overflow: auto; background: var(--bg); }
  .start { max-width: 520px; margin: 12vh 0 var(--s-8) 14vw; }
  h1 { margin: 0; font-size: var(--fs-h1); font-weight: 600; }
  .lede { margin: var(--s-1) 0 var(--s-8); color: var(--muted); }
  h2 { margin: var(--s-6) 0 var(--s-2); font-size: var(--fs-small); font-weight: 600; color: var(--muted); }
  .row { display: flex; align-items: center; gap: var(--s-3); width: 100%; height: 36px; padding: 0 var(--s-2); margin-left: calc(-1 * var(--s-2)); border: 0; border-radius: var(--r-1); background: none; text-align: left; color: var(--accent-text); }
  .row:hover { background: var(--hover); }
  .row :global(.icon) { color: var(--muted); }
  .row .kbd, .row .hint2 { margin-left: auto; font-size: var(--fs-small); color: var(--muted); }
  .kbd { font-family: var(--mono); }
  .fine { margin: var(--s-8) 0 0; font-size: var(--fs-small); color: var(--muted); max-width: 420px; }
  .fine code { font: var(--fs-caption) var(--mono); }

  .dropzone { position: fixed; inset: 0; z-index: 40; display: grid; place-items: center; background: rgb(47 93 135 / 0.08); border: 2px dashed var(--accent); pointer-events: none; }
  .dropzone div { padding: var(--s-3) var(--s-5); background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); box-shadow: var(--shadow-pop); }
  .update { position: fixed; right: var(--s-4); bottom: 40px; z-index: 45; display: flex; align-items: center; gap: var(--s-2); padding: var(--s-1) var(--s-1) var(--s-1) var(--s-3); background: var(--panel); border: 1px solid var(--border-strong); border-radius: var(--r-2); box-shadow: var(--shadow-pop); }
  .toast { position: fixed; left: 50%; bottom: 40px; transform: translateX(-50%); z-index: 50; display: flex; align-items: center; gap: var(--s-2); max-width: min(640px, 90vw); padding: var(--s-1) var(--s-1) var(--s-1) var(--s-3); background: var(--neutral-900); color: var(--neutral-0); border-radius: var(--r-2); box-shadow: var(--shadow-pop); }
  .toast.error { background: var(--danger-600); }
  .toast .btn { color: inherit; }
  .toast .btn:hover { background: rgb(255 255 255 / 0.12); }
</style>
