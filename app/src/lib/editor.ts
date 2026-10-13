// The canvas (AntV X6) and the model behind it. Every change on the canvas is written into the
// model (sync.ts) and sent to the engine; the engine's answer (threats, stencil tags) comes back
// without disturbing what the user did meanwhile.
//
// Connecting works like Figma or Lucidchart: hovering an element shows a "+" on each side. Drag one
// to any element to draw a flow, or click it to link to the nearest element on that side (a new
// process is added when there is none).
import { Graph, type Cell as XCell } from "@antv/x6";
import { Clipboard } from "@antv/x6-plugin-clipboard";
import { History } from "@antv/x6-plugin-history";
import { Keyboard } from "@antv/x6-plugin-keyboard";
import { Scroller } from "@antv/x6-plugin-scroller";
import { Selection } from "@antv/x6-plugin-selection";
import { Snapline } from "@antv/x6-plugin-snapline";
import { Transform } from "@antv/x6-plugin-transform";
import { engine } from "../engine/client";
import { KIND_OF_TYPE, newCell, registerShapes, type Kind } from "./shapes";
import { forCanvas, fromCanvas, patchCell } from "./sync";
import type { AnalyzeResult, Cell, Model } from "./types";

const NODE_SHAPES = new Set(["actor", "process", "store", "td-text-block", "trust-boundary-box"]);
const EDGE_SHAPES = new Set(["flow", "trust-boundary-curve", "trust-broundary-curve"]);
const DEFAULT_NAMES: Record<Kind, string> = {
  actor: "External interactor", process: "Process", store: "Data store", flow: "Data flow",
  boundary_box: "Trust boundary", boundary_curve: "Trust boundary", text: "Note",
};

export type EditorEvents = {
  analysed: (r: AnalyzeResult) => void;
  selected: (cellId: string | null) => void;
  changed: () => void; // the model changed (unsaved work)
  failed: (message: string) => void;
  edit: (cellId: string) => void; // double-click: edit this element's name
};

function canvasJSON(c: XCell): Record<string, any> {
  const j = c.toJSON() as Record<string, any>;
  delete j.tools;
  return j;
}

export class Editor {
  graph: Graph;
  model!: Model;
  diagram = 0;
  private baseline = new Map<string, string>(); // cell id -> its canvas JSON when last in step
  private applying = false;
  private loaded = false;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(container: HTMLElement, private on: EditorEvents) {
    registerShapes();
    const editor = this;
    this.graph = new Graph({
      container,
      autoResize: true,
      background: { color: "#ffffff" },
      grid: { size: 10, visible: true, type: "dot", args: { color: "#c9ced6" } },
      mousewheel: { enabled: true, global: false, modifiers: ["ctrl", "meta"], minScale: 0.2, maxScale: 3 },
      scaling: { min: 0.2, max: 3 },
      magnetThreshold: "onleave", // a click on a "+" stays a click; dragging off it draws a flow
      clickThreshold: 5,
      connecting: {
        allowBlank: false, allowLoop: false, allowMulti: true, allowNode: true, allowEdge: false,
        anchor: "center", connectionPoint: { name: "boundary", args: { selector: "body" } }, snap: { radius: 40 }, highlight: true,
        createEdge() {
          const json = forCanvas(newCell("flow", DEFAULT_NAMES.flow, 0, 0));
          delete json.source; delete json.target;
          return editor.graph.createEdge(json);
        },
        // drop anywhere on an actor, process or store (not only on its "+")
        validateConnection({ sourceCell, targetCell }) {
          return !!targetCell && sourceCell !== targetCell && isNode(targetCell);
        },
      },
      highlighting: {
        magnetAvailable: { name: "stroke", args: { padding: 4, attrs: { stroke: "#4f6bed", strokeWidth: 2 } } },
        magnetAdsorbed: { name: "stroke", args: { padding: 6, attrs: { stroke: "#4f6bed", strokeWidth: 3 } } },
      },
    });
    this.graph
      .use(new Scroller({ enabled: true, pannable: true, modifiers: ["shift"], pageVisible: false, pageBreak: false, padding: 200 }))
      .use(new Selection({
        enabled: true, multiple: true, rubberband: true, movable: true, strict: true,
        showNodeSelectionBox: true, showEdgeSelectionBox: false, multipleSelectionModifiers: ["ctrl", "meta", "shift"],
        pointerEvents: "none",
      }))
      .use(new Snapline({ enabled: true, sharp: true }))
      .use(new Transform({ resizing: { enabled: true, minWidth: 40, minHeight: 30, orthogonal: true }, rotating: false }))
      .use(new History({ enabled: true, beforeAddCommand: (_e: string, args: any) => args?.key !== "tools" && !editor.applying }))
      .use(new Clipboard({ enabled: true }))
      .use(new Keyboard({ enabled: true, global: true }));

    const changed = ({ key }: { key?: string }) => {
      if (!this.applying && key !== "tools") this.schedule();
    };
    this.graph.on("cell:added", changed);
    this.graph.on("cell:removed", changed);
    this.graph.on("cell:change:*", changed);
    this.graph.on("selection:changed", ({ selected }: { selected: XCell[] }) => {
      for (const c of this.graph.getEdges()) this.edgeTools(c, selected.includes(c));
      this.on.selected(selected.length === 1 ? selected[0].id : null);
    });
    this.graph.on("node:mouseenter", ({ view }) => view.container.classList.add("ts-hover"));
    this.graph.on("node:mouseleave", ({ view }) => view.container.classList.remove("ts-hover"));
    // flows attach to the shape's edge (as in TMT), not to the "+" they were drawn from
    this.graph.on("edge:connected", ({ edge }) => {
      const s = edge.getSourceCellId(), t = edge.getTargetCellId();
      if (s && t) { edge.setSource({ cell: s }); edge.setTarget({ cell: t }); }
    });
    this.graph.on("scale", ({ sx }) => container.style.setProperty("--zoom", String(sx)));
    this.graph.on("node:magnet:click", ({ node, magnet }) => {
      const group = magnet.closest("[port-group]")?.getAttribute("port-group");
      if (group) this.quickConnect(node.id, group);
    });
    this.graph.on("cell:dblclick", ({ cell }) => this.on.edit(cell.id));
    this.bindKeys();
  }

  // --- loading and saving --------------------------------------------------------------------

  open(model: Model) {
    this.loaded = false; // a different model: nothing on the canvas belongs to it
    this.model = model;
    this.diagram = 0;
    this.loadDiagram(0);
    return this.analyse();
  }

  loadDiagram(index: number) {
    if (this.model.detail.diagrams[index] === undefined) return;
    if (this.loaded) this.sync(); // keep what was drawn on the diagram we are leaving
    this.loaded = true;
    this.diagram = index;
    const cells = this.current().cells;
    const nodes = new Set(cells.filter((c) => c.position).map((c) => c.id));
    const drawable = cells.filter((c) => {
      if (!NODE_SHAPES.has(c.shape) && !EDGE_SHAPES.has(c.shape)) return false;
      if (c.source?.cell && !nodes.has(c.source.cell)) return false; // dangling: kept, not drawn
      if (c.target?.cell && !nodes.has(c.target.cell)) return false;
      return true;
    });
    this.applying = true;
    try {
      this.graph.clearCells();
      for (const c of drawable) {
        try {
          if (EDGE_SHAPES.has(c.shape)) this.graph.addEdge(forCanvas(c));
          else this.graph.addNode(forCanvas(c));
        } catch {
          // a shape this app cannot draw: it stays in the file untouched
        }
      }
    } finally {
      this.applying = false;
    }
    this.graph.cleanHistory();
    this.baseline = new Map(this.graph.getCells().map((c) => [c.id, JSON.stringify(canvasJSON(c))]));
    queueMicrotask(() => this.fit());
  }

  current() {
    return this.model.detail.diagrams[this.diagram];
  }

  /** The model with every canvas change written in, ready to save. */
  snapshot(): Model {
    this.sync();
    return this.model;
  }

  // --- canvas -> model ----------------------------------------------------------------------

  /** Write canvas changes into the model. Returns whether anything changed. */
  private sync(): boolean {
    const cells = this.current().cells;
    const byId = new Map(cells.map((c) => [c.id, c]));
    const seen = new Set<string>();
    let changed = false;
    for (const c of this.graph.getCells()) {
      seen.add(c.id);
      const json = canvasJSON(c);
      const now = JSON.stringify(json);
      const before = this.baseline.get(c.id);
      if (before === now) continue;
      changed = true;
      const cell = byId.get(c.id);
      if (cell && before) patchCell(cell, JSON.parse(before), json);
      else if (!cell) cells.push(fromCanvas(json) as Cell);
      this.baseline.set(c.id, now);
    }
    for (const id of [...this.baseline.keys()]) {
      if (seen.has(id)) continue;
      const i = cells.findIndex((c) => c.id === id);
      if (i >= 0) cells.splice(i, 1);
      this.baseline.delete(id);
      changed = true;
    }
    return changed;
  }

  private schedule() {
    this.on.changed();
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.analyse(), 250);
  }

  // --- engine round trips (one at a time) ----------------------------------------------------

  private run<T>(task: () => Promise<T>): Promise<T> {
    const next = this.chain.then(task);
    this.chain = next.catch((e) => this.on.failed(String(e?.message ?? e)));
    return next;
  }

  analyse() {
    return this.run(async () => {
      this.sync();
      const r = await engine.analyze(this.model);
      this.apply(r.model);
      this.on.analysed(r);
    });
  }

  setElement(cellId: string, stencil: string, attributes: Record<string, string>) {
    return this.run(async () => {
      this.sync();
      const m = await engine.setElement(this.model, cellId, stencil, attributes);
      this.apply(m, true);
      const r = await engine.analyze(this.model);
      this.apply(r.model);
      this.on.analysed(r);
      this.on.changed();
    });
  }

  setThreat(key: string, state: string, priority: string, justification: string) {
    return this.run(async () => {
      this.sync();
      const m = await engine.setThreat(this.model, key, state, priority, justification);
      this.apply(m);
      const r = await engine.analyze(this.model);
      this.apply(r.model);
      this.on.analysed(r);
      this.on.changed();
    });
  }

  /** Take the engine's model; show its outlines and tags on the canvas; keep edits made meanwhile. */
  private apply(model: Model, undoable = false) {
    const editedMeanwhile = new Set(
      this.graph.getCells().filter((c) => this.baseline.get(c.id) !== JSON.stringify(canvasJSON(c))).map((c) => c.id),
    );
    this.model = model;
    this.applying = !undoable;
    try {
      for (const cell of this.current().cells) {
        const c = this.graph.getCellById(cell.id);
        if (!c) continue;
        const desc = cell.data?.description;
        if (desc !== undefined && desc !== c.getData()?.description) {
          c.setData({ ...c.getData(), description: desc }, { overwrite: true });
        }
      }
    } finally {
      this.applying = false;
    }
    for (const c of this.graph.getCells()) {
      if (!editedMeanwhile.has(c.id) && this.baseline.has(c.id) && !undoable) {
        this.baseline.set(c.id, JSON.stringify(canvasJSON(c)));
      }
    }
    if (this.sync() && !undoable) this.schedule();
  }

  // --- editing ------------------------------------------------------------------------------

  add(kind: Kind, stencil: string | null, at?: { x: number; y: number }) {
    const p = at ?? this.freeSpot();
    const json = forCanvas(newCell(kind, DEFAULT_NAMES[kind], Math.round(p.x / 10) * 10, Math.round(p.y / 10) * 10));
    const cell = json.source ? this.graph.addEdge(json) : this.graph.addNode(json);
    this.graph.cleanSelection();
    this.graph.select(cell);
    if (stencil) {
      clearTimeout(this.timer);
      this.setElement(cell.id, stencil, {});
    }
    return cell.id;
  }

  update(cellId: string, change: { name?: string; description?: string; outOfScope?: boolean; reasonOutOfScope?: string; isBidirectional?: boolean }) {
    const c = this.graph.getCellById(cellId);
    if (!c) return;
    this.graph.startBatch("update");
    c.setData({ ...c.getData(), ...change }, { overwrite: true });
    if (change.name !== undefined) setLabel(c, change.name);
    if (change.isBidirectional !== undefined) c.setAttrByPath("line/sourceMarker", { name: change.isBidirectional ? "block" : "" });
    this.graph.stopBatch("update");
  }

  dataOf(cellId: string): Record<string, any> | null {
    return this.graph.getCellById(cellId)?.getData() ?? null;
  }

  select(cellId: string) {
    const c = this.graph.getCellById(cellId);
    if (!c) return;
    this.graph.cleanSelection();
    this.graph.select(c);
    const box = c.getBBox();
    const view = this.graph.getGraphArea();
    if (!view.containsRect(box)) this.graph.centerCell(c);
  }

  /** Link `fromId` to the nearest element on its `side`, or to a new process placed there. */
  quickConnect(fromId: string, side: string) {
    const from = this.graph.getCellById(fromId);
    if (!from?.isNode()) return;
    const dir = { top: [0, -1], right: [1, 0], bottom: [0, 1], left: [-1, 0] }[side] ?? [1, 0];
    const c = from.getBBox().getCenter();
    let best: { id: string; d: number } | null = null;
    for (const n of this.graph.getNodes()) {
      if (n.id === fromId || !isNode(n)) continue;
      const o = n.getBBox().getCenter();
      const dx = o.x - c.x, dy = o.y - c.y;
      const along = dx * dir[0] + dy * dir[1];
      const across = Math.abs(dx * dir[1] - dy * dir[0]);
      if (along <= 0 || across > along * 1.2) continue; // roughly on that side
      const d = Math.hypot(dx, dy);
      if (!best || d < best.d) best = { id: n.id, d };
    }
    this.graph.startBatch("quick-connect");
    let targetId = best?.id;
    if (!targetId) {
      const kind = this.kindOf(fromId) === "process" ? "store" : "process";
      const size = kind === "process" ? { w: 100, h: 100 } : { w: 150, h: 75 };
      const gap = 160;
      const fb = from.getBBox();
      const x = side === "left" ? fb.x - gap - size.w : side === "right" ? fb.x + fb.width + gap : c.x - size.w / 2;
      const y = side === "top" ? fb.y - gap - size.h : side === "bottom" ? fb.y + fb.height + gap : c.y - size.h / 2;
      const json = forCanvas(newCell(kind, DEFAULT_NAMES[kind], Math.round(x / 10) * 10, Math.round(y / 10) * 10));
      targetId = this.graph.addNode(json).id;
    }
    const flow = forCanvas(newCell("flow", DEFAULT_NAMES.flow, 0, 0));
    flow.source = { cell: fromId };
    flow.target = { cell: targetId };
    const edge = this.graph.addEdge(flow);
    this.graph.stopBatch("quick-connect");
    this.graph.cleanSelection();
    this.graph.select(edge);
    return edge.id;
  }

  removeSelected() {
    const cells = this.graph.getSelectedCells();
    if (cells.length) this.graph.removeCells(cells);
  }

  undo() { this.graph.undo(); }
  redo() { this.graph.redo(); }
  canUndo() { return this.graph.canUndo(); }
  zoom(by: number) { this.graph.zoom(by); }
  fit() {
    if (this.graph.getCellCount()) this.graph.zoomToFit({ padding: 40, maxScale: 1 });
    else this.graph.zoomTo(1);
  }

  centre() {
    const r = this.graph.getGraphArea();
    return { x: r.x + r.width / 2 - 60, y: r.y + r.height / 2 - 40 };
  }

  /** Where a clicked stencil goes: the middle of the view, moved right until it overlaps nothing. */
  private freeSpot() {
    const p = this.centre();
    const taken = this.graph.getNodes().filter((n) => n.shape !== "trust-boundary-box").map((n) => n.getBBox());
    for (let i = 0; i < 12 && taken.some((b) => b.isIntersectWithRect({ x: p.x - 20, y: p.y - 20, width: 190, height: 140 })); i++) p.x += 200;
    return p;
  }

  clientToLocal(x: number, y: number) {
    return this.graph.clientToLocal(x, y);
  }

  kindOf(cellId: string): Kind | null {
    const t = this.graph.getCellById(cellId)?.getData()?.type;
    return t ? KIND_OF_TYPE[t] ?? null : null;
  }

  private edgeTools(c: XCell, on: boolean) {
    if (!c.isEdge()) return;
    if (!on) { if (c.hasTools()) c.removeTools(); return; }
    c.addTools(["vertices", "source-arrowhead", "target-arrowhead"]);
  }

  private bindKeys() {
    const g = this.graph;
    const typing = () => /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? "");
    g.bindKey(["backspace", "delete"], () => { if (!typing()) this.removeSelected(); return false; });
    g.bindKey(["meta+z", "ctrl+z"], () => { if (!typing()) this.undo(); return false; });
    g.bindKey(["meta+shift+z", "ctrl+y", "ctrl+shift+z"], () => { if (!typing()) this.redo(); return false; });
    g.bindKey(["meta+a", "ctrl+a"], () => { if (!typing()) g.select(g.getCells()); return false; });
    g.bindKey(["meta+c", "ctrl+c"], () => { if (!typing()) g.copy(g.getSelectedCells()); return false; });
    g.bindKey(["meta+v", "ctrl+v"], () => {
      if (typing()) return;
      const pasted = g.paste({ offset: 30 });
      g.cleanSelection(); g.select(pasted);
      return false;
    });
    g.bindKey("escape", () => g.cleanSelection());
  }
}

function isNode(c: XCell) {
  return c.isNode() && ["tm.Actor", "tm.Process", "tm.Store"].includes(c.getData()?.type);
}

function setLabel(c: XCell, name: string) {
  const type = c.getData()?.type;
  if (type === "tm.BoundaryBox") c.setAttrByPath("label/text", name);
  else if (c.isNode()) c.setAttrByPath("text/text", name);
  else if (c.isEdge()) {
    const labels = c.getLabels();
    const first = labels[0];
    if (first && typeof first === "object" && (first as any).attrs?.labelText) {
      c.setLabelAt(0, { ...first, attrs: { ...(first as any).attrs, labelText: { ...(first as any).attrs.labelText, text: name } } });
    } else if (first && typeof first === "object") {
      c.setLabelAt(0, { ...first, attrs: { ...(first as any).attrs, label: { ...((first as any).attrs?.label ?? {}), text: name } } });
    } else c.setLabels([{ position: 0.5, attrs: { label: { text: name } } }]);
  }
}
