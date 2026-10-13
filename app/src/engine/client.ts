// The app's handle on the engine worker: `engine.call("analyze", [model])` returns a promise.
import type { AnalyzeResult, Model, Palette } from "../lib/types";

type Pending = { resolve: (v: any) => void; reject: (e: Error) => void };

export type EngineState = { status: "loading" } | { status: "ready"; version: string; ms: number }
  | { status: "failed"; error: string };

class Engine {
  private worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
  private pending = new Map<number, Pending>();
  private next = 1;
  private listeners = new Set<(s: EngineState) => void>();
  state: EngineState = { status: "loading" };

  constructor() {
    this.worker.onmessage = (ev) => {
      const m = ev.data;
      if ("ready" in m) {
        this.state = m.ready ? { status: "ready", version: m.version, ms: m.ms }
          : { status: "failed", error: m.error };
        this.listeners.forEach((f) => f(this.state));
        return;
      }
      const p = this.pending.get(m.id);
      this.pending.delete(m.id);
      if (m.ok) p?.resolve(m.result);
      else p?.reject(new Error(m.error));
    };
  }

  onState(f: (s: EngineState) => void): () => void {
    this.listeners.add(f);
    f(this.state);
    return () => this.listeners.delete(f);
  }

  call<T = unknown>(fn: string, args: unknown[] = []): Promise<T> {
    const id = this.next++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, fn, args });
    });
  }

  analyze(model: Model) { return this.call<AnalyzeResult>("analyze", [model]); }
  palette() { return this.call<Palette>("palette"); }
  newModel(title: string) { return this.call<Model>("new_model", [title]); }
  setElement(model: Model, cellId: string, stencil: string, attributes: Record<string, string>) {
    return this.call<Model>("set_element", [model, cellId, stencil, attributes]);
  }
  setThreat(model: Model, key: string, state: string, priority: string, justification: string) {
    return this.call<Model>("set_threat", [model, key, state, priority, justification]);
  }
  importTm7(bytes: Uint8Array, title: string) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return this.call<{ model: Model; warnings: string[] }>("import_tm7", [btoa(bin), title]);
  }
  exportTm7(model: Model) { return this.call<{ text: string; warnings: string[] }>("export_tm7", [model]); }
  reportHtml(model: Model) { return this.call<string>("report_html", [model]); }
  reportCsv(model: Model) { return this.call<string>("report_csv", [model]); }
}

export const engine = new Engine();
