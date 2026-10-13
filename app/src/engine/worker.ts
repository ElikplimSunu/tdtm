// Runs the Python engine (threatsketch.api) under Pyodide, off the main thread, so drawing never waits.
// Messages in: { id, fn, args }. Out: { id, ok, result } | { id, ok: false, error } | { ready }.

const FUNCTIONS = new Set([
  "new_model", "analyze", "palette", "categories", "set_element", "set_threat",
  "import_tm7", "export_tm7", "report_html", "report_csv",
]);

const base = new URL(import.meta.env.BASE_URL, self.location.origin).href;

const boot = (async () => {
  const started = performance.now();
  const phases: Record<string, number> = {};
  const mark = (name: string) => (phases[name] = Math.round(performance.now() - started));
  const { loadPyodide } = await import(/* @vite-ignore */ `${base}pyodide/pyodide.mjs`);
  mark("script");
  const py = await loadPyodide({ indexURL: `${base}pyodide/` });
  mark("pyodide");
  const wheel = await fetch(`${base}engine/threatsketch.whl`).then((r) => {
    if (!r.ok) throw new Error(`engine download failed: ${r.status}`);
    return r.arrayBuffer();
  });
  py.unpackArchive(new Uint8Array(wheel), "wheel");
  mark("wheel");
  py.runPython(`
import base64, json
from threatsketch import api, __version__

def _call(name, args_json):
    args = json.loads(args_json)
    if name == "import_tm7":
        args[0] = base64.b64decode(args[0])
    return json.dumps(getattr(api, name)(*args), ensure_ascii=False)
`);
  mark("engine");
  const call = py.globals.get("_call");
  const version = py.runPython("__version__");
  self.postMessage({ ready: true, version, ms: Math.round(performance.now() - started), phases });
  return call as (name: string, args: string) => string;
})();

boot.catch((e) => self.postMessage({ ready: false, error: String(e?.message ?? e) }));

self.onmessage = async (ev: MessageEvent) => {
  const { id, fn, args } = ev.data;
  try {
    if (!FUNCTIONS.has(fn)) throw new Error(`unknown engine function ${fn}`);
    const call = await boot;
    self.postMessage({ id, ok: true, result: JSON.parse(call(fn, JSON.stringify(args))) });
  } catch (e: any) {
    // a Python exception arrives as a PythonError whose message ends with the Python message
    const lines = String(e?.message ?? e).trim().split("\n");
    self.postMessage({ id, ok: false, error: lines[lines.length - 1] });
  }
};
