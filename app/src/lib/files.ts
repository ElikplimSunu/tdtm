// Opening and saving files. The desktop app uses the system dialogs and writes to disk; Chrome
// and Edge save back to the same file (File System Access API); other browsers open through a
// file picker and save as a download.

/** Where a file lives, to save back to it: a path in the desktop app, a handle in Chrome. */
export type Handle = FileSystemFileHandle | string;
export type Opened = { name: string; bytes: Uint8Array; handle?: Handle };

const w = window as any;
export const isDesktop = "__TAURI_INTERNALS__" in w;
export const canSaveInPlace = isDesktop || typeof w.showOpenFilePicker === "function";

const tauri = () => Promise.all([import("@tauri-apps/plugin-dialog"), import("@tauri-apps/plugin-fs")]);
const FILTERS = [{ name: "Threat models", extensions: ["json", "tm7"] }];

export const handleName = (h: Handle) => (typeof h === "string" ? h.split(/[\\/]/).pop()! : h.name);

const TYPES = [
  {
    description: "Threat models (Threat Dragon .json, Microsoft TMT .tm7)",
    accept: { "application/json": [".json"], "application/xml": [".tm7"] },
  },
];

export async function pickFile(): Promise<Opened | null> {
  if (isDesktop) {
    const [dialog, fs] = await tauri();
    const path = await dialog.open({ multiple: false, directory: false, filters: FILTERS });
    if (typeof path !== "string") return null;
    return { name: handleName(path), bytes: await fs.readFile(path), handle: path };
  }
  if (canSaveInPlace) {
    try {
      const [handle] = await w.showOpenFilePicker({ types: TYPES, multiple: false });
      const file: File = await handle.getFile();
      return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()), handle };
    } catch (e: any) {
      if (e?.name === "AbortError") return null;
      throw e;
    }
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,.tm7";
    input.onchange = async () => {
      const file = input.files?.[0];
      resolve(file ? await readFile(file) : null);
    };
    input.oncancel = () => resolve(null);
    input.click();
  });
}

export async function readFile(file: File): Promise<Opened> {
  return { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
}

/** Write to `handle` if there is one, else ask where (or download). Returns the handle used. */
export async function saveText(text: string, suggestedName: string, mime: string, handle?: Handle): Promise<Handle | undefined> {
  if (isDesktop) {
    const [dialog, fs] = await tauri();
    const ext = suggestedName.slice(suggestedName.lastIndexOf(".") + 1);
    const path = typeof handle === "string" ? handle
      : await dialog.save({ defaultPath: suggestedName, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
    if (!path) return undefined;
    await fs.writeTextFile(path, text);
    return path;
  }
  if (!handle && canSaveInPlace && typeof w.showSaveFilePicker === "function") {
    try {
      const ext = suggestedName.slice(suggestedName.lastIndexOf("."));
      handle = await w.showSaveFilePicker({ suggestedName, types: [{ description: ext, accept: { [mime]: [ext] } }] });
    } catch (e: any) {
      if (e?.name === "AbortError") return undefined;
      throw e;
    }
  }
  if (handle && typeof handle !== "string") {
    const out = await (handle as any).createWritable();
    await out.write(text);
    await out.close();
    return handle;
  }
  download(text, suggestedName, mime);
  return undefined;
}

/** Show an HTML page (the threat report): a new tab, or the default browser in the desktop app. */
export async function showHtml(html: string, name: string) {
  if (isDesktop) {
    const [{ appCacheDir, join }, fs, { openPath }] = await Promise.all([
      import("@tauri-apps/api/path"), import("@tauri-apps/plugin-fs"), import("@tauri-apps/plugin-opener"),
    ]);
    const dir = await appCacheDir();
    await fs.mkdir(dir, { recursive: true });
    const path = await join(dir, name);
    await fs.writeTextFile(path, html);
    await openPath(path);
    return;
  }
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  if (!window.open(url, "_blank")) download(html, name, "text/html");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** A yes/no question: the native dialog in the desktop app, the browser's otherwise. */
export async function ask(message: string): Promise<boolean> {
  if (!isDesktop) return confirm(message);
  const { ask } = await import("@tauri-apps/plugin-dialog");
  return ask(message, { title: "ThreatSketch", kind: "warning" });
}

/** Files the operating system asked the desktop app to open (double-clicked .tm7 files). */
export async function onOpenedFiles(take: (files: Opened[]) => void) {
  if (!isDesktop) return;
  const [{ invoke }, { listen }] = await Promise.all([import("@tauri-apps/api/core"), import("@tauri-apps/api/event")]);
  const pull = async () => {
    const files = await invoke<{ name: string; bytes: number[] }[]>("take_opened_files");
    if (files.length) take(files.map((f) => ({ name: f.name, bytes: new Uint8Array(f.bytes) })));
  };
  await listen("files-opened", pull);
  await pull();
}

export function download(text: string, name: string, mime: string) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function baseName(name: string) {
  return name.replace(/\.(json|tm7)$/i, "");
}

// Unsaved work survives a closed tab or a crash. Browser storage can be unavailable (private
// windows, blocked site data), so every access is guarded and the app works without it.
const DRAFT = "threatsketch:draft";

export function saveDraft(draft: { model: unknown; name: string }) {
  try {
    localStorage.setItem(DRAFT, JSON.stringify({ ...draft, at: new Date().toISOString() }));
  } catch {
    /* storage unavailable or full: nothing to do */
  }
}

export function loadDraft(): { model: any; name: string; at: string } | null {
  try {
    const raw = localStorage.getItem(DRAFT);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function clearDraft() {
  try {
    localStorage.removeItem(DRAFT);
  } catch {
    /* ignore */
  }
}
