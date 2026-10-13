// Opening and saving files. Chrome and Edge save back to the same file (File System Access API);
// other browsers open through a file picker and save as a download.

export type Opened = { name: string; bytes: Uint8Array; handle?: FileSystemFileHandle };

const w = window as any;
export const canSaveInPlace = typeof w.showOpenFilePicker === "function";

const TYPES = [
  {
    description: "Threat models (Threat Dragon .json, Microsoft TMT .tm7)",
    accept: { "application/json": [".json"], "application/xml": [".tm7"] },
  },
];

export async function pickFile(): Promise<Opened | null> {
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
export async function saveText(
  text: string,
  suggestedName: string,
  mime: string,
  handle?: FileSystemFileHandle,
): Promise<FileSystemFileHandle | undefined> {
  if (!handle && canSaveInPlace && typeof w.showSaveFilePicker === "function") {
    try {
      const ext = suggestedName.slice(suggestedName.lastIndexOf("."));
      handle = await w.showSaveFilePicker({ suggestedName, types: [{ description: ext, accept: { [mime]: [ext] } }] });
    } catch (e: any) {
      if (e?.name === "AbortError") return undefined;
      throw e;
    }
  }
  if (handle) {
    const out = await (handle as any).createWritable();
    await out.write(text);
    await out.close();
    return handle;
  }
  download(text, suggestedName, mime);
  return undefined;
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
