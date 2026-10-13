// Keeping the saved model (Threat Dragon JSON) in step with the canvas without losing anything.
//
// The model is the source of truth. The canvas holds a copy of each cell minus the threats (those
// belong to the engine and the threat list) and minus Threat Dragon's outline colours. When the
// canvas changes, only the values that changed there are written back; everything else in the
// file, including keys this app does not know, stays exactly as it was.

const ENGINE_DATA = ["threats", "hasOpenThreats"] as const;
const TAG_LINE = /^[ \t]*@tmt:.*$/gim;
// Outline styles Threat Dragon writes (and tdtm keeps for it); the canvas draws TMT's style instead.
const STYLE_PARTS = ["body", "line", "topLine", "bottomLine"];
const STYLE_PROPS = ["stroke", "strokeWidth", "strokeDasharray"];

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isObject = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);

/** The cell as the canvas gets it: no threats, no Threat Dragon outline styles. */
export function forCanvas(cell: Record<string, any>): Record<string, any> {
  const copy = structuredClone(cell);
  if (copy.data) for (const k of ENGINE_DATA) delete copy.data[k];
  for (const part of STYLE_PARTS) {
    const a = copy.attrs?.[part];
    if (!isObject(a)) continue;
    for (const p of STYLE_PROPS) delete a[p];
    if (!Object.keys(a).length) delete copy.attrs[part];
  }
  if (isObject(copy.attrs) && !Object.keys(copy.attrs).length) delete copy.attrs;
  return copy;
}

/**
 * Write what changed on the canvas (`before` -> `after`) into the model's `cell`, key by key and
 * down into nested objects, so whatever the canvas never saw (threats, styles, unknown keys) stays.
 */
export function patchCell(cell: Record<string, any>, before: Record<string, any>, after: Record<string, any>) {
  for (const key of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const b = before[key], a = after[key];
    if (same(b, a)) continue;
    if (!(key in after)) delete cell[key];
    else if (isObject(a) && isObject(b) && isObject(cell[key])) patchCell(cell[key], b, a);
    else cell[key] = structuredClone(a);
  }
}

/** A cell newly drawn on the canvas, as the model stores it. */
export function fromCanvas(json: Record<string, any>): Record<string, any> {
  const cell = structuredClone(json);
  if (cell.data && ["tm.Actor", "tm.Process", "tm.Store", "tm.Flow"].includes(cell.data.type)) {
    cell.data.threats ??= [];
    cell.data.hasOpenThreats ??= false;
  }
  return cell;
}

/** The description as people see and edit it: without the hidden `@tmt:` lines. */
export function visibleDescription(description: string | undefined): string {
  return (description ?? "").replace(TAG_LINE, "").replace(/\n{3,}/g, "\n\n").replace(/^\n+|\n+$/g, "");
}

/** Put edited visible text back together with the element's `@tmt:` lines. */
export function withTags(visible: string, original: string | undefined): string {
  const tags = (original ?? "").match(TAG_LINE) ?? [];
  return [visible.replace(/\n+$/, ""), ...tags].filter(Boolean).join("\n");
}
