// Threat Dragon's diagram shapes, registered under Threat Dragon's names so its files open and draw
// the same. Transcribed from OWASP Threat Dragon 2.6.2 (td.vue/src/service/x6/shapes and
// service/entity/default-properties.js), Apache-2.0; see THIRD_PARTY_NOTICES.md.
import { Graph, Path, Registry, Shape } from "@antv/x6";

// Drawn the way Microsoft TMT draws its SDL stencils: black outlines on white, red dashed trust
// boundaries. Threat Dragon's red "open threats" outlines stay in the file but are not drawn here.
export const INK = "#1b2026";
export const BOUNDARY = "#c0392f";

// Connection points: a "+" on each side, shown on hover. Drag one to draw a flow; click one to link
// to the nearest element on that side.
const port = {
  markup: [
    { tagName: "circle", selector: "circle" },
    { tagName: "path", selector: "plus" },
  ],
  attrs: {
    circle: { r: 7, magnet: true, fill: "#2f5d87", stroke: "#fbfcfc", strokeWidth: 1.5, cursor: "crosshair" },
    plus: { d: "M -3.5 0 H 3.5 M 0 -3.5 V 3.5", stroke: "#fbfcfc", strokeWidth: 1.6, pointerEvents: "none" },
  },
};
const GAP = 18; // the "+" sits just outside the shape, clear of the resize handles
const side = (position: string, dx: number, dy: number) => ({ position: { name: position, args: { dx, dy } }, ...port });
export const ports = {
  groups: {
    top: side("top", 0, -GAP), right: side("right", GAP, 0), bottom: side("bottom", 0, GAP), left: side("left", -GAP, 0),
  },
  items: [{ group: "top" }, { group: "right" }, { group: "bottom" }, { group: "left" }],
};

// names wrap inside the shape, as TMT's do
const text = { fontSize: 13, fill: INK, textWrap: { width: -12 } };

// TMT's stencil icons (from the template, via the palette): faded behind the name, centred on a
// process, in the lower right of an interactor or store, before the name of a flow or boundary.
// Painted by the editor, never saved (sync.ts strips `icon`).
// ponytail: size and fade judged against TMT screenshots; tune here if they look off.
export const ICON = 28;
const ICON_FADE = 0.35;
const LABEL_ICON = 18;
const ICON_IMG = { tagName: "image", selector: "icon" };
const lowerRight = { refX: "100%", refY: "100%", x: -ICON - 4, y: -ICON - 4, width: ICON, height: ICON, opacity: ICON_FADE, pointerEvents: "none" };
const centred = { refX: "50%", refY: "50%", x: -ICON / 2, y: -ICON / 2, width: ICON, height: ICON, opacity: ICON_FADE, pointerEvents: "none" };
// TMT's flow label: a pale green box with a dark outline, the flow stencil's icon before the name
export const LABEL_FILL = "#dde8c6";
export const LABEL_STROKE = "#5b6150";
const HALO = { tagName: "rect", selector: "halo" };
const halo = { refX: -28, refY: -28, refWidth: "100%", refWidth2: 56, refHeight: "100%", refHeight2: 56, fill: "transparent", stroke: "none" };

let registered = false;

/** Elbow lines: X6's own orthogonal router under its own name (Threat Dragon draws it too). */
export const ELBOW = { router: { name: "manhattan" }, connector: { name: "rounded", args: { radius: 8 } } };

/**
 * Elbows go round shapes but straight through trust boundaries and notes, which are not in the
 * way, and leave and enter square to the sides a flow is pinned to.
 */
function sidedManhattan(this: any, vertices: any, options: any, view: any) {
  const opts: Record<string, any> = { padding: 16, excludeShapes: ["trust-boundary-box", "td-text-block"], ...options };
  const from = view?.cell?.getSource?.()?.anchor?.name, to = view?.cell?.getTarget?.()?.anchor?.name;
  if (from in OUT) opts.startDirections = [from];
  if (to in OUT) opts.endDirections = [to];
  return manhattan.call(this, vertices, opts as any, view);
}

const OUT: Record<string, [number, number]> = { top: [0, -1], right: [1, 0], bottom: [0, 1], left: [-1, 0] };
const smooth = Registry.Connector.presets.smooth;
const BOW = 2.5; // how much further than its offset on the side a shared-side flow bows out
const manhattan = Registry.Router.presets.manhattan;

/**
 * Flows keep X6's "smooth" connector (Threat Dragon reads it), redrawn so that a flow pinned to a
 * side of each shape leaves and enters at right angles to those sides, as in Lucidchart; it curves
 * round instead of cutting back across its own shape. With bends, or unpinned, it is X6's own curve.
 */
function sidedSmooth(this: any, s: any, t: any, route: any[], options: any, view: any) {
  const from = view?.cell?.getSource?.()?.anchor, to = view?.cell?.getTarget?.()?.anchor;
  const a = OUT[from?.name], b = OUT[to?.name];
  if (route?.length || !a || !b) return smooth.call(this, s, t, route, options, view);
  const k = Math.max(40, Math.hypot(t.x - s.x, t.y - s.y) / 2.5);
  // a flow moved off a side's middle (it shares the side) bows further that way, as TMT's do, so
  // two flows between the same shapes part in the middle, where their names are
  const bow = (end: any) => [(end?.args?.dx ?? 0) * BOW, (end?.args?.dy ?? 0) * BOW];
  const [ox, oy] = bow(from), [px, py] = bow(to);
  const path = new Path();
  path.appendSegment(Path.createSegment("M", s));
  path.appendSegment(Path.createSegment("C", s.x + a[0] * k + ox, s.y + a[1] * k + oy, t.x + b[0] * k + px, t.y + b[1] * k + py, t.x, t.y));
  return options.raw ? path : path.serialize();
}

const measure = typeof document === "undefined" ? null : document.createElement("canvas").getContext("2d");

/** Lines of `text` no wider than `width`, broken only between words, as TMT wraps a name. */
export function wrapWords(text: string, width: number, widthOf: (s: string) => number): string {
  return text.split("\n").map((para) => {
    const lines: string[] = [];
    for (const word of para.split(/\s+/).filter(Boolean)) {
      const last = lines.length ? `${lines[lines.length - 1]} ${word}` : "";
      if (last && widthOf(last) <= width) lines[lines.length - 1] = last;
      else lines.push(word); // a word wider than the line stays whole and sticks out, as in TMT
    }
    return lines.join("\n");
  }).join("\n");
}

/** X6's textWrap, but breaking only between words (X6 2.x splits words and ignores `breakWord`). */
const textWrap = {
  qualify: (v: unknown) => !!v && typeof v === "object",
  set(this: any, val: any, { view, elem, attrs, refBBox }: any) {
    const w = val.width ?? 0;
    const width = typeof w === "string" && w.endsWith("%") ? (refBBox.width * parseFloat(w)) / 100 : w <= 0 ? refBBox.width + w : w;
    const txt = String(attrs.text ?? elem?.textContent ?? "");
    const style = elem ? getComputedStyle(elem) : null;
    const size = attrs.fontSize ?? attrs["font-size"] ?? parseFloat(style?.fontSize ?? "13");
    if (measure) measure.font = `${attrs.fontWeight ?? style?.fontWeight ?? 400} ${size}px ${style?.fontFamily ?? "sans-serif"}`;
    const wrapped = wrapWords(txt, width, (s) => measure?.measureText(s).width ?? s.length * size * 0.55);
    (Registry.Attr.presets as any).text.set.call(this, wrapped, { view, elem, attrs, refBBox, cell: view.cell });
  },
};

export function registerShapes() {
  if (registered) return;
  registered = true;
  Graph.registerAttr("textWrap", textWrap as any, true);
  Graph.registerConnector("smooth", sidedSmooth as any, true);
  Graph.registerRouter("manhattan", sidedManhattan as any, true);
  Graph.registerNode("actor", {
    inherit: "rect", width: 150, height: 80, zIndex: 0,
    markup: [HALO, ...(Shape.Rect.getMarkup() as any[]).slice(0, 1), ICON_IMG, ...(Shape.Rect.getMarkup() as any[]).slice(1)],
    attrs: { halo, body: { fill: "#fbfcfc", stroke: INK, strokeWidth: 1.5 }, icon: lowerRight, text },
    ports,
  }, true);
  Graph.registerNode("process", {
    inherit: "circle", width: 100, height: 100, zIndex: 0,
    markup: [HALO, ...(Shape.Circle.getMarkup() as any[]).slice(0, 1), ICON_IMG, ...(Shape.Circle.getMarkup() as any[]).slice(1)],
    attrs: {
      halo,
      body: { fill: "#fbfcfc", stroke: INK, strokeWidth: 1.5 },
      icon: centred,
      text: { ...text, textWrap: { ...text.textWrap, width: -20 } },
    },
    ports,
  }, true);
  Graph.registerNode("store", {
    inherit: "rect", width: 150, height: 75, zIndex: 0,
    markup: [
      HALO,
      ...(Shape.Rect.getMarkup() as any[]).slice(0, 1),
      ICON_IMG,
      ...(Shape.Rect.getMarkup() as any[]).slice(1),
      { tagName: "path", selector: "topLine" },
      { tagName: "path", selector: "bottomLine" },
    ],
    attrs: {
      topLine: { stroke: INK, strokeWidth: 1.5, refD: "M 0 0 l 200 0" },
      bottomLine: { stroke: INK, strokeWidth: 1.5, refDy: 0, refD: "M 0 0 l 100 0" },
      body: { fill: "transparent", stroke: "none" }, // TMT draws a data store as two lines only
      icon: lowerRight,
      halo,
      text,
    },
    ports,
  }, true);
  Graph.registerNode("td-text-block", {
    inherit: "rect", width: 150, height: 80, zIndex: 0,
    attrs: { body: { fill: "transparent", stroke: "none" }, text: { ...text, fill: "#5a6470" } },
  }, true);
  Graph.registerNode("trust-boundary-box", {
    inherit: "rect", width: 500, height: 400, zIndex: -50,
    markup: [...(Shape.Rect.getMarkup() as any[]).slice(0, 1), ICON_IMG, ...(Shape.Rect.getMarkup() as any[]).slice(1)],
    attrs: {
      body: { strokeWidth: 1.5, stroke: BOUNDARY, strokeDasharray: "7 5", fill: "transparent" },
      icon: { refX: 8, refY: 8, width: 14, height: 14, opacity: 0.5, pointerEvents: "none" },
      label: {
        text: "", fill: BOUNDARY, fontSize: 13,
        textAnchor: "start", textVerticalAnchor: "top", refX: 28, refY: 8,
        textWrap: { width: -36 },
      },
    },
  }, true);
  const label = {
    markup: [{ tagName: "rect", selector: "body" }, { tagName: "image", selector: "icon" }, { tagName: "text", selector: "label" }],
    attrs: {
      label: { fill: INK, fontSize: 12, textAnchor: "middle", textVerticalAnchor: "middle" },
      body: {
        ref: "label", fill: LABEL_FILL, stroke: LABEL_STROKE, strokeWidth: 1,
        refWidth: "100%", refWidth2: LABEL_ICON + 14, refHeight: "100%", refHeight2: 8, refX: -(LABEL_ICON + 9), refY: -4,
      },
      icon: { ref: "label", refX: 0, refY: "50%", x: -(LABEL_ICON + 5), y: -LABEL_ICON / 2, width: LABEL_ICON, height: LABEL_ICON, opacity: 0.6, pointerEvents: "none" },
    },
    position: { distance: 0.5 },
  };
  Graph.registerEdge("flow", {
    inherit: "edge", zIndex: 10,
    attrs: {
      line: { stroke: INK, strokeWidth: 1.5, sourceMarker: null, targetMarker: { name: "block", width: 9, height: 7 } },
    },
    connector: "smooth",
    defaultLabel: label,
  } as any, true);
  const curve: any = {
    inherit: "edge", zIndex: 10,
    attrs: { line: { stroke: BOUNDARY, strokeWidth: 1.5, strokeDasharray: "7 5", sourceMarker: null, targetMarker: null } },
    connector: "smooth",
    defaultLabel: {
      ...label,
      attrs: {
        ...label.attrs,
        body: { ...label.attrs.body, fill: "#fbfcfc", stroke: "none" },
        label: { ...label.attrs.label, fill: BOUNDARY, fontWeight: 600 },
      },
    },
  };
  Graph.registerEdge("trust-boundary-curve", curve, true);
  Graph.registerEdge("trust-broundary-curve", curve, true); // a typo many existing models carry
}

export type Kind = "actor" | "process" | "store" | "flow" | "boundary_box" | "boundary_curve" | "text";

export const KIND_OF_TYPE: Record<string, Kind> = {
  "tm.Actor": "actor", "tm.Process": "process", "tm.Store": "store", "tm.Flow": "flow",
  "tm.BoundaryBox": "boundary_box", "tm.Boundary": "boundary_curve", "tm.Text": "text",
};

export const KIND_NAMES: Record<Kind, string> = {
  actor: "External interactor", process: "Process", store: "Data store", flow: "Data flow",
  boundary_box: "Trust boundary (box)", boundary_curve: "Trust boundary (line)", text: "Text",
};

const line = { stroke: "#333333", strokeWidth: 1.5, strokeDasharray: null };
const base = { description: "", outOfScope: false, isTrustBoundary: false, reasonOutOfScope: "", hasOpenThreats: false };

// A new cell as Threat Dragon would write it, so files stay readable there.
export function newCell(kind: Kind, name: string, x: number, y: number): Record<string, any> {
  switch (kind) {
    case "actor":
      return {
        shape: "actor", position: { x, y }, size: { width: 150, height: 80 }, zIndex: 1,
        attrs: { text: { text: name }, body: { ...line } },
        data: { type: "tm.Actor", name, ...base, providesAuthentication: false, threats: [] },
      };
    case "process":
      return {
        shape: "process", position: { x, y }, size: { width: 100, height: 100 }, zIndex: 1,
        attrs: { text: { text: name }, body: { ...line } },
        data: {
          type: "tm.Process", name, ...base, handlesCardPayment: false, handlesGoodsOrServices: false,
          isWebApplication: false, privilegeLevel: "", threats: [],
        },
      };
    case "store":
      return {
        shape: "store", position: { x, y }, size: { width: 150, height: 75 }, zIndex: 1,
        attrs: { text: { text: name }, topLine: { ...line }, bottomLine: { ...line } },
        data: {
          type: "tm.Store", name, ...base, isALog: false, isEncrypted: false, isSigned: false,
          storesCredentials: false, storesInventory: false, threats: [],
        },
      };
    case "boundary_box":
      return {
        shape: "trust-boundary-box", position: { x, y }, size: { width: 420, height: 300 }, zIndex: -1,
        attrs: { label: { text: name } },
        data: { type: "tm.BoundaryBox", name, description: "", isTrustBoundary: true, hasOpenThreats: false },
      };
    case "boundary_curve":
      return {
        shape: "trust-boundary-curve", zIndex: 10, connector: "smooth",
        source: { x, y }, target: { x: x + 240, y: y + 40 }, vertices: [{ x: x + 120, y: y - 30 }],
        labels: [name],
        data: { type: "tm.Boundary", name, description: "", isTrustBoundary: true, hasOpenThreats: false },
      };
    case "flow":
      return {
        shape: "flow", zIndex: 10, connector: "smooth", width: 200, height: 100,
        attrs: { line: { ...line, targetMarker: { name: "block" }, sourceMarker: { name: "" } } },
        labels: [{ position: 0.5, attrs: { label: { text: name } } }],
        source: { x, y }, target: { x: x + 200, y }, vertices: [],
        data: {
          type: "tm.Flow", name, ...base, isBidirectional: false, isEncrypted: false,
          isPublicNetwork: false, protocol: "", threats: [],
        },
      };
    case "text":
      return {
        shape: "td-text-block", position: { x, y }, size: { width: 190, height: 80 }, zIndex: 1,
        attrs: { text: { text: name } }, data: { type: "tm.Text", name, hasOpenThreats: false },
      };
  }
}
