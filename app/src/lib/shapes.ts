// Threat Dragon's diagram shapes, registered under Threat Dragon's names so its files open and draw
// the same. Transcribed from OWASP Threat Dragon 2.6.2 (td.vue/src/service/x6/shapes and
// service/entity/default-properties.js), Apache-2.0; see THIRD_PARTY_NOTICES.md.
import { Graph, Shape } from "@antv/x6";

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

const text = { fontSize: 13, fill: INK };
const HALO = { tagName: "rect", selector: "halo" };
const halo = { refX: -28, refY: -28, refWidth: "100%", refWidth2: 56, refHeight: "100%", refHeight2: 56, fill: "transparent", stroke: "none" };

let registered = false;

export function registerShapes() {
  if (registered) return;
  registered = true;
  Graph.registerNode("actor", {
    inherit: "rect", width: 150, height: 80, zIndex: 0,
    markup: [HALO, ...(Shape.Rect.getMarkup() as any[])],
    attrs: { halo, body: { fill: "#fbfcfc", stroke: INK, strokeWidth: 1.5 }, text },
    ports,
  }, true);
  Graph.registerNode("process", {
    inherit: "circle", width: 100, height: 100, zIndex: 0,
    markup: [HALO, ...(Shape.Circle.getMarkup() as any[])],
    attrs: {
      halo,
      body: { fill: "#fbfcfc", stroke: INK, strokeWidth: 1.5 },
      text,
    },
    ports,
  }, true);
  Graph.registerNode("store", {
    inherit: "rect", width: 150, height: 75, zIndex: 0,
    markup: [
      HALO,
      ...(Shape.Rect.getMarkup() as any[]),
      { tagName: "path", selector: "topLine" },
      { tagName: "path", selector: "bottomLine" },
    ],
    attrs: {
      topLine: { stroke: INK, strokeWidth: 1.5, refD: "M 0 0 l 200 0" },
      bottomLine: { stroke: INK, strokeWidth: 1.5, refDy: 0, refD: "M 0 0 l 100 0" },
      body: { fill: "transparent", stroke: "none" }, // TMT draws a data store as two lines only
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
    attrs: {
      body: { strokeWidth: 1.5, stroke: BOUNDARY, strokeDasharray: "7 5", fill: "transparent" },
      label: {
        text: "", fill: BOUNDARY, fontSize: 13, fontWeight: 600,
        textAnchor: "start", textVerticalAnchor: "top", refX: 10, refY: 8,
      },
    },
  }, true);
  const label = {
    markup: [{ tagName: "rect", selector: "body" }, { tagName: "text", selector: "label" }],
    attrs: {
      label: { fill: INK, fontSize: 12, textAnchor: "middle", textVerticalAnchor: "middle" },
      body: { ref: "label", fill: "#fbfcfc", stroke: "none", refWidth: "100%", refWidth2: 8, refHeight: "100%", refHeight2: 4, refX: -4, refY: -2, rx: 3 },
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
    defaultLabel: { ...label, attrs: { ...label.attrs, label: { ...label.attrs.label, fill: BOUNDARY, fontWeight: 600 } } },
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
