import { describe, expect, it } from "vitest";
import { forCanvas, fromCanvas, patchCell, visibleDescription, withTags } from "../../src/lib/sync";

const cell = () => ({
  id: "p1",
  shape: "process",
  position: { x: 10, y: 20 },
  size: { width: 100, height: 100 },
  attrs: { text: { text: "Web" }, body: { stroke: "red", strokeWidth: 2.5, strokeDasharray: null, fill: "#fff" } },
  unknownKey: { keep: [1, 2, 3] },
  data: { type: "tm.Process", name: "Web", description: "Hi\n@tmt: Web Application", threats: [{ id: "t1" }], hasOpenThreats: true },
});

describe("forCanvas", () => {
  it("drops threats and Threat Dragon outline styles, keeps the rest", () => {
    const c = forCanvas(cell());
    expect(c.data.threats).toBeUndefined();
    expect(c.data.hasOpenThreats).toBeUndefined();
    expect(c.attrs.body).toEqual({ fill: "#fff" });
    expect(c.attrs.text).toEqual({ text: "Web" });
    expect(c.unknownKey).toEqual({ keep: [1, 2, 3] });
  });
  it("never changes the model's cell", () => {
    const original = cell();
    forCanvas(original);
    expect(original).toEqual(cell());
  });
});

describe("patchCell", () => {
  it("with no change on the canvas, the cell stays identical", () => {
    const c = cell();
    const seen = forCanvas(c);
    patchCell(c, seen, structuredClone(seen));
    expect(c).toEqual(cell());
  });
  it("writes only what changed, keeping threats, styles and unknown keys", () => {
    const c = cell();
    const before = forCanvas(c);
    const after = structuredClone(before);
    after.position = { x: 300, y: 20 };
    after.data.name = "Shop";
    after.attrs.text.text = "Shop";
    patchCell(c, before, after);
    expect(c.position).toEqual({ x: 300, y: 20 });
    expect(c.data).toEqual({ ...cell().data, name: "Shop" });
    expect(c.attrs.body).toEqual(cell().attrs.body);
    expect(c.attrs.text.text).toBe("Shop");
    expect(c.unknownKey).toEqual({ keep: [1, 2, 3] });
  });
  it("removes what the canvas removed", () => {
    const c: any = { id: "e", vertices: [{ x: 1, y: 1 }], data: { name: "f" } };
    patchCell(c, { id: "e", vertices: [{ x: 1, y: 1 }], data: { name: "f" } }, { id: "e", data: { name: "f" } });
    expect(c).toEqual({ id: "e", data: { name: "f" } });
  });
  it("replaces arrays whole", () => {
    const c: any = { vertices: [{ x: 1, y: 1 }, { x: 2, y: 2 }] };
    patchCell(c, { vertices: c.vertices }, { vertices: [{ x: 5, y: 5 }] });
    expect(c.vertices).toEqual([{ x: 5, y: 5 }]);
  });
});

describe("fromCanvas", () => {
  it("gives new threat-bearing cells an empty threat list", () => {
    expect(fromCanvas({ id: "a", data: { type: "tm.Flow" } }).data).toEqual({ type: "tm.Flow", threats: [], hasOpenThreats: false });
    expect(fromCanvas({ id: "b", data: { type: "tm.BoundaryBox" } }).data).toEqual({ type: "tm.BoundaryBox" });
  });
});

describe("descriptions", () => {
  it("hide @tmt lines and put them back after an edit", () => {
    const full = "Stores orders.\n@tmt: SQL Database; storesCredentials=Yes";
    expect(visibleDescription(full)).toBe("Stores orders.");
    expect(withTags("Stores orders and refunds.", full)).toBe("Stores orders and refunds.\n@tmt: SQL Database; storesCredentials=Yes");
    expect(withTags("", full)).toBe("@tmt: SQL Database; storesCredentials=Yes");
    expect(withTags("Plain", "Old")).toBe("Plain");
    expect(visibleDescription("  @TMT: HTTPS\nText")).toBe("Text");
  });
});
