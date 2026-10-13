// End-to-end: the production build in a real browser, driven the way a person uses it.
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = join(import.meta.dirname, "../../..");
const EXAMPLE = join(REPO, "examples/online-shop.json");
const SMALL_TM7 = join(REPO, "tests/fixtures/tm7/small.tm7");
const PRIVATE_TM7 = join(REPO, "tests/fixtures/private/mobile-banking.tm7");

test.use({ viewport: { width: 1440, height: 900 } });

// Without the File System Access API the app opens through a file chooser and saves as a
// download, which the test can catch; Safari and Firefox users get exactly this path.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    delete (window as any).showOpenFilePicker;
    delete (window as any).showSaveFilePicker;
  });
});

/** What the threatsketch CLI writes for `model` (a path), as parsed JSON. */
function cliAnalyze(model: string) {
  const dir = mkdtempSync(join(tmpdir(), "threatsketch-"));
  const copy = join(dir, "model.json");
  copyFileSync(model, copy);
  execFileSync("uv", ["run", "--project", REPO, "threatsketch", "analyze", copy], { stdio: "pipe" });
  return JSON.parse(readFileSync(copy, "utf8"));
}

async function openExample(page: Page) {
  await page.goto("./");
  await page.getByRole("button", { name: /Open the example/ }).click();
  await expect(page.getByTestId("threat-count")).toHaveText("38 threats");
}

const snapshot = (page: Page) => page.evaluate(() => JSON.parse(JSON.stringify((window as any).threatsketch.editor.snapshot())));

async function download(page: Page, click: () => Promise<void>) {
  const [d] = await Promise.all([page.waitForEvent("download"), click()]);
  return { name: d.suggestedFilename(), text: readFileSync((await d.path())!, "utf8") };
}

/** Click a menu bar menu, then return one of its items. */
async function menu(page: Page, top: string, item: string | RegExp) {
  await page.getByRole("menuitem", { name: top, exact: true }).click();
  return page.getByRole("menu", { name: top }).getByRole("menuitem", { name: item });
}

/** TMT's Analysis view: the threat list and threat properties. */
async function analysisView(page: Page) {
  await page.getByRole("button", { name: "Analysis View" }).click();
}

async function newModel(page: Page) {
  await page.goto("./");
  await expect(page.getByTestId("engine-status")).toContainText("Knowledge Base", { timeout: 30_000 });
  await page.getByRole("button", { name: "New threat model" }).click();
  await expect(page.locator(".canvas svg").first()).toBeVisible();
}

async function plus(page: Page, cellId: string, side: string) {
  // a person scrolls a shape into view before using its "+"; one at the canvas edge can sit under a panel
  await page.evaluate((id) => {
    const graph = (window as any).threatsketch.editor.graph;
    const cell = graph.getCellById(id);
    const r = graph.getPlugin("scroller").container.getBoundingClientRect();
    const view = graph.clientToLocal({ x: r.x, y: r.y, width: r.width, height: r.height });
    if (!view.containsRect(cell.getBBox().inflate(40))) graph.centerCell(cell);
  }, cellId);
  const node = page.locator(`g.x6-node[data-cell-id="${cellId}"]`);
  const handle = node.locator(`[port-group="${side}"] circle`);
  // onto the "+", as a person would; if the canvas shifts under a still pointer (panels redraw
  // when the analysis lands), the "+" moves away and hides, so aim again, as a person would
  await expect(async () => {
    await node.hover({ force: true });
    const b = (await handle.boundingBox())!;
    await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
    await expect(handle).toBeVisible({ timeout: 1000 });
  }).toPass({ timeout: 20_000 });
  return handle;
}

test("opens the example: TMT's 38 threats, drawn TMT-style", async ({ page }) => {
  await openExample(page);
  await expect(page.locator(".x6-node")).toHaveCount(6);
  await expect(page.locator(".x6-edge")).toHaveCount(7);
  await analysisView(page);
  await expect(page.getByTestId("threat-row")).toHaveCount(38);
  // trust boundaries are red dashed, as in TMT; open-threat outlines are not drawn
  const box = page.locator('g[data-cell-id="backend"] rect').first();
  await expect(box).toHaveAttribute("stroke", "#c0392f");
  await expect(page.locator('g[data-cell-id="webapp"] circle').first()).toHaveAttribute("stroke", "#1b2026");
});

test("saving writes exactly what the threatsketch CLI writes", async ({ page }) => {
  await openExample(page);
  const saved = await download(page, () => page.getByRole("button", { name: "Save" }).click());
  expect(saved.name).toBe("online-shop.json");
  expect(JSON.parse(saved.text)).toEqual(cliAnalyze(EXAMPLE));
  await expect(page.getByText("All changes saved")).toBeVisible();
});

test("a model saved without edits keeps every key of the original", async ({ page }) => {
  await openExample(page);
  await page.locator('g.x6-node[data-cell-id="customer"]').click(); // select, change nothing
  await page.locator(".canvas").click({ position: { x: 5, y: 5 } });
  expect(await snapshot(page)).toEqual(cliAnalyze(EXAMPLE));
});

/** The side of `id` that faces `other`, by their centres on the canvas. */
async function facing(page: Page, id: string, other: string) {
  const box = async (c: string) => (await page.locator(`g.x6-node[data-cell-id="${c}"]`).boundingBox())!;
  const a = await box(id), b = await box(other);
  const dx = (b.x + b.width / 2 - a.x - a.width / 2) / a.width, dy = (b.y + b.height / 2 - a.y - a.height / 2) / a.height;
  return Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? "right" : "left") : dy > 0 ? "bottom" : "top";
}

test("flows both ways between two shapes run side by side, not on top of each other", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /Generic External Interactor/ }).click();
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  const [actor, proc] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);
  await (await plus(page, actor, "right")).click(); // actor -> process
  await page.locator(".canvas").click({ position: { x: 5, y: 5 } });
  await (await plus(page, proc, "left")).click(); // process -> actor
  await expect(page.locator(".x6-edge")).toHaveCount(2);
  const flows = (await snapshot(page)).detail.diagrams[0].cells.filter((c: any) => c.data.type === "tm.Flow");
  expect(flows.map((f: any) => [f.source.cell, f.target.cell])).toEqual([[actor, proc], [proc, actor]]);
  const ends = await page.evaluate((ids) => {
    const graph = (window as any).threatsketch.editor.graph;
    return ids.map((id: string) => {
      const v = graph.findViewByCell(id);
      return [v.sourcePoint.y, v.targetPoint.y];
    });
  }, flows.map((f: any) => f.id));
  // each flow's ends sit apart from the other flow's, so the two lines never coincide
  expect(Math.abs(ends[0][0] - ends[1][1])).toBeGreaterThan(8);
  expect(Math.abs(ends[0][1] - ends[1][0])).toBeGreaterThan(8);
  // and their names do not sit on top of each other
  const [a, b] = await page.locator(".x6-edge-label").evaluateAll((ls) => ls.map((l) => l.getBoundingClientRect().toJSON()));
  const overlap = a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
  expect(overlap, JSON.stringify([a, b])).toBe(false);
});

test("elbow lines: chosen per flow, saved in the file, and new flows follow the last choice", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /Generic External Interactor/ }).click();
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  const [actor, proc] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);
  await page.evaluate((id) => { // put the process lower, so an elbow has to bend
    const cell = (window as any).threatsketch.editor.graph.getCellById(id);
    cell.translate(0, 160);
  }, proc);
  await (await plus(page, actor, "right")).click();
  await page.getByTestId("line-style").selectOption("elbow");
  const flowOf = async (from: string) =>
    (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.data.type === "tm.Flow" && c.source.cell === from);
  await expect.poll(async () => (await flowOf(actor))?.router?.name).toBe("manhattan");
  expect((await flowOf(actor)).connector.name).toBe("rounded");
  const bends = await page.evaluate((id) => (window as any).threatsketch.editor.graph.findViewByCell(id).routePoints.length, (await flowOf(actor)).id);
  expect(bends).toBeGreaterThanOrEqual(2);
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT });

  await page.keyboard.press("Escape");
  await (await plus(page, proc, "left")).click(); // a new flow: elbow, like the last one chosen
  await expect.poll(async () => (await flowOf(proc))?.router?.name).toBe("manhattan");

  await page.getByTestId("line-style").selectOption("curved");
  await expect.poll(async () => (await flowOf(proc))?.router).toBeUndefined();
  expect((await flowOf(proc)).connector).toBe("smooth");
});

test("draw from scratch: palette, click + to connect, threats appear as you draw", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /Generic External Interactor/ }).click();
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  await expect(page.locator(".x6-node")).toHaveCount(2);
  const [actor, proc] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);

  await (await plus(page, actor, "right")).click();
  await expect(page.locator(".x6-edge")).toHaveCount(1);
  await analysisView(page);
  await expect(page.getByTestId("threat-row").first()).toBeVisible();
  const flow = (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.data.type === "tm.Flow");
  expect([flow.source.cell, flow.target.cell]).toEqual([actor, proc]);
  expect(flow.data.threats.length).toBeGreaterThan(0);

  // name it from the properties pane, which focuses the new flow
  await page.getByTestId("element-name").fill("Sign in");
  await page.getByTestId("element-name").press("Enter");
  await expect(page.locator(".x6-edge-label")).toContainText("Sign in");
  expect((await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.id === flow.id).data.name).toBe("Sign in");
});

test("click + where nothing is: a new process is added and linked", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /Generic External Interactor/ }).click();
  const [actor] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);
  await (await plus(page, actor, "bottom")).click();
  await expect(page.locator(".x6-node")).toHaveCount(2);
  await expect(page.locator(".x6-edge")).toHaveCount(1);
  const types = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.data.type).sort();
  expect(types).toEqual(["tm.Actor", "tm.Flow", "tm.Process"]);
  // nothing named yet: the model pane says so before anyone reads the report
  await page.keyboard.press("Escape");
  await page.locator(".canvas").click({ position: { x: 5, y: 5 } });
  await expect(page.getByTestId("review")).toContainText("3 of 3 elements still have a default name");
});

test("drag a + onto another element to draw a flow", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  await page.getByRole("button", { name: /^Generic Data Store/ }).click();
  const [proc, store] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);
  const handle = await plus(page, proc, "right");
  const from = (await handle.boundingBox())!;
  const to = (await page.locator(`g.x6-node[data-cell-id="${store}"] > rect`).nth(1).boundingBox())!;
  await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2);
  await page.mouse.down();
  await page.mouse.move(from.x + 60, from.y + 10, { steps: 5 });
  await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 10 });
  await page.mouse.up();
  await expect(page.locator(".x6-edge")).toHaveCount(1);
  const flow = (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.data.type === "tm.Flow");
  // attached to the shape's side, not to the "+"; dropped mid-shape, it lands on the side facing back
  expect(flow.source).toEqual({ cell: proc, selector: "body", anchor: { name: "right" } }); // a circle
  expect(flow.target.cell).toBe(store);
  expect(flow.target.anchor.name).toBe(await facing(page, store, proc));
  await analysisView(page);
  await expect(page.getByTestId("threat-row").first()).toBeVisible();
});

test("choosing a stencil changes the threats, as in TMT", async ({ page }) => {
  await openExample(page);
  await page.locator('g.x6-node[data-cell-id="audit"]').click();
  await page.getByTestId("element-stencil").selectOption({ label: "SQL Database" });
  await expect(page.getByTestId("threat-count")).not.toHaveText("38 threats");
  const audit = (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.id === "audit");
  expect(audit.data.description).toContain("@tmt: SQL Database");
  // the tag is hidden from the description people edit
  await expect(page.locator("textarea").first()).not.toHaveValue(/@tmt/);
});

test("triage a threat: state, priority and justification are saved TMT's way", async ({ page }) => {
  await openExample(page);
  await analysisView(page);
  await page.getByTestId("threat-row").first().click();
  await page.getByTestId("threat-state").selectOption("Needs Investigation");
  await expect(page.getByTestId("threat-row").first()).toContainText("Needs Investigation");
  await page.getByTestId("threat-priority").selectOption("Low");
  await page.getByTestId("threat-justification").fill("Customers sign in with MFA.");
  await page.getByTestId("threat-justification").blur();
  await page.getByTestId("threat-state").selectOption("Mitigated");
  await expect(page.getByTestId("threat-row").first()).toContainText("Mitigated");
  const t = (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.id === "placeorder").data.threats[0];
  expect([t.status, t.severity, t.mitigation]).toEqual(["Mitigated", "Low", "Customers sign in with MFA."]);
  // a second threat on the same flow can be selected and triaged too, with its own values: the
  // form must not carry the first threat's priority and justification over to it
  await page.getByTestId("threat-row").nth(1).click();
  await expect(page.getByTestId("threat-justification")).toHaveValue("");
  await expect(page.getByTestId("threat-priority")).toHaveValue("High");
  await page.getByTestId("threat-state").selectOption("Not Applicable");
  await expect(page.getByTestId("threat-row").nth(1)).toContainText("Not Applicable");
  const second = (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.id === "placeorder").data.threats[1];
  expect([second.status, second.severity, second.mitigation]).toEqual(["NotApplicable", "High", ""]);
});

test("an edit saved while an analysis is running stays in the model", async ({ page }) => {
  await openExample(page);
  // a slow engine, so the save lands while an analysis is in flight
  await page.evaluate(() => {
    const engine = (window as any).threatsketch.engine;
    const analyze = engine.analyze.bind(engine);
    engine.analyze = async (m: unknown) => {
      const sent = structuredClone(m); // the worker gets a copy of the model as it is now
      await new Promise((r) => setTimeout(r, 800));
      return analyze(sent);
    };
  });
  const position = async (id: string) =>
    (await snapshot(page)).detail.diagrams[0].cells.find((c: any) => c.id === id).position;
  await page.evaluate(() => (window as any).threatsketch.editor.graph.getCellById("audit").translate(0, 40));
  await page.waitForTimeout(400); // the analysis for that move is now running
  await page.evaluate(() => (window as any).threatsketch.editor.graph.getCellById("orders").translate(0, 40));
  const moved = await position("orders"); // what Save writes (it syncs the canvas first)
  await page.getByTestId("model-title").fill("Online shop v2"); // a model field, edited meanwhile
  await page.getByTestId("model-title").press("Enter");
  await page.waitForTimeout(3000); // the slow analyses finish and are applied
  expect(await position("orders")).toEqual(moved);
  expect((await position("orders")).y).toBe(510);
  expect((await snapshot(page)).summary.title).toBe("Online shop v2");
});

test("delete and undo", async ({ page }) => {
  await openExample(page);
  await page.locator('g.x6-node[data-cell-id="audit"]').click();
  await page.keyboard.press("Delete");
  await expect(page.locator('g.x6-node[data-cell-id="audit"]')).toHaveCount(0);
  await expect(page.getByTestId("threat-count")).not.toHaveText("38 threats");
  await page.getByRole("button", { name: "Undo" }).click();
  await expect(page.locator('g.x6-node[data-cell-id="audit"]')).toHaveCount(1);
  await expect(page.getByTestId("threat-count")).toHaveText("38 threats");
});

test("import a TMT .tm7, then export .tm7, report and CSV", async ({ page }) => {
  await page.goto("./");
  await expect(page.getByTestId("engine-status")).toContainText("Knowledge Base", { timeout: 30_000 });
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.getByRole("button", { name: /Open a file/ }).click()]);
  await chooser.setFiles(SMALL_TM7);
  await analysisView(page);
  await expect(page.getByTestId("threat-row").first()).toBeVisible();
  const expected = JSON.parse(execFileSync("uv", ["run", "--project", REPO, "python", "-c",
    `import json,sys; from threatsketch.tm7 import import_tm7; from threatsketch import api; print(json.dumps(len(api.analyze(import_tm7(sys.argv[1])[0])["threats"])))`, SMALL_TM7]).toString());
  await expect(page.getByTestId("threat-row")).toHaveCount(expected);

  const tm7 = await download(page, async () => (await menu(page, "File", /TMT Model \(\.tm7\)/)).click());
  expect(tm7.name).toBe("small.tm7");
  expect(tm7.text).toContain("<ThreatModel");
  const html = await download(page, async () => (await menu(page, "Reports", /Full Report \(\.html\)/)).click());
  expect(html.text).toContain("Threat Model Summary");
  const csv = await download(page, async () => (await menu(page, "Reports", /Threat List \(\.csv\)/)).click());
  expect(csv.text.split("\r\n")[0]).toBe("Id,Title,Category,Diagram,Interaction,Priority,State,Changed By,Description,Justification,Last Modified");
});

test("unsaved work comes back after the tab closes", async ({ page }) => {
  await openExample(page);
  await page.locator('g.x6-node[data-cell-id="audit"]').click();
  await page.keyboard.press("Delete");
  await expect(page.getByTestId("threat-count")).not.toHaveText("38 threats");
  page.on("dialog", (d) => d.accept());
  await page.reload();
  await page.getByRole("button", { name: /Restore unsaved work/ }).click();
  await expect(page.locator(".x6-node")).toHaveCount(5);
  await expect(page.locator('g.x6-node[data-cell-id="audit"]')).toHaveCount(0);
});

test("multiple diagrams: add, rename, switch", async ({ page }) => {
  await openExample(page);
  await page.getByRole("button", { name: "New diagram", exact: true }).click();
  await expect(page.locator(".x6-node")).toHaveCount(0);
  await page.getByRole("tab", { name: "Diagram 2" }).dblclick();
  await page.locator(".tabedit").fill("Admin");
  await page.locator(".tabedit").press("Enter");
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  await page.getByRole("tab", { name: "Online shop" }).click();
  await expect(page.locator(".x6-node")).toHaveCount(6);
  const m = await snapshot(page);
  expect(m.detail.diagrams.map((d: any) => [d.title, d.cells.length])).toEqual([["Online shop", 13], ["Admin", 1]]);
});

test("private: the Mobile Banking model from real TMT gives TMT's threats", async ({ page }) => {
  test.skip(!existsSync(PRIVATE_TM7), "coursework model not on this machine");
  const tmt = readFileSync(PRIVATE_TM7, "utf8").split("<b:FlowGuid>").length - 1; // one per TMT threat
  await page.goto("./");
  await expect(page.getByTestId("engine-status")).toContainText("Knowledge Base", { timeout: 30_000 });
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.getByRole("button", { name: /Open a file/ }).click()]);
  await chooser.setFiles(PRIVATE_TM7);
  await expect(page.getByTestId("threat-count")).toHaveText(`${tmt} threats`);
});

test("works offline after the first visit", async ({ page, context }) => {
  await page.goto("./");
  await expect(page.getByTestId("engine-status")).toContainText("Knowledge Base");
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 30_000 }).catch(() => page.reload());
  await page.evaluate(async () => {
    const keys = await caches.keys();
    const all = (await Promise.all(keys.map(async (k) => (await caches.open(k)).keys()))).flat();
    if (!all.some((r) => r.url.includes("pyodide.asm.wasm"))) throw new Error("engine not cached");
  });
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByTestId("engine-status")).toContainText("Knowledge Base");
  await page.getByRole("button", { name: /Open the example/ }).click();
  await expect(page.getByTestId("threat-count")).toHaveText("38 threats");
});

test("the first model in docs/coming-from-tmt.md works as written", async ({ page }) => {
  await newModel(page);
  await page.getByTestId("model-title").fill("Shop");
  await page.getByTestId("model-title").press("Enter");
  for (const [stencil, name] of [["Human User", "Customer"], ["Web Application", "Shop"], ["SQL Database", "Orders"]]) {
    await page.getByRole("button", { name: new RegExp(`^${stencil}`) }).click();
    await page.getByTestId("element-name").fill(name);
    await page.getByTestId("element-name").press("Enter");
  }
  const cells = async () => (await snapshot(page)).detail.diagrams[0].cells;
  const id = async (name: string) => (await cells()).find((c: any) => c.data.name === name).id;
  const [customer, shop, orders] = [await id("Customer"), await id("Shop"), await id("Orders")];
  for (const [from, side] of [[customer, "right"], [shop, "right"], [shop, "left"], [orders, "left"]]) {
    await (await plus(page, from, side)).click();
    await page.keyboard.press("Escape");
  }
  await expect(page.locator(".x6-edge")).toHaveCount(4);

  const shopBox = (await page.locator(`g.x6-node[data-cell-id="${shop}"]`).boundingBox())!;
  const canvas = page.locator(".canvaswrap");
  const c = (await canvas.boundingBox())!;
  await page.getByRole("button", { name: /^Generic Trust Border Boundary/ }).dragTo(canvas, {
    targetPosition: { x: shopBox.x - c.x - 30, y: shopBox.y - c.y - 60 },
  });
  await expect(page.locator('g.x6-node[data-shape="trust-boundary-box"]')).toHaveCount(1);

  const model = await snapshot(page);
  const flows = model.detail.diagrams[0].cells.filter((c: any) => c.data.type === "tm.Flow");
  expect(flows.map((f: any) => [f.source.cell, f.target.cell]).sort()).toEqual(
    [[customer, shop], [shop, orders], [shop, customer], [orders, shop]].sort(),
  );
  await expect(page.getByTestId("threat-count")).not.toHaveText("0 threats");
  // the customer's flows cross the boundary; the shop-to-orders flows do not
  const mid = await page.evaluate((id) => {
    const graph = (window as any).threatsketch.editor.graph;
    const path = graph.findViewByCell(id).getConnection();
    return graph.localToClient(path.pointAtLength(path.length() / 2));
  }, flows.find((f: any) => f.source.cell === customer).id);
  await page.mouse.click(mid.x, mid.y); // on the line itself
  await expect(page.locator(".props")).toContainText("Crosses");
});

test("PDF export opens the styled report with the print dialog", async ({ page }) => {
  await openExample(page);
  const item = await menu(page, "Reports", /Full Report as PDF/);
  const [popup] = await Promise.all([page.waitForEvent("popup"), item.click()]);
  await popup.waitForLoadState();
  await expect(popup.locator("h1")).toHaveText("Online shop");
  await expect(popup.locator(".stat").first()).toContainText("38");
  expect(await popup.content()).toContain("setTimeout(print");
});

test("TMT's assumptions and external dependencies reach the .tm7 and the saved model", async ({ page }) => {
  await openExample(page);
  await page.getByTestId("model-assumptions").fill("All traffic uses TLS 1.2+");
  await page.getByTestId("model-assumptions").blur();
  const tm7 = await download(page, async () => (await menu(page, "File", /TMT Model \(\.tm7\)/)).click());
  expect(tm7.text).toContain("<Assumptions>All traffic uses TLS 1.2+</Assumptions>");
  expect((await snapshot(page)).tdtm.tm7.meta.Assumptions).toBe("All traffic uses TLS 1.2+");
});

test("shapes and flows show TMT's stencil icons, which never reach the saved model", async ({ page }) => {
  await openExample(page);
  const hrefs = await page.evaluate(() => {
    const g = (window as any).threatsketch.editor.graph;
    return {
      nodes: g.getNodes().filter((n: any) => n.shape !== "td-text-block").map((n: any) => n.getAttrByPath("icon/href") ?? ""),
      flows: g.getEdges().map((e: any) => e.getLabels()[0]?.attrs?.icon?.href ?? ""),
    };
  });
  expect(hrefs.nodes.length).toBeGreaterThan(0);
  for (const h of [...hrefs.nodes, ...hrefs.flows]) expect(h).toMatch(/^data:image\/png;base64,/);
  expect(JSON.stringify(await snapshot(page))).not.toContain("data:image/png");
  await expect(page.locator(".palette img").first()).toHaveAttribute("src", /^data:image\/png;base64,/);
});

test("TMT's menus and views: Design shows stencils, Analysis the threat list; panes toggle; Close Model", async ({ page }) => {
  await openExample(page);
  await expect(page.locator(".palette")).toBeVisible();
  await expect(page.getByTestId("threat-row")).toHaveCount(0); // Design view, as TMT opens

  await (await menu(page, "View", "Analysis View")).click();
  await expect(page.getByTestId("threat-row")).toHaveCount(38);
  await expect(page.locator(".palette")).toHaveCount(0);

  await (await menu(page, "View", "Stencils")).click(); // a pane can join either view
  await expect(page.locator(".palette")).toBeVisible();
  await expect(page.getByRole("menu", { name: "View" })).toHaveCount(0); // menus close after a pick

  await page.getByRole("button", { name: "Design View" }).click();
  await expect(page.getByTestId("threat-row")).toHaveCount(0);
  await page.getByTestId("threat-count").click(); // the status bar count opens the threat list
  await expect(page.getByTestId("threat-row")).toHaveCount(38);

  // keyboard: arrows move through items and across menus, Escape closes
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("menuitem", { name: "Undo" })).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("menu", { name: "View" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);

  page.once("dialog", (d) => d.accept()); // "Discard unsaved changes?" when there are any
  await (await menu(page, "File", "Close Model")).click();
  await expect(page.getByRole("button", { name: /Open the example/ })).toBeVisible();
});

test("the threat list has TMT's eleven columns, a filter on each, and its footer", async ({ page }) => {
  await openExample(page);
  await analysisView(page);
  const headers = page.getByRole("columnheader");
  await expect(headers).toHaveText(["ID", "Diagram", "Changed By", "Last Modified", "State", "Title", "Category",
    "Description", "Justification", "Interaction", "Priority"].map((h) => new RegExp(`^${h}`)));
  await expect(page.getByTestId("threat-row").first()).toContainText("Generated");
  await expect(page.getByTestId("threats-displayed")).toHaveText("38 Threats Displayed, 38 Total");

  await page.getByRole("button", { name: "Filter Category" }).click();
  await page.getByRole("menu", { name: "Filter Category" }).getByRole("button", { name: "Clear" }).click();
  await page.getByRole("menu", { name: "Filter Category" }).getByLabel("Spoofing").check();
  await page.keyboard.press("Escape");
  const spoofing = await page.getByTestId("threat-row").count();
  expect(spoofing).toBeGreaterThan(0);
  expect(spoofing).toBeLessThan(38);
  for (const row of await page.getByTestId("threat-row").all()) await expect(row).toContainText("Spoofing");
  await expect(page.getByTestId("threats-displayed")).toHaveText(`${spoofing} Threats Displayed, 38 Total`);

  await page.getByRole("button", { name: "Clear column filters" }).click();
  await expect(page.getByTestId("threat-row")).toHaveCount(38);
  const csv = await download(page, () => page.getByRole("button", { name: "Export Csv" }).click());
  expect(csv.name).toMatch(/\.csv$/);
});
