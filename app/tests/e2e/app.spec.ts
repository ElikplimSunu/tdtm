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

/** What the tdtm CLI writes for `model` (a path), as parsed JSON. */
function cliAnalyze(model: string) {
  const dir = mkdtempSync(join(tmpdir(), "threatsketch-"));
  const copy = join(dir, "model.json");
  copyFileSync(model, copy);
  execFileSync("uv", ["run", "--project", REPO, "tdtm", "analyze", copy], { stdio: "pipe" });
  return JSON.parse(readFileSync(copy, "utf8"));
}

async function openExample(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: /explore an example/ }).click();
  await expect(page.getByTestId("threat-count")).toHaveText("38 threats");
}

const snapshot = (page: Page) => page.evaluate(() => JSON.parse(JSON.stringify((window as any).threatsketch.editor.snapshot())));
const count = (page: Page, sel: string) => page.locator(sel).count();

async function download(page: Page, click: () => Promise<void>) {
  const [d] = await Promise.all([page.waitForEvent("download"), click()]);
  return { name: d.suggestedFilename(), text: readFileSync((await d.path())!, "utf8") };
}

async function newModel(page: Page) {
  await page.goto("/");
  await expect(page.getByTestId("engine-status")).toContainText("tdtm", { timeout: 30_000 });
  await page.getByRole("button", { name: "New threat model" }).click();
  await expect(page.locator(".canvas svg").first()).toBeVisible();
}

async function plus(page: Page, cellId: string, side: string) {
  const node = page.locator(`g.x6-node[data-cell-id="${cellId}"]`);
  await node.hover({ force: true });
  return node.locator(`[port-group="${side}"] circle`);
}

test("opens the example: TMT's 38 threats, drawn TMT-style", async ({ page }) => {
  await openExample(page);
  expect(await count(page, ".x6-node")).toBe(6);
  expect(await count(page, ".x6-edge")).toBe(7);
  await expect(page.getByTestId("threat-row")).toHaveCount(38);
  // trust boundaries are red dashed, as in TMT; open-threat outlines are not drawn
  const box = page.locator('g[data-cell-id="backend"] rect').first();
  await expect(box).toHaveAttribute("stroke", "#d13438");
  await expect(page.locator('g[data-cell-id="webapp"] circle').first()).toHaveAttribute("stroke", "#1f2328");
});

test("saving writes exactly what the tdtm CLI writes", async ({ page }) => {
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

test("draw from scratch: palette, click + to connect, threats appear as you draw", async ({ page }) => {
  await newModel(page);
  await page.getByRole("button", { name: /Generic External Interactor/ }).click();
  await page.getByRole("button", { name: /^Generic Process/ }).click();
  expect(await count(page, ".x6-node")).toBe(2);
  const [actor, proc] = (await snapshot(page)).detail.diagrams[0].cells.map((c: any) => c.id);

  await (await plus(page, actor, "right")).click();
  await expect(page.locator(".x6-edge")).toHaveCount(1);
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
  expect(flow.source).toEqual({ cell: proc }); // attached to the shape, not to the "+"
  expect(flow.target).toEqual({ cell: store });
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
  await page.goto("/");
  await expect(page.getByTestId("engine-status")).toContainText("tdtm", { timeout: 30_000 });
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.getByRole("button", { name: /Open a file/ }).click()]);
  await chooser.setFiles(SMALL_TM7);
  await expect(page.getByTestId("threat-row").first()).toBeVisible();
  const expected = JSON.parse(execFileSync("uv", ["run", "--project", REPO, "python", "-c",
    `import json,sys; from tdtm.tm7 import import_tm7; from tdtm import api; print(json.dumps(len(api.analyze(import_tm7(sys.argv[1])[0])["threats"])))`, SMALL_TM7]).toString());
  await expect(page.getByTestId("threat-row")).toHaveCount(expected);

  await page.getByRole("button", { name: "Export" }).click();
  const tm7 = await download(page, () => page.getByRole("menuitem", { name: /Microsoft TMT model/ }).click());
  expect(tm7.name).toBe("small.tm7");
  expect(tm7.text).toContain("<ThreatModel");
  await page.getByRole("button", { name: "Export" }).click();
  const html = await download(page, () => page.getByRole("menuitem", { name: /Threat report/ }).click());
  expect(html.text).toContain("Threat Model Summary");
  await page.getByRole("button", { name: "Export" }).click();
  const csv = await download(page, () => page.getByRole("menuitem", { name: /Threat list/ }).click());
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
  await page.getByRole("button", { name: "New diagram" }).click();
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

test("private: the Mobile Banking model from real TMT gives TMT's 54 threats", async ({ page }) => {
  test.skip(!existsSync(PRIVATE_TM7), "coursework model not on this machine");
  await page.goto("/");
  await expect(page.getByTestId("engine-status")).toContainText("tdtm", { timeout: 30_000 });
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.getByRole("button", { name: /Open a file/ }).click()]);
  await chooser.setFiles(PRIVATE_TM7);
  await expect(page.getByTestId("threat-count")).toHaveText("54 threats");
});

test("works offline after the first visit", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.getByTestId("engine-status")).toContainText("tdtm");
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.waitForFunction(() => !!navigator.serviceWorker.controller, null, { timeout: 30_000 }).catch(() => page.reload());
  await page.evaluate(async () => {
    const keys = await caches.keys();
    const all = (await Promise.all(keys.map(async (k) => (await caches.open(k)).keys()))).flat();
    if (!all.some((r) => r.url.includes("pyodide.asm.wasm"))) throw new Error("engine not cached");
  });
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByTestId("engine-status")).toContainText("tdtm");
  await page.getByRole("button", { name: /explore an example/ }).click();
  await expect(page.getByTestId("threat-count")).toHaveText("38 threats");
});
