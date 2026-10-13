// Screenshots of the running app (default http://localhost:5173) for the docs and for review.
// Usage: node scripts/screenshots.mjs [outDir] [baseUrl]
import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";

const out = process.argv[2] ?? "../docs/img";
const base = process.argv[3] ?? "http://localhost:5173/";
mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ channel: "chrome" });
async function shot(name, scheme, act, { keepPointer = false, fullPage = false } = {}) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
  await page.addInitScript(() => localStorage.clear());
  await page.goto(base);
  await page.getByTestId("engine-status").getByText("Knowledge Base").waitFor({ timeout: 60_000 });
  const target = (await act(page)) ?? page;
  if (!keepPointer) await page.mouse.move(0, 0);
  await page.waitForTimeout(400);
  await target.screenshot({ path: `${out}/${name}.png`, fullPage });
  await page.close();
  console.log(`${out}/${name}.png`);
}
const example = async (page) => {
  await page.getByRole("button", { name: /Open the example/ }).click();
  await page.getByTestId("threat-count").getByText("38 threats").waitFor();
};

await shot("threatsketch-welcome", "light", async () => {});
await shot("threatsketch-threat", "light", async (page) => {
  await example(page);
  await page.getByTestId("threat-row").nth(1).click();
});
await shot("threatsketch-element", "light", async (page) => {
  await example(page);
  await page.locator('g.x6-node[data-cell-id="orders"]').click();
});
await shot("threatsketch-hover", "light", async (page) => {
  await example(page);
  await page.locator('g.x6-node[data-cell-id="payments"]').hover();
  await page.waitForTimeout(200);
  const box = await page.locator('g.x6-node[data-cell-id="payments"] [port-group="bottom"] circle').boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
}, { keepPointer: true });
await shot("threatsketch-triage", "light", async (page) => {
  await example(page);
  const rows = page.getByTestId("threat-row");
  const triage = async (i, state, priority, text) => {
    await rows.nth(i).click();
    await page.getByTestId("threat-state").selectOption(state);
    await page.getByTestId("threat-priority").selectOption(priority);
    await page.getByTestId("threat-justification").fill(text);
    await page.getByTestId("threat-justification").blur();
    await page.waitForTimeout(400);
  };
  await triage(0, "Mitigated", "High", "Customers sign in with a password and a one-time code.");
  await triage(2, "Needs Investigation", "Medium", "Check whether order changes are logged with the user ID.");
  await triage(3, "Not Applicable", "Low", "The web app runs behind a load balancer with health checks.");
  await triage(1, "Mitigated", "High", "All output is encoded by the template engine; a CSP blocks inline scripts.");
});
await shot("threatsketch-report", "light", async (page) => {
  await example(page);
  const [popup] = await Promise.all([page.waitForEvent("popup"), page.getByRole("button", { name: "Report" }).click()]);
  await popup.setViewportSize({ width: 1100, height: 900 });
  await popup.waitForLoadState();
  return popup;
});
await shot("threatsketch-report-full", "light", async (page) => {
  await example(page);
  const [popup] = await Promise.all([page.waitForEvent("popup"), page.getByRole("button", { name: "Report" }).click()]);
  await popup.setViewportSize({ width: 1100, height: 900 });
  await popup.waitForLoadState();
  return popup;
}, { fullPage: true });
await shot("threatsketch-dark", "dark", async (page) => {
  await example(page);
  await page.getByTestId("threat-row").nth(0).click();
});
await browser.close();
