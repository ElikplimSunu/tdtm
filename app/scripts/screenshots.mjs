// Screenshots of the running app (default http://localhost:5173) for the docs and for review.
// Usage: node scripts/screenshots.mjs [outDir] [baseUrl]
import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";

const out = process.argv[2] ?? "../docs/img";
const base = process.argv[3] ?? "http://localhost:5173/";
mkdirSync(out, { recursive: true });

const browser = await chromium.launch({ channel: "chrome" });
async function shot(name, scheme, act) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
  await page.addInitScript(() => localStorage.clear());
  await page.goto(base);
  await page.getByTestId("engine-status").getByText("Knowledge Base").waitFor({ timeout: 60_000 });
  await act(page);
  await page.mouse.move(0, 0);
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${out}/${name}.png` });
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
});
await shot("threatsketch-dark", "dark", async (page) => {
  await example(page);
  await page.getByTestId("threat-row").nth(0).click();
});
await browser.close();
