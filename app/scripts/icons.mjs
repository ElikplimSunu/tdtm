import { chromium } from "@playwright/test";
import { readFileSync } from "node:fs";
const [svgPath, outDir] = process.argv.slice(2);
const svg = readFileSync(svgPath, "utf8");
const b = await chromium.launch({ channel: "chrome" });
for (const size of [1024, 512, 192, 180]) {
  const p = await b.newPage({ viewport: { width: size, height: size } });
  await p.setContent(`<html><body style="margin:0;background:transparent">${svg.replace("<svg ", `<svg width="${size}" height="${size}" `)}</body></html>`);
  await p.screenshot({ path: `${outDir}/icon-${size}.png`, omitBackground: true });
  await p.close();
}
await b.close();
