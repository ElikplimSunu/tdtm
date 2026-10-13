import { expect, test } from "@playwright/test";

test("the engine loads in the browser and analyses the example", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("engine")).toHaveText("ready");
  await expect(page.getByTestId("count")).toHaveText("38");
});
