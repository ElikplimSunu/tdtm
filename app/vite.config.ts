import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vitest/config";

// BASE is "/tdtm/" for GitHub Pages, "/" elsewhere (dev, tests, the desktop app).
export default defineConfig({
  base: process.env.BASE ?? "/",
  plugins: [svelte()],
  optimizeDeps: { exclude: ["pyodide"] },
  worker: { format: "es" },
  build: { target: "es2022", chunkSizeWarningLimit: 1200 },
  server: { port: 5173, strictPort: true },
  test: { include: ["tests/unit/**/*.test.ts"] },
});
