import { svelte } from "@sveltejs/vite-plugin-svelte";
import { VitePWA } from "vite-plugin-pwa";
import { defineConfig } from "vitest/config";

// BASE is "/tdtm/" for GitHub Pages, "/" elsewhere (dev, tests, the desktop app).
export default defineConfig({
  base: process.env.BASE ?? "/",
  plugins: [
    svelte(),
    // Installable, and works offline after the first visit: the engine (Pyodide + tdtm, ~13 MB)
    // is cached with the app. Not in the desktop app, which ships the files itself.
    VitePWA({
      disable: !!process.env.TAURI_ENV_PLATFORM,
      registerType: "prompt", // the app asks before switching (lib/updates.ts)
      injectRegister: false,
      includeAssets: ["favicon.svg", "apple-touch-icon.png"],
      manifest: {
        name: "ThreatSketch",
        short_name: "ThreatSketch",
        description: "Draw a data-flow diagram and get Microsoft TMT's STRIDE threats as you draw.",
        theme_color: "#4f6bed",
        background_color: "#f4f5f7",
        display: "standalone",
        icons: [
          { src: "icon-192.png", sizes: "192x192", type: "image/png" },
          { src: "icon-512.png", sizes: "512x512", type: "image/png" },
          { src: "icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
        file_handlers: [{ action: "./", accept: { "application/json": [".json"], "application/xml": [".tm7"] } }],
      },
      workbox: {
        globPatterns: ["**/*.{js,mjs,css,html,svg,png,wasm,zip,whl,json}"],
        maximumFileSizeToCacheInBytes: 16 * 1024 * 1024,
      },
    }),
  ],
  optimizeDeps: { exclude: ["pyodide"] },
  worker: { format: "es" },
  build: { target: "es2022", chunkSizeWarningLimit: 1200 },
  server: { port: 5173, strictPort: true },
  test: { include: ["tests/unit/**/*.test.ts"] },
});
