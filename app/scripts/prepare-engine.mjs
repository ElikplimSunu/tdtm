// Puts the threat engine where the app serves it from: tdtm's wheel, built from this repo, in
// public/engine/, and the Pyodide runtime in public/pyodide/. Both folders are generated.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = mkdtempSync(join(tmpdir(), "tdtm-wheel-"));
execFileSync("uv", ["build", "--wheel", "--out-dir", out, ".."], { cwd: app, stdio: "inherit" });
const wheel = readdirSync(out).find((f) => f.endsWith(".whl"));
mkdirSync(join(app, "public/engine"), { recursive: true });
copyFileSync(join(out, wheel), join(app, "public/engine/tdtm.whl"));
rmSync(out, { recursive: true });

const pyodide = join(app, "node_modules/pyodide");
mkdirSync(join(app, "public/pyodide"), { recursive: true });
for (const f of ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]) {
  copyFileSync(join(pyodide, f), join(app, "public/pyodide", f));
}
mkdirSync(join(app, "public/examples"), { recursive: true });
copyFileSync(join(app, "../examples/online-shop.json"), join(app, "public/examples/online-shop.json"));
console.log(`engine ready: ${wheel} + Pyodide runtime`);
