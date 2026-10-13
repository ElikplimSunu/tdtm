// New versions. The desktop app checks GitHub Releases for a signed update; the web app's
// service worker fetches a new build in the background. Either way the user decides when to
// switch, so nothing reloads in the middle of their work.
import { isDesktop } from "./files";

export type Update = { version: string; apply: () => Promise<void> };

/** A newer desktop release, if there is one (null offline, in the browser, or when current). */
export async function checkDesktop(): Promise<Update | null> {
  if (!isDesktop) return null;
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (!update) return null;
    return {
      version: update.version,
      apply: async () => {
        await update.downloadAndInstall();
        const { relaunch } = await import("@tauri-apps/plugin-process");
        await relaunch();
      },
    };
  } catch {
    return null; // offline, or the release feed is unreachable: try again next start
  }
}

/** Calls `ready` when the web app has downloaded a new version and can switch to it. */
export async function watchWeb(ready: (u: Update) => void) {
  if (isDesktop || !("serviceWorker" in navigator)) return;
  const { registerSW } = await import("virtual:pwa-register");
  const update = registerSW({
    onNeedRefresh: () => ready({ version: "", apply: () => update(true) }),
  });
}
