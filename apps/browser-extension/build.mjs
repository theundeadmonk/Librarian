import { build } from "esbuild";
import { fileURLToPath } from "node:url";

const shared = { absWorkingDir: fileURLToPath(new URL(".", import.meta.url)),
  tsconfig: "tsconfig.json", bundle: true, platform: "browser",
  target: ["chrome106", "edge106"], legalComments: "none" };

// Bundled content scripts run in Chromium's isolated world without exposing
// extension modules to page imports or adding web-accessible resources.
await Promise.all([
  build({ ...shared, entryPoints: ["./src/background.ts"], outfile: "dist/background.js", format: "esm" }),
  build({ ...shared, entryPoints: ["./src/content.ts"], outfile: "dist/content.js", format: "iife" }),
]);
