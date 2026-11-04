import { readdirSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { initializeProvider } from "./triage-provider.mts";

const promptfooDist = path.resolve(
  import.meta.dirname,
  "../node_modules/promptfoo/dist/src",
);

// Pinned Promptfoo 0.124.1 bundles separate native classes for the CLI, viewer,
// and public API. Initialize every ESM copy before providers are constructed,
// including viewer replay, which does not run saved extension hooks.
for (const filename of readdirSync(promptfooDist)) {
  if (!filename.startsWith("codex-sdk-") || !filename.endsWith(".js")) continue;
  const module = await import(
    pathToFileURL(path.join(promptfooDist, filename)).href
  );
  for (const Provider of Object.values(module)) {
    if (
      typeof Provider === "function" &&
      typeof Provider.prototype?.getCodexInstanceForTurn === "function" &&
      typeof Provider.prototype?.callApiInternal === "function"
    ) {
      initializeProvider(Provider.prototype);
    }
  }
}
