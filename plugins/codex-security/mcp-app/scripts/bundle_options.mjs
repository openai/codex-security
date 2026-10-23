import { createRequire } from "node:module";
import { dirname } from "node:path";

// Source tests and shipped runtimes use the same CommonJS and dependency resolution.
export const mcpBundleOptions = {
  bundle: true,
  alias: {
    zod: dirname(createRequire(import.meta.url).resolve("zod/package.json")),
  },
  banner: {
    js: "const __codexSecurityModuleUrl = require('node:url').pathToFileURL(__filename).href;",
  },
  define: { "import.meta.url": "__codexSecurityModuleUrl" },
  external: ["fsevents"],
  format: "cjs",
  loader: { ".md": "text" },
  logOverride: { "empty-import-meta": "silent" },
  platform: "node",
  target: "node20",
};
