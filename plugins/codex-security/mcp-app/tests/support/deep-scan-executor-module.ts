import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "../import-module.ts";

const executorSource = new URL(
  "../../src/deep-scan/executor.ts",
  import.meta.url,
);
export const executor = await importModule({
  banner: {
    js: `const require = process.getBuiltinModule("node:module").createRequire(${JSON.stringify(executorSource.href)});`,
  },
  define: {
    "import.meta.url": JSON.stringify(executorSource.href),
  },
  stdin: {
    // Expose internal worker checks only to the test fixtures.
    contents: `${await readFile(executorSource, "utf8")}
export { snapshotWorkerEnvironment, appendItemDiagnostic, verifyBoundCodexExecutable };
export * from "./recovery-settings.js";
export { WorkbenchDeepScanStore } from "./store.js";
export { parseDeepScan } from "./response.js";`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource),
  },
});

export const verifyBoundCodexExecutable: (executable: {
  path: string;
  identity: import("node:fs").BigIntStats;
}) => Promise<void> = executor.verifyBoundCodexExecutable;
