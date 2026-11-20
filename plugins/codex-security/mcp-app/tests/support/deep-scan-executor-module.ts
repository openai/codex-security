import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "../import-module.ts";

const executorSource = new URL(
  "../../src/deep-scan/executor.ts",
  import.meta.url,
);
export const executor = await importModule({
  define: {
    "import.meta.url": JSON.stringify(executorSource.href),
  },
  stdin: {
    // Expose internal worker checks only to the test fixtures.
    contents: `${await readFile(executorSource, "utf8")}
export { snapshotWorkerEnvironment, appendItemDiagnostic, bindCodexExecutable, verifyBoundCodexExecutable };
export { parseDeepScan } from "./response.js";`,
    loader: "ts",
    resolveDir: path.dirname(fileURLToPath(executorSource)),
    sourcefile: fileURLToPath(executorSource),
  },
});

export const verifyBoundCodexExecutable: (
  executable: {
    path: string;
    identity: import("node:fs").BigIntStats;
    sha256?: string;
  },
  signal?: AbortSignal,
) => Promise<void> = executor.verifyBoundCodexExecutable;

export const bindCodexExecutable: (
  environment: NodeJS.ProcessEnv,
  cwd: string,
  signal?: AbortSignal,
) => Promise<Parameters<typeof verifyBoundCodexExecutable>[0]> =
  executor.bindCodexExecutable;
