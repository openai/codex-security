import { mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as auth from "../../sdk/typescript/dist/auth.js";
import {
  createIsolatedHome,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import {
  codexSettings,
  preflightEval,
  prepareEval,
  runPreparedEval,
} from "./harness.mts";
import { withEvalState } from "./runtime.mts";

const { values, positionals } = parseArgs({
  options: { "external-token-scanner": { type: "boolean", default: false } },
  allowPositionals: true,
});
if (positionals.length > 1) throw new Error("Expected at most one model name");
const reports = join(import.meta.dirname, "reports/");
await mkdir(reports, { recursive: true });
const reportDirectory = await mkdtemp(join(reports, "run-"));
console.log(`Eval artifacts: ${reportDirectory}`);
await withEvalState(
  createIsolatedHome,
  (
    auth as unknown as typeof import("../../sdk/typescript/src/auth.js")
  ).configuredCodexHome(process.env),
  async ({ root, home, signal }) => {
    const prepared = await prepareEval(root, {
      externalTokenScanner: values["external-token-scanner"],
    });
    const codexPath = await realpath(resolveCodexCommand({}).command);
    const settings = await preflightEval(
      prepared,
      codexSettings(home, codexPath),
      signal,
    );
    const codex = new Codex(settings);
    const { report, semanticResult } = await runPreparedEval(prepared, codex, {
      model: positionals[0],
      signal,
    });
    await writeFile(
      join(reportDirectory, "result.json"),
      JSON.stringify(semanticResult, null, 2) + "\n",
    );
    await writeFile(
      join(reportDirectory, "report.json"),
      JSON.stringify(report, null, 2) + "\n",
    );
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.passed ? 0 : 1;
  },
);
