import { mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import { configuredCodexHome } from "../../sdk/typescript/dist/auth.js";
import {
  createIsolatedHome,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import {
  codexSettings,
  preflightEval,
  prepareEval,
  runPreparedEval,
} from "./harness.mjs";
import { createEvalHome, withEvalState } from "./runtime.mjs";

const reports = fileURLToPath(new URL("./reports/", import.meta.url));
await mkdir(reports, { recursive: true });
const reportDirectory = await mkdtemp(join(reports, "run-"));
console.log(`Eval artifacts: ${reportDirectory}`);
await withEvalState(
  () => createEvalHome(createIsolatedHome, configuredCodexHome(process.env)),
  async ({ root, home, signal }) => {
    const prepared = await prepareEval(root);
    const codexPath = await realpath(resolveCodexCommand({}).command);
    const settings = await preflightEval(
      prepared,
      codexSettings(home, codexPath),
      signal,
    );
    const codex = new Codex(settings);
    const { report, semanticResult } = await runPreparedEval(prepared, codex, {
      model: process.argv[2],
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
