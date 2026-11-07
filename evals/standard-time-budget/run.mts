import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  bundledPluginRoot,
  createIsolatedHome,
} from "../../sdk/typescript/dist/runtime.js";
import {
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "../../sdk/typescript/dist/version.js";
import { withEvalState } from "../secret-discovery/runtime.mts";
import {
  createStandardRunner,
  preflightStandardEval,
  snapshotCodexExecutable,
} from "./production.mts";
import { prepareStandardEval } from "./fixtures.mts";
import {
  runComparison,
  snapshotEvaluator,
  snapshotFiles,
  validateExperiment,
} from "./experiment.mts";
import { summarizeRuns } from "./summary.mts";

const config = validateExperiment(
  JSON.parse(
    await readFile(
      process.argv[2] ?? new URL("./experiment.json", import.meta.url),
      "utf8",
    ),
  ),
);
preflightStandardEval(process.env, config.budgetMinutes);
const codexExecutable = await snapshotCodexExecutable(process.env);
const pluginRoot = await bundledPluginRoot();
const reports = fileURLToPath(new URL("./reports/", import.meta.url));
await mkdir(reports, { recursive: true });
const reportDirectory = await mkdtemp(join(reports, "run-"));
const saveJson = (path: string, value: unknown) =>
  writeFile(path, JSON.stringify(value, null, 2) + "\n");
console.log(`Eval artifacts: ${reportDirectory}`);
await withEvalState(
  createIsolatedHome,
  undefined,
  async ({ root, home, signal }) => {
    const prepared = await prepareStandardEval(root, pluginRoot);
    await saveJson(join(reportDirectory, "experiment.json"), {
      ...config,
      reasoningEffort: "xhigh",
      execution: "CodexSecurity.run Standard production pipeline",
      order: "alternating baseline-first and time-aware-first pairs",
      evaluator: await snapshotEvaluator(),
      source: await snapshotFiles(prepared.repo),
      plugin: await snapshotFiles(pluginRoot),
      sdk: await snapshotFiles(
        fileURLToPath(new URL("../../sdk/typescript/dist/", import.meta.url)),
      ),
      packageVersions: {
        "@openai/codex-security": VERSION,
        "@openai/codex-sdk": CODEX_SDK_VERSION,
        "@openai/codex": CODEX_EXECUTABLE_VERSION,
      },
      codexExecutable,
    });
    await saveJson(join(reportDirectory, "fixture.json"), prepared.fixture);
    const records = await runComparison({
      prepared,
      config,
      signal,
      run: createStandardRunner({
        stateRoot: join(root, "states"),
        outputRoot: reportDirectory,
        environment: { ...process.env, CODEX_HOME: home },
      }),
      onStart: async (record) => {
        const directory = join(
          reportDirectory,
          `pair-${record.pair}-${record.variant}`,
        );
        await mkdir(directory);
        console.log(`Pair ${record.pair}/${config.pairs}: ${record.variant}`);
      },
      onResult: async (record, semanticResult, completedRecords, prompt) => {
        const directory = join(
          reportDirectory,
          `pair-${record.pair}-${record.variant}`,
        );
        if (prompt !== undefined)
          await writeFile(join(directory, "prompt.txt"), prompt);
        if (semanticResult !== undefined) {
          await saveJson(join(directory, "result.json"), semanticResult);
        }
        await saveJson(join(directory, "report.json"), record);
        await saveJson(join(reportDirectory, "runs.json"), completedRecords);
        await saveJson(
          join(reportDirectory, "summary.json"),
          summarizeRuns(completedRecords),
        );
        console.log(
          `${record.variant}: ${record.status}, ${(record.elapsedMs / 1000).toFixed(1)}s`,
        );
      },
    });
    console.log(JSON.stringify(summarizeRuns(records), null, 2));
    process.exitCode = records.some((record) => record.status === "failed")
      ? 1
      : 0;
  },
);
