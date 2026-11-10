import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import * as auth from "../../sdk/typescript/dist/auth.js";
import {
  createIsolatedHome,
  resolveCodexCommand,
} from "../../sdk/typescript/dist/runtime.js";
import { preflightEval } from "../secret-discovery/harness.mts";
import { withEvalState } from "../secret-discovery/runtime.mts";
import { cases } from "./cases.mts";
import {
  prepareRoutingEval,
  routingSettings,
  runRoutingCase,
  summarizeRoutingCases,
  type Skill,
} from "./harness.mts";

const reports = join(import.meta.dirname, "reports");
await mkdir(reports, { recursive: true });
const directory = await mkdtemp(join(reports, "run-"));
const model = process.argv[2];
const sourceRoot = join(import.meta.dirname, "../..");
const git = (...args: string[]) =>
  execFileSync("git", args, { cwd: sourceRoot, encoding: "utf8" }).trim();
const packageVersion = async (file: string) =>
  JSON.parse(await readFile(join(sourceRoot, file), "utf8")).version as string;
const identity = {
  sourceRevision: git("rev-parse", "HEAD"),
  sourceDirty: git("status", "--porcelain", "--untracked-files=normal") !== "",
  packageVersion: await packageVersion("sdk/typescript/package.json"),
  codexSdkVersion: await packageVersion(
    "sdk/typescript/node_modules/@openai/codex-sdk/package.json",
  ),
  codexCliVersion: await packageVersion(
    "sdk/typescript/node_modules/@openai/codex/package.json",
  ),
  requestedModel: model ?? null,
  modelSelection: model
    ? "explicit"
    : "Codex default; SDK does not expose resolved model",
  scope:
    "repository-installed skill routing; workflow execution is not evaluated",
};
const results: Awaited<ReturnType<typeof runRoutingCase>>["report"][] = [];
let skills: Skill[] = [];
let interrupted = false;
let error: string | undefined;
const saveReport = () =>
  writeFile(
    join(directory, "report.json"),
    JSON.stringify(
      {
        ...identity,
        ...summarizeRoutingCases(results, { interrupted, error }),
        skills,
        results,
      },
      null,
      2,
    ) + "\n",
  );
console.log(`Eval artifacts: ${directory}`);
await saveReport();
try {
  await withEvalState(
    createIsolatedHome,
    (
      auth as unknown as typeof import("../../sdk/typescript/src/auth.js")
    ).configuredCodexHome(process.env),
    async ({ root, home, signal }) => {
      try {
        const prepared = await prepareRoutingEval(root);
        skills = prepared.skills;
        const codexPath = await realpath(resolveCodexCommand({}).command);
        const settings = await preflightEval(
          prepared,
          routingSettings(home, codexPath),
          signal,
        );
        const codex = new Codex(settings);
        for (const scenario of cases) {
          signal.throwIfAborted();
          const { events, report } = await runRoutingCase(
            prepared,
            scenario,
            codex,
            { model, signal },
          );
          await writeFile(
            join(directory, `${scenario.id}.jsonl`),
            events.map((event) => JSON.stringify(event)).join("\n") + "\n",
          );
          results.push(report);
          await saveReport();
          console.log(`${scenario.id}: ${report.passed ? "PASS" : "FAIL"}`);
        }
        process.exitCode = results.every((result) => result.passed) ? 0 : 1;
      } finally {
        interrupted = signal.aborted;
      }
    },
  );
} catch (failure) {
  error = failure instanceof Error ? failure.message : String(failure);
  throw failure;
} finally {
  // withEvalState can finish before its callback after an early signal.
  interrupted ||= process.exitCode === 130 || process.exitCode === 143;
  await saveReport();
}
