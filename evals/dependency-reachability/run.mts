import { spawn } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { gitOutput } from "../../sdk/typescript/dist/targets.js";
import { isRecord } from "../../sdk/typescript/src/record.ts";
import {
  cases,
  challengeCases,
  type ReachabilityCase,
  type Repository,
} from "./cases.mts";
import {
  cve as smokeCve,
  fixture,
  gradeCommand,
  readFixture,
} from "./command.mts";
import { gradeCommandCase } from "./grade-command-case.mts";
import { prepareSnapshot, snapshotDigest } from "./prepare.mts";

const smoke = { id: "mixed-services", cve: smokeCve } as const;
const { values } = parseArgs({
  options: {
    repos: { type: "string" },
    case: { type: "string" },
    suite: { type: "string" },
    jobs: { type: "string", default: "1" },
    help: { type: "boolean", short: "h" },
  },
});
const usage =
  "Usage: run.mts --repos DIR [--case ID] [--suite SUITE] [--jobs N]\n       run.mts --case mixed-services";
if (values.help) {
  console.log(usage);
  console.log(cases.map((c) => c.id).join(", "));
  process.exit(0);
}
const selected =
  values.case === smoke.id && !values.suite
    ? [smoke]
    : (values.suite === "challenge"
        ? challengeCases
        : cases.filter((c) => !values.suite || c.suite === values.suite)
      ).filter((c) => !values.case || c.id === values.case);
if (!selected.length)
  throw new Error("No matching dependency reachability cases");
if (!values.repos && selected.some((c) => "stage" in c)) throw new Error(usage);
const jobs = Number(values.jobs);
if (!Number.isSafeInteger(jobs) || jobs < 1)
  throw new Error("--jobs must be a positive integer");
const clones: Partial<Record<Repository, string>> = {};
for (const c of selected) {
  if (!("stage" in c)) continue;
  for (const slug of [
    c.repository,
    ...c.stage.flatMap((f) => (f.kind === "git" ? [f.repository] : [])),
  ]) {
    clones[slug] = resolve(values.repos!, slug);
  }
}

const sourceRoot = join(import.meta.dirname, "../..");
const binary = join(sourceRoot, "sdk/typescript/bin/codex-security.mjs");
const reports = join(import.meta.dirname, "reports");
await mkdir(reports, { recursive: true });
const directory = await mkdtemp(join(reports, "command-"));
const sourceRevision = (
  await gitOutput(sourceRoot, ["rev-parse", "HEAD"])
).trim();
const sourceDirty = !!(
  await gitOutput(sourceRoot, ["status", "--porcelain"])
).trim();
console.log(`Eval artifacts: ${directory}`);

const controller = new AbortController();
process.once("SIGINT", () => {
  process.exitCode = 130;
  controller.abort("SIGINT");
});
process.once("SIGTERM", () => {
  process.exitCode = 143;
  controller.abort("SIGTERM");
});
const { signal } = controller;

type CaseGrade = { pass: boolean; errors: string[] };

async function runCase(c: ReachabilityCase | typeof smoke) {
  let root: string | undefined;
  const argv = [binary, "exploitability", "check", c.cve, "--json"];
  let snapshotSha256: string | undefined;
  let answer: unknown;
  let grade: CaseGrade | undefined;
  let stdout = "";
  let stderr = "";
  let commandExitCode: number | null = null;
  let commandSignal: NodeJS.Signals | null = null;
  let analysisMs: number | undefined;
  let error: string | undefined;
  try {
    root = await mkdtemp(join(tmpdir(), "checkout-"));
    let repo: string;
    let gradeAnswer: (output: unknown) => CaseGrade | Promise<CaseGrade>;
    if ("stage" in c) {
      repo = await prepareSnapshot(root, c, clones, signal);
      snapshotSha256 = await snapshotDigest(repo, c);
      gradeAnswer = (output) => gradeCommandCase(output, c, repo);
    } else {
      repo = join(root, "source");
      await cp(fixture, repo, { recursive: true });
      const input = await readFixture(repo);
      snapshotSha256 = input.sha256;
      gradeAnswer = (output) => gradeCommand(output, input.files);
    }
    await gitOutput(repo, ["init", "--quiet"], signal);
    // Index exactly the materialized files, including ignored installed-package
    // evidence. Keep upstream history, case names and the grading oracle outside.
    await writeFile(
      join(repo, ".git/info/attributes"),
      "* -filter -ident -text !eol !working-tree-encoding\n",
    );
    await gitOutput(repo, ["add", "--force", "--", "."], signal);
    await gitOutput(
      repo,
      [
        "-c",
        "user.name=Eval",
        "-c",
        "user.email=eval@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "Source snapshot",
      ],
      signal,
    );
    signal.throwIfAborted();
    const started = performance.now();
    const child = spawn(process.execPath, argv, {
      cwd: repo,
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
      stderr += chunk;
    });
    const stop = () => {
      child.kill(signal.reason === "SIGINT" ? "SIGINT" : "SIGTERM");
    };
    signal.addEventListener("abort", stop, { once: true });
    try {
      [commandExitCode, commandSignal] = (await once(child, "close")) as [
        number | null,
        NodeJS.Signals | null,
      ];
    } finally {
      signal.removeEventListener("abort", stop);
      analysisMs = Math.round(performance.now() - started);
    }
    if (commandExitCode !== 0)
      throw new Error(
        `Command exited with ${commandSignal ?? commandExitCode}: ${stderr || stdout}`,
      );
    answer = JSON.parse(stdout);
    grade = await gradeAnswer(answer);
  } catch (failure) {
    error = failure instanceof Error ? failure.message : String(failure);
  } finally {
    if (root) {
      try {
        await rm(root, { recursive: true, force: true });
      } catch (failure) {
        error = [error, String(failure)].filter(Boolean).join("\n");
      }
    }
  }
  return {
    id: c.id,
    cve: c.cve,
    revision: "stage" in c ? c.revision : null,
    argv: [process.execPath, ...argv],
    snapshotSha256,
    analysisMs,
    commandExitCode,
    commandSignal,
    answer,
    grade,
    usage: isRecord(answer) ? (answer.usage ?? null) : null,
    error,
    stderr,
    ...(error === undefined ? {} : { stdout }),
  };
}

const results: Awaited<ReturnType<typeof runCase>>[] = [];
const queue = selected.values();
async function worker() {
  for (const c of queue) {
    if (signal.aborted) break;
    const result = await runCase(c);
    results.push(result);
    await writeFile(
      join(directory, c.id + ".json"),
      JSON.stringify(result, null, 2) + "\n",
    );
    console.log(
      `${c.id}: ${result.error ? "ERROR" : result.grade?.pass ? "PASS" : "FAIL"} (${result.analysisMs ?? 0} ms)`,
    );
    if (result.error) console.error(result.error);
    else if (!result.grade?.pass) console.log(JSON.stringify(result.grade));
  }
}
await Promise.all(
  Array.from({ length: Math.min(jobs, selected.length) }, worker),
);
const ids = selected.map((c) => c.id);
results.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
const passed = results.filter((r) => !r.error && r.grade?.pass).length;
const report = {
  sourceRevision,
  sourceDirty,
  selected: ids,
  interrupted: signal.aborted ? signal.reason : null,
  complete: results.length === ids.length && !signal.aborted,
  passed,
  results,
};
await writeFile(
  join(directory, "report.json"),
  JSON.stringify(report, null, 2) + "\n",
);
console.log(`Passed ${passed}/${selected.length} cases`);
if (passed !== selected.length && !process.exitCode) process.exitCode = 1;
