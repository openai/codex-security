import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isRecord } from "../../sdk/typescript/src/record.ts";
import { commandArgs, fixture, gradeCommand, readFixture } from "./command.mts";

if (process.argv.length > 2) {
  console.error(
    "Usage: run.mts (for caller-scoped cases, use run-skill-baseline.mts)",
  );
  process.exit(
    process.argv[2] === "--help" && process.argv.length === 3 ? 0 : 2,
  );
}

const root = join(import.meta.dirname, "../..");
const git = (...args: string[]) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
const binary = join(root, "sdk/typescript/bin/codex-security.mjs");
const reports = join(import.meta.dirname, "reports");
await mkdir(reports, { recursive: true });
const directory = await mkdtemp(join(reports, "command-"));
const base = {
  argv: [process.execPath, binary, ...commandArgs],
  sourceRevision: git("rev-parse", "HEAD"),
  sourceDirty: git("status", "--porcelain") !== "",
};
const repo = await mkdtemp(join(tmpdir(), "checkout-"));
console.log(`Eval artifacts: ${directory}`);
let stdout = "";
let stderr = "";
let started: number | undefined;
let analysisMs: number | undefined;
let commandExitCode: number | null = null;
let commandSignal: NodeJS.Signals | null = null;
let snapshotSha256: string | undefined;
let answer: unknown;
let grade: ReturnType<typeof gradeCommand> | undefined;
let error: string | undefined;
try {
  await cp(fixture, repo, { recursive: true });
  const input = await readFixture(repo);
  snapshotSha256 = input.sha256;
  git("-C", repo, "init", "--quiet");
  git("-C", repo, "add", "--force", "--", ...input.files.keys());
  started = performance.now();
  const child = spawn(process.execPath, [binary, ...commandArgs], {
    cwd: repo,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
    stderr += chunk;
  });
  [commandExitCode, commandSignal] = (await once(child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  analysisMs = Math.round(performance.now() - started);
  if (commandExitCode !== 0)
    throw new Error(
      `Command exited with ${commandSignal ?? commandExitCode}: ${stderr || stdout}`,
    );
  answer = JSON.parse(stdout);
  grade = gradeCommand(answer, input.files);
  console.log(grade.pass ? "PASS" : JSON.stringify(grade, null, 2));
  if (!grade.pass) process.exitCode = 1;
} catch (failure) {
  error = failure instanceof Error ? failure.message : String(failure);
  console.error(error);
  process.exitCode = commandExitCode || 1;
} finally {
  await rm(repo, { recursive: true, force: true });
  const report = {
    ...base,
    snapshotSha256,
    analysisMs:
      analysisMs ??
      (started === undefined ? null : Math.round(performance.now() - started)),
    commandExitCode,
    commandSignal,
    error,
    grade,
    answer,
    usage: isRecord(answer) ? (answer.usage ?? null) : null,
    stderr,
    ...(error === undefined ? {} : { stdout }),
  };
  await writeFile(
    join(directory, "report.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
}
