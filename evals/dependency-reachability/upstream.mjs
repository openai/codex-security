import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { invokeCli, writeCliLogs } from "./cli.mjs";
import { commitFixture, jsonFile } from "./fixtures.mjs";
import { cases } from "./upstream/cases.mjs";
import { gradeSnapshot, validateSnapshot } from "./upstream/grade.mjs";

const usage = `Usage: node upstream.mjs --cache DIR [--suite mailparser|pillow|backstage] [--case ID]
       (--prepare-only | --cli PATH | --grade-existing RESULTS_DIR) [--model MODEL] [--out NEW_DIR]
Fetch verified public inputs using: python3 upstream/assets.py fetch CACHE`;
const { values } = parseArgs({
  options: {
    cache: { type: "string" },
    suite: { type: "string" },
    case: { type: "string" },
    cli: { type: "string" },
    out: { type: "string" },
    model: { type: "string" },
    "prepare-only": { type: "boolean" },
    "grade-existing": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});
if (values.help) {
  console.log(usage + "\nCases: " + cases.map((c) => c.id).join(", "));
  process.exit(0);
}
if (
  !values.cache ||
  [values["prepare-only"], values.cli, values["grade-existing"]].filter(Boolean)
    .length !== 1
)
  throw Error(usage);
const selected = cases.filter(
  (c) =>
    (!values.suite || c.suite === values.suite) &&
    (!values.case || c.id === values.case),
);
if (!selected.length) throw Error(usage);
const cli = values.cli && (await realpath(resolve(values.cli)));
const cache = resolve(values.cache);
const out = values.out
  ? resolve(values.out)
  : await mkdtemp(join(tmpdir(), "upstream-results-"));
if (values.out) await mkdir(out, { mode: 0o700 });
const abort = new AbortController();
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    process.exitCode = signal === "SIGINT" ? 130 : 143;
    abort.abort();
  });
const results = [];
console.log("Results: " + out);
for (const scenario of selected) {
  if (abort.signal.aborted) break;
  const scratch = await mkdtemp(join(tmpdir(), "upstream-eval-"));
  const dest = join(out, scenario.id);
  await mkdir(dest, { mode: 0o700 });
  const result = {
    id: scenario.id,
    suite: scenario.suite,
    cve: scenario.cve,
    upstreamRevision: scenario.revision,
  };
  try {
    const repo = execFileSync(
      "python3",
      [
        join(import.meta.dirname, "upstream/assets.py"),
        "materialize",
        cache,
        join(scratch, "tree"),
      ],
      {
        input: JSON.stringify({
          repository: scenario.repository,
          revision: scenario.revision,
          stage: scenario.stage,
        }),
        encoding: "utf8",
      },
    ).trimEnd();
    const sha = commitFixture(repo);
    result.sourceSha = sha;
    result.evidence = validateSnapshot(scenario, repo, sha);
    result.status = "prepared";
    if (values["grade-existing"]) {
      result.status = "grade_error";
      const original = join(
        resolve(values["grade-existing"]),
        scenario.id,
        "report.json",
      );
      const report = JSON.parse(await readFile(original, "utf8"));
      result.grade = gradeSnapshot(report, scenario, repo, sha);
      result.status = result.grade.pass ? "passed" : "grade_error";
    }
    if (cli) {
      const config = join(scratch, "scope.json");
      await jsonFile(config, {
        exploitability: { scope: { instructions: scenario.callerScope } },
      });
      const reportFile = join(scratch, "answer.json");
      const args = [
        "check",
        scenario.cve,
        "--config",
        config,
        "--report-file",
        reportFile,
        "--json",
      ];
      if (values.model) args.push("--model", values.model);
      const start = performance.now();
      const proc = await invokeCli(cli, repo, args, { signal: abort.signal });
      result.elapsedMs = Math.round(performance.now() - start);
      await writeCliLogs(dest, proc);
      if (proc.code !== 0) {
        result.status = "execution_error";
        result.exitCode = proc.code;
        result.signal = proc.signal;
      } else {
        result.status = "grade_error";
        const reportBytes = await readFile(reportFile);
        await writeFile(join(dest, "report.json"), reportBytes, {
          mode: 0o600,
          flag: "wx",
        });
        const report = JSON.parse(reportBytes.toString("utf8"));
        assert.deepEqual(report, JSON.parse(proc.stdout.toString("utf8")));
        result.grade = gradeSnapshot(report, scenario, repo, sha);
        result.status = result.grade.pass ? "passed" : "grade_error";
      }
    }
  } catch (error) {
    result.status =
      result.status === "grade_error" ? "grade_error" : "execution_error";
    result.error = error.message;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
  console.log(scenario.id + ": " + result.status);
  results.push(result);
  await writeFile(
    join(out, "results.json"),
    JSON.stringify({ model: values.model ?? null, results }, null, 2) + "\n",
    { mode: 0o600 },
  );
}
if (
  results.length !== selected.length ||
  results.some(
    (r) => r.status !== (values["prepare-only"] ? "prepared" : "passed"),
  )
)
  process.exitCode ||= 1;
