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
       (--prepare-only | --cli PATH | --skill-baseline | --grade-existing RESULTS_DIR) [--jobs N] [--model MODEL] [--out NEW_DIR]
       For --skill-baseline, append -- COMMAND [ARG...] to evaluate a local adapter.
Fetch verified public inputs using: python3 upstream/assets.py fetch CACHE`;
const separator = process.argv.indexOf("--", 2);
const adapter = separator < 0 ? [] : process.argv.slice(separator + 1);
const { values } = parseArgs({
  args: process.argv.slice(2, separator < 0 ? undefined : separator),
  options: {
    cache: { type: "string" },
    suite: { type: "string" },
    case: { type: "string" },
    cli: { type: "string" },
    jobs: { type: "string", default: "1" },
    "skill-baseline": { type: "boolean" },
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
const jobs = Number(values.jobs);
if (
  !Number.isSafeInteger(jobs) ||
  jobs < 1 ||
  (separator >= 0 &&
    (!adapter.length || !values["skill-baseline"] || values.model)) ||
  !values.cache ||
  [
    values["prepare-only"],
    values.cli,
    values["skill-baseline"],
    values["grade-existing"],
  ].filter(Boolean).length !== 1
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
let saved = Promise.resolve();
console.log("Results: " + out);
async function runCase(scenario, runSkill) {
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
    if (runSkill) {
      result.status = "execution_error";
      const { runBaseline } = await import("./upstream/skill-baseline.mjs");
      const start = performance.now();
      const { answer, grade, usage, promptSha256 } = await runBaseline(
        runSkill,
        scenario,
        repo,
        sha,
      );
      result.elapsedMs = Math.round(performance.now() - start);
      Object.assign(result, {
        grade,
        usage,
        promptSha256,
        evaluator: adapter.length ? "adapter" : "attack-path-analysis",
      });
      await jsonFile(join(dest, "answer.json"), answer);
      result.status = grade.pass ? "passed" : "grade_error";
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
  saved = saved.then(() =>
    writeFile(
      join(out, "results.json"),
      JSON.stringify(
        {
          model: values.model ?? null,
          results: selected.flatMap((c) =>
            results.filter((r) => r.id === c.id),
          ),
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    ),
  );
  await saved;
}
async function runSelected(runSkill) {
  const queue = selected.values();
  async function worker() {
    for (const scenario of queue) {
      if (abort.signal.aborted) return;
      await runCase(scenario, runSkill);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(jobs, selected.length) }, worker),
  );
}
if (adapter.length) {
  const { runAdapter } = await import("./upstream/adapter.mjs");
  await runSelected((repo, prompt) =>
    runAdapter(adapter, repo, prompt, abort.signal),
  );
} else if (values["skill-baseline"]) {
  const { withModel } = await import("./model.mts");
  await withModel(values.model, (state) => runSelected(state.run));
} else {
  await runSelected();
}
if (
  results.length !== selected.length ||
  results.some(
    (r) => r.status !== (values["prepare-only"] ? "prepared" : "passed"),
  )
)
  process.exitCode ||= 1;
