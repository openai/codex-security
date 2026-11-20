import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { invokeCli, writeCliLogs } from "./cli.mjs";
import { commitFixture, jsonFile, sha256 } from "./fixtures.mjs";
import { reviewerMode, sourceReader, verifyClaimCitations } from "./grade.mjs";
import { cases as pinnedCases, originalCases } from "./upstream/cases.mjs";
import { checkoutOf } from "./upstream/checkout.mjs";
import { compareRuns } from "./upstream/compare.mjs";
import { gradeSnapshot, validateSnapshot } from "./upstream/grade.mjs";

const separator = process.argv.indexOf("--", 2);
const adapter = separator < 0 ? [] : process.argv.slice(separator + 1);
const { values } = parseArgs({
  args: process.argv.slice(2, separator < 0 ? undefined : separator),
  options: {
    cache: { type: "string" },
    "case-module": { type: "string" },
    suite: { type: "string" },
    case: { type: "string", multiple: true },
    cli: { type: "string" },
    reviewer: { type: "string" },
    "isolated-state": { type: "boolean" },
    jobs: { type: "string", default: "1" },
    "skill-baseline": { type: "boolean" },
    out: { type: "string" },
    model: { type: "string" },
    "prepare-only": { type: "boolean" },
    "grade-existing": { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});
const caseModule = values["case-module"] && resolve(values["case-module"]);
const corpus = caseModule
  ? await import(pathToFileURL(caseModule).href)
  : { cases: pinnedCases, prepare, validateSnapshot, gradeSnapshot };
const { cases } = corpus;
assert(Array.isArray(cases), "Expected an array of cases");
for (const hook of ["prepare", "validateSnapshot", "gradeSnapshot"])
  assert.equal(typeof corpus[hook], "function", `Missing function ${hook}`);
const idsSeen = new Set();
for (const scenario of cases) {
  assert.match(scenario.id, /^[a-z\d_-]+$/iu, "Invalid case directory name");
  assert(!idsSeen.has(scenario.id), `Duplicate case ID: ${scenario.id}`);
  idsSeen.add(scenario.id);
}
const suites = new Set(caseModule ? [] : ["original", "added"]);
suites.add("large-repo");
for (const scenario of cases) suites.add(scenario.suite);
const usage = `Usage: node upstream.mjs (--cache DIR | --case-module PATH) [--suite ${[...suites].join("|")}] [--case ID ...]
       (--prepare-only | --cli PATH | --skill-baseline | --grade-existing RESULTS_DIR) [--jobs N] [--model MODEL] [--out NEW_DIR]
       Repeat --case ID to select several cases.
       --suite large-repo selects cases marked largeRepo: true across suites. Add --help to list their IDs.
       With --cli or --grade-existing: [--reviewer enabled|disabled|both] (default enabled for live runs)
       Regrading uses the cases and reviewer from results.json when available. Pass selectors to narrow the run.
       With --cli: [--isolated-state] creates a fresh CLI state directory per invocation.
       For --skill-baseline, append -- COMMAND [ARG...] to evaluate a local adapter on the original cases.
Fetch verified public inputs using: python3 upstream/assets.py fetch CACHE
Use --case-module PATH to load cases and their scoring function from a trusted local JavaScript module.`;
const original = new Set(originalCases.map((c) => c.id));
const matching = cases.filter((c) => {
  if (values.case && !values.case.includes(c.id)) return false;
  if (values["skill-baseline"] && !original.has(c.id)) return false;
  if (values.suite === "large-repo") return c.largeRepo === true;
  if (!caseModule && values.suite === "original") return original.has(c.id);
  if (!caseModule && values.suite === "added") return !original.has(c.id);
  return !values.suite || c.suite === values.suite;
});
if (values.help) {
  console.log(usage + "\nCases: " + matching.map((c) => c.id).join(", "));
  process.exit(0);
}
// Earlier saved manifests and reports called the reviewer setting "grader".
function normalizeReviewer(record) {
  if (record?.grader !== undefined) {
    record.reviewer = reviewerMode(record);
    delete record.grader;
  }
  return record;
}

const jobs = Number(values.jobs);
const existing = values["grade-existing"] && resolve(values["grade-existing"]);
let previous;
if (existing) {
  try {
    previous = JSON.parse(
      await readFile(join(existing, "results.json"), "utf8"),
    );
    normalizeReviewer(previous);
    previous?.results?.forEach(normalizeReviewer);
  } catch (error) {
    // A directory of reports can also be graded with explicit selectors.
    if (error.code !== "ENOENT") throw error;
  }
}
const reviewer = values.reviewer ?? previous?.reviewer ?? "enabled";
if (
  !Number.isSafeInteger(jobs) ||
  jobs < 1 ||
  (separator >= 0 &&
    (!adapter.length || !values["skill-baseline"] || values.model)) ||
  Boolean(values.cache) === Boolean(caseModule) ||
  (caseModule && values["skill-baseline"]) ||
  !["enabled", "disabled", "both"].includes(reviewer) ||
  (values.reviewer && !values.cli && !existing) ||
  (values["isolated-state"] && !values.cli) ||
  [
    values["prepare-only"],
    values.cli,
    values["skill-baseline"],
    existing,
  ].filter(Boolean).length !== 1
)
  throw Error(usage);
if (
  previous?.reviewer &&
  previous.reviewer !== "both" &&
  previous.reviewer !== reviewer
)
  throw Error(
    `The saved run only contains results with the reviewer ${previous.reviewer}.`,
  );

const savedIds = previous?.selected ?? previous?.results?.map((r) => r.id);
const selected = matching.filter((c) => !savedIds || savedIds.includes(c.id));
const ids = selected.map((c) => c.id);
const requested = values.case ?? (values.suite ? [] : savedIds) ?? [];
const unmatched = requested.filter((id) => !ids.includes(id));
if (unmatched.length)
  throw Error("Cases unavailable for this selection: " + unmatched.join(", "));
if (!selected.length) throw Error("No matching cases.\n" + usage);
const cli = values.cli && (await realpath(resolve(values.cli)));
const checkouts = {
  runner: checkoutOf(import.meta.filename),
  cli: checkoutOf(cli),
  caseModule: checkoutOf(caseModule, "directory"),
};
const cache = values.cache && resolve(values.cache);
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

const paired = reviewer === "both";
const pairedReports = (previous?.reviewer ?? reviewer) === "both";
const modes = paired ? ["enabled", "disabled"] : [reviewer];
if (paired) {
  for (const mode of modes) await mkdir(join(out, mode), { mode: 0o700 });
}
// Alternate which mode starts first to balance launch order and cache effects.
const tasks = selected.flatMap((scenario, index) =>
  (index % 2 ? modes.toReversed() : modes).map((mode) => ({
    scenario,
    reviewer: cli || existing ? mode : undefined,
    path: paired ? join(mode, scenario.id) : scenario.id,
  })),
);
const results = new Map();
let saved = Promise.resolve();
console.log("Results: " + out);

function prepare(scenario, scratch) {
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
  return { repo, sha: commitFixture(repo) };
}

async function reviewBatches(file) {
  // A missing or truncated progress log cannot establish zero reviewer calls.
  try {
    const lines = (await readFile(file, "utf8")).trim().split("\n");
    const events = lines.map((line) => JSON.parse(line));
    if (events.at(-1)?.type !== "finished") return null;
    return events.filter((event) => event.type === "review").length;
  } catch {
    return null;
  }
}

async function checkRepository(task, repo, scratch, dest, result) {
  const config = join(scratch, "scope.json");
  await jsonFile(config, {
    exploitability: { scope: { instructions: task.scenario.callerScope } },
  });
  const progress = join(dest, "progress.jsonl");
  const reportFile = join(dest, "report.json");
  const args = ["check"];
  if (task.reviewer === "disabled") args.push("--reviewer=disabled");
  args.push(
    task.scenario.cve,
    "--config",
    config,
    "--report-file",
    reportFile,
    "--progress-events",
    progress,
    "--json",
  );
  if (values.model) args.push("--model", values.model);
  result.argv = [process.execPath, cli, "exploitability", ...args];
  const start = performance.now();
  const proc = await invokeCli(cli, repo, args, {
    signal: abort.signal,
    stateDirectory: values["isolated-state"]
      ? join(scratch, "state")
      : undefined,
  });
  result.elapsedMs = Math.round(performance.now() - start);
  result.reviewBatches = await reviewBatches(progress);
  await writeCliLogs(dest, proc);
  if (proc.code !== 0) {
    result.exitCode = proc.code;
    result.signal = proc.signal;
    throw Error(
      `CLI exited with ${proc.signal ?? proc.code}, see stderr.log and stdout.log`,
    );
  }
  const report = JSON.parse(await readFile(reportFile, "utf8"));
  assert.deepEqual(report, JSON.parse(proc.stdout.toString("utf8")));
  return report;
}

async function readSavedReport(task, result) {
  const { id } = task.scenario;
  const dir = pairedReports
    ? join(existing, task.reviewer, id)
    : join(existing, id);
  const attempt = previous?.results?.find(
    (r) => r.id === id && (!r.reviewer || r.reviewer === task.reviewer),
  );
  if (attempt?.status === "execution_error") {
    // Keep a failed investigation in the denominator with its original diagnostic.
    Object.assign(result, attempt);
    throw Error(attempt.error ?? `Investigation failed, see ${dir}`);
  }
  result.elapsedMs = attempt?.elapsedMs;
  result.argv = attempt?.argv;
  result.reviewBatches = await reviewBatches(join(dir, "progress.jsonl"));
  return normalizeReviewer(
    JSON.parse(await readFile(join(dir, "report.json"), "utf8")),
  );
}

async function runCase(task, runSkill) {
  const { scenario } = task;
  const scratch = await mkdtemp(join(tmpdir(), "upstream-eval-"));
  const dest = join(out, task.path);
  const result = {
    id: scenario.id,
    suite: scenario.suite,
    cve: scenario.cve,
    upstreamRevision: scenario.revision,
    reviewer: task.reviewer,
    callerScope: scenario.callerScope,
    status: "execution_error",
  };
  try {
    await mkdir(dest, { mode: 0o700 });
    const savedReport = existing && (await readSavedReport(task, result));
    const { repo, sha } = await corpus.prepare(
      scenario,
      scratch,
      commitFixture,
    );
    result.sourceSha = sha;
    result.evidence = await corpus.validateSnapshot(scenario, repo, sha);
    if (values["prepare-only"]) {
      result.status = "prepared";
    } else if (runSkill) {
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
    } else {
      const report = existing
        ? savedReport
        : await checkRepository(task, repo, scratch, dest, result);
      result.status = "grade_error";
      if (report.advisoryDetails)
        result.advisorySha256 = sha256(JSON.stringify(report.advisoryDetails));
      result.usage = report.usage ?? null;
      if (report.target?.sha)
        assert.equal(
          report.target.sha,
          sha,
          "report used a different checkout",
        );
      if (pairedReports)
        assert(
          report.assumptions?.some((s) => s.includes(scenario.callerScope)),
          "report is missing the supplied caller scope",
        );
      result.grade = await corpus.gradeSnapshot(
        report,
        scenario,
        repo,
        sha,
        task.reviewer,
        { sourceReader, verifyClaimCitations },
      );
      assert.equal(typeof result.grade.pass, "boolean", "Missing grade.pass");
      if (result.grade.pass) result.status = "passed";
    }
  } catch (error) {
    result.error = error.message;
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
  console.log(task.path + ": " + result.status);
  results.set(task.path, result);
  saved = saved.then(saveResults);
  await saved;
}

function comparison() {
  return compareRuns(ids, [...results.values()]);
}
async function saveResults() {
  const tmp = join(out, "results.tmp");
  await writeFile(
    tmp,
    JSON.stringify(
      {
        model: previous ? (previous.model ?? null) : (values.model ?? null),
        checkouts: existing ? (previous?.checkouts ?? null) : checkouts,
        regradeCheckouts: existing ? checkouts : undefined,
        regradedFrom: existing,
        jobs,
        isolatedState: cli ? !!values["isolated-state"] : undefined,
        reviewer: cli || existing ? reviewer : undefined,
        selected: ids,
        complete: results.size === tasks.length && !abort.signal.aborted,
        comparison: paired ? comparison() : undefined,
        results: tasks.map((t) => results.get(t.path)).filter(Boolean),
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
  await rename(tmp, join(out, "results.json"));
}

async function runSelected(runSkill) {
  const queue = tasks.values();
  async function worker() {
    for (const task of queue) {
      if (abort.signal.aborted) return;
      await runCase(task, runSkill);
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(jobs, tasks.length) }, worker),
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
if (paired) {
  const score = comparison();
  const table = {};
  for (const metric of Object.keys(score.enabled))
    table[metric] = {
      disabled: score.disabled[metric],
      enabled: score.enabled[metric],
    };
  console.table(table);
  for (const field of ["gainedWithReview", "lostWithReview", "inputMismatch"])
    console.log(field + ": " + (score[field].join(", ") || "none"));
  if (score.inputMismatch.length) process.exitCode ||= 1;
}
if (
  results.size !== tasks.length ||
  [...results.values()].some(
    (r) => r.status !== (values["prepare-only"] ? "prepared" : "passed"),
  )
)
  process.exitCode ||= 1;
