import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { invokeCli, writeCliLogs } from "../cli.mjs";
import { cases } from "./cases.mjs";
import { grade } from "./grade.mjs";
import { scenarios, setupInventory } from "./inventory.mjs";

const filter = { type: "string", multiple: true };
const { values } = parseArgs({
  options: {
    repos: { type: "string" },
    out: { type: "string" },
    cli: { type: "string" },
    model: { type: "string" },
    jobs: { type: "string", default: "3" },
    case: filter,
    scenario: filter,
    reviewer: filter,
    help: { type: "boolean" },
  },
});
const modes = ["enabled", "disabled", "outcome"];
if (values.help) {
  console.log(`node evals/dependency-reachability/outcomes/run.mjs --repos DIR --out NEW_DIR
  [--model MODEL] [--jobs N] [--cli CLI_ENTRYPOINT]
  [--case ID] [--scenario NAME] [--reviewer MODE]

Each checkout should be at DIR/<case ID>, at its pinned revision.
Cases       ${cases.map((c) => c.id).join(", ")}
Scenarios   ${scenarios.join(", ")}
Reviewers   ${modes.join(", ")}
Runs every combination by default. Repeat a filter to select several values.`);
  process.exit(0);
}
assert(values.repos && values.out, "Specify --repos and --out, see --help");
const jobs = Number(values.jobs);
assert(
  Number.isSafeInteger(jobs) && jobs > 0,
  "Expected positive integer --jobs",
);
const cli = values.cli
  ? resolve(values.cli)
  : resolve(
      import.meta.dirname,
      "../../../sdk/typescript/bin/codex-security.mjs",
    );
assert(existsSync(cli), "Missing CLI at " + cli);
const out = resolve(values.out);
const json = (file, value) =>
  writeFileSync(file, JSON.stringify(value, null, 2) + "\n");
const rows = (path) =>
  readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((s) => JSON.parse(s));
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const git = (cwd, ...args) =>
  execFileSync("git", args, { cwd, encoding: "utf8" }).trim();

function select(key, names) {
  for (const value of values[key] ?? []) {
    assert(
      names.includes(value),
      `Unknown ${key} ${value}. Choose from ${names.join(", ")}`,
    );
  }
  return names.filter((name) => !values[key] || values[key].includes(name));
}

const ids = select(
  "case",
  cases.map((c) => c.id),
);
const selectedScenarios = select("scenario", scenarios);
const reviewers = select("reviewer", modes);
const model = values.model;
const pending = [];
const fingerprints = new Map();
const serverSha256 = sha256(
  readFileSync(new URL("./inventory.mjs", import.meta.url)),
);
for (const fixture of cases.filter((c) => ids.includes(c.id))) {
  const repo = resolve(values.repos, fixture.id);
  assert.equal(git(repo, "rev-parse", "HEAD"), fixture.revision, repo);
  assert.equal(
    git(repo, "status", "--porcelain"),
    "",
    `Expected clean checkout at ${repo}`,
  );
  for (const scenario of selectedScenarios) {
    // The model gets the opaque digest only from a successful inventory call.
    const digest = "sha256:" + randomBytes(32).toString("hex");
    for (const reviewer of reviewers) {
      pending.push({ fixture, repo, scenario, reviewer, digest });
    }
  }
}
process.umask(0o077);
mkdirSync(out);
const abort = new AbortController();
process.once("SIGINT", () => abort.abort());
process.once("SIGTERM", () => abort.abort());

async function run({ fixture, repo, scenario, reviewer, digest }) {
  const { id, subject, description, service, revision, outcomes, callerScope } =
    fixture;
  const location = join(id, scenario, reviewer);
  const slot = join(out, location);
  mkdirSync(slot, { recursive: true });
  const scratch = mkdtempSync(join(tmpdir(), "oc-"));
  const result = {
    id,
    scenario,
    reviewer,
    revision,
    model,
    status: "error",
    passed: false,
  };
  const start = performance.now();
  try {
    const { config, journalPath, expected } = setupInventory({
      directory: scratch,
      scenario,
      service,
      revision,
      digest,
    });
    config.exploitability.scope = { instructions: callerScope };
    config.exploitability.outcomes = outcomes;
    const settings = join(scratch, "project.json");
    const file = join(scratch, "report.json");
    const progress = join(scratch, "progress.jsonl");
    json(settings, config);
    const question = {
      subject,
      description,
      revision,
      model,
      exploitability: config.exploitability,
    };
    const input = { question, scenario, expected, serverSha256 };
    result.inputSha256 = sha256(JSON.stringify(input));
    const pair = join(id, scenario);
    if (!fingerprints.has(pair)) fingerprints.set(pair, result.inputSha256);
    assert.equal(
      result.inputSha256,
      fingerprints.get(pair),
      "Reviewer inputs differ",
    );
    const args = ["check", subject];
    if (reviewer !== "enabled") args.push("--reviewer=" + reviewer);
    if (description) args.push("--vuln-description", description);
    if (model) args.push("--model", model);
    args.push(
      "--config",
      settings,
      "--report-file",
      file,
      "--progress-events",
      progress,
      "--json",
    );
    json(join(slot, "command.json"), [
      process.execPath,
      cli,
      "exploitability",
      ...args,
    ]);
    const proc = await invokeCli(cli, repo, args, {
      signal: abort.signal,
      stateDirectory: join(scratch, "state"),
    });
    result.exitCode = proc.code;
    await writeCliLogs(slot, proc);
    const calls = existsSync(journalPath) ? rows(journalPath) : [];
    json(join(slot, "calls.json"), calls);
    // Save expected inventory after execution, outside the checkout.
    json(join(slot, "input.json"), input);
    result.inventoryCalls = calls.map(
      ({ name, status }) => name + ":" + status,
    );
    if (existsSync(progress)) {
      writeFileSync(join(slot, "progress.jsonl"), readFileSync(progress));
      const events = rows(progress);
      result.programs = [
        ...new Set(
          events
            .filter((e) => e.type === "access_program")
            .map((e) => e.program),
        ),
      ];
      result.reviewBatches = events.filter((e) => e.type === "review").length;
      result.outcomeAttempts = events.filter(
        (e) => e.type === "outcome_review",
      ).length;
    }
    assert(
      proc.code === 0 || proc.code === 2,
      `CLI failed (${proc.signal ?? proc.code}). See stderr.log`,
    );
    const output = JSON.parse(proc.stdout.toString("utf8"));
    if (proc.code === 0) {
      const bytes = readFileSync(file);
      writeFileSync(join(slot, "report.json"), bytes);
      assert.deepEqual(
        JSON.parse(bytes),
        output,
        "CLI stdout differs from saved report",
      );
      result.reportSha256 = sha256(bytes);
      assert.equal(output.target?.sha, revision);
      assert.equal(output.reviewer ?? "enabled", reviewer);
      if (reviewer === "outcome") {
        const decision = (output.checks?.[0] ?? output).outcomeReview;
        assert.equal(decision?.status, "satisfied");
        assert.deepEqual(
          decision.criteria.map((c) => c.outcome),
          outcomes,
        );
        assert(decision.criteria.every((c) => c.status === "satisfied"));
      }
    } else {
      assert(!existsSync(file), "CLI wrote a report on a blocked run");
      json(join(slot, "blocked.json"), output);
    }
    Object.assign(
      result,
      grade({
        fixture,
        expected,
        calls,
        scenario,
        repo,
        output,
        code: proc.code,
      }),
    );
  } catch (error) {
    result.error = error.message;
  } finally {
    result.elapsedMs = Math.round(performance.now() - start);
    rmSync(scratch, { recursive: true, force: true });
  }
  json(join(slot, "result.json"), result);
  console.log(
    location,
    result.status,
    result.passed ? "pass" : "fail",
    result.error ?? "",
  );
  return result;
}

const results = [];
const count = pending.length;
async function worker() {
  while (!abort.signal.aborted && pending.length) {
    results.push(await run(pending.shift()));
    json(join(out, "results.json"), { planned: count, results });
  }
}
await Promise.all(Array.from({ length: Math.min(jobs, count) }, worker));
for (const reviewer of reviewers) {
  const group = results.filter((row) => row.reviewer === reviewer);
  const passed = group.filter((row) => row.passed).length;
  const errors = group.filter((row) => row.status === "error").length;
  console.log(
    `${reviewer}  ${passed}/${group.length} outcomes satisfied, ${errors} errors`,
  );
}
if (abort.signal.aborted || results.some((row) => !row.passed))
  process.exitCode = 1;
