import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { invokeCli, writeCliLogs } from "./cli.mjs";
import { gradeMixed, gradeStack, reviewerMode } from "./grade.mjs";
import { rateReport } from "./grade-reports.mjs";
import { mixedReportReference } from "./report-runtime.mjs";
import {
  git,
  jsonFile,
  mixedFixture,
  mixedRecords,
  mixedRequestService,
  restorePackets,
  reviewedCve,
  sha256,
  summaryCve,
  summaryFixtures,
} from "./fixtures.mjs";

const usage = `Usage: node run.mjs behavior [--out NEW_DIR]
       node run.mjs contracts --cli /path/to/codex-security.mjs [--out NEW_DIR]
       node run.mjs benchmark --cli /path/to/codex-security.mjs [--out NEW_DIR]
       node run.mjs live --cli /path/to/codex-security.mjs [--case CASE] [--model MODEL] [--out NEW_DIR]
       With --case mixed-*: [--reviewer enabled|disabled] (default enabled) [--rater-model MODEL]
Use --packets DIR to reuse an earlier run's packets/ directory.
Cases: positive, fixed, unbound, missing-version, mixed-services, mixed-package, mixed-evidence, mixed-evidence-no-access, mixed-evidence-sibling, or all (default).`;
const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    packets: { type: "string" },
    help: { type: "boolean", short: "h" },
    cli: { type: "string" },
    model: { type: "string" },
    reviewer: { type: "string" },
    "rater-model": { type: "string" },
    case: { type: "string" },
    out: { type: "string" },
  },
});
if (values.help) {
  console.log(usage);
  process.exit(0);
}
const [mode] = positionals;
const raterModel = values["rater-model"];
const allCases = [
  "positive",
  "fixed",
  "unbound",
  "missing-version",
  "mixed-services",
  "mixed-package",
  "mixed-evidence",
  "mixed-evidence-no-access",
  "mixed-evidence-sibling",
];
if (
  positionals.length !== 1 ||
  !["behavior", "benchmark", "contracts", "live"].includes(mode) ||
  (mode !== "behavior" && !values.cli) ||
  (values.case &&
    (mode !== "live" || ![...allCases, "all"].includes(values.case))) ||
  (values.model && mode !== "live") ||
  (raterModel !== undefined &&
    (!raterModel.trim() || !values.case?.startsWith("mixed-"))) ||
  (values.reviewer !== undefined &&
    (!["enabled", "disabled"].includes(values.reviewer) ||
      !values.case?.startsWith("mixed-"))) ||
  (values.packets && mode === "behavior")
) {
  throw new Error(usage);
}
const selected =
  values.case && values.case !== "all" ? [values.case] : allCases;
const cli = values.cli && (await realpath(resolve(values.cli)));
const out = values.out
  ? resolve(values.out)
  : await mkdtemp(join(tmpdir(), "dependency-results-"));
if (values.out) await mkdir(out, { mode: 0o700 });
const scratch = await mkdtemp(join(tmpdir(), "dependency-samples-"));
const abort = new AbortController();
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    process.exitCode = signal === "SIGTERM" ? 143 : 130;
    abort.abort();
  });
}
console.log("Results: " + out);

async function runJson(repo, args, input) {
  const result = await invokeCli(cli, repo, [...args, "--json"], {
    input,
    signal: abort.signal,
  });
  if (result.code !== 0)
    throw new Error(result.stderr || "CLI terminated: " + result.signal);
  return JSON.parse(result.stdout.toString("utf8"));
}
async function initialize(fixture) {
  const sdkEntry = createRequire(pathToFileURL(cli)).resolve(
    "@openai/codex-security/stack-packet",
  );
  const { prepareStackPacket } = await import(pathToFileURL(sdkEntry).href);
  const attempt = await mkdtemp(join(scratch, "attempt-"));
  const inputs = join(attempt, "inputs"),
    state = join(attempt, "state.sqlite");
  const { manifest } = await prepareStackPacket({
    cve: summaryCve,
    sourcesPath: join(fixture.input, "sources.json"),
    sinksPath: join(fixture.input, "sinks.json"),
    stacksPath: join(fixture.input, "stacks.json"),
    inputsDir: inputs,
    repository: fixture.repo,
    toolRevision: "eval-harness",
  });
  await runJson(fixture.repo, [
    "run",
    "init",
    "--state",
    state,
    "--inputs",
    inputs,
    "--repo",
    fixture.repo,
  ]);
  const tool = (verb, input) =>
    runJson(
      fixture.repo,
      [
        "run",
        verb,
        "--state",
        state,
        ...(input === undefined ? [] : ["--json-stdin"]),
      ],
      input,
    );
  return { manifest, tool };
}

// This scripted handoff exercises the public host and the grader without a model.
async function contracts(fixture) {
  const { manifest, tool } = await initialize(fixture);
  const next = await tool("next");
  // The harness can also compare CLI builds that returned only a frame count.
  const item = Array.isArray(next.workItem.observation.frames)
    ? { ...next.workItem, receiptId: next.receiptId }
    : await tool("read-stacks", { workItemId: next.workItem.id });
  const binding = item.observation.bindings[0];
  const result = await tool("record-claims", {
    claims: [
      {
        id: "running-version",
        scope: fixture.scope,
        payload: binding,
        receiptSelections: [
          {
            receiptId: item.receiptId,
            textBlock: null,
            record: ["observation", "bindings", 0],
          },
        ],
      },
    ],
  });
  const supportingClaims = result.claims.map(({ id, revision, hash }) => ({
    id,
    revision,
    hash,
  }));
  await tool("record-assessments", {
    items: [
      {
        workItemId: item.id,
        verdict: "ruled_out",
        reason: "The recorded version is outside the advisory range.",
        supportingClaims,
      },
    ],
  });
  const report = await tool("finalize");
  assert.equal(report.runId, manifest.runId);
  assert.equal(report.attemptId, manifest.attemptId);
  await jsonFile(join(out, "scripted-report.json"), report);
  const grade = gradeStack(report, fixture, { reviewed: false });
  const tampered = structuredClone(report);
  tampered.claims[0].receipts[0].result.version = "0.2.0";
  assert.throws(
    () => gradeStack(tampered, fixture, { reviewed: false }),
    /original capture selection/u,
  );
  return grade;
}

async function benchmark(fixture) {
  const trials = [];
  for (let i = 1; i <= 5; i++) {
    const { manifest, tool } = await initialize(fixture);
    const claims = Array.from({ length: 10 }, (_, index) => ({
      id: "sample-" + index,
      payload: { sample: index },
      scope: { service: "summary" },
      evidence: [
        { path: "sample-summary/index.cjs", startLine: 2, endLine: 3 },
      ],
    }));
    const ids = claims.map((c) => c.id);
    const start = performance.now();
    await tool("record-claims", { claims });
    const read = await tool("query-claims", { ids });
    const elapsedMs = performance.now() - start;
    assert.equal(read.claims.length, 10);
    assert.deepEqual(read.missingIds, []);
    for (const { id, payload } of claims) {
      const claim = read.claims.find((entry) => entry.id === id);
      assert.equal(claim?.revision, 1);
      assert.match(claim.hash, /^[a-f0-9]{64}$/u);
      assert.deepEqual(claim.payload, payload);
    }
    trials.push({ attemptId: manifest.attemptId, elapsedMs });
  }
  const medianMs = trials.map((t) => t.elapsedMs).sort((a, b) => a - b)[2];
  return {
    measurement:
      "ten claims in one transaction and one lookup in a second CLI process",
    trials,
    medianMs,
  };
}

try {
  let summaries;
  if (mode !== "live" || selected.some((id) => !id.startsWith("mixed-"))) {
    if (values.packets) {
      summaries = {
        fixtures: await restorePackets(scratch, resolve(values.packets)),
      };
    } else {
      summaries = await summaryFixtures(scratch);
      await jsonFile(join(out, "behavior.json"), summaries.outcomes);
      console.log(
        summaries.outcomes.map((o) => o.version + " " + o.after).join(", "),
      );
    }
    await mkdir(join(out, "packets"));
    for (const [id, fixture] of Object.entries(summaries.fixtures)) {
      await cp(fixture.input, join(out, "packets", id), { recursive: true });
    }
  }
  if (mode === "contracts") {
    const result = await contracts(summaries.fixtures.fixed);
    await jsonFile(join(out, "contracts.json"), result);
    console.log("Fixed binding, reopened claims and tamper check passed");
  }
  if (mode === "benchmark") {
    const result = await benchmark(summaries.fixtures.positive);
    await jsonFile(join(out, "benchmark.json"), result);
    console.log(
      "Median write plus lookup: " + result.medianMs.toFixed(1) + " ms",
    );
  }
  if (mode === "live") {
    const results = [];
    for (const id of selected) {
      if (abort.signal.aborted) break;
      const runDir = join(out, id);
      await mkdir(runDir, { mode: 0o700 });
      const mixed = id.startsWith("mixed-");
      const fixture = mixed
        ? await mixedFixture(scratch)
        : summaries.fixtures[id];
      // Keep labels such as "positive" out of the command's arguments.
      const answerDir = await mkdtemp(join(scratch, "answer-"));
      const reportFile = join(answerDir, "report.json");
      const subject =
        id === "mixed-package"
          ? "npm:linkify-it"
          : mixed
            ? reviewedCve
            : summaryCve;
      const reviewer = values.reviewer ?? "enabled";
      const args = ["check"];
      if (reviewer === "disabled") args.push("--reviewer=disabled");
      args.push(subject);
      if (mixed) args.push("--progress-events", join(runDir, "progress.jsonl"));
      if (!mixed) {
        for (const role of ["sources", "sinks", "stacks"])
          args.push("--" + role, join(fixture.input, role + ".json"));
      }
      let transcript;
      const requestService = mixedRequestService(id);
      if (id.startsWith("mixed-evidence")) {
        const records = join(answerDir, "records.json");
        transcript = join(answerDir, "calls.jsonl");
        const config = join(answerDir, "project.json");
        await writeFile(transcript, "", { mode: 0o600 });
        await jsonFile(records, mixedRecords(id, fixture.sha));
        await jsonFile(config, {
          exploitability: {
            evidence_sources: [
              {
                server: "service_records",
                instructions:
                  "Use the release and request records to check which package is running in a service and who could reach its parser.",
              },
            ],
          },
          codex: {
            mcp_servers: {
              service_records: {
                command: process.execPath,
                args: [
                  join(import.meta.dirname, "fixtures", "evidence-server.mjs"),
                  records,
                  transcript,
                ],
                enabled_tools: ["release_record", "request_record"],
              },
            },
          },
        });
        args.push("--config", config);
      }
      if (values.model) args.push("--model", values.model);
      args.push("--json", "--report-file", reportFile);
      assert.equal(git(fixture.repo, "status", "--porcelain"), "");
      const result = {
        id,
        ...(mixed && {
          reviewer,
          argv: [process.execPath, cli, "exploitability", ...args],
        }),
        sourceSha: mixed ? fixture.sha : fixture.target.sha,
        fixtureDigest: mixed
          ? fixture.sha
          : sha256(JSON.stringify(fixture.files)),
      };
      const start = performance.now();
      try {
        const processResult = await invokeCli(cli, fixture.repo, args, {
          signal: abort.signal,
        });
        result.elapsedMs = Math.round(performance.now() - start);
        await writeCliLogs(runDir, processResult);
        const calls = transcript
          ? (await readFile(transcript, "utf8"))
              .trim()
              .split("\n")
              .filter(Boolean)
              .map((line) => JSON.parse(line))
          : undefined;
        if (calls) await jsonFile(join(runDir, "source-calls.json"), calls);
        if (processResult.code !== 0) {
          result.status = "execution_error";
          result.exitCode = processResult.code;
          result.signal = processResult.signal;
        } else {
          result.status = raterModel ? "rating_error" : "grade_error";
          const reportBytes = await readFile(reportFile);
          await writeFile(join(runDir, "report.json"), reportBytes, {
            mode: 0o600,
            flag: "wx",
          });
          const report = JSON.parse(reportBytes.toString("utf8"));
          assert.deepEqual(
            JSON.parse(processResult.stdout.toString("utf8")),
            report,
            "stdout equals saved report",
          );
          if (raterModel) {
            assert.equal(reviewerMode(report), reviewer);
            assert.equal(report.target?.sha, fixture.sha);
            if (id === "mixed-package")
              assert.equal(report.package?.name, "linkify-it");
            else assert.equal(report.cve, reviewedCve);
            result.reportScore = await rateReport({
              report,
              reference: mixedReportReference(id, fixture, calls),
              ...fixture,
              dest: runDir,
              model: raterModel,
              signal: abort.signal,
            });
            result.status = "scored";
          } else {
            result.grade = mixed
              ? gradeMixed(
                  report,
                  fixture,
                  id === "mixed-package",
                  calls && { calls, requestService },
                  reviewer,
                )
              : gradeStack(report, fixture, { reviewed: true });
            result.status = "passed";
          }
        }
      } catch (error) {
        result.elapsedMs ??= Math.round(performance.now() - start);
        result.status ??= "execution_error";
        result.error = error.message;
      }
      results.push(result);
      const score = result.reportScore
        ? " " + result.reportScore.blended.toFixed(1)
        : "";
      console.log(
        id + ": " + result.status + score + " (" + result.elapsedMs + " ms)",
      );
      if (result.error) console.error(result.error);
      await writeFile(
        join(out, "results.json"),
        JSON.stringify(
          { model: values.model ?? null, raterModel, results },
          null,
          2,
        ) + "\n",
        { mode: 0o600 },
      );
    }
    if (
      results.length !== selected.length ||
      results.some((r) => r.status !== "passed" && r.status !== "scored")
    )
      process.exitCode ||= 1;
  }
} finally {
  await rm(scratch, { recursive: true, force: true });
}
