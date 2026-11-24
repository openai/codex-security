import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  compareBaselines,
  createReleaseBaseline,
  hashSnapshotMap,
  loadBaseline,
  validateReleaseBaseline,
} from "./baseline.mts";
import { hashText, type RunRecord } from "./experiment.mts";
import { createFixture, type Fixture, type SourceCase } from "./fixtures.mts";
import { gradeResult, type Result } from "./grade.mts";

const fixture = createFixture();
const metadata = {
  pair: 1,
  variant: "baseline",
  startedAt: "2026-10-01T00:00:00Z",
  elapsedMs: 100,
  advisoryBudgetMinutes: null,
  promptSha256: null,
  usage: null,
} as const;
const failed: RunRecord = {
  ...metadata,
  variant: "time-aware",
  status: "failed",
  error: "Failed in /synthetic/run-2",
};

function finding(
  f: Fixture,
  { id, path, line, cwes }: SourceCase,
): Result["findings"][number] {
  return {
    title: id,
    taxonomy: { cwe: [cwes[0]!] },
    locations: [{ path, startLine: line, role: "root_control" }],
    codeEvidence: [
      { path, startLine: line, code: f.files[path]!.split("\n")[line - 1]! },
    ],
  };
}
function completed(
  f: Fixture,
  found = f.positives,
  extra: Result["findings"] = [],
) {
  return {
    ...metadata,
    status: "completed" as const,
    usage: { input_tokens: 100, output_tokens: 20 },
    report: {
      ...gradeResult(
        { findings: [...found.map((c) => finding(f, c)), ...extra] },
        f,
      ),
      scanDir: "/local/scan",
      reportPath: "/local/scan/report.md",
    },
  };
}
function saved(f: Fixture, runs: RunRecord[] = [completed(f)], pairs = 1) {
  const source = Object.fromEntries(
    Object.entries(f.files).map(([name, text]) => [name, hashText(text)]),
  );
  const experiment = {
    model: "synthetic-model",
    pairs,
    budgetMinutes: 5,
    reasoningEffort: "high",
    source,
    evaluator: { "fixtures.mts": hashText(JSON.stringify(f.positives)) },
    codexExecutable: {
      command: "/local/cli",
      files: [{ path: "/local/cli", sha256: hashText("bin") }],
    },
  };
  return { experiment, fixture: f, runs };
}

test("snapshot digests use code unit order across locales", () => {
  const digest = hashText("source");
  assert.equal(
    hashSnapshotMap({ ä: digest, z: digest }),
    hashText(
      JSON.stringify([
        ["z", digest],
        ["ä", digest],
      ]),
    ),
  );
});

test("CLI round-trips saved runs, omits source and host fields, and preserves failure diagnostics", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "baseline-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inputs = saved(fixture, [completed(fixture), failed]);
  for (const [name, content] of Object.entries(inputs))
    await writeFile(join(root, name + ".json"), JSON.stringify(content));
  const cli = (...args: string[]) =>
    spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        join(import.meta.dirname, "baseline.mts"),
        ...args,
      ],
      { encoding: "utf8" },
    );
  const file = join(root, "baseline.json");
  const exported = cli("export", root, file);
  assert.equal(exported.status, 0, exported.stderr);
  const text = await readFile(file, "utf8");
  assert.doesNotMatch(text, /\/local\/|scanDir|reportPath|requests\.head/);
  const baseline = await loadBaseline(file);
  assert.deepEqual(baseline, createReleaseBaseline(inputs));
  assert.deepEqual(baseline.experiment.digests.codexExecutableSha256, [
    hashText("bin"),
  ]);
  const compared = cli("compare", file, root);
  assert.equal(compared.status, 0, compared.stderr);
  const result = JSON.parse(compared.stdout);
  assert.equal(result.provenance.fixtureIdentical, true);
  assert.equal(
    result.arms["time-aware"].baseline.failures[0].error,
    failed.error,
  );
  assert.notEqual(cli("compare", file, root, file).status, 0);
  assert.equal(await readFile(file, "utf8"), text);
  assert.match(cli("compare", file).stderr, /Usage/);
});

test("added cases cannot mask a regression on shared cases", () => {
  const smaller = { ...fixture, positives: fixture.positives.slice(0, -2) };
  const before = createReleaseBaseline(saved(smaller));
  const compare = (found: SourceCase[]) =>
    compareBaselines(
      before,
      createReleaseBaseline(saved(fixture, [completed(fixture, found)])),
    );
  const same = compare(smaller.positives);
  assert.equal(same.corpus.positives.added.length, 2);
  assert.equal(same.provenance.digests.fixturesModuleSha256.changed, true);
  assert.equal(same.arms.baseline.delta.comparableRecall, 0);
  assert.ok(same.arms.baseline.delta.rawRecall! < 0);
  const masked = compare(fixture.positives.slice(1)).arms.baseline;
  assert.ok(masked.candidate.rawFoundCount! > masked.baseline.rawFoundCount!);
  assert.ok(masked.delta.comparableRecall! < 0);
  assert.deepEqual(masked.flags.regressedCases, [smaller.positives[0]!.id]);
});

test("source or span changes break comparability, unlike reordered CWEs or explicit single-line spans", () => {
  const f = createFixture();
  const [edited, moved, same] = f.positives;
  f.files[edited!.path] += "\n";
  moved!.line++;
  same!.cwes.reverse();
  same!.endLine = same!.line;
  const removed = f.positives.pop()!;
  const result = compareBaselines(
    createReleaseBaseline(saved(fixture)),
    createReleaseBaseline(saved(f)),
  );
  assert.deepEqual(result.corpus.sourceFiles.changed, [edited!.path]);
  assert.deepEqual(result.corpus.positives.changed, [edited!.id, moved!.id]);
  assert.deepEqual(result.corpus.positives.removed, [removed.id]);
  assert.ok(result.corpus.positives.comparable.includes(same!.id));
  assert.deepEqual(result.arms.baseline.flags.regressedCases, []);
});

test("quality, missing runs and unknown usage stay visible across unequal corpora", () => {
  const smaller = { ...fixture, controls: fixture.controls.slice(0, 1) };
  const before = createReleaseBaseline(saved(smaller));
  const extras = [
    finding(fixture, fixture.positives[0]!),
    ...fixture.controls.slice(0, 2).map((c) => finding(fixture, c)),
    { ...finding(fixture, fixture.positives[1]!), codeEvidence: [] },
  ];
  const after = createReleaseBaseline(
    saved(
      fixture,
      [
        completed(fixture, fixture.positives, extras),
        { ...failed, variant: "baseline", pair: 2 },
      ],
      3,
    ),
  );
  const { arms } = compareBaselines(before, after);
  const { baseline, candidate, flags } = arms.baseline;
  assert.equal(baseline.usage.totals.total_tokens, 120);
  assert.equal(baseline.usage.totals.cached_input_tokens, null);
  assert.equal(candidate.usage.totals.total_tokens, null);
  assert.equal(candidate.usage.missingUsageRuns, 2);
  assert.equal(candidate.missing, 1);
  assert.equal(candidate.successRate, 1 / 2);
  assert.equal(candidate.completionRate, 1 / 3);
  assert.equal(candidate.safeControlFindings, 2);
  assert.equal(candidate.comparableSafeControlFindings, 1);
  assert.equal(candidate.duplicateFindings, 1);
  assert.equal(candidate.unmatchedFindings, 1);
  assert.equal(flags.hasRunFailures, true);
  assert.equal(flags.needsAdjudication, true);
  assert.equal(flags.evidenceErrorsIncreased, true);
  assert.equal(flags.comparableControlAccusationsIncreased, true);
  assert.equal(arms["time-aware"].cases.comparable[0]!.status, "unmeasured");
});

test("equivalent rates across pair counts have zero delta and retain the range", () => {
  const sample = (pairs: number) => {
    const runs = Array.from({ length: pairs }, (_, i) => ({
      ...completed(fixture, i % 3 ? fixture.positives : []),
      pair: i + 1,
    }));
    return createReleaseBaseline(saved(fixture, runs, pairs));
  };
  const { candidate, delta, cases } = compareBaselines(sample(3), sample(6))
    .arms.baseline;
  assert.deepEqual(candidate.comparableRecall, { mean: 2 / 3, min: 0, max: 1 });
  assert.equal(cases.comparable[0]!.recallDelta, 0);
  assert.equal(delta.comparableRecall, 0);
});

test("rejects mismatched samples, duplicate attempts and altered snapshot metadata", () => {
  const inputs = saved(fixture);
  const run = inputs.runs[0]!;
  assert.throws(
    () => createReleaseBaseline({ ...inputs, runs: [run, run] }),
    /Duplicate run/,
  );
  const other = { ...fixture, positives: fixture.positives.slice(1) };
  assert.throws(
    () => createReleaseBaseline({ ...inputs, fixture: other }),
    /corpus positives/,
  );
  assert.throws(
    () =>
      createReleaseBaseline({ ...inputs, fixture: { ...fixture, files: {} } }),
    /fixture\.files/,
  );
  const valid = createReleaseBaseline(inputs);
  assert.throws(
    () => validateReleaseBaseline({ ...valid, schemaVersion: 2 }),
    /schemaVersion/,
  );
  valid.experiment.digests.sourceSha256 = hashText("other");
  assert.throws(() => validateReleaseBaseline(valid), /digest mismatch/);
});
