import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { writeFixture } from "../secret-discovery/fixtures.mts";
import {
  createFixture,
  prepareStandardEval,
  type PreparedStandardEval,
} from "./fixtures.mts";
import { gradeResult, type Result } from "./grade.mts";
import {
  hashText,
  runComparison,
  snapshotEvaluator,
  snapshotFiles,
  validateExperiment,
  type RunRecord,
} from "./experiment.mts";

const config = { model: "eval-model", pairs: 2, budgetMinutes: 5 };
const preparedStub: PreparedStandardEval = {
  repo: "/synthetic/repo",
  runtime: "/synthetic/runtime",
  fixture: createFixture(),
};

function mockResult() {
  return {
    report: {
      ...gradeResult({ findings: [] }, preparedStub.fixture),
    },
    semanticResult: { findings: [] },
  };
}

test("evaluator provenance tracks implementation and shared helpers, not reports", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "time-budget-provenance-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, "standard-time-budget");
  const files = Object.fromEntries(
    [
      "run.mts",
      "production.mts",
      "experiment.mts",
      "fixtures.mts",
      "grade.mts",
      "summary.mts",
      "../secret-discovery/fixtures.mts",
      "../secret-discovery/runtime.mts",
    ].map((path) => [path, path]),
  );
  await writeFixture(directory, { files });
  const before = await snapshotEvaluator(directory);
  assert.deepEqual(
    before,
    Object.fromEntries(
      Object.entries(files).map(([path, text]) => [path, hashText(text)]),
    ),
  );
  await writeFixture(directory, {
    files: {
      "grade.mts": "changed grader",
      "../secret-discovery/runtime.mts": "changed state helper",
      "reports/run-123/experiment.json": "generated report",
    },
  });
  assert.deepEqual(await snapshotEvaluator(directory), {
    ...before,
    "grade.mts": hashText("changed grader"),
    "../secret-discovery/runtime.mts": hashText("changed state helper"),
  });
});

test("pairs stage source without labels, alternate order, and opt in only for treatment", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "time-budget-eval-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const prepared = await prepareStandardEval(root, "/synthetic/plugin");
  const sourceBefore = await snapshotFiles(prepared.repo);
  assert.deepEqual(
    Object.keys(sourceBefore).sort(),
    Object.keys(prepared.fixture.files).sort(),
  );
  const requests: (number | undefined)[] = [];
  const records = await runComparison({
    prepared,
    config,
    run: async (actual, options) => {
      assert.equal(actual, prepared);
      requests.push(options.maxTimeMinutes);
      options.observation.prompt = "Captured production prompt";
      return mockResult();
    },
  });
  assert.deepEqual(requests, [undefined, 5, 5, undefined]);
  assert.deepEqual(
    records.map(({ pair, variant }) => [pair, variant]),
    [
      [1, "baseline"],
      [1, "time-aware"],
      [2, "time-aware"],
      [2, "baseline"],
    ],
  );
  assert.equal(records[0].promptSha256, hashText("Captured production prompt"));
});

test("monotonic elapsed time includes runner work but not artifact callbacks", async () => {
  let elapsed = 0;
  let calls = 0;
  const records = await runComparison({
    prepared: preparedStub,
    config: { ...config, pairs: 1 },
    elapsedNow: () => elapsed,
    onStart: async () => {
      elapsed += 60_000;
    },
    run: async () => {
      calls += 1;
      elapsed += calls === 1 ? 1_000 : 400_000;
      return mockResult();
    },
    onResult: async () => {
      elapsed += 60_000;
    },
  });
  assert.equal(calls, 2);
  assert.deepEqual(
    records.map((record) => record.elapsedMs),
    [1_000, 400_000],
  );
  assert.equal(records[1].status, "completed");
});

test("retains exact failures and still runs the paired arm", async () => {
  const saved: {
    record: RunRecord;
    result: Result | undefined;
    count: number;
  }[] = [];
  let calls = 0;
  const records = await runComparison({
    prepared: preparedStub,
    config: { ...config, pairs: 1 },
    run: async () => {
      calls += 1;
      if (calls === 1)
        throw new Error("model stream failed: synthetic diagnostic");
      return mockResult();
    },
    onResult: async (record, result, records) =>
      saved.push({ record, result, count: records.length }),
  });
  assert.equal(records[0].status, "failed");
  assert.equal(records[0].error, "model stream failed: synthetic diagnostic");
  assert.equal(records[0].promptSha256, null);
  assert.equal(records[1].status, "completed");
  assert.deepEqual(
    saved.map(({ count }) => count),
    [1, 2],
  );
  assert.equal(saved[0].result, undefined);
});

test("explicit cancellation saves the interrupted attempt and stops the comparison", async () => {
  const controller = new AbortController();
  const saved: RunRecord[] = [];
  let calls = 0;
  await assert.rejects(
    runComparison({
      prepared: preparedStub,
      config,
      signal: controller.signal,
      run: async (_prepared, { signal }) => {
        calls += 1;
        controller.abort(new Error("user canceled"));
        signal!.throwIfAborted();
        throw new Error("Cancellation should abort the runner");
      },
      onResult: async (record) => saved.push(record),
    }),
    /user canceled/,
  );
  assert.equal(calls, 1);
  assert.equal(saved.length, 1);
  assert.equal(saved[0].status, "failed");
});

test("requires an explicit model and valid experiment sizes without imposing a cap", () => {
  for (const change of [
    { model: "" },
    { pairs: 0 },
    { pairs: 1.5 },
    { budgetMinutes: 0 },
    { budgetMinutes: Infinity },
  ]) {
    assert.throws(() => validateExperiment({ ...config, ...change }));
  }
  assert.deepEqual(
    validateExperiment({ ...config, pairs: 100, budgetMinutes: 0.25 }),
    { ...config, pairs: 100, budgetMinutes: 0.25 },
  );
});
