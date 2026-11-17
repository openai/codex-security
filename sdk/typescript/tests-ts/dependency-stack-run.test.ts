import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DependencyAttemptStore } from "../src/dependency-attempt-store.js";
import type { DependencyClaimReference } from "../src/dependency-claims.js";
import { prepareStackPacket } from "../src/dependency-stack-packet.js";
import {
  executeStackRun,
  readFinalStackReport,
} from "../src/dependency-stack-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("a reopened run recovers identical writes and requires a fresh assessment when its premise changes", async () => {
  await using scratch = await scopedTemporaryDirectory("stack-state-");
  const root = join(scratch.path, "fixture");
  const prepare = fileURLToPath(
    new URL(
      "../../../evals/dependency-reachability/fixtures/stack-workflow/prepare.mjs",
      import.meta.url,
    ),
  );
  execFileSync(process.execPath, [prepare, root, "fixed"]);
  const state = join(scratch.path, "run.sqlite");
  const repo = join(root, "target");
  const inputs = join(scratch.path, "inputs");
  const files = {
    cve: "CVE-2099-0001",
    repository: repo,
    toolRevision: "test-revision",
    sourcesPath: join(root, "sources.json"),
    sinksPath: join(root, "sinks.json"),
    stacksPath: join(root, "stacks.json"),
  };
  await prepareStackPacket({ ...files, inputsDir: inputs });
  await executeStackRun("init", { state, inputs, repo });
  const otherInputs = join(scratch.path, "other");
  await prepareStackPacket({ ...files, inputsDir: otherInputs });
  await expect(
    executeStackRun("init", { state, inputs: otherInputs, repo }),
  ).rejects.toThrow(/different packet, target, run or attempt/);
  const call = (name: string, input?: unknown) =>
    executeStackRun(name, { state, input });
  const next = (await call("next")) as {
    workItem: { id: string };
    receiptId: string;
  };
  const workItemId = next.workItem.id;
  const stack = await call("read-stacks", { workItemId });
  expect(stack).toMatchObject({
    receiptId: next.receiptId,
    rootFirstRawIndices: [1, 0],
  });
  const row = {
    id: "deployed-version",
    scope: { workItemId },
    payload: { version: "2.1.0" },
    receiptSelections: [
      {
        receiptId: next.receiptId,
        textBlock: null,
        record: ["observation", "bindings", 0],
      },
    ],
  };
  const write = { operationId: "record-version", claims: [row] };
  const first = (await call("record-claims", write)) as {
    claims: DependencyClaimReference[];
  };
  expect(await call("record-claims", write)).toEqual(first);
  await expect(
    call("record-claims", { ...write, claims: [{ ...row, id: "other" }] }),
  ).rejects.toThrow(/different arguments/);
  expect(await call("query-claims", { ids: [row.id] })).toMatchObject({
    claims: [{ ...first.claims[0], state: "recorded" }],
  });
  await expect(
    call("record-claims", {
      claims: [
        {
          id: "dependent",
          scope: {},
          payload: "uses old version",
          dependencies: first.claims,
        },
        { ...row, expectedRevision: 1, payload: "revised version claim" },
      ],
    }),
  ).rejects.toThrow(/invalidates a sibling/);
  expect(
    await call("query-claims", { ids: [row.id, "dependent"] }),
  ).toMatchObject({ missingIds: ["dependent"], claims: [first.claims[0]] });
  await expect(call("finalize")).rejects.toThrow();
  const assess = (refs: DependencyClaimReference[]) => ({
    items: [
      {
        workItemId,
        verdict: "ruled_out",
        reason: "The captured deployment binds 2.1.0 to this service.",
        supportingClaims: refs,
      },
    ],
  });
  await call("record-assessments", assess(first.claims));
  expect(await call("next")).toMatchObject({ workItem: null });

  const updated = (await call("record-claims", {
    claims: [
      {
        ...row,
        expectedRevision: 1,
        payload: { version: "2.1.0", package: "sample-codec" },
      },
    ],
  })) as { claims: DependencyClaimReference[] };
  expect(updated.claims[0]?.revision).toBe(2);
  await expect(call("finalize")).rejects.toThrow(/stale/);
  expect(await call("next")).toMatchObject({ workItem: { id: workItemId } });
  await call("record-assessments", assess(updated.claims));
  const report = await call("finalize");
  expect(report).toMatchObject({
    verdict: "ruled_out",
    coverage: { total: 1, assessed: 1 },
    claims: updated.claims,
  });
  expect(await call("finalize")).toEqual(report);
  expect(report).toEqual(await readFinalStackReport(state));
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    store.set("report", "final", {
      ...(await readFinalStackReport(state)),
      verdict: "exploitable",
      claims: [],
      assessments: [],
    });
  } finally {
    store.close();
  }
  await expect(readFinalStackReport(state)).rejects.toThrow(
    /saved report differs/,
  );
  await expect(call("finalize")).rejects.toThrow(/saved report differs/);
});
