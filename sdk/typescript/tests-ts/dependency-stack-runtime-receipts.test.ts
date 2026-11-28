import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DependencyAttemptStore } from "../src/exploitability/attempt-store.js";
import { prepareStackAssessment } from "../src/exploitability/analyzers/stacks/assessment.js";
import type { DependencyClaimRecord } from "../src/exploitability/analyzers/stacks/claims.js";
import type {
  StackPacket,
  StackWorkItem,
} from "../src/exploitability/analyzers/stacks/packet.js";
import {
  isRuntimeReceipt,
  prepareRuntimeEvidence,
  runtimeEvidenceInputSchema,
  saveRuntimeEvidence,
  selectRuntimeReceipt,
} from "../src/exploitability/analyzers/stacks/runtime-receipts.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("runtime evidence preserves and selects the host-saved original across reopen", async () => {
  await using dir = await scopedTemporaryDirectory("runtime-receipt-");
  const state = join(dir.path, "attempt.sqlite");
  const prepared = await prepareRuntimeEvidence(
    {
      kind: "runtime",
      server: "synthetic-provider",
      tool: "inspect",
      arguments: { image: "sample:tag" },
      scope: { environment: "test" },
      result: {
        structuredContent: { rows: [{ version: "1.2.3" }] },
        content: [{ type: "text", text: '{"status":"complete"}' }],
      },
    },
    dir.path,
  );
  let store = new DependencyAttemptStore(state);
  const saved = saveRuntimeEvidence(store, prepared);
  expect(saveRuntimeEvidence(store, prepared)).toEqual(saved);
  store.close();
  store = new DependencyAttemptStore(state, { create: false });
  try {
    const selected = selectRuntimeReceipt(store, saved.receiptId, {
      receiptId: saved.receiptId,
      textBlock: null,
      record: ["rows", 0, "version"],
    });
    expect(selected.result).toBe("1.2.3");
    expect(isRuntimeReceipt(selected)).toBe(true);
    expect(selected.server).toBe("runtime-import");
    expect(selected.origin.tool).toBe("record-evidence");
    expect(selected.origin.arguments).toMatchObject({
      provenance: "caller_imported",
      verification: "unverified",
      declaredServer: "synthetic-provider",
      declaredTool: "inspect",
    });
    expect(selected.origin.arguments["arguments"]).toEqual({
      image: "sample:tag",
    });
    expect(
      selectRuntimeReceipt(store, saved.receiptId, {
        receiptId: saved.receiptId,
        textBlock: 0,
        record: ["status"],
      }).result,
    ).toBe("complete");
    store.set("runtime-receipt", saved.receiptId, {
      ...prepared.record,
      result: "changed",
    });
    expect(() => selectRuntimeReceipt(store, saved.receiptId)).toThrow(
      "original record",
    );
  } finally {
    store.close();
  }
});

test("runtime resource verifies exact bytes and retains their original hash", async () => {
  await using dir = await scopedTemporaryDirectory("runtime-resource-");
  const path = join(dir.path, "resource.json");
  const bytes = Buffer.from('{ "rows": [1, 2] }\n');
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  await writeFile(path, bytes);
  const input = {
    kind: "runtime",
    server: "synthetic",
    tool: "read",
    resource: { path, sha256 },
  };
  const prepared = await prepareRuntimeEvidence(input, dir.path);
  const store = new DependencyAttemptStore(":memory:");
  try {
    const { receiptId } = saveRuntimeEvidence(store, prepared);
    expect(selectRuntimeReceipt(store, receiptId).originalPayloadSha256).toBe(
      sha256,
    );
    expect(selectRuntimeReceipt(store, receiptId).result).toEqual({
      rows: [1, 2],
    });
  } finally {
    store.close();
  }
  await writeFile(path, "changed");
  await expect(prepareRuntimeEvidence(input, dir.path)).rejects.toThrow(
    "SHA-256",
  );
});

test("runtime imports cannot impersonate captures or provide ambiguous payloads", () => {
  expect(
    runtimeEvidenceInputSchema.safeParse({
      kind: "runtime",
      server: "stack-packet",
      tool: "inspect",
      result: {},
    }).success,
  ).toBe(false);
  expect(
    runtimeEvidenceInputSchema.safeParse({
      kind: "runtime",
      server: "stack-observation",
      tool: "inspect",
      result: {},
    }).success,
  ).toBe(false);
  expect(
    runtimeEvidenceInputSchema.safeParse({
      kind: "runtime",
      server: "synthetic",
      tool: "inspect",
    }).success,
  ).toBe(false);
  expect(
    runtimeEvidenceInputSchema.safeParse({
      kind: "runtime",
      server: "synthetic",
      tool: "inspect",
      result: null,
    }).success,
  ).toBe(true);
});

test("only a frame citation from the relevant capture can exclude a fixed copy", async () => {
  const sha = "a".repeat(40),
    inputDigest = "b".repeat(64),
    captureHash = "c".repeat(64);
  const pkg = {
    name: "sample-codec",
    version: "3.0.0",
    provenance: "synthetic",
  };
  const stack = {
    labels: { service: "decoder" },
    frames: [{ name: "decode", package: pkg, sourceRevision: sha }],
  };
  const work: StackWorkItem = {
    id: "captures/0/stacks/0",
    captureIndex: 0,
    stackIndex: 0,
    status: "observed",
    stack,
    scopeConflicts: [],
    sinkMatches: [{ sinkId: "sink", rawIndex: 0 }],
    leads: [],
  };
  const packet = {
    manifest: {
      inputDigest,
      target: { sha },
      files: { stacks: { sha256: captureHash } },
    },
    sinks: {
      sinks: [
        {
          id: "sink",
          function: "decode",
          package: "sample-codec",
          versionScheme: "semver",
          affectedVersions: ["<2.0.0"],
          preconditions: [],
        },
      ],
    },
  } as unknown as StackPacket;
  const store = new DependencyAttemptStore(":memory:");
  try {
    const prepared = await prepareRuntimeEvidence(
      {
        kind: "runtime",
        server: "synthetic",
        tool: "inspect",
        result: { stack },
      },
      process.cwd(),
    );
    const { receiptId } = saveRuntimeEvidence(store, prepared);
    const selected = selectRuntimeReceipt(store, receiptId, {
      receiptId,
      textBlock: null,
      record: ["stack", "frames", 0, "package"],
    });
    const ref = { id: "binding", revision: 1, hash: "e".repeat(64) };
    const claim = {
      ...ref,
      scope: "work",
      payload: "fixed version",
      dependencies: [],
      excerpts: [],
      receipts: [selected],
    } as DependencyClaimRecord;
    const reader = { isUsable: () => true, get: () => claim };
    const input = {
      workItemId: work.id,
      verdict: "ruled_out",
      reason: "fixed copy",
      supportingClaims: [ref],
      remainingQuestions: [],
    };
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "Supply an evidence-backed use",
    );
    claim.receipts = [
      {
        ...selected,
        receiptId: "capture",
        server: "stack-packet",
        originalPayloadSha256: captureHash,
        origin: {
          tool: "next",
          arguments: { inputDigest, workItemId: work.id },
        },
      },
    ];
    expect(prepareStackAssessment(input, work, packet, reader).verdict).toBe(
      "ruled_out",
    );
    claim.receipts[0]!.origin.arguments["workItemId"] = "another-work-item";
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "outside work item",
    );
    claim.receipts[0]!.origin.arguments["workItemId"] = work.id;
    const other = saveRuntimeEvidence(
      store,
      await prepareRuntimeEvidence(
        {
          kind: "runtime",
          server: "synthetic",
          tool: "inspect",
          scope: { labels: { service: "different-service" } },
          result: stack,
        },
        process.cwd(),
      ),
    );
    claim.receipts.push(selectRuntimeReceipt(store, other.receiptId));
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      /service|scope|label/i,
    );
  } finally {
    store.close();
  }
});
