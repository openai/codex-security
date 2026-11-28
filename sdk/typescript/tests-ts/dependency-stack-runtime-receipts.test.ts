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

test("a runtime-shaped binding selection cannot substitute for this observation's capture receipt", async () => {
  const sha = "a".repeat(40);
  const inputDigest = "b".repeat(64);
  const captureHash = "c".repeat(64);
  const imageDigest = "sha256:" + "d".repeat(64);
  const binding = {
    package: "sample-codec",
    version: "3.0.0",
    provenance: "synthetic",
    frameIndices: [0],
    imageDigest,
    sourceSha: sha,
  };
  const observation = {
    id: "observation",
    stackHash: "stack",
    framesTruncated: false,
    sinkIndex: 0,
    sinkIds: ["sink"],
    frames: [{ name: "decode", type: "js" }],
    bindings: [binding],
  };
  const work = {
    id: "work",
    queryId: "query",
    groupId: "group",
    status: "observed",
    scope: { service: "decoder", image_digest: imageDigest },
    queryScope: {},
    scopeConflicts: [],
    truncated: false,
    observation,
  } as unknown as StackWorkItem;
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
        result: { observation: { bindings: [binding] } },
      },
      process.cwd(),
    );
    const { receiptId } = saveRuntimeEvidence(store, prepared);
    const selected = selectRuntimeReceipt(store, receiptId, {
      receiptId,
      textBlock: null,
      record: ["observation", "bindings", 0],
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
    const contradictory = saveRuntimeEvidence(
      store,
      await prepareRuntimeEvidence(
        {
          kind: "runtime",
          server: "synthetic",
          tool: "inspect",
          scope: {
            service: "decoder",
            selector: { service: "different-service" },
          },
          result: observation,
        },
        process.cwd(),
      ),
    );
    claim.receipts.push(selectRuntimeReceipt(store, contradictory.receiptId));
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "conflicts with this work item's service",
    );
    claim.receipts.pop();
    const laterWindow = saveRuntimeEvidence(
      store,
      await prepareRuntimeEvidence(
        {
          kind: "runtime",
          server: "synthetic",
          tool: "inspect",
          scope: {
            window: {
              start: "2026-01-01T02:00:00Z",
              end: "2026-01-01T03:00:00Z",
            },
          },
          result: { version: "3.0.0" },
        },
        process.cwd(),
      ),
    );
    const timestamped = {
      ...work,
      scope: {
        ...work.scope,
        window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T04:00:00Z" },
      },
      observation: { ...observation, observedAt: "2026-01-01T01:00:00Z" },
    } as StackWorkItem;
    claim.receipts.push(selectRuntimeReceipt(store, laterWindow.receiptId));
    expect(() =>
      prepareStackAssessment(input, timestamped, packet, reader),
    ).toThrow("conflicts with this work item's window");
    claim.receipts.pop();
    const scoped = await prepareRuntimeEvidence(
      {
        kind: "runtime",
        server: "synthetic",
        tool: "inspect",
        scope: { service: "different-service" },
        result: { version: "3.0.0" },
      },
      process.cwd(),
    );
    const source = saveRuntimeEvidence(store, scoped);
    const imported = selectRuntimeReceipt(store, source.receiptId);
    claim.receipts.push(imported);
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "conflicts with this work item's service",
    );
    expect(
      prepareStackAssessment(
        {
          ...input,
          verdict: "unknown",
          reason: "The imported version is for a different service.",
          remainingQuestions: ["Which workload does this evidence cover?"],
          questionChecks: [
            {
              question: "Which workload does this evidence cover?",
              checked: "Compared the service in the import with the capture.",
              missingEvidence: "A version record for the captured service.",
              claims: [ref],
            },
          ],
        },
        work,
        packet,
        reader,
      ).verdict,
    ).toBe("unknown");
    claim.receipts = [
      {
        ...claim.receipts[0]!,
        server: "stack-observation",
        origin: {
          tool: "next",
          arguments: {
            inputDigest,
            workItemId: work.id,
            sourceReceiptId: source.receiptId,
          },
        },
      },
    ];
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "original runtime import receipt",
    );
    claim.receipts.push(imported);
    expect(() => prepareStackAssessment(input, work, packet, reader)).toThrow(
      "conflicts with this work item's service",
    );
    const matching = saveRuntimeEvidence(
      store,
      await prepareRuntimeEvidence(
        {
          kind: "runtime",
          server: "synthetic",
          tool: "inspect",
          scope: { service: "decoder" },
          result: observation,
        },
        process.cwd(),
      ),
    );
    claim.receipts[0]!.origin.arguments["sourceReceiptId"] = matching.receiptId;
    claim.receipts[1] = selectRuntimeReceipt(store, matching.receiptId);
    expect(prepareStackAssessment(input, work, packet, reader).verdict).toBe(
      "ruled_out",
    );
  } finally {
    store.close();
  }
});
