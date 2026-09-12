import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import {
  deduplicateRecords,
  type DeduplicateRecordsOptions,
  type DeduplicationCheckpointStore,
  type DeduplicationReviewRequest,
  type Finding,
  type FindingsDocument,
} from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const fixture: FindingsDocument = JSON.parse(
  await readFile(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
    "utf8",
  ),
);

function finding(index: number): Finding {
  return {
    ...structuredClone(fixture.findings[0]!),
    findingId: `csf_${index.toString(16).padStart(24, "0")}`,
    occurrenceId: `occ_${index.toString(16).padStart(24, "0")}`,
    title: `Synthetic issue ${index}`,
    extensions: {
      originalEvidence: { description: `Complete evidence ${index}` },
    },
  };
}

function assigned(request: DeduplicationReviewRequest): Finding[] {
  return JSON.parse(
    request.prompt.slice(request.prompt.lastIndexOf("\n\n") + 2),
  ).findings;
}

function submission(request: DeduplicationReviewRequest, same = true): unknown {
  const findings = assigned(request);
  if (request.stage === "screening")
    return {
      decisions: Object.fromEntries(
        findings.slice(1).map((_, index) => [
          `pair-${index + 1}`,
          {
            decision: same ? "SAME" : "DISTINCT",
            rationale: same
              ? "One control closes both reported paths."
              : "Independent corrections are required.",
          },
        ]),
      ),
    };
  return same
    ? {
        decision: "SAME",
        rationale: "The inspected shared control closes both complete paths.",
        canonicalFindingId: findings[0]!.findingId,
        mergedFinding: {
          ...findings[0],
          title: findings.map((value) => value.title).join("; "),
          extensions: { originalFindings: findings },
        },
      }
    : {
        decision: "DISTINCT",
        rationale: "Independent corrections are required.",
      };
}

class Checkpoints implements DeduplicationCheckpointStore {
  readonly values = new Map<string, unknown>();
  readonly bindings = new Map<string, object>();
  async getReview(key: string): Promise<unknown | null> {
    return this.values.get(key) ?? null;
  }
  async saveReview(
    key: string,
    binding: object,
    result: unknown,
  ): Promise<void> {
    this.values.set(key, structuredClone(result));
    this.bindings.set(key, structuredClone(binding));
  }
}

function options(
  findings = [finding(1), finding(2)],
): DeduplicateRecordsOptions {
  return {
    observations: findings,
    candidateProvider: {
      async potentialDuplicates(anchor) {
        return findings.filter(
          (candidate) => candidate.findingId !== anchor.findingId,
        );
      },
    },
    reviewRunner: {
      async run(request) {
        return submission(request);
      },
    },
    sourceManifest: {
      repositories: [
        { id: "synthetic-repository", revisions: ["a".repeat(40)] },
      ],
    },
    async verifySource() {},
    scopeKey: "synthetic-scope",
    concurrency: 1,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

test("public record API reviews complete records without artifacts or a findings service", async () => {
  const input = options();
  const requests: DeduplicationReviewRequest[] = [];
  input.reviewRunner = {
    async run(request) {
      requests.push(request);
      return submission(request);
    },
  };
  const result = await deduplicateRecords(input);
  expect(result.deduplicationStatus).toBe("completed");
  expect(result.uniqueFindingIds).toEqual([input.observations[0]!.findingId]);
  expect(result.duplicateGroups).toHaveLength(1);
  expect(result.pairOutcomes).toHaveLength(1);
  expect(result.pairOutcomes[0]!.origin).toBe("pair-review");
  expect(result.pairOutcomes[0]!.review?.decision).toBe("SAME");
  expect(result.pairOutcomes[0]!.screenings).toHaveLength(2);
  expect(result.pairOutcomes[0]!.bindingDigest).toMatch(/^[a-f0-9]{64}$/);
  expect(result.sameComponents).toHaveLength(1);
  expect(
    requests.map(({ stage, model, effort }) => [stage, model, effort]),
  ).toEqual([
    ["screening", "gpt-5.6-luna", "xhigh"],
    ["screening", "gpt-5.6-luna", "xhigh"],
    ["pair-review", "gpt-5.6-sol", "high"],
  ]);
  expect(assigned(requests[2]!)[0]!.extensions).toEqual(
    input.observations[1]!.extensions,
  );
  expect(result.checkpointKeys).toEqual([]);
});

test("empty or isolated records do not invoke a reviewer", async () => {
  for (const observations of [[], [finding(1)]]) {
    const input = options(observations);
    input.reviewRunner = {
      async run() {
        throw new Error("No review should run");
      },
    };
    expect((await deduplicateRecords(input)).uniqueFindingIds).toEqual(
      observations.map((value) => value.findingId),
    );
  }
});

test("conflicting candidate identities fail before any model review", async () => {
  const input = options();
  input.candidateProvider = {
    async potentialDuplicates(anchor) {
      return [
        { ...anchor, title: "Different evidence under the same identifier" },
      ];
    },
  };
  input.reviewRunner = {
    async run() {
      throw new Error("No review should run");
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "Conflicting finding content",
  );
});

test("raw model output and checkpoint hits are validated by the SDK", async () => {
  const store = new Checkpoints();
  const input = { ...options(), checkpointStore: store };
  input.reviewRunner = {
    async run() {
      return { decisions: {} };
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "assigned screening pair slots",
  );
  expect(store.values.size).toBe(0);
  input.reviewRunner = {
    async run(request) {
      return submission(request);
    },
  };
  await deduplicateRecords(input);
  const screeningKey = [...store.bindings].find(
    ([, binding]) =>
      (binding as { request: DeduplicationReviewRequest }).request.stage ===
      "screening",
  )![0];
  store.values.set(screeningKey, { decisions: {} });
  input.reviewRunner = {
    async run() {
      throw new Error("Cached result should be checked");
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "assigned screening pair slots",
  );
});

test("a screening veto remains DISTINCT and preserves its evidence without pair review", async () => {
  const input = options();
  input.reviewRunner = {
    async run(request) {
      expect(request.stage).toBe("screening");
      return submission(
        request,
        assigned(request)[0]!.findingId === input.observations[0]!.findingId,
      );
    },
  };
  const result = await deduplicateRecords(input);
  expect(result.duplicateGroups).toEqual([]);
  expect(result.pairOutcomes[0]!.decision).toBe("DISTINCT");
  expect(result.pairOutcomes[0]!.origin).toBe("screening");
  expect(
    result.pairOutcomes[0]!.screenings.map((value) => value.result.decision),
  ).toEqual(["SAME", "DISTINCT"]);
});

test("prior DISTINCT survives missing nominations and exposes the raw SAME bridge", async () => {
  const left = finding(1);
  const middle = finding(2);
  const right = finding(3);
  const previous = options([left, right]);
  previous.reviewRunner = {
    async run(request) {
      return submission(request, false);
    },
  };
  const prior = await deduplicateRecords(previous);
  const current = options([middle]);
  current.candidateProvider = {
    async potentialDuplicates() {
      return [left, right];
    },
  };
  current.priorDecisions = prior.pairOutcomes;
  const result = await deduplicateRecords(current);
  expect(
    result.pairOutcomes.find(({ origin }) => origin === "prior")?.decision,
  ).toBe("DISTINCT");
  expect(result.sameComponents.map((group) => [...group].sort())).toEqual([
    [left.findingId, middle.findingId, right.findingId].sort(),
  ]);
  expect(
    result.duplicateGroups.some(
      (group) =>
        group.includes(left.findingId) && group.includes(right.findingId),
    ),
  ).toBe(false);
});

test("matching prior decisions skip repeated reviews while stale source bindings fail", async () => {
  const input = options();
  const previous = await deduplicateRecords(input);
  input.priorDecisions = previous.pairOutcomes;
  input.reviewRunner = {
    async run() {
      throw new Error("Prior decisions avoid repeated review");
    },
  };
  const replay = await deduplicateRecords(input);
  expect(replay.pairOutcomes[0]!.origin).toBe("prior");
  expect(replay.duplicateGroups).toEqual(previous.duplicateGroups);
  input.sourceManifest = {
    repositories: [{ id: "synthetic-repository", revisions: ["b".repeat(40)] }],
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "current record/source binding",
  );
});

test("checkpoint persistence is acknowledged before scheduling the next review", async () => {
  const saving = deferred<void>();
  const release = deferred<void>();
  const store = new Checkpoints();
  let writes = 0;
  const originalSave = store.saveReview.bind(store);
  store.saveReview = async (key, binding, result) => {
    if (++writes === 1) {
      saving.resolve();
      await release.promise;
    }
    await originalSave(key, binding, result);
  };
  let calls = 0;
  const input = { ...options(), checkpointStore: store };
  input.reviewRunner = {
    async run(request) {
      calls++;
      return submission(request);
    },
  };
  const pending = deduplicateRecords(input);
  await saving.promise;
  expect(calls).toBe(1);
  expect(store.values.size).toBe(0);
  release.resolve();
  expect((await pending).deduplicationStatus).toBe("completed");
  expect(store.values.size).toBe(3);
});

test("failed reviews resume from durable screening checkpoints", async () => {
  const store = new Checkpoints();
  const input = { ...options(), checkpointStore: store };
  input.reviewRunner = {
    async run(request) {
      if (request.stage === "pair-review")
        throw new Error("Required revision unavailable");
      return submission(request);
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "Required revision unavailable",
  );
  expect(store.values.size).toBe(2);
  const resumed: string[] = [];
  input.reviewRunner = {
    async run(request) {
      resumed.push(request.stage);
      return submission(request);
    },
  };
  expect((await deduplicateRecords(input)).deduplicationStatus).toBe(
    "completed",
  );
  expect(resumed).toEqual(["pair-review"]);
});

test.each(["source", "tools", "settings", "scope"])(
  "changed %s binding invalidates cached reviews",
  async (changed) => {
    const store = new Checkpoints();
    const input = { ...options(), checkpointStore: store };
    let calls = 0;
    input.reviewRunner = {
      async run(request) {
        calls++;
        return submission(request);
      },
    };
    await deduplicateRecords(input);
    await deduplicateRecords(input);
    expect(calls).toBe(3);
    if (changed === "source") input.sourceManifest = { revision: "changed" };
    if (changed === "tools")
      input.sourceTools = [
        {
          namespace: "repository_source",
          name: "read",
          description: "Read approved source",
          inputSchema: { type: "object" },
          version: "2",
        },
      ];
    if (changed === "settings") input.settingsDigest = "changed";
    if (changed === "scope") input.scopeKey = "another-scope";
    await deduplicateRecords(input);
    expect(calls).toBe(6);
  },
);

test("injected runner receives frozen source tools and complete submission contracts", async () => {
  const input = options();
  input.sourceTools = [
    {
      namespace: "repository_source",
      name: "read",
      description: "Read a file at an approved immutable revision",
      inputSchema: {
        type: "object",
        properties: { revision: { type: "string" } },
      },
      version: "1",
    },
  ];
  const checkedManifests: unknown[] = [];
  input.verifySource = async (manifest) => {
    checkedManifests.push(manifest);
  };
  input.reviewRunner = {
    async run(request) {
      expect(request.sourceTools).toEqual(input.sourceTools!);
      expect(Object.isFrozen(request)).toBe(true);
      expect(Object.isFrozen(request.sourceTools[0]!.inputSchema)).toBe(true);
      expect(request.instructions.source).toContain("revision-scoped");
      expect(request.instructions.submission).toContain(
        "review_validator.submit_decisions",
      );
      expect(request.instructions.error).toContain("blocker");
      expect(checkedManifests.at(-1)).toEqual(request.sourceManifest);
      return submission(request);
    },
  };
  await deduplicateRecords(input);
  input.verifySource = async () => {
    throw new Error("Approved source is unavailable");
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "Approved source is unavailable",
  );
});

test("cancellation and source changes never save an incomplete verdict", async () => {
  const controller = new AbortController();
  const store = new Checkpoints();
  const input = {
    ...options(),
    checkpointStore: store,
    signal: controller.signal,
  };
  input.reviewRunner = {
    async run(request) {
      controller.abort("cancelled");
      return submission(request);
    },
  };
  await expect(deduplicateRecords(input)).rejects.toBe("cancelled");
  expect(store.values.size).toBe(0);
});

test("source drift after model execution prevents acknowledging the review", async () => {
  const store = new Checkpoints();
  let changed = false;
  const input = { ...options(), checkpointStore: store };
  input.verifySource = async () => {
    if (changed) throw new Error("Source changed during the review");
  };
  input.reviewRunner = {
    async run(request) {
      changed = true;
      return submission(request);
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow("Source changed");
  expect(store.values.size).toBe(0);
});

test("checkpoint write failures do not acknowledge completion and can be retried", async () => {
  const store = new Checkpoints();
  const save = store.saveReview.bind(store);
  store.saveReview = async () => {
    throw new Error("Checkpoint store unavailable");
  };
  const input = { ...options(), checkpointStore: store };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "Checkpoint store unavailable",
  );
  expect(store.values.size).toBe(0);
  store.saveReview = save;
  const result = await deduplicateRecords(input);
  expect(result.checkpointKeys).toHaveLength(3);
  expect(store.values.size).toBe(3);
});

test("raw SAME submissions must include a valid merged original finding", async () => {
  const input = options();
  input.reviewRunner = {
    async run(request) {
      return request.stage === "screening"
        ? submission(request)
        : {
            decision: "SAME",
            rationale: "One shared correction",
            canonicalFindingId: input.observations[0]!.findingId,
            mergedFinding: {},
          };
    },
  };
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "generated mergedFinding",
  );
});

test("conflicting persisted pair constraints cannot silently overwrite each other", async () => {
  const input = options();
  const previous = await deduplicateRecords(input);
  input.priorDecisions = [
    ...previous.pairOutcomes,
    { ...previous.pairOutcomes[0]!, decision: "DISTINCT" },
  ];
  await expect(deduplicateRecords(input)).rejects.toThrow(
    "Conflicting prior decisions",
  );
});

test("detailed outcomes preserve input order when screening completion order changes", async () => {
  async function run(order: [number, number]) {
    const input = options();
    input.concurrency = 2;
    const started = [deferred<void>(), deferred<void>()];
    const released = [deferred<void>(), deferred<void>()];
    const completed: number[] = [];
    input.reviewRunner = {
      async run(request) {
        if (request.stage === "screening") {
          const index = input.observations.findIndex(
            (value) => value.findingId === assigned(request)[0]!.findingId,
          );
          started[index]!.resolve();
          await released[index]!.promise;
          completed.push(index);
        }
        return submission(request);
      },
    };
    const pending = deduplicateRecords(input);
    await Promise.all(started.map((gate) => gate.promise));
    released[order[0]]!.resolve();
    released[order[1]]!.resolve();
    const result = await pending;
    expect(completed).toEqual(order);
    return result;
  }
  expect(await run([1, 0])).toEqual(await run([0, 1]));
});
