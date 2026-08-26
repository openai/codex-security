import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { CodexReview } from "../src/server/codex-review.js";
import { DeduplicationService } from "../src/server/deduplication.js";
import { findingNeighborhoods } from "../src/server/deduplication-neighbors.js";
import {
  CodexDeduplicationReviewer,
  pairKey,
  validateScreening,
  type DeduplicationReviewer,
  type DuplicateDecision,
  type ScreeningResult,
} from "../src/server/deduplication-reviewer.js";
import { FindingsError } from "../src/server/errors.js";
import type { EmbeddedFinding } from "../src/server/storage.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const document: FindingsDocument = JSON.parse(
  await readFile(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
    "utf8",
  ),
);
function entry(index: number, vector = [1, 0]): EmbeddedFinding {
  return {
    finding: {
      ...structuredClone(document.findings[0]!),
      findingId: `csf_${index.toString(16).padStart(24, "0")}`,
      occurrenceId: `occ_${index.toString(16).padStart(24, "0")}`,
      title: `Synthetic finding ${index}`,
      extensions: {
        originalEvidence: {
          text: `Complete report ${index}`,
          repository: `synthetic-${index}`,
        },
      },
    },
    embedding: { model: "synthetic", vector },
  };
}
const same: DuplicateDecision = {
  decision: "SAME",
  rationale: "One existing control corrects every path.",
};
const distinct: DuplicateDecision = {
  decision: "DISTINCT",
  rationale: "Independent controls require different corrections.",
};

function screening(
  findings: readonly Finding[],
  nominated: ReadonlySet<string>,
): ScreeningResult {
  return {
    decisions: findings.slice(1).map((finding) => {
      const findingIds: [string, string] = [
        findings[0]!.findingId,
        finding.findingId,
      ];
      return {
        findingIds,
        ...(nominated.has(pairKey(findingIds)) ? same : distinct),
      };
    }),
  };
}

test("ranks compatible cosine neighbors with the inclusive cutoff and a stable top 50", () => {
  const anchor = entry(0, [7, 0]);
  const boundary = entry(1, [0.55, Math.sqrt(1 - 0.55 ** 2)]);
  const below = entry(2, [0.54, Math.sqrt(1 - 0.54 ** 2)]);
  const otherModel = entry(3);
  otherModel.embedding.model = "other-model";
  const otherDimensions = entry(4, [1, 0, 0]);
  expect(
    findingNeighborhoods(
      [anchor, below, otherModel, otherDimensions, boundary],
      [anchor.finding.findingId],
    ),
  ).toEqual([[anchor.finding, boundary.finding]]);
  const tied = Array.from({ length: 60 }, (_, index) => entry(index + 1));
  expect(
    findingNeighborhoods([anchor, ...tied], [anchor.finding.findingId])[0],
  ).toEqual([
    anchor.finding,
    ...tied.slice(0, 50).map(({ finding }) => finding),
  ]);
});

test("missing or invalid embeddings never become evidence of uniqueness", () => {
  expect(() => findingNeighborhoods([], [entry(1).finding.findingId])).toThrow(
    "changed before deduplication",
  );
  const invalid = entry(1, [0, 0]);
  expect(() =>
    findingNeighborhoods([invalid], [invalid.finding.findingId]),
  ).toThrow("cannot be compared");
});

test("reviews nominated pairs once and judges the complete group before selecting its canonical", async () => {
  const entries = [entry(1), entry(2), entry(3), entry(4)];
  entries[1]!.finding.severity.level = "critical";
  const ids = entries.map(({ finding }) => finding.findingId);
  const nominations = new Set([
    pairKey([ids[0]!, ids[1]!]),
    pairKey([ids[1]!, ids[2]!]),
    pairKey([ids[0]!, ids[3]!]),
  ]);
  const phases: string[] = [];
  const reviewedPairs: string[] = [];
  const reviewer: DeduplicationReviewer = {
    async screen(findings) {
      phases.push("screen");
      expect(findings).toHaveLength(4);
      for (const finding of findings)
        expect(finding).toEqual(
          entries.find(
            (entry) => entry.finding.findingId === finding.findingId,
          )!.finding,
        );
      return screening(findings, nominations);
    },
    async reviewPair(findings) {
      phases.push("pair");
      const key = pairKey(findings.map((finding) => finding.findingId));
      reviewedPairs.push(key);
      return findings.some((finding) => finding.findingId === ids[3])
        ? distinct
        : same;
    },
    async reviewGroup(findings) {
      phases.push("group");
      expect(findings).toEqual([
        entries[1]!.finding,
        entries[0]!.finding,
        entries[2]!.finding,
      ]);
      return same;
    },
  };
  const service = new DeduplicationService(
    { listEmbedded: async () => entries },
    reviewer,
  );
  expect(await service.run([...ids, ids[0]!])).toEqual({
    uniqueFindingIds: [ids[1]!, ids[3]!],
    duplicateGroups: [[ids[1]!, ids[0]!, ids[2]!]],
    deduplicationStatus: "completed",
  });
  expect(new Set(reviewedPairs)).toEqual(nominations);
  expect(reviewedPairs).toHaveLength(3);
  expect(phases).toEqual([
    "screen",
    "screen",
    "screen",
    "screen",
    "pair",
    "pair",
    "pair",
    "group",
  ]);
});

test("whole-group rejection keeps a transitive chain separate", async () => {
  const entries = [entry(1), entry(2), entry(3)];
  const ids = entries.map(({ finding }) => finding.findingId);
  const service = new DeduplicationService(
    { listEmbedded: async () => entries },
    {
      async screen(findings) {
        return screening(
          findings,
          new Set([pairKey([ids[0]!, ids[1]!]), pairKey([ids[1]!, ids[2]!])]),
        );
      },
      async reviewPair() {
        return same;
      },
      async reviewGroup() {
        return distinct;
      },
    },
  );
  expect(await service.run(ids)).toEqual({
    uniqueFindingIds: ids,
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
});

test("matches an import to an existing canonical without judging a two-finding group again", async () => {
  const existing = entry(1);
  const imported = entry(2);
  imported.finding.severity.level = "low";
  const ids = [existing.finding.findingId, imported.finding.findingId];
  const service = new DeduplicationService(
    { listEmbedded: async () => [existing, imported] },
    {
      async screen(findings) {
        return screening(findings, new Set([pairKey(ids)]));
      },
      async reviewPair() {
        return same;
      },
      async reviewGroup() {
        throw new Error("Two-finding groups do not need another review");
      },
    },
  );
  expect(await service.run([imported.finding.findingId])).toEqual({
    uniqueFindingIds: [existing.finding.findingId],
    duplicateGroups: [ids],
    deduplicationStatus: "completed",
  });
});

test("empty and isolated imports avoid models, while review failures propagate", async () => {
  const first = entry(1);
  const second = entry(2, [0, 1]);
  const failure = new FindingsError(
    "deduplication_failed",
    "Synthetic review failed",
  );
  const reviewer: DeduplicationReviewer = {
    async screen() {
      throw failure;
    },
    async reviewPair() {
      throw failure;
    },
    async reviewGroup() {
      throw failure;
    },
  };
  const service = new DeduplicationService(
    { listEmbedded: async () => [first, second] },
    reviewer,
  );
  expect(await service.run([])).toEqual({
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect(
    (await service.run([first.finding.findingId])).uniqueFindingIds,
  ).toEqual([first.finding.findingId]);
  second.embedding.vector = [1, 0];
  await expect(service.run([first.finding.findingId])).rejects.toBe(failure);
});

test("validates complete screening assignments including off-edge nominations", () => {
  const findings = [entry(1).finding, entry(2).finding, entry(3).finding];
  const ids = findings.map((finding) => finding.findingId);
  const result = screening(findings, new Set([pairKey([ids[0]!, ids[1]!])]));
  result.decisions.push({ findingIds: [ids[1]!, ids[2]!], ...same });
  expect(validateScreening(result, findings)).toEqual(result);
  for (const invalid of [
    { decisions: result.decisions.slice(1) },
    {
      decisions: [
        ...result.decisions,
        { findingIds: [ids[1], ids[0]], ...same },
      ],
    },
    {
      decisions: [
        ...result.decisions.slice(0, 2),
        { findingIds: [ids[1], "outside"], ...same },
      ],
    },
    {
      decisions: [
        ...result.decisions.slice(0, 2),
        { findingIds: [ids[1], ids[2]], ...distinct },
      ],
    },
    {
      decisions: result.decisions.map((value) => ({
        ...value,
        rationale: " ",
      })),
    },
  ])
    expect(() => validateScreening(invalid, findings)).toThrow();
});

test("uses independent model assignments and complete originals without earlier rationales", async () => {
  const findings = [entry(1).finding, entry(2).finding, entry(3).finding];
  const calls: CodexReview<unknown>[] = [];
  const reviewer = new CodexDeduplicationReviewer({
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls.push(review);
      return review.validate(
        calls.length === 1
          ? {
              decisions: screening(findings, new Set()).decisions.map(
                (value) => ({
                  ...value,
                  rationale: "SCREENING_ONLY_RATIONALE",
                }),
              ),
            }
          : { ...same, rationale: "PAIR_ONLY_RATIONALE" },
      );
    },
  });
  await reviewer.screen(findings);
  await reviewer.reviewPair(findings.slice(0, 2));
  await reviewer.reviewGroup(findings);
  expect(calls.map(({ model, effort }) => [model, effort])).toEqual([
    ["gpt-5.6-luna", "xhigh"],
    ["gpt-5.6-sol", "ultra"],
    ["gpt-5.6-sol", "ultra"],
  ]);
  expect(calls[0]!.prompt).toContain(JSON.stringify({ findings }));
  expect(calls[1]!.prompt).toContain(
    JSON.stringify({ findings: findings.slice(0, 2) }),
  );
  expect(calls[2]!.prompt).toContain(JSON.stringify({ findings }));
  expect(
    calls
      .slice(1)
      .every(
        ({ prompt }) =>
          !prompt.includes("SCREENING_ONLY_RATIONALE") &&
          !prompt.includes("PAIR_ONLY_RATIONALE"),
      ),
  ).toBe(true);
});
