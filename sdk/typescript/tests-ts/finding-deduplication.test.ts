import { chmod, cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { CodexReview } from "../src/deduplication/codex-review.js";
import {
  contradictionFreeSubgroups,
  FindingDeduplicator,
} from "../src/deduplication/deduplication.js";
import {
  CodexDeduplicationReviewer,
  pairKey,
  screeningPairSlot,
  validateReview,
  validateScreening,
  type DeduplicationReviewer,
  type DuplicateDecision,
  type ScreeningResult,
} from "../src/deduplication/deduplication-reviewer.js";
import { CodexSecurityError } from "../src/errors.js";
import { FindingsClient } from "../src/findings-client.js";
import { deduplicateScanDirectory } from "../src/index.js";
import {
  deduplicateScanDirectoryInternal,
  deduplicateScanInternal,
} from "../src/deduplication/scan.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { JsonObject } from "../src/config.js";

const document: FindingsDocument = JSON.parse(
  await readFile(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
    "utf8",
  ),
);
function entry(index: number): Finding {
  return {
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
  };
}
function candidates(findings: Finding[]) {
  return {
    potentialDuplicates: async (id: string) => ({
      finding: findings.find((finding) => finding.findingId === id)!,
      potentialDuplicates: findings.filter(
        (finding) => finding.findingId !== id,
      ),
    }),
  };
}

function same(
  findings: readonly Finding[],
): Extract<DuplicateDecision, { decision: "SAME" }> {
  return {
    decision: "SAME",
    rationale: "One existing control corrects every path.",
    canonicalFindingId: findings[0]!.findingId,
    mergedFinding: {
      ...findings[0],
      title: findings.map((finding) => finding.title).join("; "),
      extensions: { ...findings[0]!.extensions, mergedOriginals: findings },
    },
  };
}
const distinct: DuplicateDecision = {
  decision: "DISTINCT",
  rationale: "Independent controls require different corrections.",
};

function screening(
  findings: readonly Finding[],
  nominated: ReadonlySet<string>,
): ScreeningResult {
  const decisions = findings.slice(1).map((finding, index) => {
    const pair: [string, string] = [findings[0]!.findingId, finding.findingId];
    return [
      screeningPairSlot(index),
      nominated.has(pairKey(pair))
        ? {
            decision: "SAME" as const,
            rationale: "One existing control corrects every path.",
          }
        : distinct,
    ] as const;
  });
  return {
    // Deliberately reverse insertion order: slot names, not object order, bind pairs.
    decisions: Object.fromEntries(decisions.reverse()),
  };
}

test("reviews nominated pairs once and groups non-conflicting accepted pairs by severity", async () => {
  const entries = [entry(1), entry(2), entry(3), entry(4)];
  entries[1]!.severity.level = "critical";
  const ids = entries.map((finding) => finding.findingId);
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
          entries.find((entry) => entry.findingId === finding.findingId)!,
        );
      return screening(findings, nominations);
    },
    async reviewPair(findings) {
      phases.push("pair");
      const key = pairKey(findings.map((finding) => finding.findingId));
      reviewedPairs.push(key);
      return findings.some((finding) => finding.findingId === ids[3])
        ? distinct
        : same(findings);
    },
  };
  const service = new FindingDeduplicator(candidates(entries), reviewer);
  expect(await service.run([...ids, ids[0]!])).toEqual({
    uniqueFindingIds: [ids[1]!, ids[2]!, ids[3]!],
    duplicateGroups: [[ids[1]!, ids[0]!]],
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
  ]);
});

test("groups accepted neighbors transitively without screening them as anchors", async () => {
  const entries = [entry(1), entry(2), entry(3)];
  const ids = entries.map((finding) => finding.findingId);
  const screened: string[] = [];
  const service = new FindingDeduplicator(candidates(entries), {
    async screen(findings) {
      screened.push(findings[0]!.findingId);
      return screening(
        findings,
        new Set([pairKey([ids[0]!, ids[1]!]), pairKey([ids[1]!, ids[2]!])]),
      );
    },
    async reviewPair(findings) {
      return same(findings);
    },
  });
  expect(await service.run([ids[1]!])).toEqual({
    uniqueFindingIds: [ids[0]!],
    duplicateGroups: [ids],
    deduplicationStatus: "completed",
  });
  expect(screened).toEqual([ids[1]!]);
});

test("an explicit DISTINCT screening vetoes the same unordered pair", async () => {
  const entries = [entry(1), entry(2)];
  const ids = entries.map((finding) => finding.findingId);
  for (const selected of [ids, [...ids].reverse()]) {
    let pairReviews = 0;
    const service = new FindingDeduplicator(candidates(entries), {
      async screen(findings) {
        return screening(
          findings,
          findings[0]!.findingId === ids[0]
            ? new Set([pairKey(ids)])
            : new Set(),
        );
      },
      async reviewPair() {
        pairReviews += 1;
        return same(entries);
      },
    });
    expect(await service.run(selected)).toEqual({
      uniqueFindingIds: selected,
      duplicateGroups: [],
      deduplicationStatus: "completed",
    });
    expect(pairReviews).toBe(0);
  }
});

test("does not connect DISTINCT findings through accepted transitive pairs", async () => {
  const entries = [entry(1), entry(2), entry(3)];
  const ids = entries.map((finding) => finding.findingId);
  const nominations = new Set([
    pairKey([ids[0]!, ids[1]!]),
    pairKey([ids[1]!, ids[2]!]),
  ]);
  const reviewedPairs: string[] = [];
  const service = new FindingDeduplicator(candidates(entries), {
    async screen(findings) {
      return screening(findings, nominations);
    },
    async reviewPair(findings) {
      reviewedPairs.push(pairKey(findings.map((finding) => finding.findingId)));
      return same(findings);
    },
  });
  expect(await service.run(ids)).toEqual({
    uniqueFindingIds: [ids[0]!, ids[2]!],
    duplicateGroups: [[ids[0]!, ids[1]!]],
    deduplicationStatus: "completed",
  });
  expect(new Set(reviewedPairs)).toEqual(nominations);
  expect(reviewedPairs).toHaveLength(2);
});

test("does not connect findings through a pair rejected by Sol", async () => {
  const entries = [entry(1), entry(2), entry(3)];
  const ids = entries.map((finding) => finding.findingId);
  const nominations = new Set([
    pairKey([ids[0]!, ids[1]!]),
    pairKey([ids[0]!, ids[2]!]),
    pairKey([ids[1]!, ids[2]!]),
  ]);
  const reviewedPairs: string[] = [];
  const service = new FindingDeduplicator(candidates(entries), {
    async screen(findings) {
      return screening(findings, nominations);
    },
    async reviewPair(findings) {
      const key = pairKey(findings.map((finding) => finding.findingId));
      reviewedPairs.push(key);
      return key === pairKey([ids[0]!, ids[2]!]) ? distinct : same(findings);
    },
  });
  expect(await service.run(ids)).toEqual({
    uniqueFindingIds: [ids[0]!, ids[2]!],
    duplicateGroups: [[ids[0]!, ids[1]!]],
    deduplicationStatus: "completed",
  });
  expect(new Set(reviewedPairs)).toEqual(nominations);
  expect(reviewedPairs).toHaveLength(3);
});

test("prefers the better-supported legal subgroup in a conflicted star", async () => {
  const entries = [entry(1), entry(2), entry(3), entry(4)];
  const ids = entries.map((finding) => finding.findingId);
  const nominations = new Set([
    pairKey([ids[0]!, ids[1]!]),
    pairKey([ids[0]!, ids[2]!]),
    pairKey([ids[0]!, ids[3]!]),
    pairKey([ids[2]!, ids[3]!]),
  ]);
  const neighborIndexes = [[1, 2, 3], [2, 3], [3], []];
  const service = new FindingDeduplicator(
    {
      async potentialDuplicates(findingId) {
        const index = ids.indexOf(findingId);
        return {
          finding: entries[index]!,
          potentialDuplicates: neighborIndexes[index]!.map(
            (neighbor) => entries[neighbor]!,
          ),
        };
      },
    },
    {
      async screen(findings) {
        return screening(findings, nominations);
      },
      async reviewPair(findings) {
        return same(findings);
      },
    },
  );
  expect(await service.run(ids)).toEqual({
    uniqueFindingIds: [ids[0]!, ids[1]!],
    duplicateGroups: [[ids[0]!, ids[2]!, ids[3]!]],
    deduplicationStatus: "completed",
  });
});

test("keeps disconnected groups ordered and conflict ties in finding insertion order", async () => {
  const aCenter = entry(30);
  const bCenter = entry(40);
  const aLeft = entry(10);
  const bLeft = entry(20);
  const aRight = entry(50);
  const bRight = entry(60);
  const cleanCenter = entry(80);
  const cleanNeighbor = entry(70);
  const isolated = entry(90);
  const entries = [
    aCenter,
    bCenter,
    aLeft,
    bLeft,
    aRight,
    bRight,
    cleanCenter,
    cleanNeighbor,
    isolated,
  ];
  for (const finding of entries) finding.severity.level = "medium";
  aLeft.severity.level = aRight.severity.level = "critical";
  const nominations = new Set(
    [
      [aCenter, aLeft],
      [aCenter, aRight],
      [bCenter, bLeft],
      [bCenter, bRight],
      [cleanCenter, cleanNeighbor],
    ].map((pair) => pairKey(pair.map((finding) => finding.findingId))),
  );
  const selected = [aCenter, bCenter, aLeft, bLeft, cleanCenter, isolated];
  for (const reverse of [false, true]) {
    const aNeighbors = reverse ? [aRight, aLeft] : [aLeft, aRight];
    const bNeighbors = reverse ? [bRight, bLeft] : [bLeft, bRight];
    const neighborhoods = new Map<string, Finding[]>([
      [
        aCenter.findingId,
        [
          bCenter,
          aNeighbors[0]!,
          bNeighbors[0]!,
          aNeighbors[1]!,
          bNeighbors[1]!,
          cleanCenter,
          cleanNeighbor,
          isolated,
        ],
      ],
      [bCenter.findingId, [bLeft, bRight]],
      [aLeft.findingId, [aRight]],
      [bLeft.findingId, [bRight]],
      [cleanCenter.findingId, [cleanNeighbor]],
    ]);
    const service = new FindingDeduplicator(
      {
        async potentialDuplicates(findingId) {
          return {
            finding: entries.find((entry) => entry.findingId === findingId)!,
            potentialDuplicates: neighborhoods.get(findingId) ?? [],
          };
        },
      },
      {
        async screen(findings) {
          return screening(findings, nominations);
        },
        async reviewPair(findings) {
          return same(findings);
        },
      },
    );
    expect(
      await service.run(selected.map((finding) => finding.findingId)),
    ).toEqual({
      uniqueFindingIds: (reverse
        ? [aRight, bCenter, aLeft, bLeft, cleanNeighbor, isolated]
        : [aLeft, bLeft, cleanNeighbor, isolated]
      ).map((finding) => finding.findingId),
      duplicateGroups: [
        [aNeighbors[0]!, aCenter],
        reverse ? [bCenter, bRight] : [bLeft, bCenter],
        [cleanNeighbor, cleanCenter],
      ].map((group) => group.map((finding) => finding.findingId)),
      deduplicationStatus: "completed",
    });
  }
});

test("scales contradiction grouping with conflict neighbors instead of all clusters", () => {
  const count = 200;
  const ids = Array.from(
    { length: count },
    (_value, index) => `finding-${index}`,
  );
  const samePairs: [string, string][] = [];
  for (let left = 0; left < count; left++) {
    for (let right = left + 1; right < Math.min(count, left + 51); right++)
      samePairs.push([ids[left]!, ids[right]!]);
  }
  const metrics = { candidateEvaluations: 0, conflictNeighborChecks: 0 };
  const groups = contradictionFreeSubgroups(
    ids,
    samePairs,
    [[ids[0]!, ids[count - 1]!]],
    undefined,
    metrics,
  );
  expect(groups).toHaveLength(1);
  expect(groups[0]!.size).toBe(count - 1);
  expect(groups[0]!.has(ids[0]!) && groups[0]!.has(ids[count - 1]!)).toBe(
    false,
  );
  expect(metrics.candidateEvaluations).toBeLessThan(count * samePairs.length);
  expect(metrics.conflictNeighborChecks).toBeLessThan(
    metrics.candidateEvaluations * 3,
  );
});

test("matches an import to an existing canonical", async () => {
  const existing = entry(1);
  const imported = entry(2);
  imported.severity.level = "low";
  const ids = [existing.findingId, imported.findingId];
  const service = new FindingDeduplicator(candidates([existing, imported]), {
    async screen(findings) {
      return screening(findings, new Set([pairKey(ids)]));
    },
    async reviewPair(findings) {
      return same(findings);
    },
  });
  expect(await service.run([imported.findingId])).toEqual({
    uniqueFindingIds: [existing.findingId],
    duplicateGroups: [ids],
    deduplicationStatus: "completed",
  });
});

test("empty and isolated imports avoid models, while review failures propagate", async () => {
  const first = entry(1);
  const second = entry(2);
  const findings = [first];
  const failure = new CodexSecurityError("Synthetic review failed");
  const reviewer: DeduplicationReviewer = {
    async screen() {
      throw failure;
    },
    async reviewPair() {
      throw failure;
    },
  };
  const service = new FindingDeduplicator(candidates(findings), reviewer);
  expect(await service.run([])).toEqual({
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect((await service.run([first.findingId])).uniqueFindingIds).toEqual([
    first.findingId,
  ]);
  findings.push(second);
  await expect(service.run([first.findingId])).rejects.toBe(failure);
});

test("validates exact screening slots without model-owned finding identity", () => {
  const findings = [entry(1), entry(2), entry(3)];
  const ids = findings.map((finding) => finding.findingId);
  const result = screening(findings, new Set([pairKey([ids[0]!, ids[1]!])]));
  expect(validateScreening(result, findings)).toEqual(result);
  expect(Object.keys(result.decisions)).toEqual(["pair-2", "pair-1"]);
  for (const invalid of [
    {
      decisions: { "pair-1": result.decisions["pair-1"] },
    },
    {
      decisions: {
        ...result.decisions,
        "pair-3": { decision: "DISTINCT", rationale: "Outside assignment." },
      },
    },
    {
      decisions: Object.fromEntries(
        Object.entries(result.decisions).map(([slot, decision]) => [
          slot,
          { ...decision, findingIds: [ids[0], "outside"] },
        ]),
      ),
    },
    {
      decisions: Object.fromEntries(
        Object.entries(result.decisions).map(([slot, decision]) => [
          slot,
          { ...decision, rationale: " " },
        ]),
      ),
    },
    {
      decisions: Object.fromEntries(
        Object.entries(result.decisions).map(([slot, decision]) => [
          slot,
          decision.decision === "SAME"
            ? { ...decision, canonicalFindingId: ids[0] }
            : decision,
        ]),
      ),
    },
  ])
    expect(() => validateScreening(invalid, findings)).toThrow();
});

test("keeps recommendation-only screening independent from complete pair reviews", async () => {
  const findings = [entry(1), entry(2), entry(3)];
  const linkedId = entry(4).findingId;
  findings[0]!.extensions = {
    ...findings[0]!.extensions,
    parent: { id: "external-parent", url: "https://issues.example/parent" },
    duplicateOf: { id: linkedId, url: "https://issues.example/duplicate" },
  };
  const calls: CodexReview<unknown>[] = [];
  const reviewer = new CodexDeduplicationReviewer({
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls.push(review);
      let result: ScreeningResult | DuplicateDecision;
      if (calls.length === 1) {
        result = screening(
          findings,
          new Set([
            pairKey(findings.slice(0, 2).map((finding) => finding.findingId)),
          ]),
        );
        for (const decision of Object.values(result.decisions))
          decision.rationale = "SCREENING_ONLY_RATIONALE";
      } else {
        result = same(
          calls.length === 2 ? findings.slice(0, 2) : findings.slice(1),
        );
        result.rationale = "PAIR_ONLY_RATIONALE";
        result.mergedFinding["title"] = "PAIR_ONLY_MERGED";
      }
      const validateSchema = new Ajv2020({ strict: false }).compile(
        review.schema as object,
      );
      expect(validateSchema(result)).toBe(true);
      if ("decisions" in result) {
        expect(
          validateSchema({
            decisions: { "pair-1": result.decisions["pair-1"] },
          }),
        ).toBe(false);
        expect(
          validateSchema({
            decisions: {
              ...result.decisions,
              "pair-3": result.decisions["pair-1"],
            },
          }),
        ).toBe(false);
        const decisionsWithFindingIds = Object.fromEntries(
          Object.entries(result.decisions).map(([slot, decision]) => [
            slot,
            {
              ...decision,
              findingIds: [findings[0]!.findingId, findings[1]!.findingId],
            },
          ]),
        );
        expect(validateSchema({ decisions: decisionsWithFindingIds })).toBe(
          false,
        );
        for (const field of ["canonicalFindingId", "mergedFinding"] as const) {
          const invalid = {
            decisions: Object.fromEntries(
              Object.entries(result.decisions).map(([slot, decision]) => [
                slot,
                decision.decision === "SAME"
                  ? { ...decision, [field]: null }
                  : decision,
              ]),
            ),
          };
          expect(validateSchema(invalid)).toBe(false);
        }
      } else {
        for (const field of ["canonicalFindingId", "mergedFinding"] as const) {
          for (const value of [undefined, null]) {
            const invalid = { ...result, [field]: value };
            expect(validateSchema(invalid)).toBe(false);
          }
        }
      }
      return review.validate(result);
    },
  });
  await reviewer.screen(findings);
  await reviewer.reviewPair(findings.slice(0, 2));
  await reviewer.reviewPair(findings.slice(1));
  expect(
    calls.map(({ stage, model, effort }) => [stage, model, effort]),
  ).toEqual([
    ["screening", "gpt-5.6-luna", "xhigh"],
    ["pair-review", "gpt-5.6-sol", "xhigh"],
    ["pair-review", "gpt-5.6-sol", "xhigh"],
  ]);
  expect(calls[0]!.prompt).toContain(JSON.stringify({ findings }));
  expect(calls[1]!.prompt).toContain(
    JSON.stringify({ findings: findings.slice(0, 2) }),
  );
  expect(calls[2]!.prompt).toContain(
    JSON.stringify({ findings: findings.slice(1) }),
  );
  expect(
    calls
      .slice(1)
      .every(
        ({ prompt }) =>
          !prompt.includes("SCREENING_ONLY_RATIONALE") &&
          !prompt.includes("PAIR_ONLY_RATIONALE") &&
          !prompt.includes("PAIR_ONLY_MERGED"),
      ),
  ).toBe(true);
  expect(calls[0]!.prompt).not.toContain("canonicalFindingId");
  expect(calls[0]!.prompt).not.toContain("mergedFinding");
  for (const { prompt } of calls) {
    expect(prompt).toMatch(/incomplete or insufficient.*DISTINCT/);
    expect(prompt).toMatch(/failure prevents a required check.*submit_error/);
    expect(prompt).toMatch(
      /failed optional lookup.*continue when other available evidence is sufficient/,
    );
  }
  for (const { prompt } of calls.slice(1)) {
    expect(prompt).toMatch(/exactly the two supplied findings/);
    expect(prompt).toMatch(
      /Linked parent tickets, duplicate targets, and related-ticket records are metadata/,
    );
    expect(prompt).toMatch(/Do not fetch those records or expand the pair/);
    expect(prompt).toMatch(
      /unsupplied linked duplicate target is not automatically the canonical finding.*not itself an error/,
    );
    expect(prompt).toMatch(
      /Necessary source-code investigation.*remains allowed/,
    );
  }
  expect(() =>
    validateReview(
      {
        ...same(findings.slice(0, 2)),
        canonicalFindingId: linkedId,
        mergedFinding: { ...findings[0], findingId: linkedId },
      },
      findings.slice(0, 2),
    ),
  ).toThrow("The canonical finding must belong to the assigned findings.");
});

test("accepts complete canonical and merged reviews and rejects invalid assignments", () => {
  const findings = [entry(1), entry(2)];
  const result = {
    ...same(findings),
    mergedFinding: {
      ...findings[0],
      extensions: { preserved: "complete original evidence" },
    },
  };
  expect(validateReview(result, findings)).toEqual(result);
  expect(validateReview(distinct, findings)).toEqual(distinct);
  expect(
    validateReview(
      { ...distinct, canonicalFindingId: null, mergedFinding: null },
      findings,
    ),
  ).toEqual({
    ...distinct,
    canonicalFindingId: null,
    mergedFinding: null,
  });
  for (const invalid of [
    { decision: "SAME", rationale: "Missing canonical and merged finding." },
    { ...result, canonicalFindingId: undefined },
    { ...result, canonicalFindingId: null },
    { ...result, mergedFinding: undefined },
    { ...result, mergedFinding: null },
    { ...result, mergedFinding: {} },
    {
      ...result,
      mergedFinding: {
        ...result.mergedFinding,
        findingId: findings[1]!.findingId,
      },
    },
    { ...result, canonicalFindingId: "outside" },
    {
      ...result,
      canonicalFindingId: undefined,
      canonicalIssueId: result.canonicalFindingId,
    },
    { ...result, decision: "DISTINCT" },
  ]) {
    expect(() => validateReview(invalid, findings)).toThrow();
  }
});

test("resolves a saved scan and retrieves its IDs without uploading or modifying artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dedupe-scan-"));
  try {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), directory, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const original = await readFile(join(directory, "findings.json"), "utf8");
    for (const [requestedId, allRepositories] of [
      ["scan_example", false],
      ["latest", false],
      ["scan_example_001", true],
    ] as const) {
      const commands: string[][] = [];
      const requests: string[] = [];
      const result = await deduplicateScanInternal(
        requestedId,
        { findingsUrl: "http://synthetic.test/api", allRepositories },
        {
          currentDirectory: () => directory,
          runWorkbench: async (args): Promise<JsonObject> => {
            commands.push([...args]);
            return args[0] === "list-scans"
              ? { scans: [{ scanId: "scan_example_001" }] }
              : {
                  scan: {
                    scanId: "scan_example_001",
                    scanDir: directory,
                    progress: { status: "complete" },
                  },
                };
          },
          fetch: async (url, options) => {
            requests.push(String(url));
            expect(options?.method).toBeUndefined();
            expect(options?.body).toBeUndefined();
            expect(options?.headers).toBeUndefined();
            return Response.json({
              finding: document.findings[0],
              potentialDuplicates: [],
            });
          },
          reviewer: {
            async screen() {
              throw new Error("No review for an empty neighborhood");
            },
            async reviewPair() {
              throw new Error("No pair to review");
            },
          },
        },
      );
      expect(result).toEqual({
        scanId: "scan_example_001",
        uniqueFindingIds: document.findings.map((finding) => finding.findingId),
        duplicateGroups: [],
        deduplicationStatus: "completed",
      });
      expect(commands.at(-1)).toEqual([
        "get-scan",
        "--scan-id",
        requestedId === "latest" ? "scan_example_001" : requestedId,
      ]);
      if (requestedId === "latest")
        expect(commands[0]).toEqual([
          "list-scans",
          "--repository",
          directory,
          "--status",
          "complete",
        ]);
      expect(requests).toEqual([
        `http://synthetic.test/api/v1/finding/${document.findings[0]!.findingId}/potential-duplicates?${allRepositories ? "allRepositories=true" : "repositoryId=target_sha256_example"}`,
      ]);
    }
    expect(await readFile(join(directory, "findings.json"), "utf8")).toBe(
      original,
    );
    await expect(
      deduplicateScanInternal(
        "wrong-scan",
        { findingsUrl: "http://synthetic.test" },
        {
          runWorkbench: async () => ({
            scan: {
              scanId: "wrong-scan",
              scanDir: directory,
              progress: { status: "complete" },
            },
          }),
          fetch: async () => {
            throw new Error(
              "Must not retrieve candidates for a mismatched scan",
            );
          },
        },
      ),
    ).rejects.toThrow("do not match selected scan");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deduplicates an explicit sealed scan directory without reading scan history", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dedupe-directory-"));
  const repository = await mkdtemp(join(tmpdir(), "dedupe-repository-"));
  try {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), directory, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const original = await readFile(join(directory, "findings.json"), "utf8");
    const commands: string[][] = [];
    const requests: string[] = [];
    const result = await deduplicateScanDirectoryInternal(
      directory,
      {
        repository,
        expectedScanId: "scan_example_001",
        findingsUrl: "http://synthetic.test/api",
      },
      {
        runWorkbench: async (args) => {
          commands.push([...args]);
          throw new Error("Explicit scan directories must not read history");
        },
        fetch: async (url, options) => {
          requests.push(String(url));
          expect(options?.method).toBeUndefined();
          return Response.json({
            finding: document.findings[0],
            potentialDuplicates: [],
          });
        },
        reviewer: {
          async screen() {
            throw new Error("No review for an empty neighborhood");
          },
          async reviewPair() {
            throw new Error("No pair to review");
          },
        },
      },
    );
    expect(result).toEqual({
      scanId: "scan_example_001",
      uniqueFindingIds: document.findings.map((finding) => finding.findingId),
      duplicateGroups: [],
      deduplicationStatus: "completed",
    });
    expect(commands).toEqual([]);
    expect(requests).toEqual([
      `http://synthetic.test/api/v1/finding/${document.findings[0]!.findingId}/potential-duplicates?repositoryId=target_sha256_example`,
    ]);
    expect(await readFile(join(directory, "findings.json"), "utf8")).toBe(
      original,
    );
    await expect(
      deduplicateScanDirectory(directory, {
        repository,
        expectedScanId: "scan_other",
        findingsUrl: "http://synthetic.test/api",
      }),
    ).rejects.toThrow("do not match selected scan");
  } finally {
    await Promise.all([
      rm(directory, { recursive: true, force: true }),
      rm(repository, { recursive: true, force: true }),
    ]);
  }
});

test("lookup failures and cancellation never produce a completed uniqueness result", async () => {
  for (const status of [404, 502]) {
    const client = new FindingsClient(
      "http://synthetic.test",
      undefined,
      async () => new Response("", { status }),
    );
    await expect(
      client.potentialDuplicates(entry(1).findingId, { allRepositories: true }),
    ).rejects.toThrow(`HTTP ${status}`);
  }
  const controller = new AbortController();
  controller.abort("synthetic cancellation");
  await expect(
    new FindingDeduplicator(
      candidates([]),
      {} as DeduplicationReviewer,
      controller.signal,
    ).run([]),
  ).rejects.toBe("synthetic cancellation");
  await expect(
    deduplicateScanInternal("scan-id", {
      findingsUrl: "http://synthetic.test",
      signal: controller.signal,
    }),
  ).rejects.toBe("synthetic cancellation");
});

test("writes accepted groups only after all reviews and fails on review or write-back errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dedupe-writeback-"));
  try {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), directory, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const findings = [document.findings[0]!, entry(2), entry(3)];
    const ids = findings.map((finding) => finding.findingId);
    for (const failure of ["none", "write", "review"]) {
      const phases: string[] = [];
      const controller = new AbortController();
      const result = deduplicateScanInternal(
        "scan_example_001",
        {
          findingsUrl: "http://synthetic.test/api/",
          signal: controller.signal,
        },
        {
          runWorkbench: async () => ({
            scan: {
              scanId: "scan_example_001",
              scanDir: directory,
              progress: { status: "complete" },
            },
          }),
          fetch: async (url, options) => {
            expect(options.signal).toBe(controller.signal);
            if (options.method === "POST") {
              phases.push("store");
              expect(String(url)).toBe(
                "http://synthetic.test/api/v1/dedupe-groups",
              );
              expect(JSON.parse(options.body as string)).toEqual({
                groups: [[...ids].sort()],
              });
              return Response.json([], {
                status: failure === "write" ? 409 : 201,
              });
            }
            phases.push("lookup");
            return Response.json({
              finding: findings[0],
              potentialDuplicates: findings.slice(1),
            });
          },
          reviewer: {
            async screen(values) {
              phases.push("screen");
              return screening(
                values,
                new Set(
                  values
                    .slice(1)
                    .map((value) => pairKey([ids[0]!, value.findingId])),
                ),
              );
            },
            async reviewPair(values) {
              phases.push("pair");
              if (failure === "review" && values[1]!.findingId === ids[2])
                throw new CodexSecurityError(
                  "Required source revision could not be read.",
                );
              return same(values);
            },
          },
        },
      );
      if (failure === "none") {
        expect((await result).duplicateGroups).toEqual([[...ids].sort()]);
      } else if (failure === "review") {
        await expect(result).rejects.toThrow(
          "Required source revision could not be read.",
        );
      } else {
        await expect(result).rejects.toThrow(
          "POST /v1/dedupe-groups failed (HTTP 409)",
        );
      }
      expect(phases).toEqual([
        "lookup",
        "screen",
        "pair",
        "pair",
        ...(failure === "review" ? [] : ["store"]),
      ]);
    }
    expect(
      JSON.parse(await readFile(join(directory, "findings.json"), "utf8")),
    ).toEqual(document);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
