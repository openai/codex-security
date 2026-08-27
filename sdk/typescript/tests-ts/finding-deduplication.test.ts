import { chmod, cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import type { Finding, FindingsDocument } from "../src/models.js";
import type { CodexReview } from "../src/deduplication/codex-review.js";
import { FindingDeduplicator } from "../src/deduplication/deduplication.js";
import {
  CodexDeduplicationReviewer,
  pairKey,
  validateReview,
  validateScreening,
  type DeduplicationReviewer,
  type DuplicateDecision,
  type ScreeningResult,
} from "../src/deduplication/deduplication-reviewer.js";
import { CodexSecurityError } from "../src/errors.js";
import { FindingsClient } from "../src/findings-client.js";
import { deduplicateScanInternal } from "../src/deduplication/scan.js";
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
  return {
    decisions: findings.slice(1).map((finding) => {
      const findingIds: [string, string] = [
        findings[0]!.findingId,
        finding.findingId,
      ];
      return {
        findingIds,
        ...(nominated.has(pairKey(findingIds))
          ? same([findings[0]!, finding])
          : distinct),
      };
    }),
  };
}

test("reviews nominated pairs once and groups accepted pairs by reported severity", async () => {
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

test("validates complete screening assignments and rejects non-anchor pairs", () => {
  const findings = [entry(1), entry(2), entry(3)];
  const ids = findings.map((finding) => finding.findingId);
  const result = screening(findings, new Set([pairKey([ids[0]!, ids[1]!])]));
  expect(validateScreening(result, findings)).toEqual(result);
  for (const invalid of [
    { decisions: result.decisions.slice(1) },
    {
      decisions: [
        ...result.decisions,
        { findingIds: [ids[1], ids[0]], ...same(findings.slice(0, 2)) },
      ],
    },
    {
      decisions: [
        ...result.decisions.slice(0, 2),
        { findingIds: [ids[0], "outside"], ...same(findings.slice(0, 2)) },
      ],
    },
    {
      decisions: [
        ...result.decisions,
        { findingIds: [ids[1], ids[2]], ...same(findings.slice(1)) },
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
    {
      decisions: result.decisions.map((value) =>
        value.decision === "SAME"
          ? { ...value, canonicalFindingId: ids[2] }
          : value,
      ),
    },
  ])
    expect(() => validateScreening(invalid, findings)).toThrow();
});

test("requires complete SAME tool outputs and keeps reviews independent", async () => {
  const findings = [entry(1), entry(2), entry(3)];
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
        for (const decision of result.decisions) {
          decision.rationale = "SCREENING_ONLY_RATIONALE";
          if (decision.decision === "SAME")
            decision.mergedFinding["title"] = "SCREENING_ONLY_MERGED";
        }
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
      for (const field of ["canonicalFindingId", "mergedFinding"] as const) {
        for (const value of [undefined, null]) {
          const invalid =
            "decisions" in result
              ? {
                  decisions: result.decisions.map((decision) =>
                    decision.decision === "SAME"
                      ? { ...decision, [field]: value }
                      : decision,
                  ),
                }
              : { ...result, [field]: value };
          expect(validateSchema(invalid)).toBe(false);
        }
      }
      return review.validate(result);
    },
  });
  await reviewer.screen(findings);
  await reviewer.reviewPair(findings.slice(0, 2));
  await reviewer.reviewPair(findings.slice(1));
  expect(calls.map(({ model, effort }) => [model, effort])).toEqual([
    ["gpt-5.6-luna", "xhigh"],
    ["gpt-5.6-sol", "xhigh"],
    ["gpt-5.6-sol", "xhigh"],
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
          !prompt.includes("SCREENING_ONLY_MERGED") &&
          !prompt.includes("PAIR_ONLY_MERGED"),
      ),
  ).toBe(true);
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
    expect(() =>
      validateScreening(
        {
          decisions: [
            {
              ...invalid,
              findingIds: findings.map((finding) => finding.findingId),
            },
          ],
        },
        findings,
      ),
    ).toThrow();
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

test("writes accepted groups only after all reviews and fails when write-back fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dedupe-writeback-"));
  try {
    await cp(join(PLUGIN_ROOT, "examples/completed-scan"), directory, {
      recursive: true,
    });
    if (process.platform !== "win32") await chmod(directory, 0o700);
    const findings = [document.findings[0]!, entry(2), entry(3)];
    const ids = findings.map((finding) => finding.findingId);
    for (const status of [201, 409]) {
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
              return Response.json([], { status });
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
              return same(values);
            },
          },
        },
      );
      if (status === 201) {
        expect((await result).duplicateGroups).toEqual([[...ids].sort()]);
      } else {
        await expect(result).rejects.toThrow(
          "POST /v1/dedupe-groups failed (HTTP 409)",
        );
      }
      expect(phases).toEqual(["lookup", "screen", "pair", "pair", "store"]);
    }
    expect(
      JSON.parse(await readFile(join(directory, "findings.json"), "utf8")),
    ).toEqual(document);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
