import { join, dirname } from "node:path";
import { mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import { build } from "esbuild";
import {
  combineScanCoverage,
  createScanMerger,
  reconcileScanMerge,
  materializeScanAggregate,
  hydrateScanAggregate,
  serializeScanAggregate,
  scanAggregateRevisionArtifacts,
  saveScanMergeSources,
  type ScanMergeInput,
} from "../src/scan-merge.js";
import {
  prepareSemanticScanDraft,
  scanFindingIdentity,
  type JsonObject,
  type SemanticCoverage,
  type SemanticFinding,
} from "../src/scan-semantics.js";
import { semanticFinding, semanticCoverage } from "./helpers/semantic-scan.js";

const parent = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const targetContract = {
  target: {
    allowedKinds: ["repository"],
    targetId: "fixture",
    displayName: "Fixture",
  },
  scope: {
    requiredIncludePaths: ["src"],
    requiredExcludePaths: ["vendor"],
  },
};
const root = fileURLToPath(
  new URL("./fixtures/merge-parent/", import.meta.url),
);
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const mergeOptions = { contextPath: join(root, "merge-context.json") };
const merge = reconcileScanMerge.bind(undefined, parent);
let mergeScans: Awaited<ReturnType<typeof createScanMerger>>;
beforeAll(async () => {
  mergeScans = await createScanMerger(pluginRoot);
});
function finding(anchor = "shared", extra: Partial<SemanticFinding> = {}) {
  return semanticFinding({ identity: { anchor }, ...extra });
}
function child(
  scanId: string,
  findings: SemanticFinding[] = [finding()],
  coverage: JsonObject = {},
): ScanMergeInput {
  return {
    scanId,
    scanDir: join(root, "artifacts", "scans", scanId),
    sourceFindings: structuredClone(findings),
    draft: {
      scanId: parent,
      findings: findings.map((value, index) => ({
        ...structuredClone(value),
        provenance: {
          ...value.provenance,
          sourceFindingIds: [`${scanId}:${index}`],
        },
      })),
      coverage: semanticCoverage(coverage),
    },
  };
}

describe("local scan merging", () => {
  test("keeps immutable originals once and materializes only public exports", () => {
    const input = child("a", [
      finding("shared", { extensions: { detail: "exact" } }),
    ]);
    const result = merge([["a:0"]], [input], null);
    expect(result.aggregate.sourceFindings).toEqual({
      "a:0": input.sourceFindings[0]!,
    });
    expect(
      result.aggregate.findings[0]!.provenance.sourceFindings,
    ).toBeUndefined();
    const exported = materializeScanAggregate(result.aggregate);
    expect(exported).not.toHaveProperty("sourceFindings");
    expect(exported.findings[0]!.provenance.sourceFindings).toEqual([
      { id: "a:0", finding: input.sourceFindings[0]! },
    ]);
    exported.findings[0]!.title = "changed export";
    result.aggregate.sourceFindings["a:0"]!["title"] = "changed internal copy";
    expect(input.sourceFindings[0]!["title"]).toBe("Unsafe output");
    expect(result.aggregate.findings[0]!.title).toBe("Unsafe output");
  });

  test.each([
    [[["unknown:0"]], "unknown source"],
    [[["a:0"], ["a:0"]], "more than once"],
    [[], "unaccounted"],
  ])("rejects incomplete or invalid source partitions %#", (raw, message) => {
    expect(() => merge(raw, [child("a")], null)).toThrow(String(message));
  });

  test("rejects unfinished inputs and a different parent", () => {
    const input = child("a");
    input.draft.complete = false;
    expect(() => merge([["a:0"]], [input], null)).toThrow("completed inputs");
    delete input.draft.complete;
    input.draft.scanId = "different";
    expect(() => merge([["a:0"]], [input], null)).toThrow("different parent");
  });

  test("retains accepted identities, prevents splits, and attributes novel groups once", () => {
    const a = child("a"),
      b = child("b");
    const first = merge([["a:0", "b:0"]], [a, b], null);
    expect(first.newFindingScanIds).toEqual(["a"]);
    expect(() => merge([["a:0"], ["b:0"]], [], first.aggregate)).toThrow(
      "split",
    );
    const later = merge(
      [["c:0"], ["d:0", "b:0", "a:0"]],
      [child("c"), child("d")],
      first.aggregate,
    );
    expect(later.newFindingScanIds).toEqual(["c"]);
    expect(scanFindingIdentity(later.aggregate.findings[1]!)).toBe(
      scanFindingIdentity(first.aggregate.findings[0]!),
    );
    expect(
      new Set(later.aggregate.findings.map(scanFindingIdentity)).size,
    ).toBe(2);
    expect(
      later.aggregate.findings.every(
        (f) => f.provenance["previousFindings"] === undefined,
      ),
    ).toBe(true);
  });

  test("combines repairs and locations and retains the highest observed severity", () => {
    const a = child("a", [
      finding("a", {
        remediation: "Repair first",
        severity: { level: "low" },
        remediationTests: ["test first"],
      }),
    ]);
    const b = child("b", [
      finding("b", {
        remediation: "Repair second",
        locations: [{ path: "src/second.ts", startLine: 2 }],
        preventiveControls: ["control second"],
      }),
    ]);
    const result = merge([["a:0", "b:0"]], [a, b], null).aggregate.findings[0]!;
    expect(result.remediation).toBe("Repair first\n\nRepair second");
    expect(result.locations).toHaveLength(2);
    expect(result.remediationTests).toEqual(["test first"]);
    expect(result.preventiveControls).toEqual(["control second"]);
    expect(result.severity.level).toBe("high");
  });

  test("merges accepted aliases while preserving every original identity in exports", () => {
    const inputs = [
      child("a", [finding("alias-a")]),
      child("b", [finding("alias-b")]),
    ];
    const previous = merge([["a:0"], ["b:0"]], inputs, null).aggregate;
    const result = merge([["b:0", "a:0"]], [], previous);
    expect(result.newFindingScanIds).toEqual([]);
    expect(result.aggregate.findings[0]!.identity).toEqual(
      previous.findings[0]!.identity,
    );
    expect(
      materializeScanAggregate(result.aggregate).findings[0]!.provenance
        .sourceFindings,
    ).toHaveLength(2);
  });

  test("does not repeat accepted summary and repair paragraphs in later observations", () => {
    const a = child("a", [
      finding("a", { summary: "First detail", remediation: "First repair" }),
    ]);
    const b = child("b", [
      finding("b", {
        summary: "Second detail\n\nShared detail",
        remediation: "Second repair\n\nShared repair",
      }),
    ]);
    const first = merge([["a:0", "b:0"]], [a, b], null).aggregate;
    first.findings[0]!.summary += "\n\nAccepted context";
    const before = structuredClone(first);
    const repeated = merge(
      [["a:0", "b:0", "c:0"]],
      [child("c", [b.draft.findings[0]!])],
      first,
    ).aggregate;
    expect(repeated.findings[0]!.summary).toBe(
      "First detail\n\nSecond detail\n\nShared detail\n\nAccepted context",
    );
    expect(repeated.findings[0]!.remediation).toBe(
      "First repair\n\nSecond repair\n\nShared repair",
    );
    expect(first).toEqual(before);
    expect(
      materializeScanAggregate(repeated).findings[0]!.provenance.sourceFindings,
    ).toHaveLength(3);
  });

  test("stores accepted revisions once without recursive histories", () => {
    const first = merge([["a:0"]], [child("a")], null).aggregate;
    const second = merge([["a:0", "b:0"]], [child("b")], first).aggregate;
    expect(Object.values(second.revisions!)).toEqual(first.findings);
    expect(
      materializeScanAggregate(second).findings[0]!.provenance[
        "previousFindings"
      ],
    ).toEqual(first.findings);
    const repeated = merge([["a:0", "b:0"]], [], second).aggregate;
    expect(repeated.revisions).toEqual(second.revisions);
    expect(repeated.findings[0]!.provenance["revisionIds"]).toEqual(
      second.findings[0]!.provenance["revisionIds"],
    );
  });

  test("round-trips aggregate references without copying original payloads into checkpoints", async () => {
    const directory = await mkdtemp(join(tmpdir(), "merge-references-"));
    try {
      const a = child("a"),
        b = child("b");
      const first = merge([["a:0"]], [a], null).aggregate;
      const aggregate = {
        ...merge([["a:0", "b:0"]], [b], first).aggregate,
        coverage: semanticCoverage(),
      };
      const artifacts = scanAggregateRevisionArtifacts(aggregate, new Set());
      await saveScanMergeSources([a, b], {
        async restore() {
          throw new Error("Batch required");
        },
        async restoreMany(sources) {
          artifacts.push(
            ...sources.map(({ path, contents }) => ({
              path,
              contents: Buffer.from(contents),
            })),
          );
        },
      });
      for (const artifact of artifacts) {
        await mkdir(dirname(join(directory, artifact.path)), {
          recursive: true,
          mode: 0o700,
        });
        await writeFile(join(directory, artifact.path), artifact.contents, {
          mode: 0o600,
        });
      }
      const stored = serializeScanAggregate(aggregate);
      expect(stored).not.toHaveProperty("sourceFindings");
      expect(stored).not.toHaveProperty("revisions");
      expect(stored.sourceFindingIds).toEqual(["a:0", "b:0"]);
      expect(await hydrateScanAggregate(directory, stored)).toEqual(aggregate);
      expect(
        scanAggregateRevisionArtifacts(aggregate, new Set(stored.revisionIds)),
      ).toEqual([]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("requires reconciled context when empty scans disagree", async () => {
    const a = child("a", []),
      b = child("b", []);
    a.draft.threatModel = { summary: "First context" };
    b.draft.threatModel = { summary: "Second context" };
    await expect(
      mergeScans(
        parent,
        [a, b],
        null,
        new AbortController().signal,
        async () => ({}),
        mergeOptions,
      ),
    ).rejects.toThrow("ambiguous threatModel");
  });

  test("shared matching needs no model for a first report or compatible empty scans", async () => {
    const noModel = async () => {
      throw new Error("No model call expected");
    };
    const match = (
      inputs: ScanMergeInput[],
      previous: ReturnType<typeof merge>["aggregate"] | null = null,
    ) =>
      mergeScans(
        parent,
        inputs,
        previous,
        new AbortController().signal,
        noModel,
        mergeOptions,
      );
    const a = child("a");
    const first = await match([a]);
    const previous = first.aggregate;
    expect(first).toEqual(merge([["a:0"]], [a], null));
    expect(await match([child("a", []), child("b", [])])).toEqual(
      merge([], [], null),
    );
    expect(await match([a, child("b", [])])).toEqual(first);
    expect(await match([child("b", []), a])).toEqual(first);
    expect((await match([child("b", [])], previous)).aggregate).toEqual(
      previous,
    );
  });

  test("unions already projected coverage without mutating inputs or namespacing twice", () => {
    const first = child("first", [], {
      completeness: "partial",
      surfaces: [
        {
          id: "first/api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/first/artifacts/review.json"],
        },
      ],
      deferred: [
        {
          candidateId: "first-candidate",
          reason: "Check ownership.",
          surfaceIds: ["first/api"],
        },
      ],
      openQuestions: ["Can an untrusted caller reach the route?"],
    });
    const second = child("second", [], {
      surfaces: [
        {
          id: "second/api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/second/artifacts/review.json"],
        },
      ],
      deferred: [
        {
          candidateId: "second-candidate",
          reason: "Check ownership.",
          surfaceIds: ["second/api"],
        },
      ],
      openQuestions: first.draft.coverage.openQuestions,
    });
    const before = structuredClone([first, second]);
    const combined = combineScanCoverage(
      [first.draft.coverage, second.draft.coverage],
      ["One interrupted scan retains unfinished work."],
    );
    expect(combined.completeness).toBe("partial");
    expect(combined.surfaces).toEqual([
      ...first.draft.coverage.surfaces,
      ...second.draft.coverage.surfaces,
    ]);
    expect(combined.deferred).toEqual([
      ...first.draft.coverage.deferred,
      ...second.draft.coverage.deferred,
      { reason: "One interrupted scan retains unfinished work." },
    ]);
    expect(combined.openQuestions).toHaveLength(1);
    combined.surfaces[0]!.id = "changed";
    expect([first, second]).toEqual(before);
    expect(
      combineScanCoverage([
        child("unknown", [], { completeness: "unknown" }).draft.coverage,
      ]).completeness,
    ).toBe("unknown");
    expect(
      combineScanCoverage([child("empty", []).draft.coverage]).completeness,
    ).toBe("complete");
    expect(combineScanCoverage([], ["No scan completed."]).completeness).toBe(
      "partial",
    );
  });

  test("combines large coverage and unresolved lists on Node without argument limits", async () => {
    // Bun accepts more function arguments than supported Node runtimes do.
    const bundled = await build({
      stdin: {
        resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
        contents: `
import assert from "node:assert/strict";
import { combineScanCoverage } from "./scan-merge.ts";
const count = 150_000;
const coverage = {
  completeness: "complete",
  surfaces: Array.from({ length: count }, (_, index) => ({
    id: "child/surface-" + index, label: "Surface " + index, disposition: "no_issue_found",
  })),
  explicitExclusions: [],
  deferred: Array.from({ length: count }, (_, index) => ({ reason: "Deferred " + index })),
};
const unresolved = Array.from({ length: count }, (_, index) => "Unresolved " + index);
const combined = combineScanCoverage([coverage], unresolved);
assert.equal(combined.completeness, "partial");
assert.deepEqual(combined.surfaces, coverage.surfaces);
assert.deepEqual(combined.deferred.slice(0, count), coverage.deferred);
assert.deepEqual(combined.deferred.slice(count), unresolved.map(reason => ({ reason })));
combined.surfaces[0].label = "Changed";
assert.equal(coverage.surfaces[0].label, "Surface 0");
`,
      },
      bundle: true,
      platform: "node",
      format: "cjs",
      write: false,
    });
    execFileSync("node", ["--input-type=commonjs"], {
      input: bundled.outputFiles[0]!.text,
      encoding: "utf8",
    });
  });

  test("retains saved parent coverage without rebasing its identities or receipts", () => {
    const prior: SemanticCoverage = {
      completeness: "partial",
      surfaces: [
        {
          id: "prior/surface",
          label: "Saved surface",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/deep-scan/prior/review.json"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Generated dependencies." },
      ],
      deferred: [
        {
          candidateId: "prior:candidate",
          reason: "Saved incomplete validation.",
          surfaceIds: ["prior/surface"],
          receiptRefs: ["artifacts/deep-scan/prior/candidate.json"],
        },
      ],
      openQuestions: ["Can a caller reach the saved candidate?"],
    };
    const original = structuredClone(prior);
    const fresh = child("fresh", [], {
      completeness: "complete",
      surfaces: [
        {
          id: "fresh/new-surface",
          label: "Fresh surface",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/fresh/artifacts/fresh.json"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Generated dependencies." },
      ],
    });
    const coverage = combineScanCoverage([fresh.draft.coverage], [], prior);
    expect(coverage["completeness"]).toBe("partial");
    expect(coverage["surfaces"]).toEqual([
      prior.surfaces[0]!,
      {
        id: "fresh/new-surface",
        label: "Fresh surface",
        disposition: "no_issue_found",
        receiptRefs: ["artifacts/scans/fresh/artifacts/fresh.json"],
      },
    ]);
    expect(coverage["deferred"]).toEqual(prior.deferred);
    expect(coverage["explicitExclusions"]).toEqual(prior.explicitExclusions);
    expect(coverage["openQuestions"]).toEqual(prior.openQuestions);
    (coverage["surfaces"] as JsonObject[])[0]!["id"] = "changed";
    expect(prior).toEqual(original);
    expect(
      combineScanCoverage([], [], {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      })["completeness"],
    ).toBe("complete");
    expect(
      combineScanCoverage([fresh.draft.coverage], [], {
        completeness: "unknown",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      })["completeness"],
    ).toBe("unknown");
  });

  test("uses ordinary target and coverage publication at the export boundary", () => {
    const input = child("first");
    const { aggregate } = merge([["first:0"]], [input], null);
    const prepared = prepareSemanticScanDraft(
      {
        mode: "deep",
        targetRevision: "pinned-revision",
        targetContract: {
          target: {
            allowedKinds: ["repository"],
            targetId: "fixture",
            displayName: "Fixture",
          },
          scope: {
            requiredIncludePaths: ["src"],
            requiredExcludePaths: ["vendor"],
          },
        },
      },
      {
        ...materializeScanAggregate(aggregate),
        coverage: combineScanCoverage([input.draft.coverage]),
      },
    );
    expect(prepared.manifest).toHaveProperty(
      "scan.target.revision",
      "pinned-revision",
    );
    expect(prepared.coverage).toHaveProperty("mode", "scoped_path");
    expect(prepared.findings).toHaveProperty(
      "findings.0.provenance.sourceFindings",
      [{ id: "first:0", finding: input.sourceFindings[0]! }],
    );
  });

  test("publishes only new immutable originals and keeps complete oversized evidence", async () => {
    const a = child("a", [
      finding("a", { summary: "Unicode π. ".repeat(50_000) + "tail evidence" }),
    ]);
    const saved: { path: string; contents: Uint8Array }[][] = [];
    const writer = {
      async restore() {
        throw new Error("Batch required");
      },
      async restoreMany(
        artifacts: readonly { path: string; contents: Uint8Array }[],
      ) {
        saved.push([...artifacts]);
      },
    };
    await saveScanMergeSources([a], writer);
    const b = child("b");
    await saveScanMergeSources([b], writer);
    expect(saved.map((batch) => batch.length)).toEqual([2, 2]);
    expect(saved[0]![0]!.path).not.toBe(saved[1]![0]!.path);
    for (const [index, input] of [a, b].entries())
      expect(
        JSON.parse(Buffer.from(saved[index]![0]!.contents).toString()),
      ).toEqual(input.sourceFindings[0]);
  });

  test("uses shared matching without collapsing repeated original IDs or splitting accepted groups", async () => {
    const a = child("a"),
      b = child("b");
    const previous = merge([["a:0", "b:0"]], [a, b], null).aggregate;
    const c = child("c", [finding(), finding("different")]);
    for (const source of [
      ...Object.values(previous.sourceFindings),
      ...c.sourceFindings,
    ])
      source["findingId"] = "same-original-id";
    const originals = structuredClone(previous.sourceFindings);
    const evidence: JsonObject[] = [];
    const signal = new AbortController().signal;
    let calls = 0;
    const matched = await mergeScans(
      parent,
      [c],
      previous,
      signal,
      async (prompt, actualSignal, schema) => {
        expect(actualSignal).toBe(signal);
        expect(schema).toBeDefined();
        const input = JSON.parse(prompt.split("\n").at(-1)!);
        if (input.findings) {
          calls++;
          expect(
            input.findings.before.map(
              (entry: JsonObject) => entry["occurrenceId"],
            ),
          ).toEqual(["b:0"]);
          expect(
            input.findings.after.map((entry: JsonObject) => entry["findingId"]),
          ).toEqual(["c:0", "c:1"]);
        } else evidence.push(JSON.parse(input.content));
        return {
          matches: [
            {
              beforeOccurrenceIds: ["b:0"],
              afterOccurrenceIds: ["c:0"],
              confidence: "high",
              reason: "Same correction.",
            },
          ],
          uncertain: [],
          related: [
            {
              beforeOccurrenceId: "b:0",
              afterOccurrenceId: "c:1",
              reason: "A separate correction is required.",
            },
          ],
          request: null,
        };
      },
      mergeOptions,
    );
    expect(calls).toBe(1);
    expect(evidence).toHaveLength(1);
    expect(
      (evidence[0]!["before"] as JsonObject[]).map(
        (entry) => entry["occurrenceId"],
      ),
    ).toEqual(["a:0", "b:0"]);
    const result = matched.aggregate;
    expect(
      result.findings.map((entry) => entry.provenance.sourceFindingIds),
    ).toEqual([["a:0", "b:0", "c:0"], ["c:1"]]);
    expect(result.findings[0]!.identity).toEqual(
      previous.findings[0]!.identity,
    );
    expect(previous.sourceFindings).toEqual(originals);
    expect(
      materializeScanAggregate(result).findings[0]!.provenance.sourceFindings,
    ).toHaveLength(3);
  });

  test("keeps an uncertain earlier finding separate from a confirmed later match", async () => {
    const inputs = ["a", "b", "c"].map((id) => child(id, [finding(id)]));
    let calls = 0;
    let retries = 0;
    let evidence: JsonObject | undefined;
    const matched = await mergeScans(
      parent,
      inputs,
      null,
      new AbortController().signal,
      async (prompt) => {
        const input = JSON.parse(prompt.split("\n").at(-1)!);
        if (++calls === 1) return { matches: [], uncertain: [] };
        if (input.content) evidence = JSON.parse(input.content);
        return {
          matches: [
            {
              beforeOccurrenceIds: ["b:0"],
              afterOccurrenceIds: ["c:0"],
              confidence: "high",
              reason: "The same control is missing.",
            },
          ],
          uncertain: [
            {
              beforeOccurrenceId: "a:0",
              afterOccurrenceId: "c:0",
              reason:
                "The earlier observation may require a different correction.",
            },
          ],
        };
      },
      {
        ...mergeOptions,
        async onInvalidResponse() {
          retries++;
          return false;
        },
      },
    );
    expect(matched).toEqual(merge([["a:0"], ["b:0", "c:0"]], inputs, null));
    expect(calls).toBe(3);
    expect(retries).toBe(0);
    expect(evidence).toEqual({
      before: [
        {
          ...inputs[1]!.sourceFindings[0],
          occurrenceId: "b:0",
          findingId: "b:0",
        },
      ],
      after: [
        {
          ...inputs[2]!.sourceFindings[0],
          occurrenceId: "c:0",
          findingId: "c:0",
        },
      ],
    });
    expect(matched.aggregate.sourceFindings).toEqual(
      Object.fromEntries(
        inputs.map((input) => [`${input.scanId}:0`, input.sourceFindings[0]!]),
      ),
    );
  });

  test("retains uncertain observations and does not return partial results after a later comparison fails", async () => {
    const inputs = [child("a"), child("b"), child("c")];
    let calls = 0;
    const failure = new Error("comparison transport failed");
    await expect(
      mergeScans(
        parent,
        inputs,
        null,
        new AbortController().signal,
        async () => {
          if (++calls === 2) throw failure;
          return {
            matches: [],
            uncertain: [
              {
                beforeOccurrenceId: "a:0",
                afterOccurrenceId: "b:0",
                reason: "Insufficient shared evidence.",
              },
            ],
            related: [],
            request: null,
          };
        },
        mergeOptions,
      ),
    ).rejects.toBe(failure);
    expect(calls).toBe(2);
    const retained = await mergeScans(
      parent,
      inputs.slice(0, 2),
      null,
      new AbortController().signal,
      async () => ({
        matches: [],
        uncertain: [
          {
            beforeOccurrenceId: "a:0",
            afterOccurrenceId: "b:0",
            reason: "Insufficient shared evidence.",
          },
        ],
        related: [],
        request: null,
      }),
      mergeOptions,
    );
    expect(retained).toEqual(
      merge([["a:0"], ["b:0"]], inputs.slice(0, 2), null),
    );
  });

  test("reconciles only context for empty scans and validates it before acceptance", async () => {
    const a = child("a", []),
      b = child("b", []);
    a.draft.threatModel = {
      summary: "First context. ".repeat(100_000),
      assumptions: ["First limitation"],
    };
    b.draft.threatModel = {
      summary: "Second context. ".repeat(100_000),
      assumptions: ["Second limitation"],
    };
    let contexts: unknown;
    await saveScanMergeSources([a, b], {
      async restore() {
        throw new Error("Batch required");
      },
      async restoreMany(artifacts) {
        contexts = JSON.parse(
          Buffer.from(artifacts.at(-1)!.contents).toString(),
        );
      },
    });
    expect(contexts).toEqual([
      { threatModel: a.draft.threatModel },
      { threatModel: b.draft.threatModel },
    ]);
    let calls = 0;
    const result = await mergeScans(
      parent,
      [a, b],
      null,
      new AbortController().signal,
      async (prompt) => {
        calls++;
        expect(prompt).toContain(JSON.stringify(mergeOptions.contextPath));
        expect(prompt).not.toContain(a.draft.threatModel!.summary);
        return {
          threatModel: {
            summary: "Both contexts",
            assumptions: ["First limitation", "Second limitation"],
          },
        };
      },
      mergeOptions,
    );
    expect(calls).toBe(1);
    expect(result.aggregate.threatModel).toEqual({
      summary: "Both contexts",
      assumptions: ["First limitation", "Second limitation"],
    });
    await expect(
      mergeScans(
        parent,
        [a, b],
        null,
        new AbortController().signal,
        async () => ({ threatModel: { summary: 12 } }),
        mergeOptions,
      ),
    ).rejects.toThrow("Invalid scan merge");
  });
});

test("publishes the first real scope after an earlier threat-model-only batch", () => {
  const first = child("first", []);
  first.draft.threatModel = { summary: "Initial threat model." };
  const previous = merge([], [first], null).aggregate;
  const second = child("second", []);
  second.draft.scope = {
    summary: "Review of the service entry points.",
    limitations: ["External dependencies were not inspected."],
  };
  const current = merge([], [second], previous).aggregate;
  const prepared = prepareSemanticScanDraft(
    { mode: "deep", targetRevision: "pinned", targetContract },
    { ...current, coverage: combineScanCoverage([second.draft.coverage]) },
  );
  expect(prepared.manifest.scan.scope).toMatchObject(second.draft.scope);
  expect(current.scope?.["sourceScans"]).toHaveLength(2);
  const third = child("third", []);
  third.draft.scope = { summary: "Later scope details." };
  expect(merge([], [third], current).aggregate.scope).toMatchObject(
    second.draft.scope,
  );
});

test.each([false, true])(
  "retains prior threat-model contexts through a context-free merge (new child: %p)",
  (addChild) => {
    const first = child("first", []);
    const second = child("second", []);
    first.draft.threatModel = { summary: "First threat model." };
    second.draft.threatModel = { summary: "Second threat model." };
    const previous = merge([], [first, second], null).aggregate;
    const before = structuredClone(previous);
    const current = merge(
      previous.findings.map((finding) => finding.provenance.sourceFindingIds!),
      addChild ? [child("third", [])] : [],
      previous,
    ).aggregate;
    expect(current).toEqual(previous);
    expect(current.scope?.["sourceScans"]).toEqual([
      {
        scanId: "first",
        threatModel: first.draft.threatModel,
        scope: undefined,
      },
      {
        scanId: "second",
        threatModel: second.draft.threatModel,
        scope: undefined,
      },
    ]);
    (
      current.scope!["sourceScans"] as { threatModel: { summary: string } }[]
    )[1]!.threatModel.summary = "Changed copy.";
    expect(previous).toEqual(before);
  },
);

test("retains one unresolved task through saved coverage resumes and publication", () => {
  const reason = "artifacts/deep-scan/passes/pass-2";
  const owned = semanticCoverage({
    completeness: "partial",
    deferred: [{ id: "child/task", reason }],
  });
  const original = structuredClone(owned);
  let coverage = combineScanCoverage([owned], [reason]);
  const expected = structuredClone(coverage);
  for (let resume = 0; resume < 3; resume++) {
    coverage = combineScanCoverage(
      [],
      [reason, reason],
      JSON.parse(JSON.stringify(coverage)),
    );
    const published = prepareSemanticScanDraft(
      { mode: "deep", targetRevision: "pinned", targetContract },
      { scanId: parent, findings: [], coverage },
    );
    expect(coverage).toEqual(expected);
    expect(published.coverage.deferred).toHaveLength(2);
    expect(new Set(published.coverage.deferred.map((row) => row.id)).size).toBe(
      2,
    );
  }
  const nextReason = "artifacts/deep-scan/passes/pass-3";
  expect(
    combineScanCoverage([], [reason, nextReason], coverage).deferred,
  ).toEqual([...expected.deferred, { reason: nextReason }]);
  expect(owned).toEqual(original);
});

test("publishes coverage metadata and retains conflicting source values on resume", () => {
  const first = semanticCoverage({
    toolMetadata: { scanner: "first" },
    sourceScans: ["source-owned metadata"],
  });
  const second = semanticCoverage({
    toolMetadata: { scanner: "second" },
    limitations: ["External dependencies were not inspected."],
  });
  const original = structuredClone({ first, second });
  const single = combineScanCoverage([second]);
  expect(single["toolMetadata"]).toEqual(second["toolMetadata"]);
  const combined = combineScanCoverage([first, second]);
  expect(combined["sourceScans"]).toEqual([
    {
      toolMetadata: first["toolMetadata"],
      sourceScans: first["sourceScans"],
    },
    {
      toolMetadata: second["toolMetadata"],
      limitations: second["limitations"],
    },
  ]);
  const resumed = combineScanCoverage([], ["Pending pass."], combined);
  const prepared = prepareSemanticScanDraft(
    { mode: "deep", targetRevision: "pinned", targetContract },
    { scanId: parent, findings: [], coverage: resumed },
  );
  expect(prepared.coverage["toolMetadata"]).toEqual(first["toolMetadata"]);
  expect(prepared.coverage["sourceScans"]).toEqual(combined["sourceScans"]);
  expect(prepared.coverage.completeness).toBe("partial");
  const third = semanticCoverage({ toolMetadata: { scanner: "third" } });
  const next = combineScanCoverage([third], [], resumed);
  expect(next["sourceScans"]).toEqual([
    {
      toolMetadata: first["toolMetadata"],
      limitations: second["limitations"],
      sourceScans: combined["sourceScans"],
    },
    { toolMetadata: third["toolMetadata"] },
  ]);
  (next["toolMetadata"] as { scanner: string }).scanner = "changed";
  expect({ first, second }).toEqual(original);
});
