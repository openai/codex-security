import type {
  SemanticFinding,
  SemanticCoverage,
} from "../src/semantic-models.js";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import { semanticFinding, semanticCoverage } from "./helpers/semantic-scan.js";
import { build } from "esbuild";
import {
  combineScanCoverage,
  createScanMergeValidator,
  type ScanMergeInput,
  scanMergePrompt,
  scanMergeModelInputs,
  type ScanAggregate,
} from "../src/scan-merge.js";
import {
  prepareSemanticScanDraft,
  scanFindingIdentity,
  type JsonObject,
} from "../src/scan-semantics.js";

const parent = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const root = fileURLToPath(
  new URL("./fixtures/merge-parent/", import.meta.url),
);
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
let merge: Awaited<ReturnType<typeof createScanMergeValidator>>;
beforeAll(async () => {
  merge = await createScanMergeValidator(pluginRoot);
});

function finding(id = "shared", extra: JsonObject = {}): SemanticFinding {
  return semanticFinding({ identity: { anchor: id }, ...extra });
}

function child(
  scanId: string,
  findings: SemanticFinding[] = [finding()],
  coverage: JsonObject = {},
): ScanMergeInput {
  const sourceFindings = findings.map((value, index) => ({
    ...structuredClone(value),
    findingId: `${scanId}-finding-${index}`,
    occurrenceId: `${scanId}-occurrence-${index}`,
    fingerprints: { stable: `${scanId}-${index}` },
  }));
  return {
    scanId,
    scanDir: join(root, "artifacts", "scans", scanId),
    sourceFindings,
    draft: {
      scanId: parent,
      findings: findings.map((value, index) => ({
        ...structuredClone(value),
        provenance: {
          ...structuredClone(value.provenance),
          sourceFindingIds: [`${scanId}:${index}`],
        },
      })),
      coverage: semanticCoverage(coverage),
    },
  };
}

function submission(
  findings: SemanticFinding[],
  extra: JsonObject = {},
): ScanAggregate {
  return { scanId: parent, findings, ...extra };
}

function provenance(value: JsonObject): JsonObject {
  return value["provenance"] as JsonObject;
}

function sources(
  value: JsonObject,
): Array<{ id: string; finding: JsonObject }> {
  return provenance(value)["sourceFindings"] as Array<{
    id: string;
    finding: JsonObject;
  }>;
}

describe("local scan merging", () => {
  test("restores exact source findings over model-authored replacements", () => {
    const input = child("first", [
      finding("shared", { extensions: { custom: { evidence: ["exact"] } } }),
    ]);
    const submitted = structuredClone(input.draft.findings);
    provenance(submitted[0]!)["sourceFindings"] = [
      { id: "first:0", finding: { summary: "Model-authored replacement." } },
    ];
    const result = merge(submission(submitted), [input], null);
    expect(result.newFindingScanIds).toEqual(["first"]);
    expect(sources(result.aggregate.findings[0]!)).toEqual([
      { id: "first:0", finding: input.sourceFindings[0]! },
    ]);
    provenance(result.aggregate.findings[0]!)["sourceFindings"] = [];
    expect(input.sourceFindings[0]).toHaveProperty(
      "extensions.custom.evidence",
      ["exact"],
    );
  });

  test("retains all exact sources and synthesized detail through later merges", () => {
    const first = child("first");
    const initial = merge(
      submission(first.draft.findings),
      [first],
      null,
    ).aggregate;
    initial.findings[0]!["summary"] =
      "Additional inspected evidence from the previous merge.";
    const second = child("second", [
      finding("other-name", {
        attackPath: { steps: ["Submit encoded input", "Open rendered page"] },
      }),
    ]);
    const combined = finding("shared", {
      provenance: {
        source: "local_plugin",
        sourceFindingIds: ["first:0", "second:0"],
      },
    });
    const result = merge(submission([combined]), [second], initial);
    expect(result.newFindingScanIds).toEqual([]);
    expect(sources(result.aggregate.findings[0]!)).toEqual([
      { id: "first:0", finding: first.sourceFindings[0]! },
      { id: "second:0", finding: second.sourceFindings[0]! },
    ]);
    expect(
      provenance(result.aggregate.findings[0]!)["previousFindings"],
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ summary: initial.findings[0]!["summary"] }),
      ]),
    );
  });

  test("rejects omitted, invented, reused, and implicit sources", () => {
    const input = child("first", [finding(), finding("distinct")]);
    expect(() =>
      merge(submission([input.draft.findings[0]!]), [input], null),
    ).toThrow("unaccounted source");
    expect(() => merge(submission([finding("new")]), [input], null)).toThrow(
      "explicit sourceFindingIds",
    );
    expect(() =>
      merge(
        submission([
          finding("shared", {
            provenance: {
              source: "local_plugin",
              sourceFindingIds: ["unknown:0"],
            },
          }),
        ]),
        [input],
        null,
      ),
    ).toThrow("unknown source");
    expect(() =>
      merge(
        submission([input.draft.findings[0]!, input.draft.findings[0]!]),
        [input],
        null,
      ),
    ).toThrow("more than once");
    const collision = child("collision", [
      finding(),
      finding("shared", { summary: "Independent vulnerable path." }),
    ]);
    expect(() => merge(submission([finding()]), [collision], null)).toThrow(
      "explicit sourceFindingIds",
    );
  });

  test("keeps established identities bound to their original sources", () => {
    const first = child("first");
    const previous = merge(
      submission(first.draft.findings),
      [first],
      null,
    ).aggregate;
    const next = child("second", [finding("distinct")]);
    const renamed = structuredClone(previous.findings[0]!);
    renamed["identity"] = { anchor: "renamed" };
    expect(() =>
      merge(submission([renamed, next.draft.findings[0]!]), [next], previous),
    ).toThrow("previously accepted finding identity");
    const accepted = merge(
      submission([...previous.findings, ...next.draft.findings]),
      [next],
      previous,
    );
    expect(accepted.newFindingScanIds).toEqual([next.scanId]);
    expect(
      merge(submission(accepted.aggregate.findings), [], accepted.aggregate)
        .newFindingScanIds,
    ).toEqual([]);
  });

  test("validates findings before accepting a merge and excludes model-authored coverage", () => {
    const input = child("first");
    expect(() =>
      merge(submission(input.draft.findings, { coverage: {} }), [input], null),
    ).toThrow("Invalid scan merge");
    expect(() =>
      merge(
        submission(input.draft.findings, { complete: false }),
        [input],
        null,
      ),
    ).toThrow("complete aggregate");
    const invalidEvidence = structuredClone(input.draft.findings[0]!);
    invalidEvidence["validation"] = { evidenceRefs: ["missing-evidence"] };
    expect(() => merge(submission([invalidEvidence]), [input], null)).toThrow(
      "existing code-evidence IDs",
    );
    const invertedLocation = structuredClone(input.draft.findings[0]!);
    invertedLocation["locations"] = [
      { path: "src/render.js", startLine: 10, endLine: 2 },
    ];
    expect(() => merge(submission([invertedLocation]), [input], null)).toThrow(
      "must not precede",
    );
    expect(() =>
      merge(
        { scanId: "another-parent", findings: input.draft.findings },
        [input],
        null,
      ),
    ).toThrow();
  });

  test("normalizes colliding identities before novelty and ordinary publication", () => {
    const first = child("first");
    const previous = merge(
      submission(first.draft.findings),
      [first],
      null,
    ).aggregate;
    const next = child("second", [
      finding("shared", {
        summary: "A distinct reachable vulnerable instance.",
      }),
    ]);
    const result = merge(
      submission([...previous.findings, ...next.draft.findings]),
      [next],
      previous,
    );
    expect(result.newFindingScanIds).toEqual([next.scanId]);
    const identities = result.aggregate.findings.map(scanFindingIdentity);
    expect(new Set(identities).size).toBe(2);
    expect(identities[0]).toBe(scanFindingIdentity(previous.findings[0]!));
    const published = prepareSemanticScanDraft(
      {
        mode: "deep",
        targetContract: {
          target: {
            allowedKinds: ["git_worktree"],
            targetId: "fixture",
            displayName: "Fixture",
          },
          scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
        },
      },
      {
        ...result.aggregate,
        coverage: combineScanCoverage([first, next]),
      },
    );
    expect(
      (published.findings["findings"] as JsonObject[]).map(scanFindingIdentity),
    ).toEqual(identities);
    const reordered = merge(
      submission([...next.draft.findings, ...previous.findings]),
      [next],
      previous,
    );
    expect(reordered.aggregate.findings.map(scanFindingIdentity)).toEqual(
      [...identities].reverse(),
    );
    expect(reordered.newFindingScanIds).toEqual([next.scanId]);
  });

  test("credits a new issue to its earliest source pass regardless of output or reference order", () => {
    const first = child("first");
    const second = child("second");
    const third = child("third", [finding("another-issue")]);
    const shared = finding("shared", {
      provenance: {
        source: "local_plugin",
        sourceFindingIds: ["second:0", "first:0"],
      },
    });
    const duplicateOnly = merge(submission([shared]), [first, second], null);
    expect(duplicateOnly.newFindingScanIds).toEqual(["first"]);

    const result = merge(
      submission([third.draft.findings[0]!, shared]),
      [first, second, third],
      null,
    );
    expect(result.newFindingScanIds).toEqual(["first", "third"]);
    const rediscovered = child("fourth");
    const retained = structuredClone(result.aggregate.findings);
    (provenance(retained[1]!)["sourceFindingIds"] as string[]).push("fourth:0");
    const repeated = merge(
      submission(retained),
      [rediscovered],
      result.aggregate,
    );
    expect(repeated.newFindingScanIds).toEqual([]);
  });

  test("requires reconciliation of differing source contexts even without findings", () => {
    const first = child("first", []);
    const second = child("second", []);
    first.draft.threatModel = { summary: "Public entrypoint." };
    second.draft.threatModel = { summary: "Local entrypoint." };
    expect(() => merge(submission([]), [first, second], null)).toThrow(
      "ambiguous threatModel",
    );
    const threatModel = { summary: "Public and local entrypoints." };
    expect(
      merge(submission([], { threatModel }), [first, second], null),
    ).toEqual({
      aggregate: submission([], { threatModel }),
      newFindingScanIds: [],
    });
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
      [first, second],
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
      combineScanCoverage([child("unknown", [], { completeness: "unknown" })])
        .completeness,
    ).toBe("unknown");
    expect(combineScanCoverage([child("empty", [])]).completeness).toBe(
      "complete",
    );
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
const combined = combineScanCoverage([{ draft: { coverage } }], unresolved);
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
    const coverage = combineScanCoverage([fresh], [], prior);
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
      combineScanCoverage([fresh], [], {
        completeness: "unknown",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      })["completeness"],
    ).toBe("unknown");
  });

  test("uses ordinary target, scope and coverage publication for the aggregate", () => {
    const input = child("first");
    const { aggregate } = merge(
      submission(input.draft.findings, {
        scope: { notes: "Requested source." },
      }),
      [input],
      null,
    );
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
      { ...aggregate, coverage: combineScanCoverage([input]) },
    );
    expect(prepared.manifest).toHaveProperty(
      "scan.target.revision",
      "pinned-revision",
    );
    expect(prepared.manifest).toHaveProperty("scan.scope.includePaths", [
      "src",
    ]);
    expect(prepared.coverage).toHaveProperty("mode", "scoped_path");
    expect(prepared.coverage).toHaveProperty("excludePaths", ["vendor"]);
    expect(prepared.findings).toHaveProperty(
      "findings.0.provenance.sourceFindings",
      [{ id: "first:0", finding: input.sourceFindings[0]! }],
    );
  });

  for (const count of [1, 2048]) {
    test(`merge reads ${count} assigned findings from a saved evidence file`, async () => {
      const input = child(
        "first",
        Array.from({ length: count }, (_, index) => finding(`issue-${index}`)),
      );
      const previous: ScanAggregate = {
        scanId: parent,
        findings: [finding("previous")],
      };
      let saved = "";
      const prompt = await scanMergePrompt(parent, [input], previous, root, {
        async restore(path, contents) {
          if (path === "artifacts/deep-scan/merge-evidence.jsonl") {
            expect(contents.byteLength).toBe(0);
            return;
          }
          expect(path).toBe("artifacts/deep-scan/merge-inputs.json");
          saved = Buffer.from(contents).toString("utf8");
        },
      });
      const payload = JSON.parse(saved);
      expect(payload.scans[0].childScanId).toBe("first");
      expect(payload.scans[0].scanId).toBe(parent);
      expect(payload.scans[0]).not.toHaveProperty("coverage");
      expect(payload.scans[0].findings).toEqual(input.draft.findings);
      expect(payload.previous).toEqual(previous);
      expect(JSON.parse(prompt.split("\n").at(-1)!)).toBe(
        join(root, "artifacts/deep-scan/merge-inputs.json"),
      );
      if (count > 1) expect([...saved].length).toBeGreaterThan(1 << 20);
      expect([...prompt].length).toBeLessThan(1 << 20);
    });
  }
});

test("consolidates accepted aliases without counting their retained lineage as novel", () => {
  const a = child("alias-a", [finding("identity-a")]);
  const b = child("alias-b", [finding("identity-b")]);
  const previous = merge(
    submission([a.draft.findings[0]!, b.draft.findings[0]!]),
    [a, b],
    null,
  ).aggregate;
  const combined = structuredClone(previous.findings[0]!);
  provenance(combined)["sourceFindingIds"] = ["alias-a:0", "alias-b:0"];
  const result = merge(submission([combined]), [], previous);
  expect(result.newFindingScanIds).toEqual([]);
  expect(sources(result.aggregate.findings[0]!)).toHaveLength(2);
  expect(provenance(result.aggregate.findings[0]!)["previousFindings"]).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ identity: { anchor: "identity-b" } }),
    ]),
  );
  expect(previous.findings).toHaveLength(2);
});

test("requires justification for changed or conflicting severity", () => {
  const source = child("severity");
  const lower = structuredClone(source.draft.findings[0]!);
  lower["severity"] = { level: "low", rationale: "Reworded only." };
  expect(() => merge(submission([lower]), [source], null)).toThrow(
    "severity.changeConditions",
  );
  (lower["severity"] as JsonObject)["changeConditions"] =
    "A public deployment without the documented restriction would increase impact.";
  (lower["severity"] as JsonObject)["rationale"] =
    "The retained deployment evidence limits affected users to the isolated test environment.";
  expect(
    merge(submission([lower]), [source], null).aggregate.findings[0]![
      "severity"
    ],
  ).toEqual(lower["severity"]);
  expect(
    sources(
      merge(submission([lower]), [source], null).aggregate.findings[0]!,
    )[0]!.finding["severity"],
  ).toEqual({ level: "high" });
});

test("compact merge inputs preserve complete indexed Unicode and oversized lineage", () => {
  const original = finding("large", {
    remediation: "Preserve the distinct tail repair Ω.",
    summary: "filler ".repeat(20000) + "tail fact Ω",
  });
  const accepted = finding("canonical");
  provenance(accepted)["sourceFindingIds"] = ["child:0"];
  provenance(accepted)["sourceFindings"] = [
    { id: "child:0", finding: original },
  ];
  provenance(accepted)["previousFindings"] = [
    finding("earlier", { remediationTests: ["A distinct retained test."] }),
  ];
  const previous = submission([accepted]);
  const before = structuredClone(previous);
  const payload = scanMergeModelInputs([], previous);
  const index = JSON.parse(payload.index.toString());
  expect(payload.index.length).toBeLessThan(payload.evidence.length / 10);
  expect(index.previous.findings[0].provenance.sourceFindingIds).toEqual([
    "child:0",
  ]);
  expect(index.previous.findings[0].provenance.sourceFindings).toBeUndefined();
  const restored = structuredClone(index.previous);
  for (const entry of index.retainedEvidence) {
    const record = JSON.parse(
      payload.evidence
        .subarray(entry.offset, entry.offset + entry.length)
        .toString(),
    );
    expect(record.owner).toBe("previous:0");
    (restored.findings[0].provenance[record.field] ??= [])[record.index] =
      record.value;
  }
  expect(restored).toEqual(before);
  expect(previous).toEqual(before);
});
