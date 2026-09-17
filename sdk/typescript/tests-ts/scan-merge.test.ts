import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  combineScanCoverage,
  createScanMergeValidator,
  scanMergeInput,
  projectScanMergeWriteups,
  scanMergePrompt,
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
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

beforeAll(async () => {
  merge = await createScanMergeValidator(pluginRoot);
});

function finding(id = "shared", extra: JsonObject = {}): JsonObject {
  return {
    ruleId: "cross-site-scripting.request-output",
    identity: { anchor: id },
    title: "Unsafe request output",
    summary: "A request-controlled value reaches an HTML response.",
    severity: { level: "high" },
    confidence: {
      level: "high",
      rationale: "The source establishes reachability.",
    },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: "src/render.js", startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" },
    ...extra,
  };
}

function child(
  scanId: string,
  findings: JsonObject[] = [finding()],
  coverage: JsonObject = {},
  includePaths: readonly string[] = ["src"],
) {
  return scanMergeInput(
    {
      scanDir: join(root, "artifacts", "scans", scanId),
      manifest: {
        scan: {
          id: scanId,
          scope: { includePaths, excludePaths: [] },
        },
      },
      findings: {
        findings: findings.map((value, index) => ({
          ...value,
          findingId: `${scanId}-finding-${index}`,
          occurrenceId: `${scanId}-occurrence-${index}`,
          fingerprints: { stable: `${scanId}-${index}` },
        })),
      },
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
        ...coverage,
      },
    } as unknown as Parameters<typeof scanMergeInput>[0],
    parent,
  );
}

function submission(
  findings: JsonObject[],
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
  test.each([
    { includePaths: ["src"], expected: ["inside", "mixed"] },
    { includePaths: ["src/render.js"], expected: ["inside", "mixed"] },
    {
      includePaths: ["."],
      expected: ["outside", "prefix", "inside", "mixed"],
    },
    { includePaths: ["src", "docs"], expected: ["outside", "inside", "mixed"] },
    { includePaths: ["other"], expected: [] },
  ])(
    "admits findings within $includePaths without changing their locations",
    ({ includePaths, expected }) => {
      const findings = [
        { id: "outside", paths: ["docs/index.js"] },
        { id: "prefix", paths: ["src-private/render.js"] },
        { id: "inside", paths: ["src/render.js"] },
        { id: "mixed", paths: ["docs/index.js", "./src/render.js"] },
      ].map(({ id, paths }) =>
        finding(id, {
          locations: paths.map((path) => ({ path, startLine: 1 })),
        }),
      );
      const original = structuredClone(findings);
      const input = child("scoped", findings, {}, includePaths);
      expect(input.draft.findings.map((value) => value["identity"])).toEqual(
        expected.map((anchor) => ({ anchor })),
      );
      const retained = original.filter((value) =>
        expected.some(
          (anchor) => anchor === (value["identity"] as JsonObject)["anchor"],
        ),
      );
      expect(input.draft.findings).toMatchObject(retained);
      expect(input.sourceFindings).toMatchObject(retained);
      const merged = merge(submission(input.draft.findings), [input], null);
      expect(merged.newFindings).toBe(expected.length);
      expect(
        merged.aggregate.findings
          .flatMap(sources)
          .map(({ finding }) => finding),
      ).toEqual(input.sourceFindings);
      expect(findings).toEqual(original);
    },
  );

  test("rebinds semantic input while retaining exact sealed findings", () => {
    const input = child("first", [
      finding("shared", { extensions: { custom: { evidence: ["exact"] } } }),
    ]);
    expect(input.scanId).toBe("first");
    expect(input.draft.scanId).toBe(parent);
    expect(input.draft.scope).toBeUndefined();
    expect(input.draft.findings[0]).not.toHaveProperty("findingId");
    expect(input.sourceFindings[0]).toHaveProperty(
      "findingId",
      "first-finding-0",
    );
    const submitted = structuredClone(input.draft.findings);
    provenance(submitted[0]!)["sourceFindings"] = [
      { id: "first:0", finding: { summary: "Model-authored replacement." } },
    ];
    const result = merge(submission(submitted), [input], null);
    expect(result.newFindings).toBe(1);
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
    expect(result.newFindings).toBe(0);
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

  test("rejects omitted, invented, reused, and ambiguous sources", () => {
    const input = child("first", [finding(), finding("distinct")]);
    expect(() =>
      merge(submission([input.draft.findings[0]!]), [input], null),
    ).toThrow("unaccounted source");
    expect(() => merge(submission([finding("new")]), [input], null)).toThrow(
      "no assigned source",
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
      "ambiguous source",
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
    expect(accepted.newFindings).toBe(1);
    expect(
      merge(submission(accepted.aggregate.findings), [], accepted.aggregate)
        .newFindings,
    ).toBe(0);
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
    expect(result.newFindings).toBe(1);
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
        coverage: combineScanCoverage([first, next], root),
      },
    );
    expect(
      (published.findings["findings"] as JsonObject[]).map(scanFindingIdentity),
    ).toEqual(identities);
    expect(() =>
      merge(
        submission([...next.draft.findings, ...previous.findings]),
        [next],
        previous,
      ),
    ).toThrow("previously accepted finding identity");
  });

  test("projects writeups and PoC bytes without changing source evidence or repository paths", async () => {
    const directory = await mkdtemp(join(tmpdir(), "scan-merge-writeups-"));
    directories.push(directory);
    const input = child("first", [
      finding("shared", { writeup: { reportPath: "findings/issue/issue.md" } }),
    ]);
    input.scanDir = directory;
    await mkdir(join(directory, "findings/issue/poc"), { recursive: true });
    await writeFile(
      join(directory, "findings/issue/issue.md"),
      "# Proof\nSee [payload](poc/payload.bin).\n",
    );
    await writeFile(
      join(directory, "findings/issue/poc/payload.bin"),
      new Uint8Array([0, 1, 254, 255]),
    );
    const original = structuredClone(input);
    const copied = new Map<string, Uint8Array>();
    const projected = await projectScanMergeWriteups(input, {
      async restore(path, contents) {
        copied.set(path, contents);
      },
    });
    expect(copied.get("findings/first-issue/first-issue.md")).toEqual(
      await readFile(join(directory, "findings/issue/issue.md")),
    );
    expect(copied.get("findings/first-issue/poc/payload.bin")).toEqual(
      new Uint8Array([0, 1, 254, 255]),
    );
    expect(projected.draft.findings[0]).toHaveProperty(
      "writeup.reportPath",
      "findings/first-issue/first-issue.md",
    );
    expect(projected.draft.findings[0]!["locations"]).toEqual(
      input.draft.findings[0]!["locations"],
    );
    expect(projected.sourceFindings).toEqual(original.sourceFindings);
    expect(input).toEqual(original);
    const result = merge(
      submission(projected.draft.findings),
      [projected],
      null,
    );
    expect(sources(result.aggregate.findings[0]!)[0]!.finding).toHaveProperty(
      "writeup.reportPath",
      "findings/issue/issue.md",
    );
    expect(result.aggregate.findings[0]).toHaveProperty(
      "writeup.reportPath",
      "findings/first-issue/first-issue.md",
    );
  });

  test("rejects writeup evidence that links outside the completed scan", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "scan-merge-linked-writeup-"),
    );
    directories.push(directory);
    const input = child("first", [
      finding("shared", { writeup: { reportPath: "findings/issue/issue.md" } }),
    ]);
    input.scanDir = directory;
    await mkdir(join(directory, "findings/issue"), { recursive: true });
    await writeFile(join(directory, "findings/issue/issue.md"), "# Proof\n");
    await writeFile(join(directory, "external.txt"), "unrelated local data");
    await symlink(
      join(directory, "external.txt"),
      join(directory, "findings/issue/linked.txt"),
    );
    const paths: string[] = [];
    await expect(
      projectScanMergeWriteups(input, {
        async restore(path) {
          paths.push(path);
        },
      }),
    ).rejects.toThrow("regular non-symlink file");
    expect(paths).toEqual(["findings/first-issue/first-issue.md"]);
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
    ).toEqual({ aggregate: submission([], { threatModel }), newFindings: 0 });
  });

  test("combines independent coverage IDs and receipt paths without mutating inputs", () => {
    const coverage = {
      completeness: "partial",
      surfaces: [
        {
          id: "api",
          label: "API",
          disposition: "reviewed",
          receiptRefs: ["artifacts/review.json"],
        },
      ],
      deferred: [
        {
          id: "pending",
          candidateId: "same-candidate",
          reason: "Check ownership.",
          surfaceIds: ["api"],
        },
      ],
      openQuestions: ["Can an untrusted caller reach the route?"],
    };
    const first = child("first", [], coverage);
    const second = child("second", [], coverage);
    const original = structuredClone(first.draft.coverage);
    const combined = combineScanCoverage([first, second], root, [
      "One interrupted scan retains unfinished work.",
    ]);
    expect(combined["completeness"]).toBe("partial");
    expect(combined["surfaces"]).toEqual([
      {
        ...coverage.surfaces[0],
        id: "first/api",
        receiptRefs: ["artifacts/scans/first/artifacts/review.json"],
      },
      {
        ...coverage.surfaces[0],
        id: "second/api",
        receiptRefs: ["artifacts/scans/second/artifacts/review.json"],
      },
    ]);
    const deferred = combined["deferred"] as JsonObject[];
    expect(deferred).toHaveLength(3);
    expect(deferred[0]!["candidateId"]).not.toBe(deferred[1]!["candidateId"]);
    expect(deferred[0]!["surfaceIds"]).toEqual(["first/api"]);
    expect(first.draft.coverage).toEqual(original);
    expect(combined["openQuestions"]).toHaveLength(1);
    expect(
      combineScanCoverage(
        [child("unknown", [], { completeness: "unknown" })],
        root,
      )["completeness"],
    ).toBe("unknown");
    expect(
      combineScanCoverage([child("empty", [])], root)["completeness"],
    ).toBe("complete");
    expect(
      combineScanCoverage([], root, ["No scan completed."])["completeness"],
    ).toBe("partial");
  });

  test("retains saved parent coverage without rebasing its identities or receipts", () => {
    const prior = {
      completeness: "partial",
      surfaces: [
        {
          id: "prior/surface",
          label: "Saved surface",
          disposition: "reviewed",
          receiptRefs: ["artifacts/deep-scan/prior/review.json"],
        },
      ],
      explicitExclusions: ["Generated dependencies."],
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
          id: "new-surface",
          label: "Fresh surface",
          disposition: "reviewed",
          receiptRefs: ["artifacts/fresh.json"],
        },
      ],
      explicitExclusions: ["Generated dependencies."],
    });
    const coverage = combineScanCoverage([fresh], root, [], prior);
    expect(coverage["completeness"]).toBe("partial");
    expect(coverage["surfaces"]).toEqual([
      prior.surfaces[0]!,
      {
        id: "fresh/new-surface",
        label: "Fresh surface",
        disposition: "reviewed",
        receiptRefs: ["artifacts/scans/fresh/artifacts/fresh.json"],
      },
    ]);
    expect(coverage["deferred"]).toEqual(prior.deferred);
    expect(coverage["explicitExclusions"]).toEqual(prior.explicitExclusions);
    expect(coverage["openQuestions"]).toEqual(prior.openQuestions);
    (coverage["surfaces"] as JsonObject[])[0]!["id"] = "changed";
    expect(prior).toEqual(original);
    expect(
      combineScanCoverage([], root, [], { completeness: "complete" })[
        "completeness"
      ],
    ).toBe("complete");
    expect(
      combineScanCoverage([fresh], root, [], { completeness: "unknown" })[
        "completeness"
      ],
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
      { ...aggregate, coverage: combineScanCoverage([input], root) },
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
