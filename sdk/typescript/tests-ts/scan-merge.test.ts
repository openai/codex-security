import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { build } from "esbuild";
import {
  combineScanCoverage,
  validateScanMerge as merge,
  scanMergePrompt,
  scanMergeModelInputs,
  unchangedScanGroups,
  type ScanMergeGroups,
  type ScanMergeInput,
} from "../src/scan-merge.js";
import {
  prepareSemanticScanDraft,
  scanFindingIdentity,
} from "../src/scan-semantics.js";
import type { SemanticFinding, SemanticScan } from "../src/semantic-models.js";
import { semanticFinding, semanticCoverage } from "./helpers/semantic-scan.js";

const parent = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const root = fileURLToPath(
  new URL("./fixtures/merge-parent/", import.meta.url),
);
const finding = (anchor = "shared", extra: Partial<SemanticFinding> = {}) =>
  semanticFinding({ identity: { anchor }, ...extra });
function child(scanId: string, findings = [finding()]): ScanMergeInput {
  return {
    scanId,
    scanDir: join(root, scanId),
    sourceFindings: findings.map((entry, index) => ({
      ...structuredClone(entry),
      findingId: `${scanId}-${index}`,
    })),
    draft: {
      scanId: parent,
      findings: findings.map((entry, index) => ({
        ...structuredClone(entry),
        provenance: {
          ...entry.provenance,
          sourceFindingIds: [`${scanId}:${index}`],
        },
      })),
      coverage: semanticCoverage(),
    },
  };
}
function submission(...groups: string[][]): ScanMergeGroups {
  return {
    scanId: parent,
    groups: groups.map((sourceFindingIds) => ({
      sourceFindingIds,
      canonicalSourceFindingId: sourceFindingIds[0]!,
    })),
  };
}

test("copies the selected finding and retains every exact source without rewriting", () => {
  const low = child("low", [finding("first", { severity: { level: "low" } })]);
  const high = child("high", [
    finding("second", {
      severity: { level: "high" },
      remediation: "Use the corrected configuration.",
    }),
  ]);
  const raw = submission(["high:0", "low:0"]);
  const before = structuredClone({ low, high, raw });
  const result = merge(raw, [low, high], null);
  expect(result.newFindingScanIds).toEqual(["low"]);
  const accepted = result.aggregate.findings[0]!;
  expect(accepted.severity).toEqual(high.draft.findings[0]!.severity);
  expect(accepted.remediation).toBe(high.draft.findings[0]!.remediation);
  expect(accepted.provenance.sourceFindings).toEqual([
    { id: "high:0", finding: high.sourceFindings[0]! },
    { id: "low:0", finding: low.sourceFindings[0]! },
  ]);
  accepted.locations[0]!.startLine = 99;
  accepted.provenance.sourceFindings![0]!.finding["summary"] = "changed";
  expect({ low, high, raw }).toEqual(before);
});

test.each([
  [
    "missing references",
    { scanId: parent, groups: [{ canonicalSourceFindingId: "one:0" }] },
  ],
  ["empty group", submission([])],
  ["unknown references", submission(["other:0"])],
  ["omitted sources", submission()],
  ["reused sources", submission(["one:0"], ["one:0"])],
  [
    "canonical outside group",
    {
      scanId: parent,
      groups: [
        { sourceFindingIds: ["one:0"], canonicalSourceFindingId: "other:0" },
      ],
    },
  ],
  ["rewritten finding", { ...submission(["one:0"]), findings: [finding()] }],
])("rejects %s", (_name, raw) => {
  expect(() => merge(raw, [child("one")], null)).toThrow();
});

test("requires completed parent-bound inputs and exact projected source IDs", () => {
  const input = child("one");
  expect(() =>
    merge({ ...submission(["one:0"]), scanId: "other" }, [input], null),
  ).toThrow("different parent");
  input.draft.complete = false;
  expect(() => merge(submission(["one:0"]), [input], null)).toThrow(
    "completed inputs",
  );
  delete input.draft.complete;
  input.draft.findings[0]!.provenance.sourceFindingIds = ["renamed:0"];
  expect(() => merge(submission(["one:0"]), [input], null)).toThrow(
    "references changed",
  );
});

test("retains accepted identity and synthesis when a new canonical source is selected", () => {
  const first = child("first");
  const previous = merge(submission(["first:0"]), [first], null).aggregate;
  previous.findings[0]!.summary = "Earlier accepted synthesis.";
  previous.findings[0]!.provenance["previousFindings"] = [
    { summary: "Earlier supporting detail." },
  ];
  const next = child("second", [
    finding("different", {
      ruleId: "different-rule",
      summary: "Better current narrative.",
    }),
  ]);
  const before = structuredClone({ previous, next });
  const current = merge(submission(["second:0", "first:0"]), [next], previous);
  expect(current.newFindingScanIds).toEqual([]);
  expect(current.aggregate.findings[0]!.identity).toEqual(
    previous.findings[0]!.identity,
  );
  expect(scanFindingIdentity(current.aggregate.findings[0]!)).toBe(
    scanFindingIdentity(previous.findings[0]!),
  );
  expect(current.aggregate.findings[0]!.summary).toBe(
    "Better current narrative.",
  );
  expect(current.aggregate.findings[0]!.provenance["previousFindings"]).toEqual(
    expect.arrayContaining([
      { summary: "Earlier supporting detail." },
      expect.objectContaining({ summary: "Earlier accepted synthesis." }),
    ]),
  );
  expect({ previous, next }).toEqual(before);
  const again = merge(
    unchangedScanGroups(parent, current.aggregate),
    [],
    current.aggregate,
  );
  expect(again.aggregate.findings).toEqual(current.aggregate.findings);
});

test("previous groups cannot split, but accepted aliases can converge", () => {
  const one = child("one");
  const two = child("two", [finding("other")]);
  const previous = merge(
    submission(["one:0", "two:0"]),
    [one, two],
    null,
  ).aggregate;
  for (const raw of [
    submission(["one:0"], ["two:0"]),
    submission(["two:0"], ["one:0"]),
  ])
    expect(() => merge(raw, [], previous)).toThrow("split");
  const separate = merge(
    submission(["one:0"], ["two:0"]),
    [one, two],
    null,
  ).aggregate;
  const united = merge(submission(["two:0", "one:0"]), [], separate);
  expect(united.newFindingScanIds).toEqual([]);
  expect(united.aggregate.findings[0]!.identity).toEqual(
    separate.findings[1]!.identity,
  );
  expect(
    united.aggregate.findings[0]!.provenance["previousFindings"],
  ).toHaveLength(1);
});

test("keeps accepted identities when independent children collide and credits earliest discovery", () => {
  const first = child("first");
  const second = child("second");
  const third = child("third", [finding("third")]);
  const previous = merge(submission(["first:0"]), [first], null).aggregate;
  const result = merge(
    submission(["second:0"], ["first:0"], ["third:0"]),
    [second, third],
    previous,
  );
  const identities = result.aggregate.findings.map(scanFindingIdentity);
  expect(new Set(identities).size).toBe(3);
  expect(identities[1]).toBe(scanFindingIdentity(previous.findings[0]!));
  expect(result.newFindingScanIds).toEqual(["second", "third"]);
  expect(
    merge(submission(["third:0", "second:0"]), [second, third], null)
      .newFindingScanIds,
  ).toEqual(["second"]);
});

test("host preserves different child contexts without a model rewrite", () => {
  const one = child("one", []);
  const two = child("two", []);
  one.draft.threatModel = { summary: "First context." };
  two.draft.threatModel = { summary: "Second context." };
  two.draft.scope = { summary: "Review details." };
  const result = merge(submission(), [one, two], null).aggregate;
  expect(result.threatModel).toEqual(one.draft.threatModel);
  expect(result.scope?.["sourceScans"]).toEqual([
    { scanId: "one", threatModel: one.draft.threatModel, scope: undefined },
    {
      scanId: "two",
      threatModel: two.draft.threatModel,
      scope: two.draft.scope,
    },
  ]);
});

test("combines coverage without namespacing twice or mutating completed inputs", () => {
  const one = child("one", []);
  one.draft.coverage = semanticCoverage({
    completeness: "partial",
    surfaces: [
      {
        id: "one/api",
        label: "API",
        disposition: "no_issue_found",
        receiptRefs: ["artifacts/one.json"],
      },
    ],
    deferred: [{ reason: "Pending review." }],
    openQuestions: ["Question?"],
  });
  const two = child("two", []);
  two.draft.coverage.openQuestions = ["Question?"];
  const original = structuredClone(one);
  const combined = combineScanCoverage([one, two], ["Unfinished pass."]);
  expect(combined.completeness).toBe("partial");
  expect(combined.surfaces).toEqual(one.draft.coverage.surfaces);
  expect(combined.deferred).toEqual([
    { reason: "Pending review." },
    { reason: "Unfinished pass." },
  ]);
  expect(combined.openQuestions).toEqual(["Question?"]);
  combined.surfaces[0]!.label = "changed";
  expect(one).toEqual(original);
  expect(
    combineScanCoverage([], [], semanticCoverage({ completeness: "unknown" }))
      .completeness,
  ).toBe("unknown");
  expect(combineScanCoverage([two]).completeness).toBe("complete");
  expect(combineScanCoverage([]).completeness).toBe("partial");
});

test("combines large coverage on Node without argument limits", async () => {
  const bundled = await build({
    stdin: {
      resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
      contents: `
import assert from "node:assert/strict";
import { combineScanCoverage } from "./scan-merge.ts";
const deferred = Array.from({length:150000}, (_,i)=>({reason:String(i)}));
const coverage = {completeness:"partial",surfaces:[],explicitExclusions:[],deferred};
assert.deepEqual(combineScanCoverage([{draft:{coverage}}]).deferred,deferred);
`,
    },
    bundle: true,
    platform: "node",
    format: "cjs",
    write: false,
  });
  execFileSync("node", ["--input-type=commonjs"], {
    input: bundled.outputFiles[0]!.text,
  });
});

test("publishes host target and scope with the selected original finding", () => {
  const input = child("first");
  const { aggregate } = merge(submission(["first:0"]), [input], null);
  const prepared = prepareSemanticScanDraft(
    {
      mode: "deep",
      targetRevision: "pinned",
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
  expect(prepared.manifest.scan.target.revision).toBe("pinned");
  expect(prepared.manifest.scan.scope.includePaths).toEqual(["src"]);
  expect(prepared.coverage.mode).toBe("scoped_path");
  expect(
    prepared.findings.findings[0]!.provenance.sourceFindings![0]!.finding,
  ).toEqual(input.sourceFindings[0]!);
});

test("model input excludes all coverage and retains complete source evidence once", async () => {
  const one = child("one", [
    finding("one", { summary: "x".repeat(150000) + "tail Ω" }),
  ]);
  const accepted = merge(submission(["one:0"]), [one], null).aggregate;
  const previous: SemanticScan = {
    ...accepted,
    coverage: semanticCoverage({
      surfaces: [
        {
          id: "coverage",
          label: "coverage-only-".repeat(100000),
          disposition: "no_issue_found",
        },
      ],
    }),
  };
  const two = child("two", [
    finding("two", {
      provenance: {
        ...finding().provenance,
        sourceFindings: [{ id: "historical:0", finding: finding("original") }],
      },
    }),
  ]);
  const original = structuredClone({ previous, two });
  const bytes = scanMergeModelInputs([two], previous);
  const parsed = JSON.parse(bytes.toString());
  expect(parsed).not.toHaveProperty("coverage");
  expect(bytes.toString()).not.toContain("coverage-only-");
  expect(parsed.sources).toEqual([
    { id: "one:0", finding: one.sourceFindings[0]! },
    { id: "two:0", finding: two.sourceFindings[0]! },
  ]);
  expect(parsed.findings[0].provenance.sourceFindings).toBeUndefined();
  const grouped = merge(
    submission(parsed.sources.map(({ id }: { id: string }) => id)),
    [two],
    previous,
  );
  expect(grouped.aggregate.findings[0]!.provenance.sourceFindings).toEqual(
    parsed.sources,
  );
  let writes = 0;
  const prompt = await scanMergePrompt(parent, [two], previous, root, {
    async restore(path, contents) {
      writes++;
      expect(path).toBe("artifacts/deep-scan/merge-inputs.json");
      expect(contents).toEqual(bytes);
    },
  });
  expect(writes).toBe(1);
  expect(JSON.parse(prompt.split("\n").at(-1)!)).toBe(
    join(root, "artifacts/deep-scan/merge-inputs.json"),
  );
  expect({ previous, two }).toEqual(original);
});
