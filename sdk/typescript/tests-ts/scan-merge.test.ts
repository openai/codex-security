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

test("publishes the first real scope after an earlier threat-model-only batch", () => {
  const first = child("first", []);
  first.draft.threatModel = { summary: "Initial threat model." };
  const previous = merge(submission(), [first], null).aggregate;
  const second = child("second", []);
  second.draft.scope = {
    summary: "Review of the service entry points.",
    limitations: ["External dependencies were not inspected."],
  };
  const current = merge(submission(), [second], previous).aggregate;
  const prepared = prepareSemanticScanDraft(
    { mode: "deep", targetRevision: "pinned", targetContract },
    { ...current, coverage: combineScanCoverage([second.draft.coverage]) },
  );
  expect(prepared.manifest.scan.scope).toMatchObject(second.draft.scope);
  expect(current.scope?.["sourceScans"]).toHaveLength(2);
  const third = child("third", []);
  third.draft.scope = { summary: "Later scope details." };
  expect(merge(submission(), [third], current).aggregate.scope).toMatchObject(
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
    const previous = merge(submission(), [first, second], null).aggregate;
    const before = structuredClone(previous);
    const current = merge(
      unchangedScanGroups(parent, previous),
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
  const combined = combineScanCoverage(
    [one.draft.coverage, two.draft.coverage],
    ["Unfinished pass."],
  );
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
  expect(combineScanCoverage([two.draft.coverage]).completeness).toBe(
    "complete",
  );
  expect(combineScanCoverage([]).completeness).toBe("partial");
});

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

test("combines large coverage on Node without argument limits", async () => {
  const bundled = await build({
    stdin: {
      resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
      contents: `
import assert from "node:assert/strict";
import { combineScanCoverage } from "./scan-merge.ts";
const deferred = Array.from({length:150000}, (_,i)=>({reason:String(i)}));
const coverage = {completeness:"partial",surfaces:[],explicitExclusions:[],deferred};
assert.deepEqual(combineScanCoverage([coverage]).deferred,deferred);
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
    { ...aggregate, coverage: combineScanCoverage([input.draft.coverage]) },
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
