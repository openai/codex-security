import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { build } from "esbuild";
import {
  combineScanCoverage,
  confirmScanMerge,
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
      reviewState: semanticCoverage(),
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
  const higherSeverity = finding("first", { severity: { level: "critical" } });
  const high = child("high", [higherSeverity]);
  const low = child("low", [
    finding("second", {
      severity: { level: "low" },
      remediation: "Use the corrected configuration.",
    }),
  ]);
  const raw = submission(["low:0", "high:0"]);
  const before = structuredClone({ low, high, raw });
  const result = merge(raw, [high, low], null);
  expect(result.newFindingScanIds).toEqual(["high"]);
  const repeat = child("repeat", [higherSeverity]);
  const repeated = merge(
    submission(["low:0", "high:0", "repeat:0"]),
    [repeat],
    result.aggregate,
  );
  expect(repeated.newFindingScanIds).toEqual([]);
  expect(repeated.aggregate.findings).toHaveLength(1);
  const accepted = repeated.aggregate.findings[0]!;
  expect(accepted.severity).toEqual(low.draft.findings[0]!.severity);
  expect(accepted.remediation).toBe(low.draft.findings[0]!.remediation);
  expect(accepted.provenance.sourceFindings).toEqual([
    { id: "low:0", finding: low.sourceFindings[0]! },
    { id: "high:0", finding: high.sourceFindings[0]! },
    { id: "repeat:0", finding: repeat.sourceFindings[0]! },
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
  one.draft.reviewState = semanticCoverage({
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
  two.draft.reviewState.openQuestions = ["Question?"];
  const original = structuredClone(one);
  const combined = combineScanCoverage(
    [one.draft.reviewState, two.draft.reviewState],
    ["Unfinished pass."],
  );
  expect(combined).not.toHaveProperty("completeness");
  expect(combined.surfaces).toEqual(one.draft.reviewState.surfaces);
  expect(combined.deferred).toEqual([
    { reason: "Pending review." },
    { reason: "Unfinished pass." },
  ]);
  expect(combined.openQuestions).toEqual(["Question?"]);
  combined.surfaces[0]!.label = "changed";
  expect(one).toEqual(original);
  const legacy = semanticCoverage({ completeness: "unknown" });
  expect(combineScanCoverage([], [], legacy)).not.toHaveProperty(
    "completeness",
  );
  expect(legacy["completeness"]).toBe("unknown");
  expect(combineScanCoverage([two.draft.reviewState])).not.toHaveProperty(
    "completeness",
  );
  expect(combineScanCoverage([])).not.toHaveProperty("completeness");
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
    {
      ...aggregate,
      reviewState: combineScanCoverage([input.draft.reviewState]),
    },
  );
  expect(prepared.manifest.scan.target.revision).toBe("pinned");
  expect(prepared.manifest.scan.scope.includePaths).toEqual(["src"]);
  expect(prepared.reviewState.mode).toBe("scoped_path");
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
    reviewState: semanticCoverage({
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
  expect(parsed).not.toHaveProperty("reviewState");
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

const codeEvidence = [
  {
    id: "sink",
    label: "Sink",
    path: "src/render.js",
    startLine: 1,
    code: "render(input)",
    explanation: "Caller-supplied input reaches the renderer.",
  },
];

test.each([
  "same",
  "survivor",
  "unavailable",
  "conflicting reviews",
  "conflicting sources",
] as const)(
  "checks disputed source reports before accepting a proposed merge (%s)",
  async (outcome) => {
    const alias = finding("earlier", {
      codeEvidence,
      severity: { level: "critical" },
    });
    const left = child("left", [alias]);
    const right = child("right", [
      finding("later", { title: "Another caller", codeEvidence }),
    ]);
    const inputs = [left, right];
    const proposed = merge(submission(["right:0", "left:0"]), inputs, null);
    const calls: string[] = [];
    const errors: unknown[] = [];
    const result = await confirmScanMerge(
      proposed,
      inputs,
      null,
      async (prompt, schema) => {
        const operation = Object.keys(schema["properties"] as object)[0]!;
        calls.push(operation);
        if (outcome === "unavailable")
          throw new Error("Synthetic comparison failure.");
        expect(prompt).toContain("Another caller");
        if (operation === "reviews")
          return {
            reviews: [
              {
                pair: 0,
                decision: "same",
                reason: "One common renderer",
                leftEvidence: 0,
                rightEvidence: 0,
              },
              ...(outcome === "conflicting reviews"
                ? [
                    {
                      pair: 0,
                      decision: "keep",
                      reason: "separate edit",
                      leftEvidence: -1,
                      rightEvidence: -1,
                    },
                  ]
                : []),
            ],
          };
        return {
          sources: [
            {
              id: 0,
              fixA: "encode in render",
              fixB: "encode the other caller",
              survivingPaths:
                outcome === "survivor" ? ["the other caller"] : [],
              same: outcome !== "survivor",
            },
            ...(outcome === "conflicting sources"
              ? [
                  {
                    id: 0,
                    fixA: "encode",
                    fixB: "escape",
                    survivingPaths: ["other caller"],
                    same: false,
                  },
                ]
              : []),
          ],
        };
      },
      (error) => errors.push(error),
    );
    expect(calls).toEqual(
      outcome === "unavailable" || outcome === "conflicting reviews"
        ? ["reviews"]
        : ["reviews", "sources"],
    );
    expect(result.aggregate.findings).toHaveLength(outcome === "same" ? 1 : 2);
    expect(
      result.aggregate.findings
        .flatMap((entry) => entry.provenance.sourceFindingIds)
        .sort(),
    ).toEqual(["left:0", "right:0"]);
    expect(result.newFindingScanIds).toEqual(
      outcome === "same" ? ["left"] : ["left", "right"],
    );
    if (outcome === "same") {
      const canonicalSeverity = right.draft.findings[0]!.severity;
      const accepted = result.aggregate.findings[0]!;
      expect(accepted.severity).toEqual(canonicalSeverity);
      expect(
        accepted.provenance.sourceFindings?.map(
          ({ finding }) => finding["severity"],
        ),
      ).toEqual([canonicalSeverity, alias.severity]);
    }
    expect(errors).toHaveLength(outcome === "unavailable" ? 1 : 0);
    if (outcome === "unavailable")
      expect(result.aggregate.scope?.limitations?.[0]).toContain(
        "Synthetic comparison failure",
      );
  },
);

test("an exact repeated report retains both sources without a confirmation turn", async () => {
  const inputs = [child("left"), child("right")];
  const proposed = merge(submission(["left:0", "right:0"]), inputs, null);
  const result = await confirmScanMerge(
    proposed,
    inputs,
    null,
    () => {
      throw new Error("An exact match required another turn");
    },
    (error) => {
      throw error;
    },
  );
  expect(result.aggregate.findings[0]?.provenance.sourceFindingIds).toEqual([
    "left:0",
    "right:0",
  ]);
});

test.each(["exact", "changed severity", "changed provenance"] as const)(
  "checks a later observation of a merged secondary report (%s)",
  async (version) => {
    const primary = finding("primary", { codeEvidence });
    const alias = finding("secondary", {
      severity: { level: "medium" },
      codeEvidence,
    });
    const previous = merge(
      submission(["first:0", "first:1"]),
      [child("first", [primary, alias])],
      null,
    ).aggregate;
    const repeated = structuredClone(alias);
    if (version === "changed severity")
      repeated.severity = { level: "critical" };
    if (version === "changed provenance")
      repeated.provenance["notes"] = "Independent source";
    const inputs = [child("next", [repeated])];
    const proposed = merge(
      submission(["first:0", "first:1", "next:0"]),
      inputs,
      previous,
    );
    let comparisons = 0;
    const result = await confirmScanMerge(
      proposed,
      inputs,
      previous,
      async () => {
        comparisons++;
        return { reviews: [] };
      },
      (error) => {
        throw error;
      },
    );
    const exact = version === "exact";
    expect(comparisons).toBe(exact ? 0 : 1);
    expect(result.newFindingScanIds).toEqual(exact ? [] : ["next"]);
    expect(result.aggregate.findings).toHaveLength(exact ? 1 : 2);
    const accepted = result.aggregate.findings[0]!;
    expect(accepted.severity).toEqual(primary.severity);
    expect(
      accepted.provenance.sourceFindings?.map(
        ({ finding }) => finding["severity"],
      ),
    ).toEqual(
      exact
        ? [primary.severity, alias.severity, alias.severity]
        : [primary.severity, alias.severity],
    );
  },
);

test.each([
  "missing archive",
  "partial archive",
  "archive without ID list",
] as const)(
  "retains historical source membership and keeps unsupported comparisons separate (%s)",
  async (kind) => {
    const original = finding("saved", { codeEvidence });
    const saved = merge(
      submission(["first:0"]),
      [child("first", [original])],
      null,
    ).aggregate;
    const provenance = saved.findings[0]!.provenance;
    if (kind === "missing archive") delete provenance.sourceFindings;
    if (kind === "partial archive")
      provenance.sourceFindings![0]!.finding = { title: original.title };
    if (kind === "archive without ID list") delete provenance.sourceFindingIds;
    const inputs = [
      child("next", [
        finding("next", { title: "Different report", codeEvidence }),
      ]),
    ];
    const raw = submission(["first:0", "next:0"]);
    let calls = 0;
    const checked = await confirmScanMerge(
      merge(raw, inputs, saved),
      inputs,
      saved,
      async () => {
        calls++;
        return { reviews: [] };
      },
      (error) => {
        throw error;
      },
    );
    expect(calls).toBe(kind === "archive without ID list" ? 1 : 0);
    expect(checked.aggregate.findings).toHaveLength(2);
    const archived = checked.aggregate.findings[0]!.provenance;
    expect(archived.sourceFindingIds).toEqual(["first:0"]);
    expect(archived.sourceFindings).toEqual(provenance.sourceFindings ?? []);
    const visible = structuredClone(saved.findings[0]!);
    const repeat = [child("next", [visible])];
    const repeated = await confirmScanMerge(
      merge(raw, repeat, saved),
      repeat,
      saved,
      async () => {
        throw new Error("An exact visible repeat required review");
      },
      (error) => {
        throw error;
      },
    );
    expect(repeated.aggregate.findings).toHaveLength(1);
    expect(repeated.aggregate.findings[0]!.provenance.sourceFindingIds).toEqual(
      ["first:0", "next:0"],
    );
  },
);
