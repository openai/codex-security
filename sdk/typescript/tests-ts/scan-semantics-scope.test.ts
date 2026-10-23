import { expect, test } from "bun:test";
import {
  findingsWithinScope,
  prepareSemanticScanDraft,
  type SemanticScanContext,
} from "../src/scan-semantics.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";

const locations = [
  "src/app.ts",
  "src/./app.ts",
  "src/app.ts/generated",
  "src/app.ts-other",
  "lib/helper.ts",
];

test.each([
  { paths: ["src/app.ts"], files: ["src/app.ts"], expected: [0, 1] },
  { paths: ["./src/app.ts"], files: ["src/./app.ts"], expected: [0, 1] },
  { paths: ["src/app.ts/"], files: ["src/app.ts"], expected: [0, 1] },
  { paths: ["src/app.ts"], files: [], expected: [0, 1, 2] },
  { paths: ["./src/"], files: ["src/app.ts"], expected: [0, 1, 2, 3] },
  {
    paths: ["src/app.ts", "./lib/"],
    files: ["src/app.ts"],
    expected: [0, 1, 4],
  },
  { paths: ["./"], files: ["src/app.ts"], expected: [0, 1, 2, 3, 4] },
])(
  "scope projection preserves file and directory semantics: %j",
  ({ paths, files, expected }) => {
    const findings = locations.map((path) => ({ locations: [{ path }] }));
    expect(findingsWithinScope(findings, paths, files)).toEqual(
      expected.map((index) => findings[index]!),
    );
  },
);

test("Deep projection uses persisted file scope before assigning identities and keeps scans isolated", () => {
  const context: SemanticScanContext = {
    mode: "deep",
    targetContract: {
      target: {
        allowedKinds: ["git_revision"],
        targetId: "synthetic-target",
        displayName: "Synthetic repository",
      },
      scope: {
        requiredIncludePaths: ["./src/app.ts"],
        filePaths: ["src/app.ts"],
      },
    },
  };
  const input = {
    scanId: "synthetic-scan",
    findings: ["src/app.ts/generated", "src/app.ts"].map((path) =>
      semanticFinding({ locations: [{ path, startLine: 1 }] }),
    ),
    coverage: semanticCoverage(),
  };
  const before = structuredClone({ context, input });
  const resumed: SemanticScanContext = JSON.parse(JSON.stringify(context));
  const directory: SemanticScanContext = {
    ...context,
    targetContract: {
      ...context.targetContract,
      scope: { requiredIncludePaths: ["src/app.ts"], filePaths: [] },
    },
  };
  for (const active of [context, resumed]) {
    const prepared = prepareSemanticScanDraft(active, input);
    expect(prepared.findings.findings).toEqual([
      { ...input.findings[1]!, identity: { anchor: "unsafe-output" } },
    ]);
    expect(prepared.manifest.scan.scope.includePaths).toEqual(["./src/app.ts"]);
    expect(
      prepareSemanticScanDraft(directory, input).findings.findings,
    ).toHaveLength(2);
    expect(prepareSemanticScanDraft(active, input).findings.findings).toEqual(
      prepared.findings.findings,
    );
  }
  expect(
    prepareSemanticScanDraft({ ...context, mode: "standard" }, input).findings
      .findings,
  ).toHaveLength(2);
  expect({ context, input }).toEqual(before);
});
