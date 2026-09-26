import { tmpdir } from "node:os";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import {
  createScanMergeValidator,
  scanMergeInput,
  type ScanAggregate,
} from "../src/scan-merge.js";
import {
  containsSavedFinding,
  preserveFindingDetails,
  type JsonObject,
} from "../src/scan-semantics.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const scratch = tmpdir();
const parent = "11111111-2222-4333-8444-555555555555";
const alternate = "11111111-2222-4333-8444-666666666666";
const commonPath = "schemas/definitions/artifact-common.schema.json";
const draftPath = "schemas/tools/scan-draft.schema.json";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function schemaRoot() {
  await mkdir(scratch, { recursive: true });
  const root = await mkdtemp(join(scratch, "reconciliation-"));
  directories.push(root);
  await mkdir(join(root, "schemas/definitions"), { recursive: true });
  await mkdir(join(root, "schemas/tools"), { recursive: true });
  const [common, draft] = await Promise.all(
    [commonPath, draftPath].map(async (path) => {
      const text = await readFile(join(pluginRoot, path), "utf8");
      await writeFile(join(root, path), text);
      return JSON.parse(text);
    }),
  );
  return { root, common, draft };
}

test("schema reuse observes both files changing without changing existing validators", async () => {
  const { root, common, draft } = await schemaRoot();
  const first = await createScanMergeValidator(root);
  const repeated = await createScanMergeValidator(root);
  const empty = { scanId: parent, findings: [] };
  expect(first(empty, [], null).aggregate).toEqual(empty);
  expect(repeated(empty, [], null).aggregate).toEqual(empty);

  draft.$defs.scanDraftInput.properties.findings.minItems = 1;
  await writeFile(join(root, draftPath), JSON.stringify(draft));
  const changedDraft = await createScanMergeValidator(root);
  expect(() => changedDraft(empty, [], null)).toThrow("Invalid scan merge");
  expect(first(empty, [], null).aggregate).toEqual(empty);

  delete draft.$defs.scanDraftInput.properties.findings.minItems;
  common.$defs.scanId.const = alternate;
  await writeFile(join(root, draftPath), JSON.stringify(draft));
  await writeFile(join(root, commonPath), JSON.stringify(common));
  const changedCommon = await createScanMergeValidator(root);
  expect(() => changedCommon(empty, [], null)).toThrow("Invalid scan merge");
  expect(
    changedCommon({ ...empty, scanId: alternate }, [], null).aggregate.scanId,
  ).toBe(alternate);
  expect(repeated(empty, [], null).aggregate).toEqual(empty);

  await rm(join(root, commonPath));
  await expect(createScanMergeValidator(root)).rejects.toThrow("ENOENT");
  await writeFile(join(root, commonPath), "{");
  await expect(createScanMergeValidator(root)).rejects.toThrow(SyntaxError);
});

test("concurrent schema roots retain independent validation and errors", async () => {
  const [one, two] = await Promise.all([schemaRoot(), schemaRoot()]);
  two.common.$defs.scanId.const = alternate;
  await writeFile(join(two.root, commonPath), JSON.stringify(two.common));
  const validators = await Promise.all(
    [one.root, two.root, one.root, two.root].map(createScanMergeValidator),
  );
  for (const [index, validate] of validators.entries()) {
    const scanId = index % 2 === 0 ? parent : alternate;
    const empty = { scanId, findings: [] };
    expect(validate(empty, [], null).aggregate).toEqual(empty);
    expect(() => validate({ ...empty, findings: [{}] }, [], null)).toThrow(
      "Invalid scan merge",
    );
    expect(validate(empty, [], null).aggregate).toEqual(empty);
  }
});

function finding(anchor = "record"): JsonObject {
  return {
    ruleId: "security-misconfiguration.synthetic-record",
    identity: { anchor },
    title: "Synthetic configuration record",
    summary: "Original synthetic evidence.",
    severity: { level: "medium" },
    confidence: { level: "high", rationale: "Fixed offline fixture." },
    taxonomy: { category: "security-misconfiguration", cwe: ["CWE-16"] },
    locations: [{ path: "src/record.ts", startLine: 1, endLine: 2 }],
    remediation: "Correct the synthetic configuration.",
    provenance: { source: "local_plugin" },
    extensions: {
      opaque: { evidence: ["exact\u0000bytes", "x".repeat(16384)] },
    },
  };
}

function input(scanId: string, findings = [finding()]) {
  return scanMergeInput(
    {
      scanDir: join(scratch, scanId),
      manifest: {
        scan: {
          id: scanId,
          scope: { includePaths: ["src"], excludePaths: [] },
        },
      },
      findings: {
        findings: findings.map((entry, index) => ({
          ...entry,
          findingId: `${scanId}/${index}`,
        })),
      },
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    } as unknown as Parameters<typeof scanMergeInput>[0],
    parent,
  );
}

function provenance(entry: JsonObject): JsonObject {
  return entry["provenance"] as JsonObject;
}

function submission(findings: JsonObject[]): ScanAggregate {
  return { scanId: parent, findings };
}

test("returned aggregates detach inherited history, candidates, originals and context", async () => {
  const validate = await createScanMergeValidator(pluginRoot);
  const source = input("source");
  const previous = validate(
    submission(source.draft.findings),
    [source],
    null,
  ).aggregate;
  previous.threatModel = { notes: ["saved context"] };
  const old = provenance(previous.findings[0]!);
  old["previousFindings"] = [
    { summary: "earlier synthesis", extensions: { detail: ["history"] } },
  ];
  old["originalCandidates"] = [{ detail: ["candidate"] }];
  const raw = submission([finding()]);
  raw.findings[0]!["summary"] = "Current synthesis.";
  provenance(raw.findings[0]!)["sourceFindingIds"] = ["source:0"];
  const before = structuredClone({ source, previous, raw });
  const { aggregate, newFindings } = validate(raw, [], previous);
  expect(newFindings).toBe(0);
  const saved = provenance(aggregate.findings[0]!);
  expect(saved["sourceFindings"]).toEqual([
    { id: "source:0", finding: source.sourceFindings[0] },
  ]);
  expect(saved["previousFindings"]).toEqual(
    expect.arrayContaining(old["previousFindings"] as JsonObject[]),
  );
  expect(saved["originalCandidates"]).toEqual(old["originalCandidates"]);
  expect({ source, previous, raw }).toEqual(before);

  ((saved["previousFindings"] as JsonObject[])[0]!["extensions"] as JsonObject)[
    "detail"
  ] = ["changed"];
  (saved["originalCandidates"] as JsonObject[])[0]!["detail"] = ["changed"];
  const originals = saved["sourceFindings"] as Array<{ finding: JsonObject }>;
  (originals[0]!.finding["extensions"] as JsonObject)["opaque"] = {
    evidence: [],
  };
  (aggregate.findings[0]!["locations"] as JsonObject[])[0]!["startLine"] = 99;
  (aggregate.threatModel!["notes"] as string[]).push("changed");
  expect({ source, previous, raw }).toEqual(before);
});

test("indexed attribution keeps aggregate matching order and validates again after preservation", async () => {
  const validate = await createScanMergeValidator(pluginRoot);
  const inputs = [input("one"), input("two")];
  const group = finding();
  provenance(group)["sourceFindingIds"] = ["two:0", "one:0"];
  const previous = validate(submission([group]), inputs, null).aggregate;
  const retained = finding();
  provenance(retained)["sourceFindingIds"] = ["one:0"];
  const split = finding("separate");
  provenance(split)["sourceFindingIds"] = ["two:0"];
  const before = structuredClone({ previous, retained, split });
  expect(() => validate(submission([split, retained]), [], previous)).toThrow(
    "previously accepted finding identity",
  );
  expect(() => validate(submission([retained, split]), [], previous)).toThrow(
    "more than once",
  );
  expect({ previous, retained, split }).toEqual(before);
});

test("implicit source grouping keeps exact-source ambiguity checks and insertion order", async () => {
  const validate = await createScanMergeValidator(pluginRoot);
  const source = input("implicit");
  source.sourceFindings.push(structuredClone(source.sourceFindings[0]!));
  const raw = submission([finding()]);
  const result = validate(raw, [source], null).aggregate;
  expect(provenance(result.findings[0]!)["sourceFindingIds"]).toEqual([
    "implicit:0",
    "implicit:1",
  ]);
  expect(provenance(result.findings[0]!)["sourceFindings"]).toEqual(
    source.sourceFindings.map((entry, index) => ({
      id: `implicit:${index}`,
      finding: entry,
    })),
  );
  source.sourceFindings[1]!["summary"] =
    "Distinct evidence with the same identity.";
  expect(() => validate(raw, [source], null)).toThrow(
    "ambiguous source findings",
  );
});

test("comparison projections do not mutate prior evidence and saved synthesis stays detached", () => {
  const previous = finding();
  provenance(previous)["previousFindings"] = [{ summary: "older" }];
  const before = structuredClone(previous);
  const current = finding();
  delete current["identity"];
  expect(containsSavedFinding(current, previous)).toBe(true);
  current["summary"] = "Changed synthesis.";
  expect(containsSavedFinding(current, previous)).toBe(false);
  preserveFindingDetails(current, previous);
  const history = provenance(current)["previousFindings"] as JsonObject[];
  expect(history[1]!["summary"]).toBe(previous["summary"]);
  (history[1]!["extensions"] as JsonObject)["opaque"] = { evidence: [] };
  expect(previous).toEqual(before);
});
