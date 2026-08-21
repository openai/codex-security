const { readFileSync, writeFileSync, existsSync } = require("node:fs");
const { join, resolve } = require("node:path");
const { compile } = require("json-schema-to-typescript");
const { format } = require("prettier");

const packageRoot = resolve(__dirname, "..");
const schemas = [
  join(packageRoot, "_bundled_plugin", "schemas"),
  resolve(packageRoot, "../../plugins/codex-security/schemas"),
].find(existsSync);

if (schemas === undefined)
  throw new Error("Could not find the plugin schemas.");

function withoutAllOf(value) {
  if (Array.isArray(value)) return value.map(withoutAllOf);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key]) => key !== "allOf")
      .map(([key, child]) => [key, withoutAllOf(child)]),
  );
}

async function generate() {
  const documents = [
    ["scan-manifest.schema.json", "ScanManifest"],
    ["findings.schema.json", "FindingsDocument"],
    ["coverage.schema.json", "CoverageDocument"],
  ];
  const models = await Promise.all(
    documents.map(async ([filename, name]) => {
      const schema = JSON.parse(readFileSync(join(schemas, filename), "utf8"));
      // json-schema-to-typescript drops object fields when allOf uses contains or if/then.
      const input = withoutAllOf(schema);
      input.title = name;
      return compile(input, name, {
        bannerComment: "",
        format: false,
        ignoreMinAndMaxItems: true,
        unknownAny: true,
      });
    }),
  );

  return format(
    [
      "/* Generated from the plugin JSON Schemas. Run `pnpm generate:models`. */",
      ...models.map((model) => model.trim()),
      "export type ContractObject = Record<string, unknown>;",
      'export type ScanRecord = ScanManifest["scan"];',
      'export type ScanProducer = ScanRecord["producer"];',
      'export type ScanTargetRecord = ScanRecord["target"];',
      'export type TargetKind = ScanTargetRecord["kind"];',
      'export type ScanScope = ScanRecord["scope"];',
      'export type ThreatModel = NonNullable<ScanRecord["threatModel"]>;',
      'export type ScanHardening = NonNullable<ScanRecord["hardening"]>;',
      'export type ScanArtifact = ScanRecord["artifacts"][number];',
      'export type Finding = FindingsDocument["findings"][number];',
      'export type FindingIdentity = Finding["identity"];',
      'export type FindingFingerprints = Finding["fingerprints"];',
      'export type FindingSeverity = Finding["severity"];',
      'export type SeverityLevel = FindingSeverity["level"];',
      'export type FindingConfidence = Finding["confidence"];',
      'export type ConfidenceLevel = FindingConfidence["level"];',
      'export type FindingTaxonomy = Finding["taxonomy"];',
      'export type FindingLocation = Finding["locations"][number];',
      'export type FindingWriteup = NonNullable<Finding["writeup"]>;',
      'export type FindingCodeEvidence = NonNullable<Finding["codeEvidence"]>[number];',
      'export type FindingRootCause = Extract<Finding["rootCause"], object>;',
      'export type FindingValidation = NonNullable<Finding["validation"]>;',
      'export type FindingAttackPath = NonNullable<Finding["attackPath"]>;',
      'export type AttackPathDataflow = Extract<NonNullable<FindingAttackPath["dataFlow"]>, object>;',
      'export type AttackPathReachability = Extract<NonNullable<FindingAttackPath["reachability"]>, object>;',
      'export type FindingProvenance = Finding["provenance"];',
      'export type CoverageMode = CoverageDocument["mode"];',
      'export type CoverageCompleteness = CoverageDocument["completeness"];',
      'export type InventoryStrategy = CoverageDocument["inventoryStrategy"];',
      'export type CoverageSurface = CoverageDocument["surfaces"][number];',
      'export type SurfaceDisposition = CoverageSurface["disposition"];',
      'export type ExplicitExclusion = CoverageDocument["explicitExclusions"][number];',
      'export type DeferredCoverage = CoverageDocument["deferred"][number];',
      'export type CoverageOpenQuestion = NonNullable<CoverageDocument["openQuestions"]>[number];',
    ].join("\n\n"),
    { parser: "typescript", printWidth: 80 },
  );
}

generate().then((models) => {
  const output = join(packageRoot, "src", "models.ts");
  if (process.argv.includes("--check")) {
    if (readFileSync(output, "utf8").replaceAll("\r\n", "\n") !== models) {
      console.error(
        "src/models.ts is out of date. Run `pnpm generate:models`.",
      );
      process.exitCode = 1;
    }
    return;
  }
  writeFileSync(output, models);
});
