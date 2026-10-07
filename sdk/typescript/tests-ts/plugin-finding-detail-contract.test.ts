import { spawn } from "node:child_process";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { readJson as readJsonFile } from "./support/json.js";
import { initializeMcpClient } from "./support/mcp-client.js";

type JsonObject = Record<string, unknown>;

const invalidFindingDetails: Array<{
  section: "attackPath" | "rootCause" | "root_cause" | "validation";
  detail: JsonObject;
}> = [
  {
    section: "rootCause",
    detail: { summary: "Root cause.", code: ["not a string"] },
  },
  {
    section: "rootCause",
    detail: { summary: "Root cause.", language: 42 },
  },
  { section: "root_cause", detail: { summary: ["not a string"] } },
  { section: "root_cause", detail: { code: ["not a string"] } },
  { section: "root_cause", detail: { language: 42 } },
  { section: "attackPath", detail: { steps: "upload, then extract" } },
  { section: "attackPath", detail: { preconditions: "upload access" } },
  {
    section: "attackPath",
    detail: { reachability: { attacker: {} } },
  },
  {
    section: "attackPath",
    detail: { reachability: { entrypoint: [] } },
  },
  {
    section: "attackPath",
    detail: { reachability: { preconditions: "upload access" } },
  },
  {
    section: "attackPath",
    detail: { dataflow: { transformations: "decode, then dispatch" } },
  },
  { section: "validation", detail: { assertions: "sink reached" } },
  { section: "validation", detail: { counterEvidence: "none" } },
  { section: "validation", detail: { evidence: { kind: "trace" } } },
];

const scanDraftFinding = {
  ruleId: "path-traversal.archive-extraction",
  title: "Unsafe archive extraction",
  summary: "An untrusted archive entry reaches a filesystem write.",
  severity: { level: "high" },
  confidence: {
    level: "high",
    rationale: "Source evidence establishes reachability.",
  },
  taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
  locations: [{ path: "src/extract.py", startLine: 41 }],
  remediation: "Validate each output path before writing.",
  provenance: { source: "local_plugin" },
};

const scanDraftInput = {
  scanId: "7b95abf2-dc04-47a9-9950-53b5c2057f49",
  findings: [scanDraftFinding],
  coverage: {
    completeness: "complete",
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
  },
};

const stringAssessmentInput = {
  ...scanDraftInput,
  findings: [
    {
      ...scanDraftFinding,
      attackPath: {
        impact: "high",
        likelihood: "medium",
        reachability: {
          summary: "A repository contributor can trigger archive extraction.",
          attacker: "repository contributor",
          entrypoint: "archive extraction",
          outcome: "a file is written outside the extraction root",
          preconditions: ["The service processes the uploaded archive."],
        },
      },
    },
  ],
};

const readJson = readJsonFile<JsonObject>;

async function startMcp() {
  const child = spawn(
    process.execPath,
    [join(PLUGIN_ROOT, "mcp", "server.mjs"), "--stdio"],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  return initializeMcpClient(child, "finding-detail-contract-test", false);
}

describe("bundled plugin finding detail contracts", () => {
  test("rejects malformed known fields in scan drafts", async () => {
    const schemaRoot = join(PLUGIN_ROOT, "schemas");
    const [commonSchema, scanDraftSchema] = await Promise.all([
      readJson(join(schemaRoot, "definitions", "artifact-common.schema.json")),
      readJson(join(schemaRoot, "tools", "scan-draft.schema.json")),
    ]);
    const validator = new Ajv2020({ strict: false });
    validator.addFormat("uuid", /^[0-9a-f-]{36}$/iu);
    validator.addSchema(commonSchema);
    const validate = validator.compile(scanDraftSchema);

    expect(validate(scanDraftInput), JSON.stringify(validate.errors)).toBe(
      true,
    );
    expect(
      validate(stringAssessmentInput),
      JSON.stringify(validate.errors),
    ).toBe(true);
    expect(
      validate({
        ...scanDraftInput,
        findings: [{ ...scanDraftFinding, code_evidence: null }],
      }),
      JSON.stringify(validate.errors),
    ).toBe(false);
    for (const { section, detail } of invalidFindingDetails) {
      expect(
        validate({
          ...scanDraftInput,
          findings: [{ ...scanDraftFinding, [section]: detail }],
        }),
        `${section}: ${JSON.stringify(detail)}`,
      ).toBe(false);
    }
  });

  test("publishes the strict scan-draft contract through MCP", async () => {
    const client = await startMcp();
    try {
      const result = await client.request("tools/list", {});
      const tools = result["tools"] as Array<JsonObject>;
      const tool = tools.find(
        (candidate) => candidate["name"] === "record_codex_security_scan_draft",
      );
      expect(tool).toBeDefined();

      const validator = new Ajv({ strict: false });
      validator.addFormat("uuid", /^[0-9a-f-]{36}$/iu);
      const validate = validator.compile(tool!["inputSchema"] as JsonObject);

      expect(validate(scanDraftInput), JSON.stringify(validate.errors)).toBe(
        true,
      );
      expect(
        validate(stringAssessmentInput),
        JSON.stringify(validate.errors),
      ).toBe(true);
      expect(
        validate({
          ...scanDraftInput,
          findings: [{ ...scanDraftFinding, code_evidence: null }],
        }),
        JSON.stringify(validate.errors),
      ).toBe(false);
      for (const { section, detail } of invalidFindingDetails) {
        expect(
          validate({
            ...scanDraftInput,
            findings: [{ ...scanDraftFinding, [section]: detail }],
          }),
          `${section}: ${JSON.stringify(detail)}`,
        ).toBe(false);
      }
    } finally {
      await client.close();
    }
  });

  test("rejects malformed known fields in canonical findings", async () => {
    const [schema, example] = await Promise.all([
      readJson(join(PLUGIN_ROOT, "schemas", "findings.schema.json")),
      readJson(
        join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
      ),
    ]);
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate(example), JSON.stringify(validate.errors)).toBe(true);

    const compatibleDocument = structuredClone(example) as {
      findings: Array<JsonObject>;
    };
    compatibleDocument.findings[0]!["attackPath"] =
      stringAssessmentInput.findings[0]!.attackPath;
    expect(validate(compatibleDocument), JSON.stringify(validate.errors)).toBe(
      true,
    );

    for (const { section, detail } of invalidFindingDetails) {
      const document = structuredClone(example) as {
        findings: Array<JsonObject>;
      };
      document.findings[0]![section] = detail;
      expect(validate(document), `${section}: ${JSON.stringify(detail)}`).toBe(
        false,
      );
    }
  });
});
