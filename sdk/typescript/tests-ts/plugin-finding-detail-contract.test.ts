import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { describe, expect, test } from "bun:test";
import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type JsonObject = Record<string, unknown>;

const invalidFindingDetails: Array<{
  section: "attackPath" | "validation";
  detail: JsonObject;
}> = [
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

async function readJson(path: string): Promise<JsonObject> {
  return JSON.parse(await readFile(path, "utf8")) as JsonObject;
}

async function startMcp() {
  const child = spawn(
    process.execPath,
    [join(PLUGIN_ROOT, "mcp", "server.mjs"), "--stdio"],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const messages = createInterface({ input: child.stdout })[
    Symbol.asyncIterator
  ]();
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  let nextId = 0;

  async function request(
    method: string,
    params: JsonObject,
  ): Promise<JsonObject> {
    const id = ++nextId;
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
    );
    while (true) {
      const message = await messages.next();
      if (message.done) {
        throw new Error(`MCP server exited before replying: ${stderr}`);
      }
      const response = JSON.parse(message.value) as JsonObject;
      if (response["id"] !== id) continue;
      if (response["error"] !== undefined) {
        throw new Error(JSON.stringify(response["error"]));
      }
      return response["result"] as JsonObject;
    }
  }

  await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "finding-detail-contract-test", version: "1.0.0" },
  });
  child.stdin.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    })}\n`,
  );

  return {
    request,
    async close(): Promise<void> {
      child.stdin.end();
      await new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
    },
  };
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
