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

function projectFindingDetails(details: JsonObject): string {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const script = [
    "import json, pathlib, runpy, sys",
    "plugin = pathlib.Path(sys.argv[1])",
    "examples = plugin / 'examples' / 'completed-scan'",
    "manifest, findings, coverage = [json.loads((examples / name).read_text()) for name in ('scan-manifest.json', 'findings.json', 'coverage.json')]",
    "findings['findings'][0].update(json.loads(sys.argv[2]))",
    "projection = runpy.run_path(str(plugin / 'scripts' / 'report_projection.py'))",
    "print(projection['build_report_markdown'](manifest, findings, coverage))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", script, PLUGIN_ROOT, JSON.stringify(details)],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return new TextDecoder().decode(result.stdout);
}

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

  test.each(["dataFlow", "dataflow", "data_flow"] as const)(
    "projects scalar finding details for the %s alias",
    (dataFlowKey) => {
      const report = projectFindingDetails({
        attackPath: {
          [dataFlowKey]: "request -> archive extraction -> filesystem write",
          reachability: "An authenticated uploader can trigger extraction.",
        },
        validation: {
          assertions: ["The destination escapes the extraction root."],
          evidence: "The archive entry path is not contained.",
          limitations: ["The upload route was not exercised dynamically."],
        },
      });

      expect(report).toContain(
        "request -\\> archive extraction -\\> filesystem write",
      );
      expect(report).toContain(
        "An authenticated uploader can trigger extraction.",
      );
      expect(report).toContain("The destination escapes the extraction root.");
      expect(report).toContain("The archive entry path is not contained.");
      expect(report).toContain(
        "The upload route was not exercised dynamically.",
      );
    },
  );

  test("projects the populated data-flow alias", () => {
    const report = projectFindingDetails({
      attackPath: {
        dataFlow: { producerExtension: true },
        dataflow: {
          summary:
            "request -> populated lowercase dataflow -> filesystem write",
        },
      },
    });

    expect(report).toContain(
      "request -\\> populated lowercase dataflow -\\> filesystem write",
    );
  });

  test("ignores malformed data-flow alias values", () => {
    const report = projectFindingDetails({
      attackPath: {
        dataFlow: { summary: ["invalid canonical value"] },
        dataflow: { summary: "request -> validated sink" },
      },
    });

    expect(report).toContain("request -\\> validated sink");
  });

  test("merges transformations across data-flow aliases", () => {
    const report = projectFindingDetails({
      attackPath: {
        dataFlow: {
          transformations: ["decode archive entry", "parse *input*"],
        },
        dataflow: {
          summary: "request -> archive extraction -> filesystem write",
          transformations: ["dispatch extraction", "decode archive entry"],
        },
        data_flow: { transformations: null },
      },
    });

    expect(report).toContain("- decode archive entry");
    expect(report).toContain("- dispatch extraction");
    expect(report.match(/- decode archive entry/gu)).toHaveLength(1);
    expect(report.split(/\r?\n/u)).toContain("- parse \\*input\\*");
  });

  test("merges top-level and reachability preconditions", () => {
    const report = projectFindingDetails({
      attackPath: {
        preconditions: [
          "The service processes uploaded archives.",
          "The attacker can upload an archive.",
        ],
        reachability: {
          summary: "An authenticated uploader can trigger extraction.",
          preconditions: [
            "The attacker can upload an archive.",
            "Automatic extraction is enabled.",
          ],
        },
      },
    });

    expect(
      report.match(/- The service processes uploaded archives\./gu),
    ).toHaveLength(1);
    expect(
      report.match(/- The attacker can upload an archive\./gu),
    ).toHaveLength(1);
    expect(report.match(/- Automatic extraction is enabled\./gu)).toHaveLength(
      1,
    );
  });

  test("projects the top-level attack-path summary as reachability", () => {
    const report = projectFindingDetails({
      attackPath: {
        summary: "An authenticated uploader can trigger archive extraction.",
      },
    });

    const reachability = report
      .split("#### Reachability", 2)[1]!
      .split("#### Severity", 1)[0]!;
    expect(reachability).toContain(
      "An authenticated uploader can trigger archive extraction.",
    );
    expect(reachability).not.toContain("Reachability was not recorded");
  });

  test("projects typed attack-path steps", () => {
    const report = projectFindingDetails({
      attackPath: {
        steps: [
          "Upload an archive with a traversal entry.",
          "Trigger automatic extraction.",
        ],
      },
    });

    const dataflow = report
      .split("#### Dataflow", 2)[1]!
      .split("#### Reachability", 1)[0]!;
    expect(dataflow).toContain("Attack steps:");
    expect(dataflow).toContain("- Upload an archive with a traversal entry.");
    expect(dataflow).toContain("- Trigger automatic extraction.");
  });

  test("projects typed assessments and validation outcomes", () => {
    const report = projectFindingDetails({
      validation: {
        status: "validated",
        disposition: "reported",
        result: "The traversal write was confirmed.",
      },
      attackPath: {
        impact: {
          level: "high",
          rationale: "The write can overwrite application files.",
          why: "The destination escapes the extraction root.",
        },
        likelihood: "Likely for authenticated uploaders.",
        reachability: {
          source: "Attacker-controlled archive entry.",
          sink: "Unchecked filesystem write.",
        },
      },
    });

    expect(report).toContain("- **Status:** validated");
    expect(report).toContain("- **Disposition:** reported");
    expect(report).toContain(
      "- **Result:** The traversal write was confirmed.",
    );
    expect(report).toContain(
      "- **Source:** Attacker-controlled archive entry.",
    );
    expect(report).toContain("- **Sink:** Unchecked filesystem write.");
    expect(report).toContain("Impact assessment:");
    expect(report).toContain("- **Level:** high");
    expect(report).toContain(
      "- **Rationale:** The write can overwrite application files.",
    );
    expect(report).toContain(
      "- **Why:** The destination escapes the extraction root.",
    );
    expect(report).toContain(
      "**Likelihood assessment:** Likely for authenticated uploaders.",
    );
  });

  test("projects attack-path context lists", () => {
    const report = projectFindingDetails({
      attackPath: {
        assumptions: ["Automatic extraction is enabled."],
        blindspots: ["A downstream sandbox was not exercised."],
        controls: ["Archive uploads require authentication."],
        limitations: ["The exploit was validated statically."],
      },
    });

    const reachability = report
      .split("#### Reachability", 2)[1]!
      .split("#### Severity", 1)[0]!;
    expect(reachability).toContain("Assumptions:");
    expect(reachability).toContain("- Automatic extraction is enabled.");
    expect(reachability).toContain("Existing controls:");
    expect(reachability).toContain("- Archive uploads require authentication.");
    expect(reachability).toContain("Blind spots:");
    expect(reachability).toContain("- A downstream sandbox was not exercised.");
    expect(reachability).toContain("Limitations:");
    expect(reachability).toContain("- The exploit was validated statically.");
  });

  test("merges root-cause aliases in generated reports", () => {
    const report = projectFindingDetails({
      rootCause: { summary: "" },
      root_cause: {
        summary: "The destination is not contained before the write.",
        code: "destination.write_bytes(payload)",
        language: "python",
      },
    }).replaceAll("\r\n", "\n");

    expect(report).toContain(
      "The destination is not contained before the write.",
    );
    expect(report).toContain(
      "```python\ndestination.write_bytes(payload)\n```",
    );
  });

  test("merges scalar and list root-cause evidence references", () => {
    const report = projectFindingDetails({
      rootCause: {
        evidenceRefs: ["canonical-root-source"],
        summary: "The source reaches the write.",
      },
      root_cause: { evidence_refs: "legacy-root-source" },
      codeEvidence: [
        { id: "canonical-root-source", code: "canonical_source()" },
      ],
      code_evidence: [{ id: "legacy-root-source", code: "legacy_source()" }],
    });

    expect(report).toContain("canonical_source()");
    expect(report).toContain("legacy_source()");
  });

  test("merges embedded evidence across root-cause aliases", () => {
    const report = projectFindingDetails({
      rootCause: {
        summary: "The canonical root cause.",
        codeEvidence: [{ id: "canonical-root", code: "canonical_evidence()" }],
      },
      root_cause: {
        codeEvidence: [{ id: "legacy-root", code: "legacy_evidence()" }],
      },
    });

    expect(report).toContain("canonical_evidence()");
    expect(report).toContain("legacy_evidence()");
  });

  test("treats whitespace root-cause fields as unpopulated", () => {
    const report = projectFindingDetails({
      rootCause: { summary: "   ", code: "\t", language: "text" },
      root_cause: {
        summary: "The destination is not contained before the write.",
        code: "destination.write_bytes(payload)",
        language: "python",
      },
    }).replaceAll("\r\n", "\n");

    expect(report).toContain(
      "The destination is not contained before the write.",
    );
    expect(report).toContain(
      "```python\ndestination.write_bytes(payload)\n```",
    );
  });

  test("projects code evidence referenced by nested attack-path details", () => {
    const report = projectFindingDetails({
      attackPath: {
        dataflow: {
          evidenceRefs: [],
          evidence_refs: ["archive-source"],
          summary: "An archive entry path reaches a filesystem write.",
        },
        reachability: {
          evidenceRefs: ["archive-sink"],
          summary: "An authenticated uploader can trigger extraction.",
        },
      },
      codeEvidence: [
        {
          code: "entry_path = archive_entry.name",
          explanation: "The archive controls the path.",
          id: "archive-source",
          label: "Attacker-controlled archive path",
          path: "src/archive.py",
          startLine: 20,
        },
        {
          code: "destination.write_bytes(entry.read())",
          explanation: "The unchecked path reaches the write.",
          id: "archive-sink",
          label: "Unchecked filesystem write",
          path: "src/archive.py",
          startLine: 41,
        },
      ],
    });

    expect(report).toContain("entry_path = archive_entry.name");
    expect(report).toContain("destination.write_bytes(entry.read())");
  });

  test("normalizes scalar code-evidence references in generated reports", () => {
    const report = projectFindingDetails({
      root_cause: {
        summary: "The authorization check occurs after the write.",
        evidence_refs: "root-source",
      },
      attackPath: {
        dataflow: {
          summary: "An attacker-controlled value reaches the write.",
          evidence_refs: "dataflow-source",
        },
        reachability: {
          summary: "An authenticated caller can reach the handler.",
          evidence_refs: "reachability-source",
        },
      },
      codeEvidence: [
        { id: "root-source", code: "root_source()" },
        { id: "dataflow-source", code: "dataflow_source()" },
        { id: "reachability-source", code: "reachability_source()" },
      ],
    });

    expect(report).toContain("root_source()");
    expect(report).toContain("dataflow_source()");
    expect(report).toContain("reachability_source()");
  });

  test("rejects unknown code evidence referenced by nested attack-path details", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "finding = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())['findings'][0]",
      "finding['attackPath'] = {'dataflow': {'evidenceRefs': ['missing-evidence']}}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "try:",
      "    finalizer['_validate_finding'](finding, 'findings[0]')",
      "except finalizer['ContractError'] as error:",
      "    print(error)",
      "else:",
      "    print('accepted')",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(new TextDecoder().decode(result.stdout)).toContain(
      "attackPath.dataflow.evidenceRefs: unknown code-evidence ids: missing-evidence",
    );
  });

  test("accepts nested references to the legacy code evidence catalog", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "finding = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())['findings'][0]",
      "finding.pop('codeEvidence', None)",
      "finding['code_evidence'] = [{'id': 'legacy-source', 'code': 'entry_path = archive_entry.name'}]",
      "finding['attackPath'] = {'dataflow': {'evidence_refs': ['legacy-source']}}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "finalizer['_validate_finding'](finding, 'findings[0]')",
      "print('accepted')",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(new TextDecoder().decode(result.stdout)).toContain("accepted");
  });

  test("rejects duplicate IDs across code evidence catalogs", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "finding = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())['findings'][0]",
      "finding['codeEvidence'] = [{'id': 'shared-source', 'code': 'canonical_source()'}]",
      "finding['code_evidence'] = [{'id': 'shared-source', 'code': 'conflicting_legacy_source()'}]",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "try:",
      "    finalizer['_validate_finding'](finding, 'findings[0]')",
      "except finalizer['ContractError'] as error:",
      "    print(error)",
      "else:",
      "    print('accepted')",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(new TextDecoder().decode(result.stdout)).toContain(
      "code_evidence[0].id: duplicate code-evidence id",
    );
  });

  test("keeps legacy sealed evidence references compatible", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "findings['findings'][0]['codeEvidence'] = [{'id': 'shared-source', 'label': 'Canonical source', 'path': 'src/extract.py', 'startLine': 41, 'code': 'canonical_source()', 'explanation': 'Canonical snippet.'}]",
      "findings['findings'][0]['code_evidence'] = [",
      "    {'id': 'shared-source', 'code': 'legacy_source()'},",
      "    {'id': 'legacy-duplicate', 'code': 'first_legacy_source()'},",
      "    {'id': 'legacy-duplicate', 'code': 'second_legacy_source()'},",
      "]",
      "findings['findings'][0]['validation'] = {'evidence_refs': ['legacy-validation-evidence'], 'counterEvidence': None, 'limitations': '', 'method': [], 'status': '', 'summary': {}, 'disposition': '', 'result': ''}",
      "findings['findings'][0]['rootCause'] = {'summary': 'Canonical root cause.', 'code': 'canonical_root()', 'language': 'python'}",
      "findings['findings'][0]['attackPath'] = {'evidence_refs': ['legacy-attack-evidence'], 'dataFlow': '', 'dataflow': {'summary': '', 'source': None, 'sink': None, 'outcome': None, 'evidenceRefs': ['legacy-missing-evidence']}, 'impact': {'level': '', 'rationale': None, 'why': None}, 'likelihood': {'level': None, 'rationale': None, 'why': None}, 'reachability': None, 'summary': ''}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "finalizer['_validate_finding'](compatible['findings'][0], 'findings[0]')",
      "finalizer['validate_against_schema'](compatible, plugin / 'schemas' / 'findings.schema.json')",
      "print(json.dumps({'originalDataFlow': findings['findings'][0]['attackPath']['dataFlow'], 'compatibleHasDataFlow': 'dataFlow' in compatible['findings'][0]['attackPath'], 'originalNested': findings['findings'][0]['attackPath']['dataflow']['evidenceRefs'], 'compatibleNested': compatible['findings'][0]['attackPath']['dataflow']['evidenceRefs'], 'originalReachability': findings['findings'][0]['attackPath']['reachability'], 'compatibleHasReachability': 'reachability' in compatible['findings'][0]['attackPath'], 'originalAttack': findings['findings'][0]['attackPath']['evidence_refs'], 'compatibleAttack': compatible['findings'][0]['attackPath']['evidence_refs'], 'originalValidation': findings['findings'][0]['validation']['evidence_refs'], 'compatibleValidation': compatible['findings'][0]['validation']['evidence_refs'], 'compatibleHasCounterEvidence': 'counterEvidence' in compatible['findings'][0]['validation'], 'compatibleHasDisposition': 'disposition' in compatible['findings'][0]['validation'], 'compatibleHasLimitations': 'limitations' in compatible['findings'][0]['validation'], 'compatibleHasMethod': 'method' in compatible['findings'][0]['validation'], 'compatibleHasResult': 'result' in compatible['findings'][0]['validation'], 'compatibleHasRootCause': 'rootCause' in compatible['findings'][0], 'compatibleHasStatus': 'status' in compatible['findings'][0]['validation'], 'compatibleHasSummary': 'summary' in compatible['findings'][0]['validation'], 'originalMethod': findings['findings'][0]['validation']['method'], 'originalRootCauseSummary': findings['findings'][0]['rootCause']['summary'], 'originalSummary': findings['findings'][0]['validation']['summary'], 'originalLegacyCatalog': findings['findings'][0]['code_evidence'], 'compatibleLegacyCatalog': compatible['findings'][0]['code_evidence']}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      compatibleAttack: [],
      compatibleLegacyCatalog: [
        { code: "first_legacy_source()", id: "legacy-duplicate" },
      ],
      compatibleHasDataFlow: false,
      compatibleHasReachability: false,
      compatibleNested: [],
      compatibleValidation: [],
      compatibleHasCounterEvidence: false,
      compatibleHasDisposition: false,
      compatibleHasLimitations: false,
      compatibleHasMethod: false,
      compatibleHasResult: false,
      compatibleHasRootCause: true,
      compatibleHasStatus: false,
      compatibleHasSummary: false,
      originalAttack: ["legacy-attack-evidence"],
      originalLegacyCatalog: [
        { code: "legacy_source()", id: "shared-source" },
        { code: "first_legacy_source()", id: "legacy-duplicate" },
        { code: "second_legacy_source()", id: "legacy-duplicate" },
      ],
      originalMethod: [],
      originalDataFlow: "",
      originalNested: ["legacy-missing-evidence"],
      originalReachability: null,
      originalRootCauseSummary: "Canonical root cause.",
      originalSummary: {},
      originalValidation: ["legacy-validation-evidence"],
    });
  });

  test("normalizes formerly free-form sealed details for validation", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "finding = findings['findings'][0]",
      "finding['validation'] = {'evidence': {'kind': 'trace'}, 'counterEvidence': [None, 'The mitigation was checked.']}",
      "finding['attackPath'] = {'steps': {'first': 'upload'}}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "finalizer['_validate_finding'](compatible['findings'][0], 'findings[0]')",
      "finalizer['validate_against_schema'](compatible, plugin / 'schemas' / 'findings.schema.json')",
      "print(json.dumps({'originalValidation': finding['validation'], 'originalAttackPath': finding['attackPath'], 'compatibleValidation': compatible['findings'][0]['validation'], 'compatibleAttackPath': compatible['findings'][0]['attackPath']}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      originalValidation: {
        evidence: { kind: "trace" },
        counterEvidence: [null, "The mitigation was checked."],
      },
      originalAttackPath: { steps: { first: "upload" } },
      compatibleValidation: {
        counterEvidence: ["The mitigation was checked."],
      },
      compatibleAttackPath: {},
    });
  });

  test("rejects malformed canonical root causes during sealed validation", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "findings['findings'][0]['rootCause'] = {'summary': []}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "try:",
      "    finalizer['validate_against_schema'](compatible, plugin / 'schemas' / 'findings.schema.json')",
      "except finalizer['ContractError'] as error:",
      "    print(error)",
      "else:",
      "    print('accepted')",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(new TextDecoder().decode(result.stdout)).toContain(
      "rootCause.summary",
    );
  });

  test("ranks legacy code evidence during interrupted recovery", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import copy, json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "examples = plugin / 'examples' / 'completed-scan'",
      "manifest = json.loads((examples / 'scan-manifest.json').read_text())",
      "example = json.loads((examples / 'findings.json').read_text())['findings'][0]",
      "first = copy.deepcopy(example)",
      "first.pop('codeEvidence', None)",
      "first['summary'] = 'FIRST'",
      "second = copy.deepcopy(first)",
      "second['summary'] = 'SECOND'",
      "second['code_evidence'] = [{'id': 'legacy-source', 'code': 'legacy_source()'}]",
      "second['root_cause'] = None",
      "findings = {'scanId': manifest['scan']['id'], 'findings': [first, second]}",
      "warnings = []",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "finalizer['_recover_unsealed_findings'](manifest, findings, plugin / 'schemas', examples, warnings)",
      "print(json.dumps({'summary': findings['findings'][0]['summary'], 'evidence': findings['findings'][0].get('code_evidence'), 'rootCause': findings['findings'][0].get('root_cause'), 'warnings': warnings}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      summary: "SECOND",
      evidence: [{ id: "legacy-source", code: "legacy_source()" }],
      rootCause: null,
      warnings: [
        "Recovered finding 2: retained stronger duplicate logical finding.",
      ],
    });
  });

  test("ranks embedded root-cause evidence during interrupted recovery", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import copy, json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "examples = plugin / 'examples' / 'completed-scan'",
      "manifest = json.loads((examples / 'scan-manifest.json').read_text())",
      "example = json.loads((examples / 'findings.json').read_text())['findings'][0]",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "results = {}",
      "for name, detail in {'embedded': {'codeEvidence': [{'id': 'embedded-root', 'code': 'embedded_root()'}]}, 'legacy-code': {'code': 'legacy_root()'}}.items():",
      "    first = copy.deepcopy(example)",
      "    first.pop('codeEvidence', None)",
      "    first['summary'] = 'FIRST'",
      "    second = copy.deepcopy(first)",
      "    second['summary'] = 'SECOND'",
      "    second['rootCause'] = {'summary': 'Richer root cause', **detail}",
      "    findings = {'scanId': manifest['scan']['id'], 'findings': [first, second]}",
      "    warnings = []",
      "    finalizer['_recover_unsealed_findings'](manifest, findings, plugin / 'schemas', examples, warnings)",
      "    results[name] = {'summary': findings['findings'][0]['summary'], 'warnings': warnings}",
      "print(json.dumps(results))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      embedded: {
        summary: "SECOND",
        warnings: [
          "Recovered finding 2: retained stronger duplicate logical finding.",
        ],
      },
      "legacy-code": {
        summary: "SECOND",
        warnings: [
          "Recovered finding 2: retained stronger duplicate logical finding.",
        ],
      },
    });
  });

  test("ignores malformed legacy evidence references in sealed validation", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "finding = findings['findings'][0]",
      "finding['code_evidence'] = [{'id': 'legacy-source', 'code': 'legacy_source()'}]",
      "finding['rootCause'] = {'summary': 'Canonical root cause.', 'evidenceRefs': ['legacy-source', 'missing-source']}",
      "finding['validation'] = {'evidenceRefs': [None, '', 42, 'legacy-source', 'missing-source']}",
      "finding['attackPath'] = {'dataflow': {'evidence_refs': [None, '', 42, 'legacy-source', 'missing-source']}}",
      "original = json.dumps(findings, sort_keys=True)",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "finalizer['_validate_finding'](compatible['findings'][0], 'findings[0]')",
      "print(json.dumps({",
      "    'originalUnchanged': json.dumps(findings, sort_keys=True) == original,",
      "    'originalRootCause': finding['rootCause'],",
      "    'compatibleRootCause': compatible['findings'][0]['rootCause'],",
      "    'originalValidation': finding['validation']['evidenceRefs'],",
      "    'compatibleValidation': compatible['findings'][0]['validation']['evidenceRefs'],",
      "    'originalDataflow': finding['attackPath']['dataflow']['evidence_refs'],",
      "    'compatibleDataflow': compatible['findings'][0]['attackPath']['dataflow']['evidence_refs'],",
      "}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      originalUnchanged: true,
      originalRootCause: {
        summary: "Canonical root cause.",
        evidenceRefs: ["legacy-source", "missing-source"],
      },
      compatibleRootCause: {
        summary: "Canonical root cause.",
        evidenceRefs: ["legacy-source"],
      },
      originalValidation: [null, "", 42, "legacy-source", "missing-source"],
      compatibleValidation: ["legacy-source"],
      originalDataflow: [null, "", 42, "legacy-source", "missing-source"],
      compatibleDataflow: ["legacy-source"],
    });
  });

  test("drops unsupported legacy attack-path sequences from sealed validation", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "findings['findings'][0]['attackPath'] = {'dataflow': ['source', 'sink'], 'reachability': ['authenticated uploader']}",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "finalizer['validate_against_schema'](compatible, plugin / 'schemas' / 'findings.schema.json')",
      "print(json.dumps({'original': findings['findings'][0]['attackPath'], 'compatible': compatible['findings'][0]['attackPath']}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      original: {
        dataflow: ["source", "sink"],
        reachability: ["authenticated uploader"],
      },
      compatible: {},
    });
  });

  test("keeps nullable legacy sealed evidence catalogs compatible", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import copy, json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "example = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())['findings'][0]",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "results = {}",
      "for field in ('codeEvidence', 'code_evidence'):",
      "    finding = copy.deepcopy(example)",
      "    finding[field] = None",
      "    compatible = finalizer['_legacy_sealed_findings_for_validation']({'findings': [finding]})",
      "    try:",
      "        finalizer['_validate_finding'](compatible['findings'][0], 'findings[0]')",
      "    except finalizer['ContractError'] as error:",
      "        outcome = str(error)",
      "    else:",
      "        outcome = 'accepted'",
      "    results[field] = {'outcome': outcome, 'present': field in compatible['findings'][0]} ",
      "print(json.dumps(results))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      codeEvidence: {
        outcome: "findings[0].codeEvidence: expected an array",
        present: true,
      },
      code_evidence: { outcome: "accepted", present: false },
    });
  });

  test("ignores malformed legacy evidence rows in sealed validation", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "findings = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())",
      "findings['findings'][0]['code_evidence'] = [None, 'legacy source', {}, {'id': '', 'code': 'empty_id()'}, {'id': 'missing-code'}, {'id': 'empty-code', 'code': ''}, {'id': 'legacy-source', 'code': 'legacy_source()'}]",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "compatible = finalizer['_legacy_sealed_findings_for_validation'](findings)",
      "finalizer['_validate_finding'](compatible['findings'][0], 'findings[0]')",
      "print(json.dumps({'original': findings['findings'][0]['code_evidence'], 'compatible': compatible['findings'][0]['code_evidence']}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      original: [
        null,
        "legacy source",
        {},
        { id: "", code: "empty_id()" },
        { id: "missing-code" },
        { id: "empty-code", code: "" },
        { id: "legacy-source", code: "legacy_source()" },
      ],
      compatible: [{ id: "legacy-source", code: "legacy_source()" }],
    });
  });

  test("projects canonical and legacy code evidence into safe SARIF locations", () => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const script = [
      "import json, pathlib, runpy, sys",
      "plugin = pathlib.Path(sys.argv[1])",
      "finding = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text())['findings'][0]",
      "finding['codeEvidence'] = [{'id': 'canonical-source', 'path': 'src/canonical.py', 'startLine': 12, 'code': 'canonical_source()'}]",
      "finding['code_evidence'] = [",
      "    {'id': 'legacy-sink', 'path': 'src/legacy.py', 'startLine': 37, 'endLine': 39, 'code': 'legacy_sink()'},",
      "    {'id': 'legacy-null-end', 'path': 'src/null_end.py', 'startLine': 48, 'endLine': None, 'code': 'null_end()'},",
      "    {'id': 'legacy-reversed-end', 'path': 'src/reversed_end.py', 'startLine': 59, 'endLine': 58, 'code': 'reversed_end()'},",
      "    {'id': 'legacy-text-end', 'path': 'src/text_end.py', 'startLine': 70, 'endLine': '71', 'code': 'text_end()'},",
      "    {'id': 'legacy-zero-start', 'path': 'src/zero.py', 'startLine': 0, 'code': 'zero_start()'},",
      "    {'id': 'legacy-unsafe-path', 'path': '../outside.py', 'startLine': 81, 'code': 'unsafe_path()'},",
      "]",
      "finalizer = runpy.run_path(str(plugin / 'scripts' / 'finalize_scan_contract.py'))",
      "result = finalizer['_sarif_result'](finding, 0)",
      "regions = {location['physicalLocation']['artifactLocation']['uri']: location['physicalLocation']['region'] for location in result['locations']}",
      "print(json.dumps(regions, sort_keys=True))",
    ].join("\n");
    const result = Bun.spawnSync(
      [python!, "-I", "-B", "-c", script, PLUGIN_ROOT],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toMatchObject({
      "src/canonical.py": { startLine: 12, endLine: 12 },
      "src/legacy.py": { startLine: 37, endLine: 39 },
      "src/null_end.py": { startLine: 48, endLine: 48 },
      "src/reversed_end.py": { startLine: 59, endLine: 59 },
      "src/text_end.py": { startLine: 70, endLine: 70 },
    });
    expect(
      JSON.parse(new TextDecoder().decode(result.stdout)),
    ).not.toHaveProperty("src/zero.py");
    expect(
      JSON.parse(new TextDecoder().decode(result.stdout)),
    ).not.toHaveProperty("../outside.py");
  });
});
