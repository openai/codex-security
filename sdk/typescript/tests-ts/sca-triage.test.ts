import { describe, expect, test } from "bun:test";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  dependencyTriageContract,
  dependencyTriagePrompt,
} from "../src/sca-triage.js";
import type { ScaResult, TriageFinding } from "../src/sca-types.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const contract = await dependencyTriageContract(pluginRoot);

test("skill digest tracks the required assessment references across installation roots", async () => {
  const root = await mkdtemp(join(tmpdir(), "sca-triage-contract-"));
  const files = [
    "skills/triage-finding/SKILL.md",
    "schemas/triage-result.schema.json",
    "skills/triage-finding/references/triage-result-contract.md",
    "references/static-finding-assessment.md",
    "references/security-guidance.md",
    "references/artifact-storage.md",
  ];
  try {
    for (const relative of files) {
      const path = join(root, relative);
      await mkdir(dirname(path), { recursive: true });
      await copyFile(join(pluginRoot, relative), path);
    }
    expect((await dependencyTriageContract(root)).skillDigest).toBe(
      contract.skillDigest,
    );
    for (const relative of files) {
      const path = join(root, relative);
      const original = await readFile(path, "utf8");
      await writeFile(path, `${original}\n`);
      expect((await dependencyTriageContract(root)).skillDigest).not.toBe(
        contract.skillDigest,
      );
      await writeFile(path, original);
    }
    expect((await dependencyTriageContract(root)).skillDigest).toBe(
      contract.skillDigest,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function fixture(): ScaResult {
  return {
    schemaVersion: "sca/v0",
    status: "completed",
    startedAt: "2026-09-01T00:00:00Z",
    completedAt: "2026-09-01T00:01:00Z",
    repository: {
      path: "/work/synthetic-project",
      revision: "synthetic-revision",
      dirty: false,
    },
    scanner: {
      name: "osv-scanner",
      version: "2.6.0",
      argv: [],
      startedAt: "2026-09-01T00:00:00Z",
      completedAt: "2026-09-01T00:00:30Z",
      exitCode: 1,
      rawOutputPath: "/reports/osv.json",
      stderrPath: "/reports/osv.stderr",
      advisoryMode: "offline",
      advisorySnapshotId: "synthetic-snapshot",
    },
    coverage: {
      status: "complete",
      inputs: [],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [1, 2, 3].map((index) => ({
      id: `component-${index}`,
      name: `synthetic-package-${index}`,
      version: "1.0.0",
      ecosystem: "npm",
      sourcePath: "package-lock.json",
      dependencyGroups: [],
    })),
    matches: [1, 2, 3].map((index) => ({
      id: `match-${index}`,
      componentId: `component-${index}`,
      advisoryIds: [`SYNTHETIC-${index}`],
      aliases: [],
      sourceAdvisories: [],
      severity: null,
      fixedVersions: [],
      advisoryModifiedAt: [],
    })),
    assessments: [],
    diagnostics: [],
    model: { model: null, skillDigest: null, threadId: null, costUsd: null },
    outputDir: "/reports",
  };
}

function finding(index: number): TriageFinding {
  return {
    triage_item_id: `assessment-${index}`,
    input_id: `match-${index}`,
    source_type: "advisory",
    title: `Synthetic package ${index} assessment`,
    normalized_input: {
      vulnerable_component: `synthetic-package-${index}`,
      claimed_source: "unknown",
      claimed_sink: "unknown",
      claimed_control: "unknown",
      affected_version_or_path: "1.0.0 in package-lock.json",
      preconditions: [],
      impact: "synthetic impact",
      references: [`SYNTHETIC-${index}`],
    },
    verdict: "needs_review",
    confidence: "low",
    affected_locations: [],
    reachable_path: [],
    boundary_assessment: {
      product_surface: "unknown",
      source_trust: "unknown",
      boundary_crossed: null,
      policy_basis: "insufficient context",
    },
    exploitability_stack_rank: {
      rank_queue: "needs_review",
      rank: index,
      rationale: "insufficient evidence",
      drivers: [],
    },
    evidence: [],
    counterevidence: [],
    proof_gaps: ["Deployment configuration unavailable"],
    recommended_next_step: "Review configuration",
    fix_finding_handoff: null,
  };
}

function response(
  findings: unknown[],
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    schema_version: "triage-finding/v0",
    repository: {
      path: fixture().repository.path,
      revision: fixture().repository.revision,
    },
    findings,
    ...overrides,
  });
}

describe("SCA static triage contract", () => {
  test("accepts a valid assessment for every match and restores match order", () => {
    const result = fixture();
    const assessments = contract.parse(
      response([finding(3), finding(1), finding(2)]),
      result,
    );
    expect(assessments.map((assessment) => assessment.matchId)).toEqual([
      "match-1",
      "match-2",
      "match-3",
    ]);
    expect(
      assessments.every((assessment) => assessment.status === "completed"),
    ).toBe(true);
    expect(
      assessments.every((assessment) => assessment.verdict === "needs_review"),
    ).toBe(true);
    expect(result.matches).toHaveLength(3);
  });

  test("retains valid assessments when a match is omitted", () => {
    const assessments = contract.parse(
      response([finding(1), finding(3)]),
      fixture(),
    );
    expect(assessments.map((assessment) => assessment.status)).toEqual([
      "completed",
      "failed",
      "completed",
    ]);
    expect(assessments[1]!.error).toContain("omitted");
    expect(assessments[1]!.verdict).toBeNull();
    expect(assessments[1]!.triage).toBeNull();
  });

  test("validates each finding against the shared schema", () => {
    const invalid = { ...finding(2), verdict: "invented-status" };
    const assessments = contract.parse(
      response([finding(1), invalid, finding(3)]),
      fixture(),
    );
    expect(assessments.map((assessment) => assessment.status)).toEqual([
      "completed",
      "failed",
      "completed",
    ]);
    expect(assessments[1]!.error).toContain("triage-finding/v0");
  });

  test.each(["sarif", "cve"] as const)(
    "rejects schema-valid %s source types without losing independent assessments",
    (source_type) => {
      const result = fixture();
      const matches = structuredClone(result.matches);
      const assessments = contract.parse(
        response([finding(1), { ...finding(2), source_type }, finding(3)]),
        result,
      );
      expect(assessments.map((assessment) => assessment.status)).toEqual([
        "completed",
        "failed",
        "completed",
      ]);
      expect(assessments[1]).toMatchObject({
        verdict: null,
        triage: null,
        error: "Dependency triage returned a non-advisory source type.",
      });
      expect(result.matches).toEqual(matches);
    },
  );

  test.each([
    ["package", { vulnerable_component: "synthetic-package-3" }],
    ["version", { affected_version_or_path: "2.0.0 in package-lock.json" }],
    [
      "source",
      { affected_version_or_path: "1.0.0 in other/package-lock.json" },
    ],
    ["advisory", { references: ["SYNTHETIC-3"] }],
    ["package suffix", { vulnerable_component: "synthetic-package-2-extra" }],
    ["package scope", { vulnerable_component: "@other/synthetic-package-2" }],
    [
      "version prefix",
      { affected_version_or_path: "11.0.0 in package-lock.json" },
    ],
    [
      "version build",
      { affected_version_or_path: "1.0.0+other in package-lock.json" },
    ],
    [
      "source suffix",
      { affected_version_or_path: "1.0.0 in package-lock.json.backup" },
    ],
    [
      "source prefix",
      { affected_version_or_path: "1.0.0 in other\\package-lock.json" },
    ],
    ["advisory suffix", { references: ["SYNTHETIC-20"] }],
    [
      "reference without identity",
      { references: ["https://advisory.example.invalid/details"] },
    ],
  ] as const)(
    "rejects mismatched %s identity while retaining independent assessments",
    (_label, identity) => {
      const result = fixture();
      const originalMatches = structuredClone(result.matches);
      const invalid = finding(2);
      Object.assign(invalid.normalized_input, identity);
      invalid.verdict = "not_actionable";
      const assessments = contract.parse(
        response([finding(1), invalid, finding(3)]),
        result,
      );
      expect(assessments.map(({ status }) => status)).toEqual([
        "completed",
        "failed",
        "completed",
      ]);
      expect(assessments[1]).toMatchObject({
        verdict: null,
        triage: null,
        error:
          "Dependency triage assessment does not identify the selected package, version, source, and advisory.",
      });
      expect(assessments[0]!.triage).toEqual(finding(1));
      expect(assessments[2]!.triage).toEqual(finding(3));
      expect(result.matches).toEqual(originalMatches);
    },
  );

  test.each([
    ["ID", "SYNTHETIC-1"],
    ["alias", "SYNTHETIC-ALIAS-1"],
    ["ID URL", "https://advisory.example.invalid/SYNTHETIC-1"],
    ["alias URL", "https://advisory.example.invalid/SYNTHETIC-ALIAS-1"],
  ])(
    "accepts a scoped package@version and matched advisory %s",
    (_label, reference) => {
      const result = fixture();
      result.components[0]!.name = "@synthetic/package";
      result.components[0]!.version = "1.2.3+build.4";
      result.components[0]!.sourcePath = "packages/service/package-lock.json";
      result.matches[0]!.aliases = ["SYNTHETIC-ALIAS-1"];
      const valid = finding(1);
      Object.assign(valid.normalized_input, {
        vulnerable_component: "@synthetic/package@1.2.3+build.4",
        affected_version_or_path: "packages/service/package-lock.json:12",
        references: [reference],
      });
      const assessment = contract.parse(response([valid]), result)[0]!;
      expect(assessment.status).toBe("completed");
      expect(assessment.triage).toEqual(valid);
    },
  );

  test("does not invent a resolved version for a component with a null version", () => {
    const result = fixture();
    result.components[0]!.version = null;
    const valid = finding(1);
    valid.normalized_input.affected_version_or_path =
      "package-lock.json (version unknown)";
    expect(contract.parse(response([valid]), result)[0]!.status).toBe(
      "completed",
    );
    valid.normalized_input.references = ["SYNTHETIC-OTHER"];
    expect(contract.parse(response([valid]), result)[0]!.status).toBe("failed");
  });

  test("marks duplicate input IDs unavailable without discarding independent results", () => {
    const assessments = contract.parse(
      response([finding(1), finding(2), finding(2), finding(3)]),
      fixture(),
    );
    expect(assessments.map((assessment) => assessment.status)).toEqual([
      "completed",
      "failed",
      "completed",
    ]);
    expect(assessments[1]!.error).toContain("duplicate");
  });

  test("marks colliding assessment IDs unavailable on each affected match", () => {
    const second = { ...finding(2), triage_item_id: "assessment-1" };
    const assessments = contract.parse(
      response([finding(1), second, finding(3)]),
      fixture(),
    );
    expect(assessments.map((assessment) => assessment.status)).toEqual([
      "failed",
      "failed",
      "completed",
    ]);
    expect(assessments[0]!.error).toContain("reused");
  });

  test("ignores foreign match IDs with a diagnostic and does not invent matches", () => {
    const result = fixture();
    const assessments = contract.parse(
      response([finding(1), finding(2), finding(3), finding(99)]),
      result,
    );
    expect(assessments).toHaveLength(3);
    expect(
      assessments.every((assessment) => assessment.status === "completed"),
    ).toBe(true);
    expect(result.diagnostics).toHaveLength(1);
    expect(result.diagnostics[0]).toContain("match-99");
  });

  test("keeps accepted assessment IDs unique across separate match responses", () => {
    const result = fixture();
    result.assessments = contract.parse(response([finding(1)]), {
      ...result,
      matches: [result.matches[0]!],
    });
    const assessments = contract.parse(
      response([{ ...finding(2), triage_item_id: "assessment-1" }]),
      { ...result, matches: [result.matches[1]!] },
    );
    expect(assessments[0]!.status).toBe("failed");
    expect(assessments[0]!.error).toContain("reused");
    expect(result.assessments[0]!.status).toBe("completed");
  });

  test("handles unidentified and empty responses as missing assessments", () => {
    const result = fixture();
    const assessments = contract.parse(
      response([null, { verdict: "confirmed" }]),
      result,
    );
    expect(
      assessments.every((assessment) => assessment.status === "failed"),
    ).toBe(true);
    expect(result.diagnostics).toHaveLength(2);
    expect(
      contract
        .parse(response([]), fixture())
        .every((assessment) => assessment.status === "failed"),
    ).toBe(true);
  });

  test.each([
    {
      repository: {
        path: "/work/other-project",
        revision: "synthetic-revision",
      },
    },
    {
      repository: {
        path: "/work/synthetic-project",
        revision: "other-revision",
      },
    },
  ])("rejects a result bound to foreign source context %j", (overrides) => {
    expect(() =>
      contract.parse(
        response([finding(1), finding(2), finding(3)], overrides),
        fixture(),
      ),
    ).toThrow("different repository or revision");
  });

  test("rejects malformed envelopes and JSON", () => {
    expect(() => contract.parse("not JSON", fixture())).toThrow("invalid JSON");
    expect(() =>
      contract.parse(
        response([finding(1)], { schema_version: "another-schema" }),
        fixture(),
      ),
    ).toThrow("triage-finding/v0");
    expect(() =>
      contract.parse(response([finding(1)], { unexpected: true }), fixture()),
    ).toThrow("triage-finding/v0");
  });

  test("prompt references saved evidence and current source context", () => {
    const result = fixture();
    const prompt = dependencyTriagePrompt(
      result,
      contract.skillPath,
      result.matches[1]!,
    );
    for (const value of [
      "match-2",
      "synthetic-project",
      "synthetic-revision",
      JSON.stringify(join(result.outputDir, "sca-result.json")),
    ])
      expect(prompt).toContain(value);
    expect(prompt).toContain("exact sourcePath in affected_version_or_path");
    expect(prompt).toContain("advisoryIds or aliases in references");
    expect(contract.skillDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});

test("model schema requires explicit scalar types and nullable revision without changing v0 parsing", async () => {
  const contract = await dependencyTriageContract(pluginRoot);
  const schema = contract.schema as { properties: Record<string, any> };
  expect(schema.properties["schema_version"].type).toBe("string");
  expect(schema.properties["repository"].required).toContain("revision");
  expect(schema.properties["repository"].properties.revision.type).toEqual([
    "string",
    "null",
  ]);
  expect(schema.properties["findings"].items.properties.verdict.type).toBe(
    "string",
  );
  expect(
    schema.properties["findings"].items.properties.exploitability_stack_rank
      .properties.rank_queue.type,
  ).toEqual(["string", "null"]);
});
