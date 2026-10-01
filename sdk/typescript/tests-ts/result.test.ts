import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScanResult } from "../src/index.js";
import { fakeResult } from "./cli-fixtures.js";
import type {
  CoverageDocument,
  FindingsDocument,
  RepositoryFinding,
  ScanManifest,
  SeverityLevel,
} from "../src/index.js";

const manifest = {
  documentType: "codex-security.scan-manifest",
  schemaVersion: "1.0",
  scan: {
    id: "scan",
    producer: { name: "codex-security-plugin", version: "0.1.14" },
    status: "completed",
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:00:01Z",
    sealedAt: "2026-01-01T00:00:01Z",
    target: { kind: "git_revision", targetId: "id", displayName: "repo" },
    scope: { includePaths: ["."], excludePaths: [] },
    coverageRef: "coverage.json",
    findingsRef: "findings.json",
    artifacts: [],
  },
} satisfies ScanManifest;

const findings = {
  documentType: "codex-security.findings",
  schemaVersion: "1.0",
  scanId: "scan",
  findings: [],
} satisfies FindingsDocument;

const coverage = {
  documentType: "codex-security.coverage",
  schemaVersion: "1.0",
  scanId: "scan",
  mode: "repository",
  completeness: "complete",
  inventoryStrategy: "repository",
  includePaths: ["."],
  excludePaths: [],
  surfaces: [],
  explicitExclusions: [],
  deferred: [],
} satisfies CoverageDocument;

describe("ScanResult", () => {
  test.each(["candidateId", "reportId", "ledgerRowId"])(
    "recognizes resolved candidates through legacy extensions.%s",
    (field) => {
      const result = fakeResult(["high"]);
      result.findings.findings[0]!.extensions = { [field]: "resolved" };
      result.coverage.deferred = [
        {
          id: "old",
          candidateId: "resolved",
          reason: "Superseded checkpoint.",
        },
        {
          id: "pending",
          candidateId: "pending",
          reason: "Still awaiting a decision.",
        },
      ];
      expect(
        result.unresolvedCandidates.map((candidate) => candidate.candidateId),
      ).toEqual(["pending"]);
      expect(result.unresolvedCandidateCount).toBe(1);
    },
  );

  test("counts saved unresolved candidates once per logical worker", () => {
    const result = fakeResult(["high"]);
    result.findings.findings[0]!.provenance["candidateId"] = "confirmed";
    result.coverage.completeness = "partial";
    result.coverage.surfaces = [
      {
        id: "rejected",
        label: "Rejected candidate",
        disposition: "rejected",
        receiptRefs: [],
        candidateId: "rejected",
      },
      {
        id: "excluded",
        label: "Not applicable",
        disposition: "not_applicable",
        receiptRefs: [],
        candidateId: "excluded",
      },
    ];
    result.coverage.deferred = [
      { id: "scan-stopped", reason: "Review did not finish." },
      { id: "old", candidateId: "pending", reason: "Awaiting evidence." },
      {
        id: "checkpoint",
        candidateId: "pending",
        reason: "Same saved candidate.",
      },
      {
        id: "confirmed",
        candidateId: "confirmed",
        reason: "Superseded by a finding.",
      },
      {
        id: "rejected",
        candidateId: "rejected",
        reason: "Superseded by rejection.",
      },
      {
        id: "excluded",
        candidateId: "excluded",
        reason: "Superseded by exclusion.",
      },
      {
        id: "worker-a",
        candidateId: "pending",
        sourceWorkerId: "worker-a",
        reason: "Worker A candidate.",
      },
      {
        id: "worker-b",
        candidateId: "pending",
        sourceWorkerId: "worker-b",
        reason: "Worker B candidate.",
      },
    ];
    expect(result.unresolvedCandidateCount).toBe(3);
    expect(
      result.unresolvedCandidates.map((candidate) => candidate.id),
    ).toEqual(["old", "worker-a", "worker-b"]);
    expect(result.toJSON()).toMatchObject({
      unresolvedCandidateCount: 3,
      unresolvedCandidates: result.unresolvedCandidates,
    });
    expect(result.findings.findings).toHaveLength(1);
    expect(result.hasFindingsAtOrAbove("high")).toBe(true);
    expect(fakeResult([]).unresolvedCandidateCount).toBe(0);
  });

  test.each([
    [{ sourceWorkerId: { imported: "worker" } }, {}, undefined],
    [{ sourceWorkerId: ["worker"] }, {}, undefined],
    [{ sourceWorkerId: " " }, {}, undefined],
    [{ sourceWorkerId: {}, workerId: "worker-a" }, {}, "worker-a"],
    [
      { sourceWorkerId: " ", workerId: [] },
      { sourceWorkerId: "worker-a" },
      "worker-a",
    ],
  ])(
    "resolves candidates using string owner metadata: %j",
    (provenance, extensions, owner) => {
      const result = fakeResult(["high"]);
      const finding = result.findings.findings[0]!;
      finding.provenance = {
        ...finding.provenance,
        ...provenance,
        candidateId: "confirmed",
      };
      finding.extensions = extensions;
      const savedFinding = structuredClone(finding);
      result.coverage.deferred = [
        {
          id: "resolved",
          candidateId: "confirmed",
          sourceWorkerId: owner,
          reason: "Earlier checkpoint.",
        },
        {
          id: "other-worker",
          candidateId: "confirmed",
          sourceWorkerId: "worker-b",
          reason: "Independent review.",
        },
      ];

      expect(
        result.unresolvedCandidates.map((candidate) => candidate.id),
      ).toEqual(["other-worker"]);
      expect(result.toJSON()).toMatchObject({
        unresolvedCandidateCount: 1,
        unresolvedCandidates: [result.coverage.deferred[1]],
      });
      expect(finding).toEqual(savedFinding);
    },
  );

  test.each([{ metadata: ["worker"] }, { metadata: { imported: "worker" } }])(
    "keeps candidates pending when a coverage decision has structured owner metadata: %j",
    ({ metadata }) => {
      const result = fakeResult([]);
      result.coverage.explicitExclusions = [
        {
          pattern: "src/other.py",
          reason: "Imported decision for an unspecified owner.",
          candidateId: "pending",
          disposition: "rejected",
          sourceWorkerId: metadata,
        },
      ];
      result.coverage.deferred = [
        {
          id: "pending-row",
          candidateId: "pending",
          reason: "Current candidate still needs review.",
        },
      ];
      const savedCoverage = structuredClone(result.coverage);

      expect(result.unresolvedCandidateCount).toBe(1);
      expect(result.unresolvedCandidates).toEqual(result.coverage.deferred);
      expect(result.coverage).toEqual(savedCoverage);
    },
  );

  test("excludes blank candidate identities without changing saved deferred work", () => {
    const result = fakeResult([]);
    result.coverage.deferred = [
      { id: "generic", reason: "Unfinished review." },
      { id: "blank", candidateId: " \t", reason: "Unfinished review." },
      {
        id: "pending",
        candidateId: "pending",
        reason: "Candidate needs validation.",
      },
    ];

    expect(result.unresolvedCandidates).toEqual([result.coverage.deferred[2]!]);
    expect(result.unresolvedCandidateCount).toBe(1);
    expect(result.coverage.deferred).toHaveLength(3);
  });

  test("rejects an unknown threshold with or without findings", () => {
    for (const levels of [[], ["high"]] satisfies SeverityLevel[][]) {
      const result = fakeResult(levels);
      expect(() =>
        result.hasFindingsAtOrAbove("hihg" as SeverityLevel),
      ).toThrow("Unknown severity threshold");
    }
  });

  test("evaluates a severity threshold without filtering findings or changing serialization", () => {
    const result = fakeResult(["medium", "informational"]);
    const serialized = result.toJSON();
    expect(result.hasFindingsAtOrAbove("high")).toBe(false);
    expect(result.hasFindingsAtOrAbove("medium")).toBe(true);
    expect(result.hasFindingsAtOrAbove("low")).toBe(true);
    expect(fakeResult(["informational"]).hasFindingsAtOrAbove("low")).toBe(
      false,
    );
    expect(
      fakeResult(["informational"]).hasFindingsAtOrAbove("informational"),
    ).toBe(true);
    expect(fakeResult([]).hasFindingsAtOrAbove("informational")).toBe(false);
    expect(result.findings.findings).toHaveLength(2);
    expect(result.toJSON()).toEqual(serialized);
  });

  test("exposes canonical paths and machine serialization", () => {
    const repositoryFinding = {
      findingId: "finding",
      occurrenceId: "occurrence",
      scanId: "scan",
      targetId: "id",
      title: "Unsafe route",
      summary: "The route is not protected.",
      severity: { level: "high" },
      status: "open",
      confirmedInLatestScan: true,
    } satisfies RepositoryFinding;
    const result = new ScanResult({
      manifest,
      findings,
      coverage,
      scanDir: "/scan",
      threadId: "thread",
      turnResult: { id: "turn", status: "completed" },
      repositoryFindings: [repositoryFinding],
    });
    expect(result.pluginVersion).toBe("0.1.14");
    expect(result.manifestPath).toBe(join("/scan", "scan-manifest.json"));
    expect(result.artifactsDir).toBe(join("/scan", "artifacts"));
    expect(result.toJSON()).toMatchObject({
      scanDir: "/scan",
      threadId: "thread",
      cost: null,
      repositoryFindings: [repositoryFinding],
    });
    expect(result.findings).toBe(findings);
  });

  test("includes the model and estimated cost in machine-readable results", () => {
    const result = new ScanResult({
      manifest,
      findings,
      coverage,
      scanDir: "/scan",
      threadId: "thread",
      turnResult: {
        model: "gpt-5.6-sol",
        usage: {
          input_tokens: 1_250,
          cached_input_tokens: 200,
          output_tokens: 30,
        },
      },
    });

    expect(result.cost?.estimatedUsd).toBe(0.00488);
    const serialized = JSON.parse(JSON.stringify(result));
    expect(serialized.cost).toEqual(result.cost);
    expect(serialized.cost).toMatchObject({
      estimatedUsdRange: { min: 0.00488, max: 0.01156, context: "unknown" },
      pricing: {
        longContextUsdPerMillionTokens: {
          input: 8,
          cacheRead: 0.8,
          cacheWrite: 10,
          output: 30,
        },
      },
    });
  });

  test("discovers SARIF at its canonical scan path", async () => {
    const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
    try {
      const sarifPath = join(scanDir, "exports", "results.sarif");
      await mkdir(join(scanDir, "exports"));
      await writeFile(sarifPath, "{}\n");
      const result = new ScanResult({
        manifest,
        findings,
        coverage,
        scanDir,
        threadId: "thread",
        turnResult: { id: "turn", status: "completed" },
      });
      expect(result.sarifPath).toBe(sarifPath);
      expect(result.toJSON()["sarifPath"]).toBe(sarifPath);
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });

  test("does not discover a directory named results.sarif", async () => {
    const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
    try {
      await mkdir(join(scanDir, "exports", "results.sarif"), {
        recursive: true,
      });
      const result = new ScanResult({
        manifest,
        findings,
        coverage,
        scanDir,
        threadId: "thread",
        turnResult: { id: "turn", status: "completed" },
      });
      expect(result.sarifPath).toBeNull();
      expect(result.toJSON()["sarifPath"]).toBeNull();
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "does not fail implicit SARIF discovery on a symlink loop",
    async () => {
      const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
      try {
        const exportsDir = join(scanDir, "exports");
        await mkdir(exportsDir);
        await symlink("loop", join(exportsDir, "loop"));
        const result = new ScanResult({
          manifest,
          findings,
          coverage,
          scanDir: join(exportsDir, "loop"),
          threadId: "thread",
          turnResult: { id: "turn", status: "completed" },
        });
        expect(result.sarifPath).toBeNull();
        expect(result.toJSON()["sarifPath"]).toBeNull();
      } finally {
        await rm(scanDir, { recursive: true, force: true });
      }
    },
  );
});
