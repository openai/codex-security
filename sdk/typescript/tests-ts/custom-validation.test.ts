import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { ThreadEvent } from "@openai/codex-sdk";
import type { ScanActivity } from "../src/scan-activity.js";
import Ajv2020 from "ajv/dist/2020.js";
import { afterEach, describe, expect, test, mock } from "bun:test";
import {
  runCustomValidation,
  type CustomValidationResult,
} from "../src/custom-validation.js";
import {
  customDiscoveryPrompt,
  customValidationConfig,
} from "../src/custom-validation-prompt.js";
import {
  DiffTarget,
  ScanResult,
  type CoverageDocument,
  type FindingsDocument,
  type ScanManifest,
} from "../src/index.js";
import { createMarketplace, resolveCodexCommand } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { runWorkbench } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { completedEvents, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson as json, jsonLines } from "./support/json.js";
import { rejecting } from "./support/errors.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
const resultName = "artifacts/custom-validation/results.json";
afterEach(cleanup);

async function loadResult(scanDir: string): Promise<ScanResult> {
  return new ScanResult({
    manifest: await json<ScanManifest>(join(scanDir, "scan-manifest.json")),
    findings: await json<FindingsDocument>(join(scanDir, "findings.json")),
    coverage: await json<CoverageDocument>(join(scanDir, "coverage.json")),
    scanDir,
    threadId: "synthetic-custom-validation",
    turnResult: {},
    sarifPath: null,
  });
}

async function save(path: string, value: unknown) {
  await writeFile(path, JSON.stringify(value));
}

async function draft(scanDir: string, scanId: string, count = 1, diff = false) {
  await copyCompletedScanFixture(scanDir);
  const manifest = await json<ScanManifest>(
    join(scanDir, "scan-manifest.json"),
  );
  const { sealedAt: _sealed, artifacts: _artifacts, ...scan } = manifest.scan;
  scan.id = scanId;
  scan.target.kind = diff ? "git_diff" : "directory_snapshot";
  scan.scope.validationMode = "custom_pending";
  await save(join(scanDir, "scan-manifest.json"), { ...manifest, scan });
  const findings = await json<FindingsDocument>(join(scanDir, "findings.json"));
  const original = findings.findings[0]!;
  findings.scanId = scanId;
  findings.findings = Array.from({ length: count }, (_, index) => ({
    ...structuredClone(original),
    identity: { anchor: `fixture-${index}` },
    title: `Fixture ${index}`,
    extensions: { customValidationSurfaceIds: [`surface-${index}`] },
  }));
  await save(join(scanDir, "findings.json"), findings);
  const coverage = await json<CoverageDocument>(join(scanDir, "coverage.json"));
  coverage.scanId = scanId;
  coverage.mode = diff ? "diff" : "repository";
  coverage.inventoryStrategy = diff ? "diff" : "directory";
  coverage.surfaces = findings.findings.map((finding, index) => ({
    id: `surface-${index}`,
    label: finding.title,
    disposition: "reported",
    receiptRefs: [],
  }));
  if (count === 0)
    coverage.surfaces.push({
      id: "reviewed",
      label: "Reviewed source",
      disposition: "no_issue_found",
      receiptRefs: [],
    });
  await save(join(scanDir, "coverage.json"), coverage);
  await rm(join(scanDir, "report.md"), { force: true });
  return findings;
}

async function publishDraft(
  scanDir: string,
  scanId: string,
  workbench: (args: readonly string[]) => Promise<Record<string, unknown>>,
) {
  const manifest = await json<ScanManifest>(
    join(scanDir, "scan-manifest.json"),
  );
  const findings = await json<FindingsDocument>(join(scanDir, "findings.json"));
  const coverage = await json<CoverageDocument>(join(scanDir, "coverage.json"));
  const staged = {
    manifest: {
      scan: {
        target: manifest.scan.target,
        scope: manifest.scan.scope,
      },
    },
    findings: {
      findings: findings.findings.map(
        ({
          findingId: _id,
          occurrenceId: _occurrence,
          fingerprints: _fingerprints,
          ...finding
        }) => finding,
      ),
    },
    coverage: {
      completeness: coverage.completeness,
      inventoryStrategy: coverage.inventoryStrategy,
      surfaces: coverage.surfaces,
      explicitExclusions: coverage.explicitExclusions,
      deferred: coverage.deferred,
    },
  };
  await mkdir(join(scanDir, "drafts"), { recursive: true });
  const draftPath = join(scanDir, "drafts", `${scanId}.json`);
  await save(draftPath, staged);
  expect(
    await workbench([
      "write-scan-draft",
      "--scan-id",
      scanId,
      "--draft-path",
      draftPath,
    ]),
  ).toMatchObject({ scanId, status: "draft_written" });
}

function result(
  ...dispositions: CustomValidationResult["validations"][number]["validation"]["disposition"][]
): CustomValidationResult {
  return {
    status: "complete",
    reason: null,
    validations: dispositions.map((disposition, index) => ({
      candidateId: `candidate-${index + 1}`,
      validation: {
        disposition,
        method: "integration test",
        confidence: "medium",
        confidence_rationale: "The test exercised the selected path.",
        rubric: "Check the protected operation.",
        evidence: ["The test returned the observed result."],
        counterevidence_or_proof_gap:
          disposition === "deferred"
            ? "The required service was unavailable."
            : "",
        remaining_uncertainty: "",
        artifact_paths: [],
      },
      severity: null,
      impact: null,
    })),
  };
}

async function fixture(count = 1) {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  await mkdir(scanDir, { mode: 0o700 });
  const scanId = randomUUID();
  const findings = await draft(scanDir, scanId, count);
  return {
    root,
    repository: root,
    target: { kind: "repository" as const, paths: [] },
    scanDir,
    scanId,
    findings,
    pluginRoot: PLUGIN_ROOT,
    prompt: "Run the selected fixture workflow.",
    signal: new AbortController().signal,
  };
}

async function* responseEvents(
  value: unknown,
  activity?: string,
): AsyncGenerator<ThreadEvent> {
  for await (const event of completedEvents("validation-thread")) {
    if (
      event.type === "item.completed" &&
      event.item.type === "agent_message"
    ) {
      if (activity !== undefined)
        yield { ...event, item: { ...event.item, text: activity } };
      yield { ...event, item: { ...event.item, text: JSON.stringify(value) } };
    } else yield event;
  }
}

for (const section of ["surfaces", "explicitExclusions"] as const) {
  for (const disposition of ["rejected", "not_applicable"] as const) {
    for (const sameOwner of [false, true]) {
      test(`current custom validation replaces ${section}/${disposition}/${sameOwner ? "same" : "other"} owner decisions`, async () => {
        const f = await fixture();
        const finding = f.findings.findings[0]!;
        finding.provenance["candidateId"] = "validated-candidate";
        finding.provenance["sourceWorkerId"] = "worker-current";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const previous = {
          id: "older-decision",
          candidateId: "validated-candidate",
          sourceWorkerId: sameOwner ? "worker-current" : "worker-other",
          label: "Older review",
          pattern: "src/older.ts",
          reason: "Older authored rationale.",
          disposition,
          notes: "Older authored evidence.",
          receiptRefs: [],
        };
        coverage[section].push(previous);
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result("deferred")),
        });
        const saved = await loadResult(f.scanDir);
        expect(saved.unresolvedCandidates).toHaveLength(1);
        expect(saved.unresolvedCandidates[0]!.candidateId).toBe(
          "validated-candidate",
        );
        if (!sameOwner)
          expect(saved.coverage[section]).toContainEqual(previous);
      });
    }
  }
}

for (const disposition of [
  "reportable",
  "deferred",
  "suppressed",
  "not_applicable",
] as const) {
  test(`independent shared surface candidate survives custom ${disposition}`, async () => {
    const f = await fixture();
    f.findings.findings[0]!.provenance["candidateId"] = "validated-b";
    f.findings.findings[0]!.provenance["sourceWorkerId"] = "worker-b";
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    coverage.surfaces[0]!.candidateId = "independent-a";
    coverage.surfaces[0]!["sourceWorkerId"] = "worker-a";
    const independent = {
      id: "independent-review",
      candidateId: "independent-a",
      sourceWorkerId: "worker-a",
      reason: "A still requires validation.",
      surfaceIds: ["surface-0"],
    };
    coverage.completeness = "partial";
    coverage.deferred = [independent];
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result(disposition)),
    });
    const saved = await loadResult(f.scanDir);
    expect(saved.unresolvedCandidates).toContainEqual(independent);
  });

  test(`saved custom validation evidence survives ${disposition}`, async () => {
    const f = await fixture();
    const finding = f.findings.findings[0]!;
    finding.provenance["candidateId"] = "saved-candidate";
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    const previous = [1, 2].map((index) => ({
      id: `saved-review-${index}`,
      candidateId: "saved-candidate",
      reason: `Saved proof gap ${index}.`,
      annotation: `Saved annotation ${index}.`,
      candidate: {
        title: `Original candidate ${index}`,
        evidence: `Original source evidence ${index}.`,
      },
      finding: {
        ...structuredClone(finding),
        title: `Earlier finding ${index}`,
      },
    }));
    coverage.completeness = "partial";
    coverage.deferred = previous;
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result(disposition)),
    });
    const saved = await loadResult(f.scanDir);
    const current =
      disposition === "reportable"
        ? saved.findings.findings[0]
        : disposition === "deferred"
          ? saved.coverage.deferred[0]?.candidate
          : saved.coverage.surfaces.find(
              (row) => row.candidateId === "saved-candidate",
            )?.["finding"];
    expect(current).toMatchObject({
      provenance: { originalCandidates: expect.arrayContaining(previous) },
    });
  });
}

describe("custom validation", () => {
  test.each(["provenance", "candidateId", "reportId", "ledgerRowId"])(
    "keeps deferred candidates distinct from confirmed findings using %s identity",
    async (field) => {
      const f = await fixture(2);
      for (const [index, finding] of f.findings.findings.entries()) {
        const source =
          field === "provenance" ? finding.provenance : finding.extensions!;
        source[field === "provenance" ? "candidateId" : field] =
          `candidate-${2 - index}`;
        if (field === "provenance")
          finding.extensions!.candidateId = `candidate-${index + 1}`;
      }
      await save(join(f.scanDir, "findings.json"), f.findings);
      await runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result("reportable", "deferred")),
      });
      const saved = await loadResult(f.scanDir);
      expect(saved.unresolvedCandidateCount).toBe(1);
      expect(saved.unresolvedCandidates[0]).toMatchObject({
        candidateId: "candidate-1",
        candidate: f.findings.findings[1],
      });
    },
  );

  test.each([undefined, "worker-current"])(
    "replaces superseded candidate rows while preserving other owners (%s)",
    async (sourceWorkerId) => {
      const f = await fixture();
      const finding = f.findings.findings[0]!;
      finding.provenance["candidateId"] = "candidate-shared";
      if (sourceWorkerId !== undefined)
        finding.provenance["sourceWorkerId"] = sourceWorkerId;
      await save(join(f.scanDir, "findings.json"), f.findings);
      const coverage = await json<CoverageDocument>(
        join(f.scanDir, "coverage.json"),
      );
      const old = {
        id: "previous-candidate",
        candidateId: "candidate-shared",
        ...(sourceWorkerId === undefined ? {} : { sourceWorkerId }),
        reason: "Obsolete checkpoint proof gap.",
        candidate: { title: "Older candidate payload" },
      };
      const unrelated = [
        { id: "general-review", reason: "Unrelated review remains." },
        {
          id: "other-worker",
          candidateId: "candidate-shared",
          sourceWorkerId: "worker-other",
          reason: "Independent worker review remains.",
        },
      ];
      coverage.completeness = "partial";
      coverage.deferred = [
        old,
        { ...old, id: "duplicate-checkpoint" },
        ...unrelated,
      ];
      await save(join(f.scanDir, "coverage.json"), coverage);
      await runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result("deferred")),
      });
      const saved = await loadResult(f.scanDir);
      expect(saved.unresolvedCandidateCount).toBe(2);
      expect(saved.coverage.deferred).toEqual([
        ...unrelated,
        {
          ...old,
          candidate: {
            ...finding,
            provenance: {
              ...finding.provenance,
              originalCandidates: [old, { ...old, id: "duplicate-checkpoint" }],
            },
          },
          reason: "The required service was unavailable.",
          paths: finding.locations.map((location) => location.path),
          surfaceIds: ["surface-0"],
        },
      ]);
      expect(saved.unresolvedCandidates).toContainEqual(
        saved.coverage.deferred[2]!,
      );
    },
  );

  test.each([
    { disposition: "suppressed", shared: false },
    { disposition: "not_applicable", shared: false },
    { disposition: "suppressed", shared: true },
    { disposition: "not_applicable", shared: true },
  ] as const)(
    "retains terminal candidate evidence for $disposition (shared surface: $shared)",
    async ({ disposition, shared }) => {
      const f = await fixture(shared ? 2 : 1);
      const finding = f.findings.findings[0]!;
      finding.provenance["candidateId"] = "source-terminal";
      finding.provenance["sourceWorkerId"] = "worker-current";
      if (shared) {
        const reported = f.findings.findings[1]!;
        reported.provenance["candidateId"] = "source-reported";
        reported.extensions!["customValidationSurfaceIds"] = ["surface-0"];
      }
      await save(join(f.scanDir, "findings.json"), f.findings);
      const coverage = await json<CoverageDocument>(
        join(f.scanDir, "coverage.json"),
      );
      coverage.surfaces = [coverage.surfaces[0]!];
      const previous = {
        id: "previous-candidate",
        candidateId: "source-terminal",
        sourceWorkerId: "worker-current",
        candidate: {
          summary: "Saved candidate",
          evidence: "Saved source evidence.",
        },
        reason: "Obsolete checkpoint proof gap.",
        surfaceIds: ["surface-0"],
      };
      const unrelated = {
        ...previous,
        id: "other-owner",
        sourceWorkerId: "worker-other",
      };
      coverage.completeness = "partial";
      coverage.deferred = [previous, unrelated];
      await save(join(f.scanDir, "coverage.json"), coverage);
      await runCustomValidation({
        ...f,
        run: async () =>
          JSON.stringify(
            shared ? result(disposition, "reportable") : result(disposition),
          ),
      });
      const saved = await loadResult(f.scanDir);
      expect(saved.findings.findings).toHaveLength(shared ? 1 : 0);
      expect(saved.coverage.deferred).toEqual([unrelated]);
      expect(saved.unresolvedCandidateCount).toBe(1);
      const terminal = saved.coverage.surfaces.find(
        (surface) =>
          surface.candidateId === previous.candidateId &&
          surface["sourceWorkerId"] === previous["sourceWorkerId"],
      );
      expect(terminal).toMatchObject({
        candidateId: previous.candidateId,
        sourceWorkerId: previous["sourceWorkerId"],
        candidate: previous.candidate,
        finding: {
          ...finding,
          provenance: {
            ...finding.provenance,
            originalCandidates: [previous],
          },
        },
        disposition:
          disposition === "suppressed" ? "rejected" : "not_applicable",
        notes: "The test returned the observed result.",
        receiptRefs: [resultName],
      });
      expect(terminal!.id).not.toBe("surface-0");
      expect(saved.coverage.surfaces[0]!.disposition).toBe(
        shared ? "reported" : terminal!.disposition,
      );
      expect(saved.coverage.surfaces[0]).not.toHaveProperty("candidateId");
    },
  );

  test("retains a deferred candidate when another finding reports their shared surface", async () => {
    const f = await fixture(2);
    for (const [index, finding] of f.findings.findings.entries()) {
      finding.provenance["candidateId"] = `source-${index}`;
      finding.extensions!["customValidationSurfaceIds"] = ["surface-0"];
    }
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    coverage.surfaces = [{ ...coverage.surfaces[0]!, candidateId: "source-0" }];
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result("deferred", "reportable")),
    });
    const saved = await loadResult(f.scanDir);
    expect(saved.findings.findings).toHaveLength(1);
    expect(saved.coverage.surfaces[0]!.disposition).toBe("reported");
    expect(saved.unresolvedCandidateCount).toBe(1);
    expect(saved.unresolvedCandidates[0]).toMatchObject({
      candidateId: "source-0",
      candidate: f.findings.findings[0],
    });
  });

  test("allocates fallback identities outside existing finding and coverage IDs", async () => {
    const f = await fixture(4);
    f.findings.findings[0]!.provenance["candidateId"] =
      "custom-validation-candidate-4";
    f.findings.findings[1]!.extensions!.reportId =
      "custom-validation-candidate-4-2";
    f.findings.findings[2]!.extensions!.ledgerRowId =
      "custom-validation-candidate-4-3";
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    coverage.completeness = "partial";
    coverage.deferred.push({
      id: "custom-validation-candidate-4-4",
      reason: "Unrelated source review remains unfinished.",
    });
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () =>
        JSON.stringify(
          result("reportable", "reportable", "reportable", "deferred"),
        ),
    });
    const saved = await loadResult(f.scanDir);
    expect(saved.unresolvedCandidateCount).toBe(1);
    expect(saved.unresolvedCandidates[0]).toMatchObject({
      id: "custom-validation-candidate-4-5",
      candidateId: "custom-validation-candidate-4-5",
      candidate: f.findings.findings[3],
    });
    expect(saved.coverage.deferred).toHaveLength(2);
  });

  test("applies dispositions and assessments without changing source identity", async () => {
    const f = await fixture(4);
    const output = result(
      "reportable",
      "suppressed",
      "not_applicable",
      "deferred",
    );
    const counterEvidence =
      "The protected caller checks a separate precondition.";
    const limitations = "The alternate configuration was not exercised.";
    output.validations[0]!.validation.counterevidence_or_proof_gap =
      counterEvidence;
    output.validations[0]!.validation.remaining_uncertainty = limitations;
    output.validations[0]!.severity = {
      level: "medium",
      rationale: "Requires an uncommon configuration.",
    };
    output.validations[0]!.impact = {
      level: "high",
      rationale: "Can modify protected files.",
    };
    output.validations[0]!.validation.artifact_paths = [
      "artifacts/custom-validation/proof.txt",
    ];
    await runCustomValidation({
      ...f,
      run: async (prompt, schema) => {
        expect(prompt).toContain(JSON.stringify(f.target));
        await writeFile(
          join(f.scanDir, "artifacts/custom-validation/proof.txt"),
          "Synthetic proof.\n",
        );
        expect(prompt).toContain(f.prompt);
        // Structured outputs cannot resolve plugin URIs or use regex lookaround.
        expect(JSON.stringify(schema)).not.toContain("codex-security://");
        expect(JSON.stringify(schema)).not.toMatch(/\(\?[=!<]/);
        const common = await json<object>(
          join(PLUGIN_ROOT, "schemas/definitions/artifact-common.schema.json"),
        );
        const existing = await json<object>(
          join(PLUGIN_ROOT, "schemas/tools/candidate-validations.schema.json"),
        );
        const ajv = new Ajv2020({ strict: false, validateFormats: false });
        ajv.addSchema(common);
        expect(
          ajv.validate(existing, {
            scanId: f.scanId,
            validations: output.validations.map(
              ({ candidateId, validation }) => ({ candidateId, validation }),
            ),
          }),
        ).toBe(true);
        return JSON.stringify(output);
      },
    });
    const findings = await json<FindingsDocument>(
      join(f.scanDir, "findings.json"),
    );
    expect(findings.findings).toHaveLength(1);
    expect(findings.findings[0]).toMatchObject({
      identity: f.findings.findings[0]!.identity,
      locations: f.findings.findings[0]!.locations,
      severity: output.validations[0]!.severity,
      confidence: { level: "medium" },
      attackPath: { impact: output.validations[0]!.impact },
      validation: {
        disposition: "reportable",
        counterEvidence: [counterEvidence],
        limitations: [limitations],
      },
    });
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    expect(coverage.surfaces.map((surface) => surface.disposition)).toEqual([
      "reported",
      "rejected",
      "not_applicable",
      "needs_follow_up",
    ]);
    expect(coverage.completeness).toBe("partial");
    expect(coverage.surfaces[0]!.receiptRefs).toContain(
      "artifacts/custom-validation/proof.txt",
    );
    expect(coverage.deferred).toHaveLength(1);
    expect(coverage.deferred[0]).toMatchObject({
      id: "custom-validation-candidate-4",
      candidateId: "custom-validation-candidate-4",
      candidate: f.findings.findings[3],
    });
    expect(await json(join(f.scanDir, resultName))).toMatchObject({
      scanId: f.scanId,
      ...output,
    });
    expect(
      await json(
        join(f.scanDir, "artifacts/custom-validation/candidates.json"),
      ),
    ).toMatchObject({
      target: f.target,
      candidates: f.findings.findings.map((finding, index) => ({
        candidateId: `candidate-${index + 1}`,
        finding,
      })),
    });
  });

  test.each([
    "sealedAt",
    "artifacts",
    "manifest ID",
    "findings ID",
    "coverage ID",
  ])("rejects an invalid discovery handoff: %s", async (kind) => {
    const f = await fixture();
    const manifest = await json<ScanManifest>(
      join(f.scanDir, "scan-manifest.json"),
    );
    if (kind === "sealedAt") manifest.scan.sealedAt = "2026-01-01T00:00:00Z";
    if (kind === "artifacts") manifest.scan.artifacts = [];
    if (kind === "manifest ID") manifest.scan.id = randomUUID();
    if (kind === "findings ID" || kind === "coverage ID") {
      const name = kind === "findings ID" ? "findings.json" : "coverage.json";
      const document = await json<{ scanId: string }>(join(f.scanDir, name));
      document.scanId = randomUUID();
      await save(join(f.scanDir, name), document);
    }
    await save(join(f.scanDir, "scan-manifest.json"), manifest);
    await expect(
      runCustomValidation({
        ...f,
        run: unexpectedValidation,
      }),
    ).rejects.toThrow("unsealed custom-validation draft");
  });

  test("validates persisted findings with empty optional dataflow details", async () => {
    const f = await fixture(3);
    for (const [index, finding] of f.findings.findings.entries()) {
      finding.attackPath = {
        dataflow: {
          source: "Synthetic request input",
          sink: index < 2 ? "" : "Synthetic output operation",
        },
      };
    }
    await save(join(f.scanDir, "findings.json"), f.findings);
    const run = mock(async () => {
      const candidates = await json<{
        candidates: Array<{ finding: unknown }>;
      }>(join(f.scanDir, "artifacts/custom-validation/candidates.json"));
      expect(candidates.candidates).toHaveLength(3);
      expect(candidates.candidates[0]!.finding).toHaveProperty(
        "attackPath.dataflow",
        { source: "Synthetic request input" },
      );
      return JSON.stringify(result("reportable", "reportable", "reportable"));
    });
    await runCustomValidation({
      ...f,
      run,
    });
    expect(run).toHaveBeenCalled();
    const saved = await json<FindingsDocument>(
      join(f.scanDir, "findings.json"),
    );
    expect(saved.findings).toHaveLength(3);
    for (const [index, finding] of saved.findings.entries()) {
      expect(finding.validation).toMatchObject({
        counterEvidence: [],
        limitations: [],
      });
      expect(finding.identity).toEqual(f.findings.findings[index]!.identity);
      expect(finding.locations).toEqual(f.findings.findings[index]!.locations);
      expect(finding.attackPath).toEqual({
        dataflow: {
          source: "Synthetic request input",
          ...(index < 2 ? {} : { sink: "Synthetic output operation" }),
        },
      });
    }
  });

  test("retains original optional details when custom validation fails", async () => {
    const f = await fixture();
    f.findings.findings[0]!.attackPath = { dataflow: { sink: "" } };
    await save(join(f.scanDir, "findings.json"), f.findings);
    await expect(
      runCustomValidation({
        ...f,
        run: rejecting("Synthetic validation failure"),
      }),
    ).rejects.toThrow("Synthetic validation failure");
    expect(
      await json<FindingsDocument>(join(f.scanDir, "findings.json")),
    ).toEqual(f.findings);
  });

  test("identifies an invalid provisional finding and field before validation", async () => {
    const f = await fixture(2);
    f.findings.findings[1]!.title = "";
    await save(join(f.scanDir, "findings.json"), f.findings);
    await expect(
      runCustomValidation({
        ...f,
        run: unexpectedValidation,
      }),
    ).rejects.toThrow(/findings\[1\].*title/);
    expect(
      await json<FindingsDocument>(join(f.scanDir, "findings.json")),
    ).toEqual(f.findings);
  });

  test("identifies invalid provisional coverage before validation", async () => {
    const f = await fixture();
    const path = join(f.scanDir, "coverage.json");
    const coverage = await json<CoverageDocument>(path);
    coverage.surfaces[0]!.label = "";
    await save(path, coverage);
    await expect(
      runCustomValidation({
        ...f,
        run: unexpectedValidation,
      }),
    ).rejects.toThrow("coverage/surfaces/0/label");
    expect(await json<CoverageDocument>(path)).toEqual(coverage);
  });

  test.each([
    "missing",
    "duplicate",
    "unknown",
    "malformed",
    "incomplete",
    "unsafe artifact",
  ])("rejects %s results without losing the draft", async (kind) => {
    const f = await fixture();
    const original = await readFile(join(f.scanDir, "findings.json"), "utf8");
    const output = result("reportable");
    if (kind === "missing") output.validations = [];
    if (kind === "duplicate") output.validations.push(output.validations[0]!);
    if (kind === "unknown") output.validations[0]!.candidateId = "unknown";
    if (kind === "unsafe artifact")
      output.validations[0]!.validation.artifact_paths = ["../outside.txt"];
    if (kind === "incomplete") {
      output.status = "incomplete";
      output.reason = "Setup failed.";
    }
    await expect(
      runCustomValidation({
        ...f,
        run: async () => {
          await writeFile(join(f.scanDir, "findings.json"), "{}");
          return kind === "malformed" ? "not JSON" : JSON.stringify(output);
        },
      }),
    ).rejects.toThrow("Custom validation is incomplete");
    expect(await json(join(f.scanDir, "findings.json"))).toEqual(
      JSON.parse(original),
    );
  });

  test("rejects output directories linked outside the scan", async () => {
    const f = await fixture();
    const outside = join(f.root, "outside");
    await mkdir(outside);
    await mkdir(join(f.scanDir, "artifacts"), { recursive: true });
    await symlink(
      outside,
      join(f.scanDir, "artifacts/custom-validation"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result("reportable")),
      }),
    ).rejects.toThrow("inside the scan directory");
    await expect(readFile(join(outside, "candidates.json"))).rejects.toThrow();
  });

  const completionScenarios: Array<{
    scenario: string;
    dispositions: Parameters<typeof result>;
    siblings?: boolean;
    staleDeferred?: boolean;
    semanticIdentity?: string;
    stopAfterValidation?: boolean;
  }> = [
    { scenario: "standard", dispositions: ["reportable"] },
    {
      scenario: "semantic-candidate-identity",
      dispositions: ["deferred"],
      semanticIdentity: "review/auth",
    },
    {
      scenario: "diff",
      dispositions: ["reportable"],
      semanticIdentity: "candidate-synthetic",
    },
    ...(["suppressed", "not_applicable"] as const).flatMap((disposition) =>
      [false, true].map((stopAfterValidation) => ({
        scenario: `diff-${disposition}-${stopAfterValidation ? "stopped" : "completed"}`,
        dispositions: [disposition] as Parameters<typeof result>,
        semanticIdentity: "candidate-synthetic",
        stopAfterValidation,
      })),
    ),
    { scenario: "empty", dispositions: [] },
    { scenario: "incomplete", dispositions: ["reportable"] },
    { scenario: "dismissed", dispositions: ["suppressed"] },
    {
      scenario: "existing-deferred",
      dispositions: ["deferred"],
      staleDeferred: true,
    },
    {
      scenario: "existing-suppressed",
      dispositions: ["suppressed"],
      staleDeferred: true,
    },
    {
      scenario: "existing-not-applicable",
      dispositions: ["not_applicable"],
      staleDeferred: true,
    },
    {
      scenario: "siblings-mixed",
      dispositions: ["reportable", "deferred"],
      siblings: true,
      staleDeferred: true,
    },
    {
      scenario: "siblings-deferred",
      dispositions: ["deferred", "deferred"],
      siblings: true,
      staleDeferred: true,
    },
    {
      scenario: "siblings-reportable-suppressed",
      dispositions: ["reportable", "suppressed"],
      siblings: true,
      staleDeferred: true,
    },
    {
      scenario: "siblings-reportable-not-applicable",
      dispositions: ["reportable", "not_applicable"],
      siblings: true,
      staleDeferred: true,
    },
    {
      scenario: "siblings-terminal",
      dispositions: ["suppressed", "not_applicable"],
      siblings: true,
      staleDeferred: true,
    },
  ];
  test.each(completionScenarios)(
    "SDK owns real workbench completion: $scenario",
    async ({
      scenario,
      dispositions,
      siblings = false,
      staleDeferred = false,
      semanticIdentity,
      stopAfterValidation = false,
    }) => {
      const diff = scenario.startsWith("diff");
      const count = dispositions.length;
      const expectedReported = dispositions.filter(
        (value) => value === "reportable",
      ).length;
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const codexHome = join(root, "codex-home");
      const stateDir = join(root, "state");
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      await mkdir(join(repository, "src"), { recursive: true });
      await writeFile(join(repository, "src/extract.py"), "# source fixture\n");
      await mkdir(scanDir, { mode: 0o700 });
      await mkdir(codexHome);
      if (diff) {
        const git = (...args: string[]) =>
          execFileSync("git", [
            "-C",
            repository,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            ...args,
          ]);
        git("init", "-q");
        git("add", ".");
        git("commit", "-qm", "base");
        await writeFile(
          join(repository, "src/extract.py"),
          "# changed fixture\n",
        );
      }
      const workflow = "Run the synthetic validation script, then clean up.";
      const workflowFile = join(root, "validation.md");
      if (scenario === "standard") await writeFile(workflowFile, workflow);
      const falsePositive = {
        reason: "The fixture is not included in the deployed application.",
      };
      let scanId = "";
      let turns = 0;
      const workingDirectories: Array<string | undefined> = [];
      const commands: string[] = [];
      const activities: ScanActivity[] = [];
      const validationActivity = "Synthetic validation activity.";
      const profileDisabledTools =
        scenario === "standard"
          ? []
          : diff
            ? ["profile_disabled_tool"]
            : undefined;
      const workbench = (args: readonly string[], input?: string) =>
        runWorkbench(
          {
            python: python!,
            pluginRoot: PLUGIN_ROOT,
            environment: {
              PATH: process.env["PATH"],
              CODEX_SECURITY_STATE_DIR: stateDir,
            },
          },
          args,
          input,
        );
      const client = new TestClient(
        profileDisabledTools === undefined
          ? {}
          : {
              codexOverrides: {
                profile: "synthetic.validation",
                profiles: {
                  "synthetic.validation": {
                    mcp_servers: {
                      "codex-security": {
                        disabled_tools: profileDisabledTools,
                      },
                    },
                  },
                },
              },
            },
        {
          environment: { CODEX_SECURITY_STATE_DIR: stateDir },
          prepareRuntime: async () => {
            const runtime = preparedRuntime(codexHome);
            runtime.plugin.version = (
              await json<{ version: string }>(
                join(PLUGIN_ROOT, ".codex-plugin/plugin.json"),
              )
            ).version;
            return runtime;
          },
          resolvePluginPython: async () => python!,
          prepareOutputDir: async () => scanDir,
          createCodex: (options) => {
            expect(options.config?.["mcp_servers"]).toMatchObject({
              "codex-security": {
                disabled_tools: expect.arrayContaining([
                  "start_codex_security_standard_scan",
                  "start_codex_security_prompt_only_scan",
                  "start_codex_security_deep_scan",
                  "complete_codex_security_scan",
                  "record_codex_security_candidate_validations",
                  "record_candidate_attack_paths",
                  ...(profileDisabledTools ?? []),
                ]),
              },
            });
            return {
              startThread: (threadOptions) => {
                expect(threadOptions.threadSource).toBe("security_scan");
                workingDirectories.push(threadOptions.workingDirectory);
                return {
                  id:
                    workingDirectories.length === 1
                      ? "thread-1"
                      : "validation-thread",
                  async runStreamed(prompt, turnOptions) {
                    expect(turnOptions.cyberAccessProgram).toBe(
                      "daybreak_blue",
                    );
                    turns += 1;
                    if (turns === 1) {
                      expect(prompt).not.toContain(workflow);
                      expect(prompt).toContain("SDK-owned discovery workflow");
                      expect(prompt).not.toContain(
                        "Independently validate each unique finding",
                      );
                      expect(prompt).not.toContain("run `$validation` once");
                      expect(turnOptions.outputSchema).toBeUndefined();
                      const provisional = await draft(
                        scanDir,
                        scanId,
                        count,
                        diff,
                      );
                      if (semanticIdentity !== undefined) {
                        provisional.findings[0]!.provenance["candidateId"] =
                          semanticIdentity;
                        await save(join(scanDir, "findings.json"), provisional);
                        if (diff) {
                          const discovery = join(
                            scanDir,
                            "artifacts/02_discovery",
                          );
                          await mkdir(discovery, { recursive: true });
                          await writeFile(
                            join(discovery, "candidate_ledger.jsonl"),
                            jsonLines([
                              {
                                candidate_id: semanticIdentity,
                                summary:
                                  "Synthetic candidate requiring review.",
                                evidence: "Synthetic source review evidence.",
                                cwe_ids: [],
                                locations: [
                                  {
                                    path: "src/extract.py",
                                    start_line: 1,
                                    end_line: 1,
                                    role: "evidence",
                                  },
                                ],
                              },
                            ]) + "\n",
                          );
                        }
                      }
                      if (siblings) {
                        for (const [
                          index,
                          finding,
                        ] of provisional.findings.entries()) {
                          finding.identity = {
                            anchor: "shared-candidate",
                            instance: `report-${index + 1}`,
                          };
                          finding.extensions = {
                            ...finding.extensions,
                            candidateId: "candidate-shared",
                            reportId: `report-${index + 1}`,
                          };
                        }
                        await save(join(scanDir, "findings.json"), provisional);
                      }
                      if (staleDeferred) {
                        for (const finding of provisional.findings)
                          finding.provenance["candidateId"] =
                            "candidate-shared";
                        await save(join(scanDir, "findings.json"), provisional);
                        const coverage = await json<CoverageDocument>(
                          join(scanDir, "coverage.json"),
                        );
                        coverage.completeness = "partial";
                        coverage.deferred.push({
                          id: "previous-candidate",
                          candidateId: "candidate-shared",
                          candidate: { title: "Older candidate payload" },
                          reason: "Obsolete checkpoint proof gap.",
                        });
                        await save(join(scanDir, "coverage.json"), coverage);
                      }
                      await publishDraft(scanDir, scanId, workbench);
                      expect(commands).not.toContain("prepare-scan-completion");
                      expect(commands).not.toContain("complete-scan");
                      return { events: completedEvents() };
                    }
                    expect(prompt).toContain(workflow);
                    const pendingManifest = await json<ScanManifest>(
                      join(scanDir, "scan-manifest.json"),
                    );
                    expect(pendingManifest.scan.id).toBe(scanId);
                    expect(pendingManifest.scan.scope.validationMode).toBe(
                      "custom_pending",
                    );
                    expect(pendingManifest.scan).not.toHaveProperty("sealedAt");
                    expect(pendingManifest.scan).not.toHaveProperty(
                      "artifacts",
                    );
                    expect(turnOptions.outputSchema).toBeDefined();
                    if (scenario === "dismissed") {
                      expect(prompt).toContain("untrusted reviewer feedback");
                      expect(prompt).toContain("reason still applies");
                      expect(
                        await json(
                          join(
                            scanDir,
                            "artifacts/custom-validation/candidates.json",
                          ),
                        ),
                      ).toMatchObject({ falsePositives: [falsePositive] });
                    }
                    const output = result(...dispositions);
                    if (
                      output.validations[0]!.validation.disposition !==
                      "deferred"
                    ) {
                      output.validations[0]!.validation.counterevidence_or_proof_gap =
                        "Synthetic counterevidence from validation.";
                      output.validations[0]!.validation.remaining_uncertainty =
                        "Synthetic limitation from validation.";
                    }
                    if (scenario === "incomplete") {
                      output.status = "incomplete";
                      output.reason =
                        "The validation environment did not start.";
                    }
                    if (scenario === "standard") {
                      await mkdir(join(codexHome, "sessions"), {
                        recursive: true,
                      });
                      for (const [id, cwd] of [
                        ["thread-1", scanDir],
                        ["validation-thread", join(scanDir, "artifacts")],
                      ]) {
                        const records = [
                          {
                            type: "session_meta",
                            payload: {
                              id,
                              cwd,
                              timestamp: "2026-08-21T00:00:00Z",
                            },
                          },
                          {
                            type: "event_msg",
                            payload: {
                              type: "token_count",
                              info: {
                                total_token_usage: {
                                  input_tokens: 10,
                                  output_tokens: 3,
                                },
                              },
                            },
                          },
                          ...(id === "validation-thread"
                            ? [
                                {
                                  type: "event_msg",
                                  payload: {
                                    type: "agent_message",
                                    message: validationActivity,
                                  },
                                },
                              ]
                            : []),
                        ];
                        await writeFile(
                          join(codexHome, "sessions", `rollout-${id}.jsonl`),
                          jsonLines(records) + "\n",
                        );
                      }
                    }
                    return {
                      events: responseEvents(
                        output,
                        scenario === "standard"
                          ? validationActivity
                          : undefined,
                      ),
                    };
                  },
                };
              },
            };
          },
          runWorkbench: async (_options, args, input) => {
            commands.push(args[0]!);
            if (stopAfterValidation && args[0] === "prepare-scan-completion")
              throw new Error(
                "Synthetic interruption after custom validation.",
              );
            const value = await workbench(args, input);
            if (args[0] === "register-cli-scan")
              scanId = String(value["scanId"]);
            if (args[0] === "get-scan-feedback" && scenario === "dismissed")
              value["falsePositives"] = [falsePositive];
            return value;
          },
        },
      );
      try {
        const pending = client.run(repository, {
          cyberAccessProgram: "daybreak_blue",
          ...(scenario === "standard"
            ? { validationPromptFile: workflowFile }
            : { validationPrompt: workflow }),
          onActivity: (activity) => activities.push(activity),
          ...(diff ? { target: DiffTarget.workingTree({}) } : {}),
        });
        if (stopAfterValidation) {
          await expect(pending).rejects.toThrow(
            "Synthetic interruption after custom validation.",
          );
          expect(commands).toContain("fail-scan");
          const assertRetainedDecision = async () => {
            const saved = await loadResult(scanDir);
            expect(saved.findings.findings).toHaveLength(0);
            expect(saved.unresolvedCandidateCount).toBe(0);
            expect(saved.coverage.surfaces).toContainEqual(
              expect.objectContaining({
                candidateId: semanticIdentity,
                disposition:
                  dispositions[0] === "suppressed"
                    ? "rejected"
                    : "not_applicable",
                finding: expect.objectContaining({ title: "Fixture 0" }),
                receiptRefs: [resultName],
              }),
            );
          };
          await assertRetainedDecision();
          const checkpoint = JSON.stringify({
            scanId,
            complete: false,
            findings: [],
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                { id: "late-review", reason: "Independent saved review." },
              ],
            },
          });
          await writeFile(
            join(
              scanDir,
              "checkpoints",
              `${createHash("sha256").update(checkpoint).digest("hex")}.json`,
            ),
            checkpoint,
          );
          await workbench(["recover-scan-results", "--scan-id", scanId]);
          await assertRetainedDecision();
          expect((await loadResult(scanDir)).coverage.deferred).toContainEqual(
            expect.objectContaining({ id: "late-review" }),
          );
          return;
        }
        if (scenario === "incomplete") {
          await expect(pending).rejects.toThrow(
            "The validation environment did not start",
          );
          expect(turns).toBe(2);
          expect(commands).not.toContain("prepare-scan-completion");
          expect(commands).not.toContain("complete-scan");
          expect(commands).toContain("fail-scan");
          expect(await json(join(scanDir, resultName))).toMatchObject({
            status: "incomplete",
          });
          expect(
            (await json<FindingsDocument>(join(scanDir, "findings.json")))
              .findings,
          ).toHaveLength(1);
          expect(
            (
              await json<{ scan: { status: string } }>(
                join(scanDir, "scan-manifest.json"),
              )
            ).scan.status,
          ).toBe("failed");
          expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
            "Fixture 0",
          );
          return;
        }
        const completed = await pending;
        if (scenario === "standard") {
          const report = await readFile(join(scanDir, "report.md"), "utf8");
          expect(report).toContain(
            "Synthetic counterevidence from validation.",
          );
          expect(report).toContain("Synthetic limitation from validation.");
          expect(
            activities.filter(
              ({ description }) => description === validationActivity,
            ),
          ).toHaveLength(1);
          expect(completed.cost?.inputTokens).toBe(20);
        }
        expect(turns).toBe(count === 0 ? 1 : 2);
        expect(workingDirectories).toEqual(
          count === 0 ? [scanDir] : [scanDir, join(scanDir, "artifacts")],
        );
        expect(commands.indexOf("prepare-scan-completion")).toBeLessThan(
          commands.indexOf("complete-scan"),
        );
        expect(completed.findings.findings).toHaveLength(expectedReported);
        if (semanticIdentity !== undefined) {
          if (dispositions[0] === "deferred") {
            expect(completed.unresolvedCandidates).toHaveLength(1);
            expect(completed.unresolvedCandidates[0]!.candidateId).toBe(
              semanticIdentity,
            );
            expect(completed.coverage.completeness).toBe("partial");
          } else {
            expect(completed.unresolvedCandidateCount).toBe(0);
            if (dispositions[0] !== "reportable")
              expect(completed.coverage.surfaces).toContainEqual(
                expect.objectContaining({
                  candidateId: semanticIdentity,
                  disposition:
                    dispositions[0] === "suppressed"
                      ? "rejected"
                      : "not_applicable",
                  finding: expect.objectContaining({ title: "Fixture 0" }),
                  receiptRefs: [resultName],
                }),
              );
          }
        }
        if (staleDeferred) {
          const expectedPending = dispositions.filter(
            (value) => value === "deferred",
          ).length;
          expect(completed.unresolvedCandidateCount).toBe(expectedPending);
          expect(completed.coverage.deferred).toHaveLength(expectedPending);
          expect(
            completed.unresolvedCandidates.every(
              (candidate) =>
                candidate.reason === "The required service was unavailable.",
            ),
          ).toBe(true);
          const report = await readFile(completed.reportPath, "utf8");
          expect(report).not.toContain("Obsolete checkpoint proof gap.");
          expect(report).not.toContain("Older candidate payload");
          if (expectedPending > 0)
            expect(report).toContain("The required service was unavailable.");
          else if (!siblings)
            expect(completed.coverage.surfaces).toContainEqual(
              expect.objectContaining({
                candidateId: "candidate-shared",
                candidate: { title: "Older candidate payload" },
                finding: expect.objectContaining({ title: "Fixture 0" }),
                disposition:
                  dispositions[0] === "suppressed"
                    ? "rejected"
                    : "not_applicable",
              }),
            );
          else
            expect(completed.coverage.surfaces).not.toContainEqual(
              expect.objectContaining({
                candidateId: "candidate-shared",
                candidate: { title: "Older candidate payload" },
              }),
            );
          for (const [index, disposition] of dispositions.entries()) {
            if (disposition === "deferred")
              expect(report).toContain(`Fixture ${index}`);
          }
        }
        if (siblings) {
          const expectedPending = dispositions.filter(
            (value) => value === "deferred",
          ).length;
          expect(completed.unresolvedCandidateCount).toBe(expectedPending);
          expect(completed.coverage.deferred).toHaveLength(expectedPending);
          if (expectedPending > 0)
            expect(completed.coverage.completeness).toBe("partial");
          expect(
            new Set(
              completed.unresolvedCandidates.map((item) => item.candidateId),
            ).size,
          ).toBe(expectedPending);
          for (const [index, disposition] of dispositions.entries()) {
            if (disposition !== "deferred") continue;
            expect(completed.unresolvedCandidates).toContainEqual(
              expect.objectContaining({
                candidateId: `custom-validation-candidate-${index + 1}`,
                candidate: expect.objectContaining({
                  identity: {
                    anchor: "shared-candidate",
                    instance: `report-${index + 1}`,
                  },
                  extensions: expect.objectContaining({
                    candidateId: "candidate-shared",
                    reportId: `report-${index + 1}`,
                  }),
                }),
              }),
            );
          }
        }
        const receipt = await json<CustomValidationResult>(
          join(scanDir, resultName),
        );
        expect(receipt.status).toBe("complete");
        expect(receipt.validations).toHaveLength(count);
        if (expectedReported > 0)
          expect(completed.findings.findings[0]?.validation?.disposition).toBe(
            "reportable",
          );
        expect(completed.manifest.scan.scope.validationMode).toBe("custom");
        expect(
          completed.manifest.scan.artifacts.map((artifact) => artifact.path),
        ).toContain(resultName);
        expect(
          completed.manifest.scan.artifacts.map((artifact) => artifact.path),
        ).toContain("artifacts/custom-validation/candidates.json");
        expect(completed.turnResult.usage).toMatchObject({
          input_tokens: count === 0 ? 10 : 20,
          output_tokens: count === 0 ? 3 : 6,
        });
        expect(await readFile(join(scanDir, "report.md"), "utf8")).toContain(
          count === 0 ? "No findings" : "Fixture 0",
        );
      } finally {
        await client.close();
      }
    },
  );

  test("rejects Deep and empty prompts before starting Codex", async () => {
    const root = await temporaryDirectory();
    const client = TestClient.withDependencies({});
    await expect(
      client.run(root, { mode: "deep", validationPrompt: "Validate." }),
    ).rejects.toThrow("not supported for Deep");
    await expect(client.run(root, { validationPrompt: " \n" })).rejects.toThrow(
      "must not be empty",
    );
    await client.close();
  });

  test("renders only the discovery portion of the shipped workflows", async () => {
    const standard = await customDiscoveryPrompt(PLUGIN_ROOT, "security-scan");
    const diff = await customDiscoveryPrompt(PLUGIN_ROOT, "security-diff-scan");
    expect(standard).toContain("## Baseline Auditor Prompt");
    expect(standard).toContain("## Focused Investigator Prompt");
    expect(standard).toContain("security_scan` capability preflight");
    expect(standard).toContain("use it for the same early model checkpoint");
    expect(standard).toContain("retain the model in an early partial");
    expect(standard).not.toContain("undefined");
    expect(standard).not.toContain(
      "Independently validate each unique finding",
    );
    expect(diff).toContain("Run `$finding-discovery`");
    expect(diff).toContain(
      "Immediately save a `complete: false` semantic draft",
    );
    expect(diff).toContain('"format": "markdown", "content": "<model text>"');
    expect(diff).not.toContain("run `$validation` once");
    expect(diff).not.toContain("Call `complete_codex_security_scan` once");
    for (const prompt of [standard, diff]) {
      expect(prompt).toContain("custom_pending");
      expect(prompt).toContain("extensions.customValidationSurfaceIds");
      expect(prompt).not.toContain("finalize_scan_contract.py");
    }
    const changed = await temporaryDirectory();
    await mkdir(join(changed, "skills/security-diff-scan"), {
      recursive: true,
    });
    await writeFile(
      join(changed, "skills/security-diff-scan/SKILL.md"),
      "Changed workflow\n",
    );
    await expect(
      customDiscoveryPrompt(changed, "security-diff-scan"),
    ).rejects.toThrow("incompatible");
  });

  test("the bundled Codex honors the invocation-only completion restriction", async () => {
    const home = await temporaryDirectory();
    const marketplace = await createMarketplace(home, PLUGIN_ROOT);
    const command = resolveCodexCommand({}).command;
    const run = (args: string[]) =>
      execFileSync(command, args, {
        env: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          TEMP: process.env["TEMP"],
          TMP: process.env["TMP"],
          CODEX_HOME: home,
        },
        encoding: "utf8",
        windowsHide: true,
      });
    run(["plugin", "marketplace", "add", marketplace]);
    run(["plugin", "add", "--json", "codex-security@codex-security-sdk"]);
    const config = await customValidationConfig(
      {
        mcp_servers: {
          "codex-security": { disabled_tools: ["user_disabled_tool"] },
        },
      },
      PLUGIN_ROOT,
    );
    const server = (config["mcp_servers"] as Record<string, unknown>)[
      "codex-security"
    ] as Record<string, unknown>;
    const overrides = Object.entries(server).flatMap(([key, value]) => [
      "-c",
      `mcp_servers.codex-security.${key}=${JSON.stringify(value)}`,
    ]);
    const effective = JSON.parse(
      run([...overrides, "mcp", "get", "codex-security", "--json"]),
    );
    expect(effective.disabled_tools).toContain("complete_codex_security_scan");
    expect(effective.disabled_tools).toContain("user_disabled_tool");
    expect(effective.transport.cwd).toBe(resolve(PLUGIN_ROOT));
    const ordinary = JSON.parse(
      run(["mcp", "get", "codex-security", "--json"]),
    );
    expect(ordinary.disabled_tools).toBeNull();
  });
});

const unexpectedValidation = rejecting("unexpected validation");

for (const prior of ["rejected", "not_applicable"] as const) {
  for (const disposition of [
    "reportable",
    "deferred",
    "suppressed",
    "not_applicable",
  ] as const) {
    for (const gap of ["generic", "other-worker", "none"] as const) {
      test(`unmapped terminal surface retains referenced evidence: ${prior}/${disposition}/${gap}`, async () => {
        const f = await fixture();
        const finding = f.findings.findings[0]!;
        finding.provenance["candidateId"] = "validated-candidate";
        finding.provenance["sourceWorkerId"] = "worker-current";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const previous = {
          id: "saved-terminal-review",
          candidateId: "validated-candidate",
          sourceWorkerId: "worker-current",
          label: "Saved terminal review",
          disposition: prior,
          notes: "Saved independent evidence.",
          receiptRefs: [],
          annotation: "Retain this authored annotation.",
        };
        coverage.surfaces.push(previous);
        coverage.completeness = "partial";
        const independent = {
          id: "independent-review",
          ...(gap === "other-worker"
            ? {
                candidateId: "validated-candidate",
                sourceWorkerId: "worker-other",
              }
            : {}),
          reason: "Independent work still uses the saved evidence.",
          surfaceIds: [previous.id],
        };
        coverage.deferred = gap === "none" ? [] : [independent];
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        const reopened = saved.unresolvedCandidates.filter(
          (row) =>
            row.candidateId === "validated-candidate" &&
            row["sourceWorkerId"] === "worker-current",
        );
        expect(reopened).toHaveLength(disposition === "deferred" ? 1 : 0);
        if (gap === "none") {
          expect(saved.coverage.surfaces).not.toContainEqual(previous);
        } else {
          const { candidateId: _candidateId, ...evidence } = previous;
          expect(saved.coverage.surfaces).toContainEqual(evidence);
          expect(saved.coverage.deferred).toContainEqual(independent);
        }
        if (disposition === "deferred") {
          expect(reopened[0]!.reason).toBe(
            "The required service was unavailable.",
          );
          expect(reopened[0]!.candidate).toMatchObject({
            provenance: {
              originalCandidates: expect.arrayContaining([previous]),
            },
          });
        }
      });
    }
    for (const owner of [
      { worker: "synthetic-worker" },
      ["synthetic-worker"],
    ]) {
      test(`structured exclusion owner remains independent: ${prior}/${disposition}/${Array.isArray(owner) ? "array" : "object"}`, async () => {
        const f = await fixture();
        f.findings.findings[0]!.provenance["candidateId"] =
          "validated-candidate";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const previous = {
          id: "independent-exclusion",
          candidateId: "validated-candidate",
          sourceWorkerId: owner,
          pattern: "src/synthetic.ts",
          reason: "Independent authored exclusion.",
          disposition: prior,
          annotation: "Retain this authored annotation.",
        };
        coverage.explicitExclusions.push(previous);
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        expect(saved.coverage.explicitExclusions).toContainEqual(previous);
      });
    }
  }
}

for (const disposition of [
  "reportable",
  "deferred",
  "suppressed",
  "not_applicable",
] as const) {
  for (const sameOwner of [false, true]) {
    for (const shared of [false, true]) {
      test(`saved unmapped follow-up reconciles custom ${disposition}, sameOwner=${sameOwner}, shared=${shared}`, async () => {
        const f = await fixture();
        const finding = f.findings.findings[0]!;
        finding.provenance["candidateId"] = "validated-candidate";
        finding.provenance["sourceWorkerId"] = "worker-current";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const previous = {
          id: "saved-follow-up",
          candidateId: "validated-candidate",
          sourceWorkerId: sameOwner ? "worker-current" : "worker-other",
          label: "Saved candidate review",
          disposition: "needs_follow_up" as const,
          notes: "Saved review evidence remains available.",
          receiptRefs: [],
          annotation: "Retain this saved annotation.",
        };
        coverage.surfaces.push(previous);
        coverage.completeness = "partial";
        coverage.deferred = [
          {
            id: "saved-pending",
            candidateId: "validated-candidate",
            sourceWorkerId: "worker-current",
            reason: "Earlier candidate proof gap.",
            surfaceIds: [previous.id],
          },
        ];
        if (shared)
          coverage.deferred.push({
            id: "independent-review",
            reason: "Independent work still needs this surface.",
            surfaceIds: [previous.id],
          });
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        const retained = saved.coverage.surfaces.find(
          (row) => row.id === previous.id,
        )!;
        expect(retained).toBeDefined();
        expect(retained["annotation"]).toBe(previous.annotation);
        expect(retained.notes).toBe(previous.notes);
        const resolved = sameOwner && !shared && disposition !== "deferred";
        expect(retained.disposition).toBe(
          resolved
            ? disposition === "reportable"
              ? "reported"
              : disposition === "suppressed"
                ? "rejected"
                : "not_applicable"
            : "needs_follow_up",
        );
        if (shared)
          expect(saved.coverage.deferred).toContainEqual({
            id: "independent-review",
            reason: "Independent work still needs this surface.",
            surfaceIds: [previous.id],
          });
      });
    }
  }
}

for (const prior of ["rejected", "not_applicable"] as const) {
  for (const disposition of [
    "reportable",
    "deferred",
    "suppressed",
    "not_applicable",
  ] as const) {
    for (const sameCandidate of [true, false]) {
      test(`custom validation preserves shared terminal ${prior} after ${disposition}, sameCandidate=${sameCandidate}`, async () => {
        const f = await fixture();
        f.findings.findings[0]!.provenance["candidateId"] =
          "validated-candidate";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        coverage.surfaces[0]!.candidateId = sameCandidate
          ? "validated-candidate"
          : "independent-candidate";
        coverage.surfaces[0]!.disposition = prior;
        coverage.surfaces[0]!["annotation"] = "Saved terminal annotation.";
        coverage.completeness = "partial";
        coverage.deferred = [
          {
            id: "old-independent-gap",
            candidateId: coverage.surfaces[0]!.candidateId,
            reason: "Historical saved proof gap.",
            surfaceIds: [coverage.surfaces[0]!.id],
          },
        ];
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        if (!sameCandidate) {
          const retained = saved.coverage.surfaces.find(
            (row) =>
              row.candidateId === "independent-candidate" &&
              row.disposition === prior,
          );
          expect(retained).toBeDefined();
          expect(retained!["annotation"]).toBe("Saved terminal annotation.");
        } else {
          expect(saved.coverage.surfaces[0]!.disposition).toBe(
            disposition === "reportable"
              ? "reported"
              : disposition === "deferred"
                ? "needs_follow_up"
                : disposition === "suppressed"
                  ? "rejected"
                  : "not_applicable",
          );
        }
      });
    }
  }
}

for (const mapped of [false, true]) {
  test(`repeated custom validation retains historical follow-up links, mapped=${mapped}`, async () => {
    const f = await fixture();
    const finding = f.findings.findings[0]!;
    finding.provenance["candidateId"] = "validated-candidate";
    finding.provenance["sourceWorkerId"] = "worker-current";
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    const previous = {
      id: "saved-follow-up",
      ...(mapped ? { candidateId: "validated-candidate" } : {}),
      sourceWorkerId: "worker-current",
      label: "Earlier route review",
      disposition: "needs_follow_up" as const,
      receiptRefs: [],
      notes: "The historical proof gap remains available.",
      annotation: "Retain this historical annotation.",
    };
    coverage.surfaces.push(previous);
    coverage.completeness = "partial";
    coverage.deferred = [
      {
        id: "saved-pending",
        candidateId: "validated-candidate",
        sourceWorkerId: "worker-current",
        reason: "Earlier candidate proof gap.",
        surfaceIds: [previous.id],
      },
    ];
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result("deferred")),
    });
    const pending = await loadResult(f.scanDir);
    if (!mapped)
      expect(pending.coverage.deferred[0]!.surfaceIds).toContain(previous.id);
    // A later producer publishes the same candidate for its next validation.
    await save(join(f.scanDir, "findings.json"), f.findings);
    const manifest = await json<ScanManifest>(
      join(f.scanDir, "scan-manifest.json"),
    );
    manifest.scan.scope.validationMode = "custom_pending";
    await save(join(f.scanDir, "scan-manifest.json"), manifest);
    await runCustomValidation({
      ...f,
      run: async () => JSON.stringify(result("reportable")),
    });
    const saved = await loadResult(f.scanDir);
    expect(
      saved.coverage.surfaces.find((row) => row.id === previous.id),
    ).toMatchObject({
      disposition: "reported",
      notes: previous.notes,
      annotation: previous.annotation,
    });
    expect(saved.coverage.deferred).toEqual([]);
  });
}

for (const owner of [{ worker: "historical-worker" }, ["historical-worker"]]) {
  for (const disposition of [
    "reportable",
    "deferred",
    "suppressed",
    "not_applicable",
  ] as const) {
    test(`historical structured deferred remains independent: ${Array.isArray(owner) ? "array" : "object"}/${disposition}`, async () => {
      const f = await fixture();
      f.findings.findings[0]!.provenance["candidateId"] = "validated-candidate";
      await save(join(f.scanDir, "findings.json"), f.findings);
      const coverage = await json<CoverageDocument>(
        join(f.scanDir, "coverage.json"),
      );
      const historical = {
        id: "historical-deferred",
        candidateId: "validated-candidate",
        sourceWorkerId: owner,
        reason: "Independent historical review remains.",
        surfaceIds: [coverage.surfaces[0]!.id],
      };
      coverage.deferred = [historical];
      coverage.completeness = "partial";
      await save(join(f.scanDir, "coverage.json"), coverage);
      await runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result(disposition)),
      });
      const saved = await loadResult(f.scanDir);
      expect(saved.coverage.deferred).toContainEqual(historical);
      expect(saved.unresolvedCandidates).toHaveLength(
        disposition === "deferred" ? 1 : 0,
      );
      if (disposition === "deferred") {
        const current = saved.unresolvedCandidates[0]!;
        expect(current["sourceWorkerId"]).toBeUndefined();
        expect(current.reason).toBe("The required service was unavailable.");
      }
    });
  }
}
for (const outcomes of [
  ["reportable", "reportable"],
  ["suppressed", "not_applicable"],
  ["reportable", "suppressed"],
  ["deferred", "suppressed"],
] as const) {
  for (const independent of [false, true]) {
    test(`sibling outcomes reconcile consumed historical follow-up: ${outcomes.join("/")}/${independent}`, async () => {
      const f = await fixture(2);
      for (const [index, finding] of f.findings.findings.entries()) {
        finding.provenance["candidateId"] = "validated-candidate";
        finding.provenance["sourceWorkerId"] = "worker-current";
        finding.identity = {
          ...finding.identity,
          instance: `sibling-${index}`,
        };
      }
      await save(join(f.scanDir, "findings.json"), f.findings);
      const coverage = await json<CoverageDocument>(
        join(f.scanDir, "coverage.json"),
      );
      const historical = {
        id: "historical-follow-up",
        candidateId: "validated-candidate",
        sourceWorkerId: "worker-current",
        label: "Historical sibling review",
        disposition: "needs_follow_up" as const,
        receiptRefs: [],
        notes: "Preserve the historical review evidence.",
      };
      coverage.surfaces.push(historical);
      coverage.deferred = [
        {
          id: "historical-gap",
          candidateId: "validated-candidate",
          sourceWorkerId: "worker-current",
          reason: "Prior sibling proof gap.",
          surfaceIds: [historical.id],
        },
      ];
      const shared = {
        id: "independent-gap",
        reason: "Other work uses the historical evidence.",
        surfaceIds: [historical.id],
      };
      if (independent) coverage.deferred.push(shared);
      coverage.completeness = "partial";
      await save(join(f.scanDir, "coverage.json"), coverage);
      await runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result(...outcomes)),
      });
      const saved = await loadResult(f.scanDir);
      const historicalSurface = saved.coverage.surfaces.find(
        (row) => row.id === historical.id,
      )!;
      expect(historicalSurface.notes).toBe(historical.notes);
      expect(historicalSurface.disposition).toBe(
        independent
          ? "needs_follow_up"
          : outcomes.some((value) => value === "reportable")
            ? "reported"
            : outcomes.some((value) => value === "deferred")
              ? "needs_follow_up"
              : "rejected",
      );
      expect(
        saved.coverage.deferred.some((row) => row.id === "historical-gap"),
      ).toBe(false);
      if (independent) expect(saved.coverage.deferred).toContainEqual(shared);
      expect(saved.unresolvedCandidates).toHaveLength(
        outcomes.some((value) => value === "deferred") ? 1 : 0,
      );
    });
  }
}

for (const owner of [
  undefined,
  "other-worker",
  { worker: "historical-worker" },
  ["historical-worker"],
]) {
  for (const mapped of [false, true]) {
    for (const disposition of [
      "reportable",
      "deferred",
      "suppressed",
      "not_applicable",
    ] as const) {
      test(`historical follow-up owner remains independent: ${JSON.stringify(owner)}/${mapped}/${disposition}`, async () => {
        const f = await fixture();
        const finding = f.findings.findings[0]!;
        finding.provenance["candidateId"] = "validated-candidate";
        if (mapped)
          finding.extensions!["customValidationSurfaceIds"] = [
            "surface-0",
            "historical-follow-up",
          ];
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const historical = {
          id: "historical-follow-up",
          candidateId: "validated-candidate",
          ...(owner === undefined ? {} : { sourceWorkerId: owner }),
          label: "Historical proof gap",
          disposition: "needs_follow_up" as const,
          notes:
            "This earlier task has no consumed deferred row or current mapping.",
          receiptRefs: [],
        };
        coverage.surfaces.push(historical);
        coverage.completeness = "partial";
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        const independent = !mapped && owner !== undefined;
        const retained = saved.coverage.surfaces.find(
          (row) => row.id === historical.id,
        )!;
        if (independent) expect(retained).toEqual(historical);
        else
          expect(retained.disposition).toBe(
            disposition === "reportable"
              ? "reported"
              : disposition === "suppressed"
                ? "rejected"
                : disposition === "deferred"
                  ? "needs_follow_up"
                  : "not_applicable",
          );
        expect(retained["sourceWorkerId"]).toEqual(owner);
        if (disposition === "deferred")
          expect(
            saved.coverage.deferred[0]!.surfaceIds!.includes(historical.id),
          ).toBe(!independent);
      });
    }
  }
}

for (const owner of [undefined, "", " ", "other-worker"]) {
  for (const disposition of [
    "reportable",
    "deferred",
    "suppressed",
    "not_applicable",
  ] as const) {
    test(`legacy linked follow-up uses effective owner: ${JSON.stringify(owner)}/${disposition}`, async () => {
      const f = await fixture();
      const finding = f.findings.findings[0]!;
      finding.provenance["candidateId"] = "validated-candidate";
      await save(join(f.scanDir, "findings.json"), f.findings);
      const coverage = await json<CoverageDocument>(
        join(f.scanDir, "coverage.json"),
      );
      const historical = {
        id: "legacy-linked-proof",
        ...(owner === undefined ? {} : { sourceWorkerId: owner }),
        label: "Historical proof",
        disposition: "needs_follow_up" as const,
        receiptRefs: [],
        notes: "Original proof evidence.",
      };
      coverage.surfaces.push(historical);
      coverage.completeness = "partial";
      coverage.deferred = [
        {
          id: "legacy-gap",
          candidateId: "validated-candidate",
          ...(owner === undefined ? {} : { sourceWorkerId: owner }),
          reason: "Earlier candidate gap.",
          surfaceIds: [historical.id],
        },
      ];
      await save(join(f.scanDir, "coverage.json"), coverage);
      await runCustomValidation({
        ...f,
        run: async () => JSON.stringify(result(disposition)),
      });
      const saved = await loadResult(f.scanDir);
      const row = saved.coverage.surfaces.find(
        (item) => item.id === historical.id,
      )!;
      if (owner === "other-worker") {
        expect(row).toEqual(historical);
        expect(
          saved.coverage.deferred.some((item) => item.id === "legacy-gap"),
        ).toBe(true);
      } else {
        expect(row.disposition).toBe(
          disposition === "reportable"
            ? "reported"
            : disposition === "deferred"
              ? "needs_follow_up"
              : disposition === "suppressed"
                ? "rejected"
                : "not_applicable",
        );
        expect(
          saved.coverage.deferred.some((item) => item.id === "legacy-gap"),
        ).toBe(disposition === "deferred");
      }
      expect(row.notes).toBe(historical.notes);
      expect(row["sourceWorkerId"]).toEqual(owner);
    });
  }
}

for (const disposition of ["reportable", "suppressed"] as const) {
  for (const independent of [false, true]) {
    for (const linked of [false, true]) {
      test(`unique cross-owner historical follow-up ${disposition}/${independent}/${linked}`, async () => {
        const f = await fixture();
        const finding = f.findings.findings[0]!;
        finding.provenance["candidateId"] = "current-candidate";
        finding.provenance["sourceWorkerId"] = "worker-current";
        await save(join(f.scanDir, "findings.json"), f.findings);
        const coverage = await json<CoverageDocument>(
          join(f.scanDir, "coverage.json"),
        );
        const historical = {
          id: "historical-proof",
          sourceWorkerId: "worker-previous",
          label: "Previously linked proof",
          disposition: "needs_follow_up" as const,
          receiptRefs: [],
          notes: "Preserve the saved proof and owner.",
        };
        coverage.surfaces.push(historical);
        coverage.completeness = "partial";
        coverage.deferred = [
          {
            id: "candidate-gap",
            candidateId: "current-candidate",
            sourceWorkerId: "worker-current",
            reason: "Previously incomplete candidate review.",
            surfaceIds: linked ? [historical.id] : [],
          },
        ];
        const generic = {
          id: "independent-gap",
          reason: "Independent pending work.",
          surfaceIds: [historical.id],
        };
        if (independent) coverage.deferred.push(generic);
        await save(join(f.scanDir, "coverage.json"), coverage);
        await runCustomValidation({
          ...f,
          run: async () => JSON.stringify(result(disposition)),
        });
        const saved = await loadResult(f.scanDir);
        const surface = saved.coverage.surfaces.find(
          (row) => row.id === historical.id,
        )!;
        expect(surface.disposition).toBe(
          linked && !independent
            ? disposition === "reportable"
              ? "reported"
              : "rejected"
            : "needs_follow_up",
        );
        expect(surface.notes).toBe(historical.notes);
        expect(surface["sourceWorkerId"]).toBe(historical.sourceWorkerId);
        expect(
          saved.coverage.deferred.some((row) => row.id === "candidate-gap"),
        ).toBe(false);
        if (independent)
          expect(saved.coverage.deferred).toContainEqual(generic);
        expect(saved.unresolvedCandidateCount).toBe(0);
      });
    }
  }
}

for (const reassessed of [false, true]) {
  test(`mapped historical decision respects current reassessment: ${reassessed}`, async () => {
    const f = await fixture(reassessed ? 2 : 1);
    f.findings.findings[0]!.provenance["candidateId"] = "candidate-a";
    if (reassessed)
      f.findings.findings[1]!.provenance["candidateId"] = "candidate-b";
    await save(join(f.scanDir, "findings.json"), f.findings);
    const coverage = await json<CoverageDocument>(
      join(f.scanDir, "coverage.json"),
    );
    const previous = {
      ...coverage.surfaces[0]!,
      candidateId: "candidate-b",
      disposition: "rejected" as const,
      notes: "Original candidate B rejection evidence.",
    };
    coverage.surfaces[0] = previous;
    await save(join(f.scanDir, "coverage.json"), coverage);
    await runCustomValidation({
      ...f,
      run: async () =>
        JSON.stringify(
          reassessed ? result("reportable", "deferred") : result("reportable"),
        ),
    });
    const saved = await loadResult(f.scanDir);
    const old = saved.coverage.surfaces.filter(
      (row) =>
        row.candidateId === "candidate-b" && row.disposition === "rejected",
    );
    expect(old).toHaveLength(reassessed ? 0 : 1);
    if (reassessed) {
      expect(saved.unresolvedCandidates).toHaveLength(1);
      expect(saved.unresolvedCandidates[0]!.candidateId).toBe("candidate-b");
      expect(saved.unresolvedCandidates[0]!.candidate).toMatchObject({
        provenance: { originalCandidates: expect.arrayContaining([previous]) },
      });
    }
  });
}
