import {
  discoverCandidate,
  importDiscoverySource,
  rememberCheckpoints,
  startDiffScan,
} from "../../../plugins/codex-security/mcp-app/tests/support/discovery.ts";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { runCustomValidation } from "../src/custom-validation.js";
import type { FindingsDocument, ScanManifest } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { readJson } from "./support/json.js";
import { readReviewState } from "./support/review-state.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const { createScanArtifactContext } = await import(
  pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-context.ts")).href
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await import(
  pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-scan-draft.ts")).href
);
const discoveryApi = await importDiscoverySource();

async function fixture() {
  const directory = await temporaryDirectory("candidate-publication-");
  const started = await startDiffScan(directory, PLUGIN_ROOT);
  const context = await createScanArtifactContext(
    started.scan.scanId,
    started.workbench,
    { requireRunning: true, pluginRoot: PLUGIN_ROOT },
  );
  return { ...started, directory, context };
}

for (const stopped of [false, true]) {
  for (const collision of [false, true]) {
    for (const existing of [false, true]) {
      test(`custom validation preserves generic closures: stopped=${stopped}, collision=${collision}, existing=${existing}`, async () => {
        const { context, directory, repository, revision, scan, workbench } =
          await fixture();
        const candidateId = "custom-validation-candidate-1";
        const closureId = collision ? `${candidateId}-2` : "independent-review";
        const closures = [
          { id: closureId, reason: "Independent generic task completed." },
          { id: "other-task", reason: "Another independent task completed." },
        ];
        const draft = {
          scanId: scan.scanId,
          handoffClaimToken: context.handoffClaimToken,
          complete: false,
          findings: [],
          scope: { validationMode: "custom_pending" },
          reviewState: {
            surfaces: [],
            explicitExclusions: [],
            deferred: closures.map(({ id }) => ({
              id,
              reason: "Independent generic review remains.",
            })),
          },
        };
        await record(context, draft, workbench);
        const finding = {
          ruleId: "synthetic-review",
          title: "Synthetic finding",
          summary: "Synthetic candidate review",
          severity: { level: "low" },
          confidence: { level: "high", rationale: "Synthetic evidence" },
          locations: [{ path: "app.ts", startLine: 1, endLine: 1 }],
          taxonomy: { category: "synthetic", cwe: [] },
          remediation: "Apply synthetic fix",
          provenance: { source: "local_plugin", candidateId },
          extensions: { customValidationSurfaceIds: ["reviewed"] },
        };
        const savedId = "saved-validation-task";
        await record(
          context,
          {
            ...draft,
            complete: true,
            findings: [finding],
            reviewState: {
              surfaces: [
                {
                  id: "reviewed",
                  label: "Synthetic review",
                  disposition: "reported",
                  receiptRefs: [],
                },
              ],
              explicitExclusions: [],
              resolvedDeferred: closures,
              deferred: existing
                ? [
                    {
                      id: savedId,
                      candidateId,
                      reason: "Existing candidate proof gap.",
                      surfaceIds: ["reviewed"],
                    },
                  ]
                : [],
            },
          },
          workbench,
        );
        const assertUnchanged = await rememberCheckpoints(context.root);
        await runCustomValidation({
          repository,
          target: { kind: "refs", paths: [], head: revision },
          scanDir: context.root,
          scanId: scan.scanId,
          pluginRoot: PLUGIN_ROOT,
          prompt: "Validate synthetic candidate",
          signal: new AbortController().signal,
          run: async () =>
            JSON.stringify({
              status: "complete",
              reason: null,
              validations: [
                {
                  candidateId: "candidate-1",
                  validation: {
                    disposition: "deferred",
                    method: "synthetic validation",
                    confidence: "high",
                    confidence_rationale: "Synthetic evidence",
                    rubric: "Check synthetic behavior",
                    evidence: ["Synthetic source trace."],
                    counterevidence_or_proof_gap:
                      "Additional validation remains necessary.",
                    remaining_uncertainty: "",
                    artifact_paths: [],
                  },
                  severity: null,
                  impact: null,
                },
              ],
            }),
        });
        const snapshot = async (stage: string) => {
          const state = await readReviewState(
            context.root,
            join(directory, "state"),
          );
          const { scan } = await readJson<ScanManifest>(
            join(context.root, "scan-manifest.json"),
          );
          return {
            stage,
            closures: state.resolvedDeferred,
            deferred:
              scan.sealedAt && !scan.coverageRef
                ? (scan.review?.unresolvedCandidates ?? [])
                : state.deferred,
          };
        };
        const snapshots = [await snapshot("custom validation")];
        for (const command of stopped
          ? ["fail-scan", "preserve-scan-results"]
          : ["prepare-scan-completion", "complete-scan"]) {
          await workbench([
            command,
            "--scan-id",
            scan.scanId,
            ...(command === "fail-scan"
              ? ["--message", "Synthetic interruption after validation"]
              : []),
          ]);
          snapshots.push(await snapshot(command));
        }
        for (const { stage, closures: savedClosures, deferred } of snapshots) {
          expect(savedClosures, stage).toEqual(
            expect.arrayContaining(closures),
          );
          expect(savedClosures, stage).toHaveLength(closures.length);
          const pending = deferred.filter(
            (row) =>
              row.candidateId === candidateId &&
              row.reason === "Additional validation remains necessary.",
          );
          expect(pending, stage).toHaveLength(1);
          if (existing) expect(pending[0]!.id, stage).toBe(savedId);
          if (existing && stopped && stage !== "custom validation")
            expect(deferred, stage).toEqual(
              expect.arrayContaining([
                expect.objectContaining({
                  candidateId,
                  reason: "Existing candidate proof gap.",
                }),
              ]),
            );
        }
        for (const { stage, deferred } of snapshots) {
          const pending = deferred.find(
            (row) => row.candidateId === candidateId,
          )!;
          expect(
            closures.map((row) => row.id),
            stage,
          ).not.toContain(pending.id);
        }
        await assertUnchanged();
      });
    }
  }
}

for (const disposition of [
  "reportable",
  "suppressed",
  "not_applicable",
  "deferred",
] as const) {
  test(`custom validation of a reopened candidate survives public stopped recovery: ${disposition}`, async () => {
    const { context, repository, revision, scan, workbench } = await fixture();
    const candidateId = await discoverCandidate(
      discoveryApi,
      context,
      "app.ts",
      "Synthetic source evidence",
    );
    const finding = {
      ruleId: "synthetic-review",
      title: "Synthetic finding",
      summary: "Synthetic candidate review",
      severity: { level: "low" },
      confidence: { level: "high", rationale: "Synthetic evidence" },
      locations: [{ path: "app.ts", startLine: 1, endLine: 1 }],
      taxonomy: { category: "synthetic", cwe: [] },
      remediation: "Apply synthetic fix",
      provenance: { source: "local_plugin", candidateId },
      extensions: { customValidationSurfaceIds: ["reviewed"] },
    };
    const coverage = {
      surfaces: [
        {
          id: "reviewed",
          label: "Synthetic review",
          disposition: "reported",
          receiptRefs: [],
        },
      ],
      explicitExclusions: [],
      deferred: [],
    };
    const draft = {
      scanId: scan.scanId,
      handoffClaimToken: context.handoffClaimToken,
      complete: false,
      findings: [finding],
      reviewState: coverage,
      scope: { validationMode: "custom_pending" },
    };
    await record(context, draft, workbench);
    const pending = {
      id: "pending-validation",
      candidateId,
      reason: "New evidence requires validation.",
      surfaceIds: ["reviewed"],
    };
    await record(
      context,
      {
        ...draft,
        complete: true,
        findings: [],
        reviewState: { ...coverage, deferred: [pending] },
      },
      workbench,
    );
    const reopened = await readJson<FindingsDocument>(
      join(context.root, "findings.json"),
    );
    expect(reopened.findings[0]!.provenance["candidateReopened"]).toBe(true);
    const assertUnchanged = await rememberCheckpoints(context.root);
    await runCustomValidation({
      repository,
      target: { kind: "refs", paths: [], head: revision },
      scanDir: context.root,
      scanId: scan.scanId,
      pluginRoot: PLUGIN_ROOT,
      prompt: "Validate synthetic candidate",
      signal: new AbortController().signal,
      run: async () =>
        JSON.stringify({
          status: "complete",
          reason: null,
          validations: [
            {
              candidateId: "candidate-1",
              validation: {
                disposition,
                method: "synthetic validation",
                confidence: "high",
                confidence_rationale: "Synthetic test ran.",
                rubric: "Check synthetic behavior",
                evidence: ["Synthetic validation evidence."],
                counterevidence_or_proof_gap:
                  disposition === "deferred"
                    ? "Additional evidence remains necessary."
                    : "",
                remaining_uncertainty: "",
                artifact_paths: [],
              },
              severity: null,
              impact: null,
            },
          ],
        }),
    });
    const accepted = await readJson<FindingsDocument>(
      join(context.root, "findings.json"),
    );
    const expectedFindings = disposition === "reportable" ? 1 : 0;
    expect(accepted.findings).toHaveLength(expectedFindings);
    for (const command of ["fail-scan", "recover-scan-results"]) {
      await workbench([
        command,
        "--scan-id",
        scan.scanId,
        ...(command === "fail-scan"
          ? ["--message", "Synthetic interruption after validation"]
          : []),
      ]);
      const saved = await readJson<FindingsDocument>(
        join(context.root, "findings.json"),
      );
      const manifest = await readJson<ScanManifest>(
        join(context.root, "scan-manifest.json"),
      );
      expect(saved.findings).toHaveLength(expectedFindings);
      if (disposition === "reportable") {
        expect(saved.findings[0]!.provenance["candidateReopened"]).not.toBe(
          true,
        );
        expect(saved.findings[0]!.provenance["originalCandidates"]).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ candidateId, reason: pending.reason }),
          ]),
        );
      }
      const remaining = (
        manifest.scan.review?.unresolvedCandidates ?? []
      ).filter((row) => row.candidateId === candidateId);
      if (disposition === "deferred")
        expect(remaining).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              reason: "Additional evidence remains necessary.",
            }),
          ]),
        );
      else expect(remaining).toHaveLength(0);
    }
    await assertUnchanged();
  });
}

const metadata = [null, false, 0, {}, ["historical"], "", " ", "review/auth"];

for (const stopped of [false, true]) {
  for (const candidateId of metadata) {
    test(`public generic surface metadata survives ${stopped ? "stopped replay" : "completion"}: ${JSON.stringify(candidateId)}`, async () => {
      const { context, scan, workbench } = await fixture();
      const surface = {
        id: "generic-review",
        label: "Generic review",
        disposition: "no_issue_found" as const,
        candidateId,
        notes: "Retain independent historical coverage metadata.",
        receiptRefs: [],
      };
      await record(
        context,
        {
          scanId: scan.scanId,
          handoffClaimToken: context.handoffClaimToken,
          complete: true,
          findings: [],
          reviewState: {
            completeness: "complete",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [],
          },
        },
        workbench,
      );
      const assertUnchanged = await rememberCheckpoints(context.root);
      const snapshots = [];
      for (const command of stopped
        ? ["fail-scan", "preserve-scan-results"]
        : ["prepare-scan-completion", "complete-scan"]) {
        await workbench([
          command,
          "--scan-id",
          scan.scanId,
          ...(command === "fail-scan"
            ? ["--message", "Synthetic interruption."]
            : []),
        ]);
        snapshots.push({
          command,
          coverage: await readReviewState(context.root),
        });
      }
      for (const { command, coverage } of snapshots)
        expect(coverage.surfaces, command).toEqual([surface]);
      const beforeLoad = await readFile(
        join(context.root, "scan-manifest.json"),
      );
      const loaded = await loadContract(context.root, {
        pluginRoot: PLUGIN_ROOT,
        expectedScanId: scan.scanId,
      });
      expect(loaded.review.excludedPaths).toEqual([]);
      expect(await readFile(join(context.root, "scan-manifest.json"))).toEqual(
        beforeLoad,
      );
      await assertUnchanged();
    });
  }
}
