import { importDiscoverySource } from "../../../plugins/codex-security/mcp-app/tests/support/discovery.ts";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { runCustomValidation } from "../src/custom-validation.js";
import type { CoverageDocument, FindingsDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson } from "./support/json.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);

for (const disposition of [
  "reportable",
  "suppressed",
  "not_applicable",
  "deferred",
] as const) {
  test(`custom validation of a reopened candidate survives public stopped recovery: ${disposition}`, async () => {
    const directory = await temporaryDirectory("custom-validation-reopening-");
    const { createScanArtifactContext } = await import(
      pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-context.ts")).href
    );
    const { recordCodexSecurityScanDraftViaWorkbench } = await import(
      pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-scan-draft.ts"))
        .href
    );
    const {
      recordCodexSecurityDiscoveryCandidates,
      listCodexSecurityCandidates,
    } = await importDiscoverySource(join(directory, "discovery.mjs"));
    const repository = join(directory, "repository");
    const home = join(directory, "home");
    await mkdir(repository);
    await mkdir(home, { mode: 0o700 });
    await writeFile(join(repository, "app.ts"), "export const value = 1;\n");
    const git = (...args: string[]) =>
      execFileSync(
        "git",
        [
          "-C",
          repository,
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          ...args,
        ],
        { encoding: "utf8" },
      ).trim();
    git("init", "-q");
    git("add", "app.ts");
    git("commit", "-qm", "Synthetic fixture");
    const revision = git("rev-parse", "HEAD");
    const workbench = async (args: string[]) =>
      JSON.parse(
        execFileSync(
          process.env["PYTHON"]?.trim() || "python3",
          [join(PLUGIN_ROOT, "scripts/workbench_db.py"), ...args],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: join(directory, "state"),
            },
          },
        ),
      );
    const { scan } = await workbench([
      "start-prompt-only-scan",
      "--thread-id",
      "synthetic-validation-review",
      "--target-path",
      repository,
      "--scope",
      ".",
      "--mode",
      "diff",
      "--diff-target-kind",
      "commit",
      "--diff-head-revision",
      revision,
      "--scan-root",
      join(directory, "scans"),
    ]);
    const context = await createScanArtifactContext(scan.scanId, workbench, {
      requireRunning: true,
      pluginRoot: PLUGIN_ROOT,
    });
    const discovery = join(context.root, "artifacts/02_discovery");
    await mkdir(discovery, { recursive: true });
    await writeFile(join(discovery, "in_scope_files.txt"), "app.ts\n");
    await recordCodexSecurityDiscoveryCandidates(
      {
        candidates: [
          {
            cwe_ids: [],
            locations: [
              { path: "app.ts", start_line: 1, end_line: 1, role: "evidence" },
            ],
            summary: "Synthetic review candidate",
            evidence: "Synthetic source evidence",
          },
        ],
      },
      context,
    );
    const listed = await listCodexSecurityCandidates({}, context);
    const candidateId = listed.rows[0].candidate_id;
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
      completeness: "partial",
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
      coverage,
      scope: { validationMode: "custom_pending" },
    };
    await recordCodexSecurityScanDraftViaWorkbench(context, draft, workbench);
    const pending = {
      id: "pending-validation",
      candidateId,
      reason: "New evidence requires validation.",
      surfaceIds: ["reviewed"],
    };
    await recordCodexSecurityScanDraftViaWorkbench(
      context,
      {
        ...draft,
        complete: true,
        findings: [],
        coverage: { ...coverage, deferred: [pending] },
      },
      workbench,
    );
    const reopened = await readJson<FindingsDocument>(
      join(context.root, "findings.json"),
    );
    expect(reopened.findings[0]!.provenance["candidateReopened"]).toBe(true);
    const checkpoints = join(context.root, "checkpoints");
    const originals = await Promise.all(
      (await readdir(checkpoints)).map(
        async (name) =>
          [name, await readFile(join(checkpoints, name))] as const,
      ),
    );
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
      const savedCoverage = await readJson<CoverageDocument>(
        join(context.root, "coverage.json"),
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
      const remaining = savedCoverage.deferred.filter(
        (row) => row.candidateId === candidateId,
      );
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
    for (const [name, bytes] of originals)
      expect(await readFile(join(checkpoints, name))).toEqual(bytes);
  });
}
