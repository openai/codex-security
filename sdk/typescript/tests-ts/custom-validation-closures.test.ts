import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { runCustomValidation } from "../src/custom-validation.js";
import type { CoverageDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { readJson } from "./support/json.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);

for (const stopped of [false, true]) {
  for (const collision of [false, true]) {
    for (const existing of [false, true]) {
      test(`custom validation preserves generic closures: stopped=${stopped}, collision=${collision}, existing=${existing}`, async () => {
        const directory = await temporaryDirectory(
          "custom-validation-closures-",
        );
        const { createScanArtifactContext } = await import(
          pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-context.ts"))
            .href
        );
        const { recordCodexSecurityScanDraftViaWorkbench: record } =
          await import(
            pathToFileURL(
              join(sourcePlugin, "mcp-app/src/artifact-scan-draft.ts"),
            ).href
          );
        const repository = join(directory, "repository");
        const home = join(directory, "home");
        await mkdir(repository);
        await mkdir(home, { mode: 0o700 });
        await writeFile(
          join(repository, "app.ts"),
          "export const value = 1;\n",
        );
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
          "synthetic-closure-review",
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
        const context = await createScanArtifactContext(
          scan.scanId,
          workbench,
          { requireRunning: true, pluginRoot: PLUGIN_ROOT },
        );
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
          coverage: {
            completeness: "partial",
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
            coverage: {
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
        const snapshots: Array<{ stage: string; coverage: CoverageDocument }> =
          [
            {
              stage: "custom validation",
              coverage: await readJson<CoverageDocument>(
                join(context.root, "coverage.json"),
              ),
            },
          ];
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
          snapshots.push({
            stage: command,
            coverage: await readJson<CoverageDocument>(
              join(context.root, "coverage.json"),
            ),
          });
        }
        for (const { stage, coverage } of snapshots) {
          expect(coverage.resolvedDeferred, stage).toEqual(
            expect.arrayContaining(closures),
          );
          expect(coverage.resolvedDeferred, stage).toHaveLength(
            closures.length,
          );
          const pending = coverage.deferred.filter(
            (row) =>
              row.candidateId === candidateId &&
              row.reason === "Additional validation remains necessary.",
          );
          expect(pending, stage).toHaveLength(1);
          if (existing) expect(pending[0]!.id, stage).toBe(savedId);
          if (existing && stopped && stage !== "custom validation")
            expect(coverage.deferred, stage).toEqual(
              expect.arrayContaining([
                expect.objectContaining({
                  candidateId,
                  reason: "Existing candidate proof gap.",
                }),
              ]),
            );
        }
        for (const { stage, coverage } of snapshots) {
          const pending = coverage.deferred.find(
            (row) => row.candidateId === candidateId,
          )!;
          expect(
            closures.map((row) => row.id),
            stage,
          ).not.toContain(pending.id);
        }
        for (const [name, bytes] of originals)
          expect(await readFile(join(checkpoints, name))).toEqual(bytes);
      });
    }
  }
}
