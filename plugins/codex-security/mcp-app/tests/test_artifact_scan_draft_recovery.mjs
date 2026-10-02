import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { loadSourceModule, privateDirectory } from "./helpers/source.mjs";

const { recordCodexSecurityScanDraftViaWorkbench } = await loadSourceModule(
  new URL("../src/artifact-scan-draft.ts", import.meta.url),
);
const { createScanArtifactContext } = await loadSourceModule(
  new URL("../src/artifact-context.ts", import.meta.url),
);
const { semanticFinding, semanticCoverage } = await loadSourceModule(
  new URL(
    "../../../../sdk/typescript/tests-ts/helpers/semantic-scan.ts",
    import.meta.url,
  ),
);
const exec = promisify(execFile);
const script = fileURLToPath(
  new URL("../../scripts/workbench_db.py", import.meta.url),
);

for (const scenario of [
  "interrupted then new draft",
  "interrupted then empty draft",
  "retry",
]) {
  test(
    `concurrent draft identities survive ${scenario} and completion`,
    { timeout: 30000 },
    async (t) => {
      const root = await privateDirectory("codex-security-draft-recovery-");
      t.after(() => rm(root, { recursive: true, force: true }));
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      await mkdir(repository);
      await mkdir(scanDir, { mode: 0o700 });
      for (const path of ["earlier.js", "later.js", "new.js", "shared.js"])
        await writeFile(join(repository, path), "export const value = 1;\n");
      const workbench = async (args, input) => {
        const execution = exec(
          process.env.PYTHON || "python3",
          [script, ...args],
          {
            env: {
              ...process.env,
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
            },
          },
        );
        execution.child.stdin.on("error", () => {});
        execution.child.stdin.end(input);
        return JSON.parse((await execution).stdout);
      };
      const { scanId } = await workbench(
        [
          "register-cli-scan",
          "--repository",
          repository,
          "--scan-dir",
          scanDir,
          "--registration-json-stdin",
        ],
        JSON.stringify({
          recipe: {
            repository,
            target: { kind: "repository", paths: [] },
            mode: "standard",
            config: {},
          },
        }),
      );
      const context = await createScanArtifactContext(scanId, workbench);
      const input = (path) => ({
        scanId,
        complete: false,
        findings: path
          ? [
              semanticFinding({
                locations: [{ path, startLine: 1 }],
                provenance: { source: "local_plugin", candidateId: path },
              }),
            ]
          : [],
        coverage: semanticCoverage({
          completeness: "partial",
          surfaces: path
            ? [
                {
                  label: "Output review",
                  disposition: "needs_follow_up",
                  paths: [path],
                },
              ]
            : [],
          deferred: path
            ? [
                {
                  reason: "Review shared output",
                  paths: ["shared.js"],
                  candidate: { summary: path },
                },
              ]
            : [],
        }),
      });
      const save = (draft, publish = workbench, signal) =>
        recordCodexSecurityScanDraftViaWorkbench(
          context,
          draft,
          publish,
          signal,
        );
      await save(input());
      let prepared, release;
      const ready = new Promise((resolve) => {
        prepared = resolve;
      });
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      const abort = new AbortController();
      const submitted = [];
      const laterInput = input("later.js");
      const later = save(
        laterInput,
        async (args, encoded) => {
          const { checkpoint } = JSON.parse(encoded);
          submitted.push({
            finding: checkpoint.findings.find(
              (row) => row.locations[0].path === "later.js",
            ).identity,
            surface: checkpoint.coverage.surfaces.find(
              (row) => row.paths[0] === "later.js",
            ).id,
            deferred: checkpoint.coverage.deferred.find(
              (row) => row.candidate.summary === "later.js",
            ).id,
          });
          if (submitted.length === 1) {
            prepared();
            await gate;
          }
          try {
            return await workbench(args, encoded);
          } catch (error) {
            assert.match(String(error), /scan_draft_conflict/);
            if (scenario !== "retry")
              abort.abort(new Error("Synthetic interruption"));
            throw error;
          }
        },
        abort.signal,
      ).then(
        () => assert.equal(scenario, "retry"),
        (error) => {
          assert.notEqual(scenario, "retry");
          assert.equal(error.message, "Synthetic interruption");
        },
      );
      await ready;
      await save(input("earlier.js"));
      release();
      await later;
      assert.equal(laterInput.findings[0].identity, undefined);
      assert.equal(submitted.length, scenario === "retry" ? 2 : 1);
      if (scenario === "retry") assert.deepEqual(submitted[1], submitted[0]);
      await save({
        ...input(
          scenario === "interrupted then new draft" ? "new.js" : undefined,
        ),
        complete: true,
      });
      const snapshotPath = join(scanDir, "artifacts/scan-draft.json");
      const saved = JSON.parse(await readFile(snapshotPath, "utf8"));
      const expected =
        scenario === "interrupted then new draft"
          ? ["earlier.js", "later.js", "new.js"]
          : ["earlier.js", "later.js"];
      assert.deepEqual(
        saved.findings.findings.map((row) => row.locations[0].path).sort(),
        expected,
      );
      assert.deepEqual(
        saved.coverage.surfaces.map((row) => row.paths[0]).sort(),
        expected,
      );
      assert.deepEqual(
        saved.coverage.deferred.map((row) => row.candidate.summary).sort(),
        expected,
      );
      assert.deepEqual(
        saved.findings.findings.map((row) => row.provenance.candidateId).sort(),
        expected,
      );
      const revision = saved.findings.findings[0];
      const identity = structuredClone(revision.identity);
      revision.remediation = "Revised repair.";
      await save({
        scanId,
        findings: [revision],
        coverage: semanticCoverage({
          completeness: saved.coverage.completeness,
          surfaces: saved.coverage.surfaces,
          explicitExclusions: saved.coverage.explicitExclusions,
          deferred: saved.coverage.deferred,
        }),
      });
      const revised = JSON.parse(await readFile(snapshotPath, "utf8"));
      assert.equal(revised.findings.findings.length, expected.length);
      assert.deepEqual(revised.findings.findings[0].identity, identity);
      assert.equal(revised.findings.findings[0].remediation, "Revised repair.");
      assert.deepEqual(revised.coverage, saved.coverage);
      await workbench(["prepare-scan-completion", "--scan-id", scanId]);
      const findings = JSON.parse(
        await readFile(join(scanDir, "findings.json"), "utf8"),
      ).findings;
      assert.deepEqual(
        findings.map((row) => row.locations[0].path).sort(),
        expected,
      );
      assert.ok(
        JSON.parse(await readFile(join(scanDir, "scan-manifest.json"), "utf8"))
          .scan.sealedAt,
      );
    },
  );
}
