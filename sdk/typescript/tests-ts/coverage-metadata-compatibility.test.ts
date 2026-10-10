import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { loadContract } from "../src/contract.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const metadata = [null, false, 0, {}, ["historical"], "", " ", "review/auth"];

for (const stopped of [false, true]) {
  for (const candidateId of metadata) {
    test(`public generic surface metadata survives ${stopped ? "stopped replay" : "completion"}: ${JSON.stringify(candidateId)}`, async () => {
      const directory = await temporaryDirectory("coverage-metadata-");
      const { createScanArtifactContext } = await import(
        pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-context.ts"))
          .href
      );
      const { recordCodexSecurityScanDraftViaWorkbench: record } = await import(
        pathToFileURL(join(sourcePlugin, "mcp-app/src/artifact-scan-draft.ts"))
          .href
      );
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
        "synthetic-metadata-review",
        "--target-path",
        repository,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        git("rev-parse", "HEAD"),
        "--scan-root",
        join(directory, "scans"),
      ]);
      const context = await createScanArtifactContext(scan.scanId, workbench, {
        requireRunning: true,
        pluginRoot: PLUGIN_ROOT,
      });
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
          coverage: {
            completeness: "complete",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [],
          },
        },
        workbench,
      );
      const checkpointRoot = join(context.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpointRoot)).map(
          async (name) =>
            [name, await readFile(join(checkpointRoot, name))] as const,
        ),
      );
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
          coverage: JSON.parse(
            await readFile(join(context.root, "coverage.json"), "utf8"),
          ),
        });
      }
      for (const { command, coverage } of snapshots)
        expect(coverage.surfaces, command).toEqual([surface]);
      const beforeLoad = await readFile(join(context.root, "coverage.json"));
      const loaded = await loadContract(context.root, {
        pluginRoot: PLUGIN_ROOT,
        expectedScanId: scan.scanId,
      });
      expect(loaded.coverage.surfaces).toEqual([surface]);
      expect(await readFile(join(context.root, "coverage.json"))).toEqual(
        beforeLoad,
      );
      for (const [name, bytes] of originals)
        expect(await readFile(join(checkpointRoot, name))).toEqual(bytes);
    });
  }
}
