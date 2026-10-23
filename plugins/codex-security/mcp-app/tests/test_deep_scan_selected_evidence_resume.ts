import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { promisify } from "node:util";
import { Readable } from "node:stream";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { buildServer, applicationRoot } from "./build-server.ts";
import { importModule } from "./import-module.ts";
import { FakeExecutor } from "./deep_scan_coordinator_fixture.ts";
import { readJson, writeJson } from "./support/json.ts";

const execFileAsync = promisify(execFile);
const pluginRoot = path.resolve(applicationRoot, "..");
const python = process.env.PYTHON?.trim() || "python3";
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
const owner = "selected-evidence-owner";
const permissionProfile = {
  type: "managed",
  file_system: {
    type: "restricted",
    entries: [
      { path: { type: "special", value: { kind: "root" } }, access: "read" },
    ],
  },
  network: "restricted",
};
const bundleRoot = await mkdtemp(
  path.join(tmpdir(), "selected-evidence-bundle-"),
);
after(() => rm(bundleRoot, { recursive: true, force: true }));
const serverPath = path.join(bundleRoot, "server.cjs");
await buildServer(serverPath, {
  define: {
    __dirname: JSON.stringify(applicationRoot),
    "import.meta.url": "__filename",
  },
  plugins: [
    {
      name: "fixture-evidence-repair-executor",
      setup(build) {
        build.onLoad({ filter: /deep-scan[/\\]executor\.ts$/ }, () => ({
          loader: "ts",
          contents: `
          import assert from "node:assert/strict";
          import { readFile, writeFile } from "node:fs/promises";
          import { join } from "node:path";
          export class CodexSdkWorkerExecutor {
            async run(request) {
              assert.equal(request.kind, "dedup", "resume must not discover more findings");
              assert.match(await readFile(request.promptPath, "utf8"), /missing evidence/i);
              const source = request.artifactContext.deepReducer.previousReducerResultPath;
              const draft = JSON.parse(await readFile(source, "utf8"));
              for (const finding of draft.findings) finding.validation = {
                method: "Static source inspection",
                summary: "The retained source demonstrates the reported query sink.",
                evidenceRefs: finding.codeEvidence.map(item => item.id),
              };
              await writeFile(join(request.artifactContext.root, "result.json"), JSON.stringify(draft));
              return { threadId: "fixture-evidence-repair" };
            }
          }
        `,
        }));
      },
    },
  ],
});
const {
  WorkbenchDeepScanStore,
  DeepScanCoordinator,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = (await importModule({
  stdin: {
    contents: `
      export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
      export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";
      export { createScanArtifactContext } from "./src/artifact-context.ts";
      export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";
    `,
    resolveDir: applicationRoot,
  },
  loader: { ".md": "text" },
})) as Pick<
  typeof import("../src/deep-scan/store.ts"),
  "WorkbenchDeepScanStore"
> &
  Pick<
    typeof import("../src/deep-scan/coordinator.ts"),
    "DeepScanCoordinator"
  > &
  Pick<
    typeof import("../src/artifact-context.ts"),
    "createScanArtifactContext"
  > &
  Pick<
    typeof import("../src/artifact-scan-draft.ts"),
    "recordCodexSecurityScanDraftViaWorkbench"
  >;

for (const { route, saturated, lateFailure } of [
  { route: "plugin", saturated: false, lateFailure: false },
  { route: "cli", saturated: false, lateFailure: false },
  { route: "headless continuation", saturated: false, lateFailure: false },
  { route: "plugin", saturated: true, lateFailure: false },
  { route: "plugin", saturated: true, lateFailure: true },
] as const) {
  test(
    `${route} repairs a selected unsealed aggregate before completion${saturated ? (lateFailure ? " with a late saturation failure" : " with saturation omissions") : ""}`,
    { timeout: 45_000 },
    async (t) => {
      const root = await mkdtemp(path.join(tmpdir(), "selected-evidence-"));
      let client: Client | undefined;
      t.after(async () => {
        await client?.close();
        await rm(root, { recursive: true, force: true });
      });
      const targetPath = path.join(root, "target");
      await mkdir(targetPath);
      await writeFile(
        path.join(targetPath, "fixture.py"),
        "connection.execute(query)\n",
      );
      const env = Object.fromEntries(
        Object.entries({
          ...process.env,
          CODEX_HOME: path.join(root, "home"),
          CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
          CODEX_SECURITY_SCAN_ROOT: path.join(root, "scans"),
        }).filter((entry): entry is [string, string] => entry[1] !== undefined),
      );
      delete env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      await mkdir(path.join(env.CODEX_HOME, "codex-security"), {
        recursive: true,
      });
      await writeFile(
        path.join(env.CODEX_HOME, "codex-security", "config.toml"),
        saturated
          ? "[deep_scan]\nworkers = 2\nmax_discovery_runs = 4\nstop_after_no_new = 1\nstop_after_consecutive_errors = 1\n"
          : "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n",
      );
      const runWorkbench = async (args: string[], input?: string | Buffer) => {
        const child = execFileAsync(python, [workbenchPath, ...args], {
          env,
          cwd: pluginRoot,
        });
        child.child.stdin!.end(input);
        return JSON.parse((await child).stdout);
      };
      const store = new WorkbenchDeepScanStore(runWorkbench);
      const run = await store.begin({
        targetPath,
        threadId: owner,
        scanRoot: env.CODEX_SECURITY_SCAN_ROOT,
      });
      const claim = await store.claimCoordinator({
        scanId: run.scanId,
        threadId: owner,
      });
      const releaseLateWorker = Promise.withResolvers<void>();
      const lateSettled = Promise.withResolvers<void>();
      const releaseSettlement = Promise.withResolvers<void>();
      const seedExecutor = new FakeExecutor({
        discoveryCandidateId: "accepted-finding",
        ...(saturated
          ? {
              discoveryGates: { "discovery-0004": releaseLateWorker.promise },
              discoveryCandidates: { "discovery-0004": "omitted-finding" },
            }
          : {}),
      });
      if (saturated) {
        const updateWorker = store.updateWorker.bind(store);
        store.updateWorker = async (update) => {
          const result = await updateWorker(update);
          if (
            update.kind === "discovery" &&
            (update.status === "succeeded" ||
              (lateFailure && update.status === "canceled")) &&
            path.basename(path.dirname(update.promptPath)) === "discovery-0004"
          ) {
            lateSettled.resolve();
            await releaseSettlement.promise;
          }
          return result;
        };
        const execute = seedExecutor.run.bind(seedExecutor);
        let reducers = 0;
        seedExecutor.run = async (request) => {
          if (
            lateFailure &&
            request.kind === "discovery" &&
            path.basename(path.dirname(request.promptPath)) === "discovery-0004"
          ) {
            await releaseLateWorker.promise;
            throw new Error("fixture late transient discovery failure");
          }
          if (request.kind === "dedup" && ++reducers === 2) {
            releaseLateWorker.resolve();
            await lateSettled.promise;
            request.signal.addEventListener(
              "abort",
              () => releaseSettlement.resolve(),
              { once: true },
            );
          }
          return execute(request);
        };
      }
      const coordinator = new DeepScanCoordinator({
        run: claim.run,
        store,
        pluginRoot,
        threadId: owner,
        executor: seedExecutor,
        retryDelaysMs: [],
        onComplete: async (draft, signal, publication) => {
          const context = await createScanArtifactContext(
            run.scanId,
            runWorkbench,
            { requireRunning: true, pluginRoot },
          );
          await recordCodexSecurityScanDraftViaWorkbench(
            context,
            draft,
            runWorkbench,
            signal,
            publication,
          );
        },
      });
      coordinator.start();
      const terminal = await coordinator.wait(undefined, 30_000);
      assert.equal(
        terminal?.status,
        "succeeded",
        terminal?.error ?? "seed coordinator failed",
      );
      const accepted = await store.get(run.scanId, owner);
      assert.ok(accepted.persistedWorkers);
      const omittedIds = accepted.persistedWorkers
        .filter((worker) => worker.mergeState === "buffered")
        .map((worker) => worker.id);
      assert.equal(accepted.terminalReason, saturated ? "saturated" : "capped");
      assert.equal(omittedIds.length, saturated && !lateFailure ? 1 : 0);
      assert.equal(accepted.consecutiveErrors, lateFailure ? 1 : 0);
      if (lateFailure)
        assert.equal(
          accepted.consecutiveErrors,
          accepted.config.stopAfterConsecutiveErrors,
        );
      const originalCoverage = await readJson(run.scanDir, "coverage.json");
      const originalFindings = (await readJson(run.scanDir, "findings.json"))
        .findings;
      const acceptedPaths = accepted.persistedWorkers.flatMap((worker) =>
        worker.resultManifestPath ? [worker.resultManifestPath] : [],
      );
      // Simulate artifacts accepted before the update, without resetting the
      // persisted terminal status, selected manifest, budget or coordinator lease.
      for (const file of [
        ...acceptedPaths,
        path.join(run.scanDir, "findings.json"),
      ]) {
        const draft = await readJson(file);
        for (const finding of draft.findings) delete finding.validation;
        await writeJson(file, draft);
      }
      const original = await Promise.all(
        acceptedPaths.map((file) => readFile(file, "utf8")),
      );
      const before = await store.get(run.scanId, owner);
      assert.equal(before.status, "succeeded");
      assert.equal(
        before.manifestPath,
        path.join(run.scanDir, "scan-manifest.json"),
      );
      assert.equal(before.evidenceRepairRequired, true);
      await assert.rejects(
        runWorkbench(["complete-scan", "--scan-id", run.scanId]),
        /validation/,
      );
      await assert.rejects(
        new WorkbenchDeepScanStore(runWorkbench).claimCoordinator({
          scanId: run.scanId,
          threadId: "unrelated-thread",
        }),
        /owning Codex thread/,
      );
      assert.equal((await store.get(run.scanId, owner)).status, "succeeded");

      const resumeOwner =
        route === "headless continuation" ? "continued-owner" : owner;
      let resume: () => Promise<void>;
      if (route === "cli") {
        resume = async () => {
          const child = execFileAsync(
            process.execPath,
            [serverPath, "--deep-scan-engine"],
            {
              cwd: applicationRoot,
              env,
              timeout: 30_000,
            },
          );
          child.child.stdin!.write(
            JSON.stringify({
              scanId: run.scanId,
              threadId: owner,
              model: "fixture-model",
              permissionProfile,
            }) + "\n",
          );
          const result = JSON.parse((await child).stdout);
          assert.equal(result.scanId, run.scanId);
          assert.equal(result.manifestPath, before.manifestPath);
        };
      } else {
        client = new Client({
          name: "selected-evidence-resume",
          version: "1.0.0",
        });
        const transport = new StdioClientTransport({
          command: process.execPath,
          args: [serverPath, "--stdio"],
          cwd: applicationRoot,
          env,
          stderr: "pipe",
        });
        if (transport.stderr instanceof Readable) transport.stderr.resume();
        await client.connect(transport);
        resume = async () => {
          const result = await client!.callTool({
            name: "start_codex_security_deep_scan",
            arguments:
              route === "headless continuation"
                ? { targetPath }
                : { scanId: run.scanId },
            _meta: {
              "openai/threadId": resumeOwner,
              "codex/sandbox-state-meta": { permissionProfile },
            },
          });
          assert.notEqual(result.isError, true, JSON.stringify(result));
        };
      }
      await resume();
      const repaired = await new WorkbenchDeepScanStore(runWorkbench).get(
        run.scanId,
        resumeOwner,
      );
      assert.equal(repaired.status, "succeeded");
      assert.equal(repaired.evidenceRepairRequired, undefined);
      assert.equal(repaired.terminalReason, before.terminalReason);
      assert.equal(repaired.consecutiveErrors, before.consecutiveErrors);
      assert.deepEqual(
        repaired.persistedWorkers
          ?.filter((worker) => worker.mergeState === "buffered")
          .map((worker) => worker.id),
        omittedIds,
      );
      assert.deepEqual(
        await readJson(run.scanDir, "coverage.json"),
        originalCoverage,
      );
      assert.deepEqual(
        (await readJson(run.scanDir, "findings.json")).findings.map(
          (finding: { id: string }) => finding.id,
        ),
        originalFindings.map((finding: { id: string }) => finding.id),
      );
      assert.equal(
        repaired.coordinatorGeneration,
        before.coordinatorGeneration! + 1,
      );
      assert.equal(repaired.dispatchedCount, before.dispatchedCount);
      assert.ok(repaired.persistedWorkers);
      assert.ok(before.persistedWorkers);
      assert.equal(
        repaired.persistedWorkers.length,
        before.persistedWorkers.length + 1,
      );
      assert.deepEqual(
        await Promise.all(acceptedPaths.map((file) => readFile(file, "utf8"))),
        original,
      );
      assert.ok(
        (await readJson(run.scanDir, "findings.json")).findings[0].validation,
      );
      await assert.rejects(
        runWorkbench([
          "finish-deep-scan",
          "--scan-id",
          run.scanId,
          "--terminal-reason",
          "capped",
          "--manifest-path",
          before.manifestPath,
          "--coordinator-generation",
          String(before.coordinatorGeneration),
        ]),
        /newer generation/,
      );

      // Complete unsealed results take the terminal shortcut, and sealed reports
      // retain their existing completion contract without reopening orchestration.
      await resume();
      assert.equal(
        (
          await new WorkbenchDeepScanStore(runWorkbench).get(
            run.scanId,
            resumeOwner,
          )
        ).coordinatorGeneration,
        repaired.coordinatorGeneration,
      );
      await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
      const sealed = await readFile(before.manifestPath, "utf8");
      const complete = await new WorkbenchDeepScanStore(runWorkbench).begin({
        scanId: run.scanId,
        threadId: resumeOwner,
        scanRoot: env.CODEX_SECURITY_SCAN_ROOT,
      });
      assert.equal(complete.evidenceRepairRequired, undefined);
      await assert.rejects(
        new WorkbenchDeepScanStore(runWorkbench).claimCoordinator({
          scanId: run.scanId,
          threadId: resumeOwner,
        }),
        /Only a running/,
      );
      assert.equal(await readFile(before.manifestPath, "utf8"), sealed);
    },
  );
}
