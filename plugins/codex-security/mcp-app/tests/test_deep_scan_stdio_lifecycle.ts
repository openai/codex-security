import type { PersistedDeepScanWorker } from "../src/deep-scan/types.js";
import { readJson, readJsonLines } from "./support/json.ts";
import { assertNoError, assertFlagPair } from "./assertions.ts";
import { readOnlyParentSandboxState } from "./sandbox-state.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { parse as parseToml } from "smol-toml";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  chmod,
  cp,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

import { applicationRoot as mcpAppRoot, buildServer } from "./build-server.ts";
import { startRpcServer } from "./support/rpc-server.ts";

const execFileAsync = promisify(execFile);

const installedPluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT;
const pluginRoot = installedPluginRoot
  ? path.resolve(installedPluginRoot)
  : path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
let parentSandboxState: unknown = readOnlyParentSandboxState(pluginRoot);

if (process.platform === "win32") {
  console.log(
    "deep scan stdio lifecycle test skipped on Windows (POSIX fake Codex executable)",
  );
} else {
  for (const mode of [
    "cancel-after-seal",
    "cancel-finalizer",
    "cancel-finalizer-failure",
    "late-rejoin",
    "late-rejoin-failure",
    "detached",
    "joined",
    "remote",
    "failure",
    "active-failure",
    "remote-replay",
    "snapshot-observer",
    "native-owner-usage",
    "native-detached-usage",
    "lost-response",
    "lost-response-corrupt",
    "lost-response-remove",
  ]) {
    await testDeepScanDetachedCompletion(mode);
  }
  await testDeepScanStdioLifecycle();
}

async function testDeepScanDetachedCompletion(mode: string) {
  const fixtureRoot = await temporaryDirectory("codex-security-deep-detached-");
  const targetPath = path.join(fixtureRoot, "target");
  const stateDir = path.join(fixtureRoot, "state");
  const scanRoot = path.join(fixtureRoot, "scans");
  const codexHome = path.join(fixtureRoot, "codex-home");
  const startLogPath = path.join(fixtureRoot, "started.jsonl");
  const exitLogPath = path.join(fixtureRoot, "exited.jsonl");
  const controlPath = path.join(fixtureRoot, "completion-control");
  const finalizerControlPath = path.join(fixtureRoot, "finalizer-control");
  const finalizerLogPath = path.join(fixtureRoot, "finalizer.jsonl");
  const committedControlPath = path.join(fixtureRoot, "committed-control");
  const committedLogPath = path.join(fixtureRoot, "committed.jsonl");
  const pythonWrapperPath = path.join(fixtureRoot, "python-wrapper.mjs");
  const fakeCodexPath = path.join(fixtureRoot, "fake-codex.mjs");
  const serverBundlePath = path.join(
    pluginRoot,
    "mcp",
    installedPluginRoot
      ? "server.mjs"
      : `.deep-scan-detached-${randomUUID()}.cjs`,
  );
  const threadId = "deep-scan-detached-result-conversation";
  const usageMode =
    mode === "native-owner-usage" || mode === "native-detached-usage";
  const explicitCompletion =
    mode === "active-failure" ||
    mode === "cancel-after-seal" ||
    mode.startsWith("cancel-finalizer") ||
    mode.startsWith("late-rejoin");
  const ownerRolloutPath = path.join(codexHome, "owner-rollout.jsonl");
  for (const directory of [
    targetPath,
    stateDir,
    scanRoot,
    path.join(codexHome, "codex-security"),
  ]) {
    await mkdir(directory, { recursive: true });
  }
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await writeFile(
    path.join(codexHome, "codex-security", "config.toml"),
    "[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = 1\nmax_discovery_runs = 2\n",
  );
  await writeFile(controlPath, "wait-for-completion");
  await writePythonWrapper(pythonWrapperPath);
  if (mode === "cancel-after-seal")
    await writeFile(committedControlPath, "wait");
  if (mode !== "detached" && !usageMode)
    await writeFile(
      finalizerControlPath,
      mode === "joined" ||
        mode === "remote" ||
        mode.startsWith("cancel-finalizer") ||
        mode.startsWith("late-rejoin")
        ? "wait"
        : mode === "active-failure" ||
            mode === "remote-replay" ||
            mode === "snapshot-observer"
          ? "failure"
          : mode.startsWith("lost-response")
            ? "lost-response"
            : mode,
    );
  await writeFakeCodex(fakeCodexPath);
  if (!installedPluginRoot)
    await buildServer(serverBundlePath, { target: "node20" });
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    OPENAI_API_KEY: "synthetic-stdio-key",
    CODEX_API_KEY: "",
    CODEX_CLI_PATH: fakeCodexPath,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_SECURITY_STATE_DIR: stateDir,
    FAKE_CODEX_START_LOG: startLogPath,
    FAKE_CODEX_EXIT_LOG: exitLogPath,
    FAKE_CODEX_RESTART_CONTROL: controlPath,
    PYTHON: pythonWrapperPath,
    REAL_PYTHON: process.env.PYTHON?.trim() || "python3",
    FAKE_WORKBENCH_LAUNCH_LOG: path.join(
      fixtureRoot,
      "workbench-launches.jsonl",
    ),
    FAKE_WORKBENCH_FINALIZER_CONTROL: finalizerControlPath,
    FAKE_WORKBENCH_FINALIZER_LOG: finalizerLogPath,
    FAKE_WORKBENCH_CANCEL_LOG: path.join(fixtureRoot, "cancel.jsonl"),
    FAKE_WORKBENCH_COMMITTED_CONTROL: committedControlPath,
    FAKE_WORKBENCH_COMMITTED_LOG: committedLogPath,
    FAKE_CODEX_SIGNAL_CHECKPOINT_CONTROL: path.join(
      fixtureRoot,
      "unused-signal-control",
    ),
  };
  if (usageMode) {
    environment.CODEX_SQLITE_HOME = codexHome;
    environment.CODEX_STATE_DB = "";
    await writeFile(
      ownerRolloutPath,
      [
        { type: "session_meta", payload: { id: threadId, source: "cli" } },
        {
          timestamp: new Date().toISOString(),
          type: "turn_context",
          payload: { turn_id: "native-owner-turn", model: "gpt-5.6-sol" },
        },
      ]
        .map((record) => JSON.stringify(record) + "\n")
        .join(""),
    );
    await execFileAsync(environment.REAL_PYTHON!, [
      "-c",
      `
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL)")
    connection.execute("CREATE TABLE thread_spawn_edges (parent_thread_id TEXT NOT NULL, child_thread_id TEXT NOT NULL)")
    connection.execute("INSERT INTO threads VALUES (?, ?)", (sys.argv[2], sys.argv[3]))
`,
      path.join(codexHome, "state_5.sqlite"),
      threadId,
      ownerRolloutPath,
    ]);
  }
  const server = startServer(serverBundlePath, environment);
  let remote: ReturnType<typeof startServer> | undefined;
  try {
    assertNoError(
      await server.request(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "deep-scan-detached-completion", version: "0.1.0" },
      }),
    );
    server.sendRequest(
      2,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        { targetPath, scope: ".", userContext: "Original discovery input" },
        threadId,
      ),
    );
    const scanId = await waitForScanId({ server, requestId: 2 });
    await waitForDeepScanWorker({ environment, scanId, threadId });
    const [worker] = await waitForJsonLines(startLogPath, 1);
    if (usageMode) await appendOwnerUsage(10);
    if (mode === "joined") {
      server.sendRequest(
        3,
        "tools/call",
        toolCall("start_codex_security_deep_scan", { scanId }, threadId),
      );
      await waitFor(
        () =>
          server
            .stderrEvents()
            .some((event) => event.event === "coordinator_joined"),
        "second observer to join",
      );
    }
    if (mode === "remote") {
      remote = startServer(serverBundlePath, environment);
      assertNoError(
        await remote.request(1, "initialize", {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "remote-observer", version: "0.1.0" },
        }),
      );
      remote.sendRequest(
        2,
        "tools/call",
        toolCall("start_codex_security_deep_scan", { scanId }, threadId),
      );
      await waitFor(
        () =>
          remote!
            .stderrEvents()
            .some((event) => event.event === "coordinator_joined"),
        "remote request to observe the existing owner",
      );
    }
    if (
      mode !== "active-failure" &&
      mode !== "native-owner-usage" &&
      mode !== "cancel-after-seal" &&
      !mode.startsWith("cancel-finalizer") &&
      !mode.startsWith("late-rejoin")
    )
      server.notify("notifications/cancelled", {
        requestId: 2,
        reason: "detach original observer",
      });
    const detached = await getDeepScan({ environment, scanId, threadId });
    const originalPublicScan = await runWorkbench(environment, [
      "get-scan",
      "--scan-id",
      scanId,
    ]);
    assert.equal(detached.status, "running");
    assert.equal(detached.cancelRequested, false);
    assertProcessAlive(worker.pid);
    assertProcessAlive(server.pid!);

    // The already-owned workers proceed after observation ends.
    await writeFile(controlPath, "after-restart");
    let finished: Awaited<ReturnType<typeof getDeepScan>>;
    await waitFor(async () => {
      finished = await getDeepScan({ environment, scanId, threadId });
      return finished.status === "succeeded";
    }, "detached discovery and reducer to finish");
    assert.equal(finished.workflowVersion, "deep-security-scan/v2");
    assert.equal(finished.finalizationInput.version, 1);
    assert.equal(
      finished.coordinatorGeneration,
      detached.coordinatorGeneration,
    );
    assert.equal(finished.userContext, detached.userContext);
    assert.deepEqual(finished.usageOwner, detached.usageOwner);
    assert.equal(
      finished.workers.filter(
        (row: PersistedDeepScanWorker) =>
          row.kind === "discovery" && row.status === "succeeded",
      ).length,
      2,
    );
    assert.equal(
      finished.workers.filter(
        (row: PersistedDeepScanWorker) =>
          row.kind === "dedup" && row.status === "succeeded",
      ).length,
      1,
    );
    const selectedBytes = await readFile(
      path.join(finished.scanDir, finished.finalizationInput.resultPath),
    );
    assert.equal(
      createHash("sha256").update(selectedBytes).digest("hex"),
      finished.finalizationInput.resultSha256,
    );
    if (usageMode) {
      if (mode === "native-owner-usage") {
        assertNoError(await server.waitForResponse(2));
      } else {
        await waitFor(
          async () =>
            (await runWorkbench(environment, ["get-scan", "--scan-id", scanId]))
              .scan.progress.status === "complete",
          "detached native publication",
        );
        await appendFile(
          ownerRolloutPath,
          JSON.stringify({
            timestamp: new Date().toISOString(),
            type: "turn_context",
            payload: { turn_id: "unrelated-later-turn", model: "gpt-5.6-sol" },
          }) + "\n",
        );
      }
      await appendOwnerUsage(1010);
      const completed = await server.request(
        60,
        "tools/call",
        toolCall("complete_codex_security_scan", { scanId }, threadId),
      );
      assertNoError(completed);
      const afterOwner = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      assert.equal(afterOwner.scan.progress.status, "complete");
      assert.equal(
        afterOwner.scan.usage.inputTokens,
        mode === "native-owner-usage" ? 1010 : 10,
        "completion accounts for the owning continuation, excluding later conversation work",
      );
      console.log("native owning continuation usage passed", mode, scanId);
      return;
    }
    if (explicitCompletion) {
      assertNoError(await server.waitForResponse(2));
      server.sendRequest(
        60,
        "tools/call",
        toolCall("complete_codex_security_scan", { scanId }, threadId),
      );
    }
    if (mode === "cancel-after-seal") {
      await waitForJsonLines(committedLogPath, 1);
      const beforeCancel = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      assert.equal(beforeCancel.scan.progress.status, "complete");
      const sealedBytes = await readFile(
        path.join(finished.scanDir, "scan-manifest.json"),
      );
      server.sendRequest(
        6,
        "tools/call",
        toolCall("cancel_codex_security_scan", { scanId }, threadId),
      );
      const cancellation = await server.waitForResponse(6);
      await rm(committedControlPath, { force: true });
      assertNoError(await server.waitForResponse(60));
      assert.equal(cancellation.result?.isError, true);
      const afterCancel = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      assert.equal(afterCancel.scan.progress.status, "complete");
      assert.equal(
        afterCancel.scan.executionAttribution.completedAt,
        beforeCancel.scan.executionAttribution.completedAt,
      );
      assert.deepEqual(
        await readFile(path.join(finished.scanDir, "scan-manifest.json")),
        sealedBytes,
      );
      return;
    }
    if (mode.startsWith("cancel-finalizer")) {
      await waitForJsonLines(finalizerLogPath, 1);
      server.sendRequest(
        6,
        "tools/call",
        toolCall("cancel_codex_security_scan", { scanId }, threadId),
      );
      const canceled = await server.waitForResponse(6);
      if (mode === "cancel-finalizer-failure")
        await writeFile(finalizerControlPath, "failure");
      else await rm(finalizerControlPath, { force: true });
      const ownerResponse = await server.waitForResponse(60);
      const publicScan = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      const stopped = await getDeepScan({ environment, scanId, threadId });
      assert.equal(
        publicScan.scan.progress.status,
        "canceled",
        "cancellation observed before parent completion must remain canceled",
      );
      assertNoError(canceled);
      assert.equal(ownerResponse.result?.isError, true);
      assert.match(
        ownerResponse.result.content
          .map((item: { text: string }) => item.text)
          .join(" "),
        /Only a running scan can be completed|injected complete-scan failure/,
      );
      assert.equal(stopped.status, "canceled");
      assert.deepEqual(
        await readFile(
          path.join(finished.scanDir, finished.finalizationInput.resultPath),
        ),
        selectedBytes,
      );
      assert.deepEqual(stopped.finalizationInput, finished.finalizationInput);
      assert.equal(
        publicScan.scan.continuationThreadId,
        originalPublicScan.scan.continuationThreadId,
      );
      return;
    }
    if (mode.startsWith("late-rejoin")) {
      await waitForJsonLines(finalizerLogPath, 1);
      remote = startServer(serverBundlePath, {
        ...environment,
        FAKE_WORKBENCH_FINALIZER_CONTROL: path.join(
          fixtureRoot,
          "remote-finalizer-control",
        ),
      });
      assertNoError(
        await remote.request(1, "initialize", {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "late-remote-observer", version: "0.1.0" },
        }),
      );
      remote.sendRequest(
        2,
        "tools/call",
        toolCall("start_codex_security_deep_scan", { scanId }, threadId),
      );
      const observed = await remote!.waitForResponse(2);
      const during = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      if (mode === "late-rejoin-failure")
        await writeFile(finalizerControlPath, "failure");
      else await rm(finalizerControlPath);
      const ownerResponse = await server.waitForResponse(60);
      const invocations = await readJsonLines(finalizerLogPath);
      assertNoError(observed);
      assert.equal(
        observed.result.structuredContent.manifestPath,
        path.join(finished.scanDir, "scan-manifest.json"),
      );
      assert.deepEqual(
        await readFile(
          path.join(finished.scanDir, finished.finalizationInput.resultPath),
        ),
        selectedBytes,
      );
      assert.equal(
        invocations.length,
        1,
        "late remote observation must not invoke a competing parent finalizer",
      );
      assert.equal(
        during.scan.progress.status,
        "running",
        "only the existing owner may finish pending parent completion",
      );
      if (mode === "late-rejoin-failure") {
        assert.equal(ownerResponse.result?.isError, true);
        assert.equal(
          (await runWorkbench(environment, ["get-scan", "--scan-id", scanId]))
            .scan.progress.status,
          "running",
        );
        return;
      }
      assertNoError(ownerResponse);
    }
    if (mode === "joined") {
      await waitForJsonLines(finalizerLogPath, 1);
      // Rejoin while finish-deep-scan is committed but public sealing is blocked.
      server.sendRequest(
        4,
        "tools/call",
        toolCall("start_codex_security_deep_scan", { scanId }, threadId),
      );
      await waitFor(
        () =>
          server
            .stderrEvents()
            .filter((event) => event.event === "coordinator_joined").length ===
          2,
        "observer to join pending public completion",
      );
      await delay(5_100); // Exercise an actual coordinator heartbeat during finalization.
      assert.equal(server.response(3), undefined);
      assert.equal(server.response(4), undefined);
      assert.equal(
        (await runWorkbench(environment, ["get-scan", "--scan-id", scanId]))
          .scan.progress.status,
        "running",
      );
      assert.equal((await readJsonLines(finalizerLogPath)).length, 1);
      await rm(finalizerControlPath);
      for (const id of [3, 4]) assertNoError(await server.waitForResponse(id));
    }
    if (mode === "remote") {
      // A remote observer retains the aggregate-ready response. It cannot run
      // the owning process's public finalizer, even after Deep itself succeeds.
      const observed = await remote!.waitForResponse(2);
      await waitForJsonLines(finalizerLogPath, 1);
      assertNoError(observed);
      assert.equal(
        observed.result.structuredContent.manifestPath,
        path.join(finished.scanDir, "scan-manifest.json"),
      );
      assert.equal((await readJsonLines(finalizerLogPath)).length, 1);
      await rm(finalizerControlPath);
    }
    if (
      mode === "failure" ||
      mode === "active-failure" ||
      mode === "remote-replay" ||
      mode === "snapshot-observer" ||
      mode.startsWith("lost-response")
    ) {
      if (mode !== "active-failure")
        await waitFor(
          () =>
            server
              .stderrEvents()
              .some(
                (event) => event.event === "coordinator_publication_pending",
              ),
          "public finalization failure to remain pending",
        );
      if (mode === "active-failure") {
        const failed = await server.waitForResponse(60);
        assert.equal(failed.result?.isError, true);
        const message = failed.result.content
          .map((item: { text: string }) => item.text)
          .join(" ");
        assert.match(message, /injected complete-scan failure/);
        assert.match(message, /Do not retry completion/);
        assert.match(message, /no final|Do not.*final/i);
      }
      const pending = await getDeepScan({ environment, scanId, threadId });
      assert.equal(pending.status, "succeeded");
      assert.equal(pending.terminalReason, finished.terminalReason);
      assert.deepEqual(pending.finalizationInput, finished.finalizationInput);
      assert.equal(
        (await readJsonLines(finalizerLogPath)).length,
        1,
        "the owner does not add a retry layer",
      );
      const beforeReplay = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      assert.equal(
        beforeReplay.scan.progress.status,
        !mode.startsWith("lost-response") ? "running" : "complete",
      );
      const manifestBeforeReplay = await readFile(
        path.join(finished.scanDir, "scan-manifest.json"),
      );
      if (mode === "snapshot-observer") {
        const observed = await server.request(
          50,
          "tools/call",
          toolCall(
            "start_codex_security_deep_scan",
            { targetPath, scope: ".", userContext: "Original discovery input" },
            "independent-snapshot-observer",
          ),
        );
        assertNoError(observed);
        assert.equal(observed.result.structuredContent.scanId, scanId);
        assert.equal(
          observed.result.structuredContent.manifestPath,
          path.join(finished.scanDir, "scan-manifest.json"),
        );
        assert.equal(
          (await readJsonLines(finalizerLogPath)).length,
          1,
          "a snapshot observer must not acquire publication ownership",
        );
      }
      let replayServer = server;
      if (mode === "remote-replay") {
        await server.stop();
        remote = startServer(serverBundlePath, environment);
        replayServer = remote;
        assertNoError(
          await remote.request(1, "initialize", {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "reconstructed-finalizer", version: "0.1.0" },
          }),
        );
      }
      const damagedArtifact = path.join(finished.scanDir, "findings.json");
      if (mode === "lost-response-corrupt") {
        await writeFile(
          damagedArtifact,
          Buffer.concat([await readFile(damagedArtifact), Buffer.from(" ")]),
        );
      } else if (mode === "lost-response-remove") {
        await rm(damagedArtifact);
      }
      const rejoined = await replayServer.request(
        5,
        "tools/call",
        toolCall("start_codex_security_deep_scan", { scanId }, threadId),
      );
      if (mode === "lost-response-corrupt" || mode === "lost-response-remove") {
        assert.equal(
          rejoined.result?.isError,
          true,
          "completion replay must reject altered sealed artifacts",
        );
        assert.match(
          rejoined.result.content
            .map((item: { text: string }) => item.text)
            .join(" "),
          /sealed artifact changed or is missing|findings\.json: expected a file/,
        );
        assert.deepEqual(
          await readFile(path.join(finished.scanDir, "scan-manifest.json")),
          manifestBeforeReplay,
        );
        assert.deepEqual(
          await readFile(
            path.join(finished.scanDir, finished.finalizationInput.resultPath),
          ),
          selectedBytes,
        );
        assert.equal(
          (await readJsonLines(startLogPath)).length,
          3,
          "rejected replay launches no workers",
        );
        const afterReplay = await runWorkbench(environment, [
          "get-scan",
          "--scan-id",
          scanId,
        ]);
        assert.equal(afterReplay.scan.progress.status, "complete");
        assert.equal(
          afterReplay.scan.executionAttribution.completedAt,
          beforeReplay.scan.executionAttribution.completedAt,
        );
        console.log(
          "native selected completion integrity passed",
          mode,
          scanId,
        );
        return;
      }
      assertNoError(rejoined);
      if (!mode.startsWith("lost-response"))
        assertNoError(
          await replayServer.request(
            61,
            "tools/call",
            toolCall("complete_codex_security_scan", { scanId }, threadId),
          ),
        );
      assert.equal(
        rejoined.result.structuredContent.manifestPath,
        path.join(finished.scanDir, "scan-manifest.json"),
      );
      if (mode.startsWith("lost-response")) {
        assert.deepEqual(
          await readFile(path.join(finished.scanDir, "scan-manifest.json")),
          manifestBeforeReplay,
        );
        const afterReplay = await runWorkbench(environment, [
          "get-scan",
          "--scan-id",
          scanId,
        ]);
        assert.equal(afterReplay.scan.progress.status, "complete");
        assert.equal(
          afterReplay.scan.executionAttribution.completedAt,
          beforeReplay.scan.executionAttribution.completedAt,
        );
      }
      assert.deepEqual(
        (await getDeepScan({ environment, scanId, threadId }))
          .finalizationInput,
        finished.finalizationInput,
      );
    }
    let publicScan: Awaited<ReturnType<typeof runWorkbench>>;
    await waitFor(async () => {
      publicScan = await runWorkbench(environment, [
        "get-scan",
        "--scan-id",
        scanId,
      ]);
      return publicScan.scan.progress.status === "complete";
    }, "public completion without another observer");
    assert.equal(publicScan.scan.progress.status, "complete");
    const manifest = JSON.parse(
      await readFile(path.join(finished.scanDir, "scan-manifest.json"), "utf8"),
    );
    assert.equal(typeof manifest.scan.sealedAt, "string");
    assert.equal(typeof manifest.scan.completedAt, "string");
    assert.equal(
      publicScan.scan.continuationThreadId,
      originalPublicScan.scan.continuationThreadId,
    );
    assert.deepEqual(
      publicScan.scan.executionAttribution.owner,
      originalPublicScan.scan.executionAttribution.owner,
    );
    assert.equal(publicScan.scan.executionAttribution.owner.threadId, threadId);
    assert.equal(
      (await readJsonLines(startLogPath)).length,
      3,
      "completion and replay launch no extra model workers",
    );
    assert.equal(
      (await readJsonLines(finalizerLogPath)).length,
      mode === "failure" ||
        mode === "active-failure" ||
        mode === "remote-replay" ||
        mode === "snapshot-observer"
        ? 2
        : 1,
    );
    assertProcessAlive(mode === "remote-replay" ? remote!.pid! : server.pid!);
    console.log("native selected completion passed", mode, scanId);
  } catch (error) {
    (error as Error).message += `\nMCP stderr:\n${server.stderrText()}`;
    throw error;
  } finally {
    await remote?.stop();
    await server.stop();
    if (!installedPluginRoot) await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
  async function appendOwnerUsage(inputTokens: number) {
    await appendFile(
      ownerRolloutPath,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: {
              input_tokens: inputTokens,
              cached_input_tokens: 0,
              cache_write_input_tokens: 0,
              output_tokens: 1,
              reasoning_output_tokens: 0,
              total_tokens: inputTokens + 1,
            },
          },
        },
      }) + "\n",
    );
  }
}

async function testDeepScanStdioLifecycle() {
  const fixtureRoot = await temporaryDirectory("codex-security-deep-stdio-");
  const targetPath = path.join(fixtureRoot, "target");
  const failedTargetPath = path.join(fixtureRoot, "failed-target");
  const stateDir = path.join(fixtureRoot, "state");
  const codexHome = path.join(fixtureRoot, "codex [home]");
  const fixturePluginRoot = path.join(codexHome, "plugins", "installed");
  const runtimeConfigPath = path.join(fixtureRoot, "active-config.toml");
  const startLogPath = path.join(fixtureRoot, "fake-codex-started.jsonl");
  const exitLogPath = path.join(fixtureRoot, "fake-codex-exited.jsonl");
  const restartControlPath = path.join(
    fixtureRoot,
    "fake-codex-restart-control.txt",
  );
  const signalCheckpointControlPath = path.join(
    fixtureRoot,
    "fake-codex-signal-checkpoint-control.txt",
  );
  const fakeCodexPath = path.join(fixtureRoot, "fake-codex.mjs");
  const pythonWrapperPath = path.join(fixtureRoot, "python-wrapper ");
  const cancelFailureControlPath = path.join(
    fixtureRoot,
    "fail-next-cancel-scan",
  );
  const cancelLogPath = path.join(fixtureRoot, "cancel-scan-calls.jsonl");
  const workbenchLaunchLogPath = path.join(
    fixtureRoot,
    "workbench-launches.jsonl",
  );
  const serverBundlePath = path.join(
    fixturePluginRoot,
    "mcp",
    installedPluginRoot
      ? "server.mjs"
      : `.deep-scan-stdio-test-${randomUUID()}.cjs`,
  );
  const threadId = "deep-scan-stdio-lifecycle-thread";

  await mkdir(targetPath, { recursive: true });
  await mkdir(failedTargetPath, { recursive: true });
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  for (const directory of [
    "scripts",
    "references",
    "schemas",
    ".codex-plugin",
    ...(installedPluginRoot ? ["mcp"] : []),
  ]) {
    await cp(
      path.join(pluginRoot, directory),
      path.join(fixturePluginRoot, directory),
      { recursive: true },
    );
  }
  const parentSandbox = readOnlyParentSandboxState(pluginRoot);
  parentSandboxState = {
    ...parentSandbox,
    permissionProfile: {
      ...parentSandbox.permissionProfile,
      file_system: {
        ...parentSandbox.permissionProfile.file_system,
        entries: [
          ...parentSandbox.permissionProfile.file_system.entries,
          { path: { type: "path", path: codexHome }, access: "deny" },
        ],
      },
    },
  };
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await writeFile(
    path.join(failedTargetPath, "fixture.py"),
    "print('failure fixture')\n",
  );
  await writeFile(
    path.join(codexHome, "codex-security", "config.toml"),
    `[deep_scan]
workers = 1
subagents = 0
stop_after_no_new = 1
max_discovery_runs = 2
`,
  );
  await writeFakeCodex(fakeCodexPath);
  await writeFile(
    runtimeConfigPath,
    `model_reasoning_summary = "detailed"
profile = "selected"
[profiles.selected]
model_reasoning_summary = "none"
`,
  );
  await writePythonWrapper(`${pythonWrapperPath}.mjs`);
  await symlink(`${pythonWrapperPath}.mjs`, pythonWrapperPath);
  if (!installedPluginRoot)
    await buildServer(serverBundlePath, { target: "node20" });

  const environment = {
    ...process.env,
    OPENAI_API_KEY: "synthetic-stdio-key",
    CODEX_API_KEY: "",
    CODEX_CLI_PATH: fakeCodexPath,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_CONFIG_PATH: runtimeConfigPath,
    CODEX_SECURITY_PLUGIN_ROOT: pluginRoot,
    CODEX_SECURITY_SCAN_ROOT: path.join(fixtureRoot, "scans"),
    CODEX_SECURITY_STATE_DIR: stateDir,
    PYTHON: pythonWrapperPath,
    CODEX_SECURITY_PYTHON_COMMAND: pythonWrapperPath,
    REAL_PYTHON: process.env.PYTHON?.trim() || "python3",
    FAKE_WORKBENCH_CANCEL_FAILURE_CONTROL: cancelFailureControlPath,
    FAKE_WORKBENCH_CANCEL_LOG: cancelLogPath,
    FAKE_WORKBENCH_LAUNCH_LOG: workbenchLaunchLogPath,
    FAKE_CODEX_EXIT_LOG: exitLogPath,
    FAKE_CODEX_RESTART_CONTROL: restartControlPath,
    FAKE_CODEX_SIGNAL_CHECKPOINT_CONTROL: signalCheckpointControlPath,
    FAKE_CODEX_START_LOG: startLogPath,
    FAKE_CODEX_DENIED_HOME: codexHome,
  };
  const server = startServer(serverBundlePath, environment);

  try {
    const initialized = await server.request(1, "initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "deep-scan-stdio-lifecycle", version: "0.1.0" },
    });
    assertNoError(initialized);
    assert.deepEqual(
      initialized.result.capabilities.experimental["codex/sandbox-state-meta"],
      {},
    );
    assert.deepEqual(
      initialized.result.capabilities.extensions["com.openai"],
      {},
    );
    assert.deepEqual(initialized.result.capabilities.logging, {});

    const missingParentSandbox = await server.request(
      2,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        {
          targetPath,
          scope: ".",
          userContext: "missing parent sandbox fixture",
        },
        threadId,
        undefined,
        null,
      ),
    );
    assert.equal(missingParentSandbox.result?.isError, true);
    assert.match(
      missingParentSandbox.result.content
        .map((item: { text: string }) => item.text)
        .join(" "),
      /parent.*sandbox|sandbox.*metadata|permission/i,
    );

    const unsupportedParentSandbox = await server.request(
      3,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        {
          targetPath,
          scope: ".",
          userContext: "unsupported parent sandbox fixture",
        },
        threadId,
        undefined,
        {
          permissionProfile: { type: "disabled" },
          sandboxCwd: pathToFileURL(pluginRoot).href,
        },
      ),
    );
    assert.equal(unsupportedParentSandbox.result?.isError, true);
    assert.match(
      unsupportedParentSandbox.result.content
        .map((item: { text: string }) => item.text)
        .join(" "),
      /parent.*sandbox|sandbox.*metadata|permission/i,
    );
    assert.deepEqual(await readLogLines(startLogPath), []);

    server.sendRequest(
      10,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        { targetPath, scope: ".", userContext: "stdio lifecycle fixture" },
        threadId,
        { model: "gpt-5.5", reasoning_effort: "xhigh" },
      ),
    );

    const scanId = await waitForScanId({ server });
    await waitForDeepScanWorker({ environment, scanId, threadId });
    const [startedWorker] = await waitForJsonLines(startLogPath, 1);
    assert.equal(startedWorker.hasExpectedApiKey, true);
    const workerContext = discoveryPromptContext(startedWorker.stdin);
    assert.match(startedWorker.stdin, /record_codex_security_scan_draft/);
    const startedState = await getDeepScan({ environment, scanId, threadId });
    const startedArtifactRoot = startedState.workers.find(
      (worker: PersistedDeepScanWorker) => worker.kind === "discovery",
    )?.artifactDir;
    assert.equal(typeof startedArtifactRoot, "string");
    await writeFile(
      path.join(fixturePluginRoot, "scripts", "workbench_db.py"),
      'raise RuntimeError("Installed plugin helpers replaced during another scan")\n',
    );
    assert.equal(workerContext.pluginRoot, pluginRoot);
    assert.equal(startedWorker.readCoreScanReference, true);
    assert.equal(workerContext.targetPath, await realpath(targetPath));
    assert.equal(workerContext.scope, ".");
    assert.equal(workerContext.scanId, scanId);
    for (const field of [
      "artifactDir",
      "threatModelPath",
      "inScopeFilesPath",
      "candidateLedgerPath",
    ]) {
      assert.equal(Object.hasOwn(workerContext, field), false);
    }
    await assert.rejects(
      readFile(
        path.join(
          startedArtifactRoot,
          "artifacts",
          "02_discovery",
          "in_scope_files.txt",
        ),
      ),
      { code: "ENOENT" },
    );
    assertFlagPair(startedWorker.argv, "--model", "gpt-5.5");
    assert.equal(
      startedWorker.argv.includes('model_reasoning_effort="xhigh"'),
      true,
    );
    assert.equal(
      startedWorker.argv.includes('model_reasoning_summary="none"'),
      true,
    );
    assertReadOnlyWorkerInvocation(startedWorker.argv, codexHome);
    assertWorkerArtifactEnvironment(
      startedWorker.argv,
      pluginRoot,
      pythonWrapperPath,
    );

    // Another client can replace this shared install while the scan is active.
    await writeFile(
      path.join(fixturePluginRoot, "scripts", "workbench_db.py"),
      "raise RuntimeError('synthetic replacement plugin helper')\n",
    );
    await rm(path.join(fixturePluginRoot, "references"), {
      recursive: true,
    });
    await rm(path.join(fixturePluginRoot, "schemas"), { recursive: true });

    // Discovery progress is admitted once the first complete Standard worker is active.
    const discoveryProgress = await server.request(
      15,
      "tools/call",
      toolCall(
        "update_codex_security_scan_progress",
        {
          scanId,
          phase: "discovery",
          reviewItemsTotal: 6,
          reviewItemsCompleted: 0,
        },
        threadId,
      ),
    );
    assertNoError(discoveryProgress);
    const discoveryScan = await runWorkbench(environment, [
      "get-scan",
      "--scan-id",
      scanId,
    ]);
    assert.equal(discoveryScan.scan.progress.phase, "discovery");
    assert.equal(discoveryScan.scan.progress.coverage.worklistRows, 6);

    // Stopping the original model response detaches only that long-poll waiter.
    server.notify("notifications/cancelled", {
      requestId: 10,
      reason: "detach the first Deep Scan waiter",
    });
    await delay(150);

    const stillRunning = await getDeepScan({ environment, scanId, threadId });
    assert.equal(stillRunning.status, "running");
    assert.equal(stillRunning.cancelRequested, false);
    assert.equal(
      stillRunning.workers.some(
        (worker: PersistedDeepScanWorker) => worker.kind === "setup",
      ),
      false,
    );
    assert.equal(stillRunning.workers.length, 1);
    assert.equal(stillRunning.workers[0].kind, "discovery");
    assert.equal(stillRunning.workers[0].status, "running");
    assertProcessAlive(startedWorker.pid);
    assert.equal((await readLogLines(startLogPath)).length, 1);

    // Two live calls with the persisted scanId must join the one coordinator.
    server.sendRequest(
      11,
      "tools/call",
      toolCall("start_codex_security_deep_scan", { scanId }, threadId),
    );
    server.sendRequest(
      12,
      "tools/call",
      toolCall("start_codex_security_deep_scan", { scanId }, threadId),
    );
    await waitFor(
      () =>
        server
          .stderrEvents()
          .filter(
            (event) =>
              event.event === "coordinator_joined" && event.scanId === scanId,
          ).length >= 2,
      "both scanId callers to join the coordinator",
    );
    assert.equal((await readLogLines(startLogPath)).length, 1);

    const rejectedWrongThreadCancel = await server.request(
      1312,
      "tools/call",
      toolCall("cancel_codex_security_scan", { scanId }, "another-thread"),
    );
    assert.equal(rejectedWrongThreadCancel.result?.isError, true);
    assert.match(
      rejectedWrongThreadCancel.result.content
        .map((item: { text: string }) => item.text)
        .join(" "),
      /owned by another continuation|owning Codex thread/,
    );
    assertProcessAlive(startedWorker.pid);

    await writeFile(signalCheckpointControlPath, "write-on-signal\n");
    await writeFile(cancelFailureControlPath, "fail\n");
    const failedCancel = await server.request(
      1313,
      "tools/call",
      toolCall("cancel_codex_security_scan", { scanId }, threadId),
    );
    assert.equal(failedCancel.result?.isError, true);
    assert.match(
      failedCancel.result.content
        .map((item: { text: string }) => item.text)
        .join(" "),
      /injected cancel-scan failure/,
    );
    await delay(150);
    const [failedFirstJoin, failedSecondJoin] = await Promise.all([
      server.waitForResponse(11),
      server.waitForResponse(12),
    ]);
    for (const failedJoin of [failedFirstJoin, failedSecondJoin]) {
      const failureText =
        failedJoin.result?.content
          ?.map((item: { text: string }) => item.text)
          .join(" ") ?? "";
      assert.equal(failedJoin.result?.isError, true);
      assert.equal(failedJoin.result?.structuredContent, undefined);
      assert.match(failureText, /injected cancel-scan failure/);
    }
    const stillDurablyRunning = await runWorkbench(environment, [
      "get-scan",
      "--scan-id",
      scanId,
    ]);
    assert.equal(stillDurablyRunning.scan.progress.status, "running");
    assert.equal(
      (await getDeepScan({ environment, scanId, threadId })).cancelRequested,
      false,
    );

    const cancelResponse = await server.request(
      1314,
      "tools/call",
      toolCall("cancel_codex_security_scan", { scanId }, threadId),
    );
    assertNoError(cancelResponse);
    assert.equal(
      (await readLogLines(cancelLogPath)).length,
      2,
      "each cancellation request must invoke the durable transition exactly once",
    );

    const [exitedWorker] = await waitForJsonLines(exitLogPath, 1);
    assert.equal(exitedWorker.pid, startedWorker.pid);
    assert.match(exitedWorker.signal, /^SIG(?:INT|TERM)$/);
    await waitFor(
      () =>
        server
          .stderrEvents()
          .some(
            (event) =>
              event.event === "coordinator_unhandled_error" &&
              event.scanId === scanId,
          ),
      "cancellation persistence failure to reach the coordinator",
    );
    const canceledManifest = await readJson(
      startedState.scanDir,
      "scan-manifest.json",
    );
    assert.equal(
      Object.keys(canceledManifest.scan.preservedSources ?? {}).some((source) =>
        source.endsWith(
          `deep_discovery/workers/discovery-0001/output/checkpoints/${"a".repeat(64)}.json`,
        ),
      ),
      true,
      "cancellation must retain a checkpoint committed while the worker exits",
    );
    await rm(signalCheckpointControlPath, { force: true });

    const canceledState = await getDeepScan({ environment, scanId, threadId });
    assert.equal(canceledState.status, "canceled");
    assert.equal(canceledState.cancelRequested, true);
    assert.equal(
      canceledState.workers.some(
        (worker: PersistedDeepScanWorker) => worker.kind === "setup",
      ),
      false,
    );
    assert.equal(
      canceledState.workers.every(
        (worker: PersistedDeepScanWorker) => worker.status === "canceled",
      ),
      true,
    );

    const lateJoin = await server.request(
      14,
      "tools/call",
      toolCall("start_codex_security_deep_scan", { scanId }, threadId),
    );
    assertCanceled(lateJoin, scanId, startedState.scanDir);
    assert.equal((await readLogLines(startLogPath)).length, 1);

    const failureThreadId = "deep-scan-stdio-failure-thread";
    server.sendRequest(
      20,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        {
          targetPath: failedTargetPath,
          scope: ".",
          userContext: "stdio failure fixture",
        },
        failureThreadId,
        { model: "gpt-5.6-sol", reasoning_effort: "high" },
      ),
    );
    const failedScanId = await waitForScanId({
      server,
      requestId: 20,
      excludedScanIds: [scanId],
    });
    await waitForDeepScanWorker({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId,
    });
    const startedWorkers = await waitForJsonLines(startLogPath, 2);
    const failedWorker = startedWorkers[1];
    const failedWorkerContext = discoveryPromptContext(failedWorker.stdin);
    const activeFailureState = await getDeepScan({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId,
    });
    const failedArtifactRoot = activeFailureState.workers.find(
      (worker: PersistedDeepScanWorker) => worker.kind === "discovery",
    )?.artifactDir;
    assert.equal(typeof failedArtifactRoot, "string");
    assert.equal(failedWorkerContext.pluginRoot, pluginRoot);
    assert.equal(failedWorker.readCoreScanReference, true);
    assert.equal(
      failedWorkerContext.targetPath,
      await realpath(failedTargetPath),
    );
    assert.equal(failedWorkerContext.scanId, failedScanId);
    assert.equal(Object.hasOwn(failedWorkerContext, "inScopeFilesPath"), false);
    await assert.rejects(
      readFile(
        path.join(
          failedArtifactRoot,
          "artifacts",
          "02_discovery",
          "in_scope_files.txt",
        ),
      ),
      { code: "ENOENT" },
    );
    assertFlagPair(failedWorker.argv, "--model", "gpt-5.6-sol");
    assert.equal(
      failedWorker.argv.includes('model_reasoning_effort="high"'),
      true,
    );
    assertReadOnlyWorkerInvocation(failedWorker.argv, codexHome);
    assert.equal(
      activeFailureState.workers.some(
        (worker: PersistedDeepScanWorker) => worker.kind === "setup",
      ),
      false,
    );
    assert.equal(activeFailureState.workers.length, 1);
    assert.equal(activeFailureState.workers[0].kind, "discovery");
    assert.equal(activeFailureState.workers[0].status, "running");
    assertProcessAlive(failedWorker.pid);

    const failureMessage = "fixture unrecoverable failure\0source";
    const failureResponse = await server.request(
      21,
      "tools/call",
      toolCall(
        "fail_codex_security_scan",
        { scanId: failedScanId, message: failureMessage },
        failureThreadId,
      ),
    );
    assertNoError(failureResponse);

    const failedWaiter = await server.waitForResponse(20);
    const failureText =
      failedWaiter.result?.content
        ?.map((item: { text: string }) => item.text)
        .join(" ") ?? "";
    assert.equal(failedWaiter.result?.isError, true);
    assert.equal(failedWaiter.result?.structuredContent, undefined);
    assert.match(failureText, /fixture unrecoverable failure/);
    assert.match(failureText, /no successful discovery manifest was returned/);
    const failedContext = await server.request(
      211,
      "tools/call",
      toolCall(
        "get_codex_security_scan_context",
        { scanId: failedScanId },
        failureThreadId,
      ),
    );
    assertNoError(failedContext);
    assert.equal(
      failedContext.result.structuredContent.scan.progress.status,
      "failed",
    );
    const exitedWorkers = await waitForJsonLines(exitLogPath, 2);
    assert.equal(exitedWorkers[1].pid, failedWorker.pid);
    assert.match(exitedWorkers[1].signal, /^SIG(?:INT|TERM)$/);
    await waitFor(
      () =>
        server
          .stderrEvents()
          .some(
            (event) =>
              event.event === "coordinator_cleanup_settled" &&
              event.scanId === failedScanId,
          ),
      "externally failed coordinator cleanup to settle",
    );

    const failedState = await getDeepScan({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId,
    });
    assert.equal(failedState.status, "failed");
    assert.equal(failedState.error, failureMessage);
    assert.equal(
      failedState.workers.some(
        (worker: PersistedDeepScanWorker) => worker.kind === "setup",
      ),
      false,
    );
    assert.equal(
      failedState.workers.every(
        (worker: PersistedDeepScanWorker) =>
          !["queued", "running"].includes(worker.status),
      ),
      true,
    );

    const failedLateJoin = await server.request(
      22,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        { scanId: failedScanId },
        failureThreadId,
      ),
    );
    const failedLateJoinText =
      failedLateJoin.result?.content
        ?.map((item: { text: string }) => item.text)
        .join(" ") ?? "";
    assert.equal(failedLateJoin.result?.isError, true);
    assert.equal(failedLateJoin.result?.structuredContent, undefined);
    assert.match(failedLateJoinText, /fixture unrecoverable failure/);
    assert.match(
      failedLateJoinText,
      /Do not call complete_codex_security_scan/,
    );

    const toolList = await server.request(23, "tools/list");
    assertNoError(toolList);
    assert.equal(
      toolList.result.tools.some(
        (tool: { name: string }) =>
          tool.name === "start_codex_security_deep_scan",
      ),
      true,
      "the MCP server must remain responsive after canceling one scan",
    );

    let resumedThreadId = "deep-scan-stdio-resumed-thread";
    const opened = await server.request(
      24,
      "tools/call",
      toolCall(
        "open_codex_security_workspace",
        { targetPath, scope: ".", mode: "deep" },
        resumedThreadId,
      ),
    );
    assertNoError(opened);
    const sessionId = opened.result.structuredContent.workspace.id;
    assertNoError(
      await server.request(
        25,
        "tools/call",
        toolCall(
          "submit_codex_security_setup",
          {
            sessionId,
            targetPath,
            scope: ".",
            mode: "deep",
            userContext: "Original discovery focus",
          },
          resumedThreadId,
        ),
      ),
    );
    const started = await server.request(
      26,
      "tools/call",
      toolCall("start_codex_security_scan", { sessionId }, resumedThreadId),
    );
    assertNoError(started);
    const resumedScan = started.result.structuredContent.workspace.results;
    const resumedScanId = resumedScan.scanId;
    let handoffClaimToken = randomUUID();
    for (const [id, name, arguments_] of [
      [
        27,
        "claim_codex_security_scan_handoff_delivery",
        {
          scanId: resumedScanId,
          claimToken: handoffClaimToken,
        },
      ],
      [
        28,
        "attach_codex_security_scan_continuation_thread",
        {
          scanId: resumedScanId,
          claimToken: handoffClaimToken,
          threadId: resumedThreadId,
        },
      ],
    ] as const) {
      assertNoError(
        await server.request(
          id,
          "tools/call",
          toolCall(name, arguments_, resumedThreadId),
        ),
      );
    }

    const restartStartIndex = (await readLogLines(startLogPath)).length;
    await writeFile(restartControlPath, "before-restart");
    server.sendRequest(
      29,
      "tools/call",
      toolCall(
        "start_codex_security_deep_scan",
        { scanId: resumedScanId, handoffClaimToken },
        resumedThreadId,
        { model: "gpt-5.6-sol", reasoning_effort: "high" },
      ),
    );
    let partial;
    await waitFor(async () => {
      if (
        !server
          .stderrEvents()
          .some(
            (event) =>
              event.event === "coordinator_started" &&
              event.scanId === resumedScanId,
          )
      )
        return false;
      partial = await getDeepScan({
        environment,
        scanId: resumedScanId,
        threadId: resumedThreadId,
      });
      return (
        partial.workers.some(
          (worker: PersistedDeepScanWorker) => worker.status === "succeeded",
        ) &&
        partial.workers.some(
          (worker: PersistedDeepScanWorker) => worker.status === "running",
        )
      );
    }, "one completed discovery and one interrupted discovery");
    const completedWorker = partial!.workers.find(
      (worker: PersistedDeepScanWorker) => worker.status === "succeeded",
    );
    const completedDraft = await readJson(completedWorker.resultManifestPath);
    assert.equal(completedDraft.scanId, resumedScanId);
    assert.deepEqual(completedDraft.findings, []);
    assert.equal(
      partial!.workflowVersion,
      "deep-security-scan/v2",
      "new scans use selected finalization by default",
    );
    assert.equal(partial!.userContext, "Original discovery focus");
    assert.equal(partial!.usageOwner.threadId, resumedThreadId);
    const settingsPath = path.join(
      resumedScan.scanDir,
      "artifacts",
      "deep_discovery",
      "execution-settings.json",
    );
    const originalSettings = await readFile(settingsPath, "utf8");
    assertNoError(
      await server.request(
        30,
        "tools/call",
        toolCall(
          "update_codex_security_scan_context",
          {
            scanId: resumedScanId,
            handoffClaimToken,
            userContext: "Later result discussion",
          },
          resumedThreadId,
        ),
      ),
    );
    await server.stop();
    assert.throws(
      () => process.kill(server.pid!, 0),
      "the original MCP server must have exited",
    );
    const paused = await runWorkbench(environment, [
      "get-scan",
      "--scan-id",
      resumedScanId,
    ]);
    assert.deepEqual(
      [paused.scan.progress.status, paused.scan.progress.phase],
      ["running", "discovery"],
    );
    assert.deepEqual(paused.scan.progress.independentReviews, {
      completed: 1,
      active: 0,
      maximum: 2,
      consolidating: false,
    });
    assert.deepEqual(
      [
        paused.scan.reportAvailable,
        paused.scan.findingCount,
        paused.scan.artifacts,
      ],
      [false, 0, {}],
    );
    const manifestPath = path.join(resumedScan.scanDir, "scan-manifest.json");
    await assert.rejects(readFile(manifestPath), { code: "ENOENT" });
    await rm(
      path.join(
        resumedScan.scanDir,
        "artifacts",
        "deep_discovery",
        `coordinator-heartbeat-${partial!.coordinatorGeneration}.json`,
      ),
      { force: true },
    );
    await execFileAsync(process.env.PYTHON?.trim() || "python3", [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?', ('2000-01-01T00:00:00Z',sys.argv[2])); c.commit()",
      path.join(stateDir, "workbench.sqlite3"),
      resumedScanId,
    ]);
    await runWorkbench(environment, [
      "release-handoff-delivery",
      "--scan-id",
      resumedScanId,
      "--claim-token",
      handoffClaimToken,
    ]);
    handoffClaimToken = randomUUID();
    resumedThreadId = "deep-scan-stdio-replacement-thread";
    await runWorkbench(environment, [
      "claim-handoff-delivery",
      "--scan-id",
      resumedScanId,
      "--claim-token",
      handoffClaimToken,
    ]);
    await runWorkbench(environment, [
      "attach-scan-continuation-thread",
      "--scan-id",
      resumedScanId,
      "--claim-token",
      handoffClaimToken,
      "--thread-id",
      resumedThreadId,
    ]);
    await writeFile(restartControlPath, "after-restart");
    await writeFile(
      runtimeConfigPath,
      'model_reasoning_summary = "detailed"\n',
    );

    const resumedStartIndex = (await readJsonLines(startLogPath)).length;
    const restartedServer = startServer(serverBundlePath, environment);
    try {
      assertNoError(
        await restartedServer.request(1, "initialize", {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: {
            name: "deep-scan-restarted-artifacts",
            version: "0.1.0",
          },
        }),
      );
      const resumed = await restartedServer.request(
        2,
        "tools/call",
        toolCall(
          "start_codex_security_deep_scan",
          { scanId: resumedScanId, handoffClaimToken },
          resumedThreadId,
          { model: "gpt-6.1-sol", reasoning_effort: "max" },
        ),
      );
      assertNoError(resumed);
      const modelRows = await execFileAsync(
        process.env.PYTHON?.trim() || "python3",
        [
          "-c",
          "import sqlite3,sys,json; c=sqlite3.connect(sys.argv[1]); print(json.dumps(c.execute('SELECT model, reasoning_effort FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()))",
          path.join(stateDir, "workbench.sqlite3"),
          resumedScanId,
        ],
      );
      const recordedSettings = JSON.parse(originalSettings).settings;
      assert.deepEqual(JSON.parse(modelRows.stdout), [
        recordedSettings.model,
        recordedSettings.reasoningEffort,
      ]);
      const instructions = resumed.result.structuredContent.instructions;
      assert.match(
        instructions,
        /Immediately call complete_codex_security_scan once/,
      );
      assert.match(
        instructions,
        /Return output only after completion succeeds/,
      );
      assert.match(
        instructions,
        /If completion fails, surface that exact error/,
      );
      assert.deepEqual(resumed.result.structuredContent, {
        scanId: resumedScanId,
        scanDir: resumedScan.scanDir,
        manifestPath,
        instructions,
      });
      assert.deepEqual(resumed.result.content, [
        { type: "text", text: instructions },
      ]);
      assert.equal(
        resumed.result.content.some((item: { text: string }) =>
          item.text.includes(resumedScanId),
        ),
        true,
        "the successful tool response must expose the authoritative scan ID for completion",
      );
      const finished = await getDeepScan({
        environment,
        scanId: resumedScanId,
        threadId: resumedThreadId,
      });
      assert.equal(finished.status, "succeeded");
      assert.equal(
        finished.coordinatorGeneration,
        partial!.coordinatorGeneration + 1,
      );
      assert.equal(finished.dispatchedCount, 2);
      assert.equal(finished.workflowVersion, partial!.workflowVersion);
      assert.equal(
        finished.finalizationInput.version,
        1,
        "recovery selects a persisted finalization input",
      );
      assert.equal(finished.userContext, partial!.userContext);
      assert.equal(
        finished.createdAt,
        partial!.createdAt,
        "recovery retains the original deadline origin",
      );
      assert.equal(finished.config.maxTimeHours, partial!.config.maxTimeHours);
      assert.deepEqual(
        finished.usageOwner,
        partial!.usageOwner,
        "a replacement continuation does not rebind original usage",
      );
      assert.equal(await readFile(settingsPath, "utf8"), originalSettings);
      const successfulDiscoveries = finished.workers.filter(
        (worker: PersistedDeepScanWorker) =>
          worker.kind === "discovery" && worker.status === "succeeded",
      );
      assert.equal(successfulDiscoveries.length, 2);
      assert.equal(successfulDiscoveries[0].id, completedWorker.id);
      assert.equal(
        finished.workers.some(
          (worker: PersistedDeepScanWorker) =>
            worker.kind === "dedup" && worker.status === "succeeded",
        ),
        true,
      );
      await assert.rejects(
        readFile(
          path.join(
            resumedScan.scanDir,
            "artifacts",
            "02_discovery",
            "in_scope_files.txt",
          ),
        ),
        { code: "ENOENT" },
      );
      assert.deepEqual(
        (await readJson(resumedScan.scanDir, "findings.json")).findings,
        [],
      );
      const completion = await restartedServer.request(
        3,
        "tools/call",
        toolCall(
          "complete_codex_security_scan",
          {
            scanId: resumed.result.structuredContent.scanId,
            handoffClaimToken,
          },
          resumedThreadId,
        ),
      );
      assertNoError(completion);
      const completedScan = resumed.result.structuredContent;
      const sealedManifest = await readJson(completedScan.manifestPath);
      assert.equal(sealedManifest.scan.status, "completed");
      assert.ok(sealedManifest.scan.sealedAt);
      const report = await readFile(
        path.join(completedScan.scanDir, "report.md"),
        "utf8",
      );
      assert.ok(report.length > 0);
      const helperLaunches = await readLogLines(workbenchLaunchLogPath);
      for (const command of ["get-scan", "write-scan-draft", "complete-scan"]) {
        const launches = helperLaunches.filter(
          (launch) => launch.workbenchArgs[0] === command,
        );
        assert.ok(launches.length > 0);
        for (const launch of launches) {
          assert.equal(launch.args[0], "-c");
          assert.equal(launch.args.at(-1), workbenchPath);
          assert.equal(launch.args.length, 3);
          assert.equal(launch.cwd, pluginRoot);
        }
      }
      const executions = (await readLogLines(startLogPath)).slice(
        restartStartIndex,
      );
      for (const [index, execution] of executions.entries()) {
        assertReadOnlyWorkerInvocation(execution.argv, codexHome);
        assert.equal(execution.readCoreScanReference, true);
        const context = discoveryPromptContext(execution.stdin);
        if (context.workerLabel) assert.equal(context.pluginRoot, pluginRoot);
        assertWorkerArtifactEnvironment(
          execution.argv,
          pluginRoot,
          pythonWrapperPath,
        );
        assertFlagPair(execution.argv, "--model", recordedSettings.model);
        assert.ok(
          execution.argv.includes(
            `model_reasoning_effort=${JSON.stringify(recordedSettings.reasoningEffort)}`,
          ),
        );

        assert.equal(
          execution.argv.includes('model_reasoning_summary="none"'),
          true,
        );
        if (context.workerLabel)
          assert.equal(context.userContext, "Original discovery focus");
      }
      assert.equal(
        executions.filter(
          (execution) =>
            discoveryPromptContext(execution.stdin).workerLabel ===
            "discovery-0001",
        ).length,
        1,
      );
    } finally {
      await restartedServer.stop();
    }
    await testCliDeepScanEngine({
      fixtureRoot,
      environment,
      serverBundlePath,
      codexHome,
      restartControlPath,
    });
  } catch (error) {
    (error as Error).message += `\nMCP stderr:\n${server.stderrText()}`;
    throw error;
  } finally {
    await server.stop();
    if (!installedPluginRoot) await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
    parentSandboxState = readOnlyParentSandboxState(pluginRoot);
  }
}

async function testCliDeepScanEngine({
  fixtureRoot,
  environment,
  serverBundlePath,
  codexHome,
  restartControlPath,
}: {
  fixtureRoot: string;
  environment: NodeJS.ProcessEnv;
  serverBundlePath: string;
  codexHome: string;
  restartControlPath: string;
}) {
  const canonicalRoot = await realpath(fixtureRoot);
  const repository = path.join(canonicalRoot, "cli-engine-target");
  await mkdir(repository);
  await writeFile(
    path.join(repository, "fixture.py"),
    "print('engine fixture')\n",
  );
  const threadId = "cli-engine-session";
  const register = async (name: string) => {
    const scanDir = path.join(canonicalRoot, name);
    await mkdir(scanDir, { mode: 0o700 });
    const registration = await runWorkbench(environment, [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        repository,
        mode: "deep",
        target: { kind: "repository", paths: [] },
        config: { model: "gpt-6.1-sol", model_reasoning_effort: "max" },
      }),
    ]);
    await runWorkbench(environment, [
      "set-scan-thread",
      "--scan-id",
      registration.scanId,
      "--thread-id",
      threadId,
    ]);
    return { scanId: registration.scanId as string, scanDir };
  };
  const launch = (scanId: string, overrides: NodeJS.ProcessEnv = {}) => {
    const execution = execFileAsync(
      process.execPath,
      [serverBundlePath, "--deep-scan-engine"],
      {
        env: { ...environment, ...overrides },
        encoding: "utf8",
        timeout: 30_000,
      },
    );
    execution.child.stdin!.write(
      JSON.stringify({
        scanId,
        threadId,
        model: "gpt-6.1-sol",
        reasoningEffort: "max",
        permissionProfile: (
          parentSandboxState as { permissionProfile: unknown }
        ).permissionProfile,
      }) + "\n",
    );
    return execution;
  };
  const completed = await register("cli-engine-completed");
  const startIndex = (await readLogLines(environment.FAKE_CODEX_START_LOG!))
    .length;
  const helperStartIndex = (
    await readLogLines(environment.FAKE_WORKBENCH_LAUNCH_LOG!)
  ).length;
  const result = await launch(completed.scanId);
  const helperLaunches = (
    await readLogLines(environment.FAKE_WORKBENCH_LAUNCH_LOG!)
  ).slice(helperStartIndex);
  assert.ok(helperLaunches.length > 0);
  for (const launch of helperLaunches) {
    assert.deepEqual(launch.args.slice(0, 5), ["-I", "-X", "utf8", "-B", "-c"]);
    assert.equal(launch.args.at(-1), workbenchPath);
    assert.equal(launch.args.length, 7);
    assert.equal(launch.cwd, pluginRoot);
  }
  assert.deepEqual(JSON.parse(result.stdout), {
    scanId: completed.scanId,
    manifestPath: path.join(completed.scanDir, "scan-manifest.json"),
  });
  const starts = (await readLogLines(environment.FAKE_CODEX_START_LOG!)).slice(
    startIndex,
  );
  assert.ok(
    starts.some((entry) => discoveryPromptContext(entry.stdin).workerLabel),
  );
  assert.ok(
    starts.some(
      (entry) => discoveryPromptContext(entry.stdin).claimedWorkerIds,
    ),
  );
  for (const entry of starts) {
    assertReadOnlyWorkerInvocation(entry.argv, codexHome);
    assertFlagPair(entry.argv, "--model", "gpt-6.1-sol");
    assert.ok(entry.argv.includes('model_reasoning_effort="max"'));
    assert.equal(entry.hasExpectedApiKey, true);
  }
  const count = (await readLogLines(environment.FAKE_CODEX_START_LOG!)).length;
  await launch(completed.scanId);
  assert.equal(
    (await readLogLines(environment.FAKE_CODEX_START_LOG!)).length,
    count,
  );
  await runWorkbench(environment, [
    "complete-scan",
    "--scan-id",
    completed.scanId,
  ]);
  const manifest = await readJson(
    path.join(completed.scanDir, "scan-manifest.json"),
  );
  assert.equal(manifest.scan.status, "completed");
  assert.ok(manifest.scan.sealedAt);
  assert.ok(
    (await readFile(path.join(completed.scanDir, "report.md"), "utf8")).length >
      0,
  );

  await rm(restartControlPath);
  const canceled = await register("cli-engine-canceled");
  const execution = launch(canceled.scanId);
  const outcome = execution.then(
    () => undefined,
    (error) => error,
  );
  try {
    await waitForJsonLines(environment.FAKE_CODEX_START_LOG!, count + 1);
    await waitForDeepScanWorker({
      environment,
      scanId: canceled.scanId,
      threadId,
    });
    const running = (
      await readLogLines(environment.FAKE_CODEX_START_LOG!)
    ).slice(count);
    assert.ok(running.length > 0);
    const observerLog = path.join(
      canonicalRoot,
      "cli-observer-workbench.jsonl",
    );
    const observer = launch(canceled.scanId, {
      FAKE_WORKBENCH_LAUNCH_LOG: observerLog,
    });
    const observerOutcome = observer.then(
      () => undefined,
      (error) => error,
    );
    try {
      await waitFor(
        async () =>
          (await readLogLines(observerLog)).some(
            (entry) => entry.workbenchArgs[0] === "get-deep-scan",
          ),
        "second CLI engine to observe the active coordinator",
      );
      observer.child.stdin!.end();
      const error = await observerOutcome;
      assert.ok(error);
      assert.equal(error.killed, false);
      for (const worker of running) assertProcessAlive(worker.pid);
      assert.equal(
        (await readLogLines(environment.FAKE_CODEX_START_LOG!)).length,
        count + running.length,
      );
    } finally {
      if (
        observer.child.exitCode === null &&
        observer.child.signalCode === null
      )
        observer.child.kill("SIGKILL");
      await observerOutcome;
    }
    execution.child.stdin!.end();
    assert.ok(await outcome);
    for (const worker of running) {
      assert.throws(() => process.kill(worker.pid, 0), /ESRCH/);
    }
    const saved = await getDeepScan({
      environment,
      scanId: canceled.scanId,
      threadId,
    });
    assert.notEqual(saved.status, "succeeded");
    assert.equal(
      saved.workers.filter(
        (worker: PersistedDeepScanWorker) => worker.status === "running",
      ).length,
      0,
    );
  } finally {
    if (
      execution.child.exitCode === null &&
      execution.child.signalCode === null
    )
      execution.child.kill("SIGKILL");
    await outcome;
  }
}

function startServer(serverPath: string, env: NodeJS.ProcessEnv) {
  return startRpcServer(
    {
      command: process.execPath,
      args: [serverPath, "--stdio"],
      cwd: pluginRoot,
      env: env,
      stderr: "pipe",
    },
    { component: "codex_security_deep_scan", timeoutMs: 15_000 },
  );
}

function toolCall(
  name: string,
  args: Record<string, unknown>,
  threadId: string,
  turnMetadata?: { model: string; reasoning_effort: string },
  sandboxState: unknown = parentSandboxState,
) {
  return {
    name,
    arguments: args,
    _meta: {
      "openai/threadId": threadId,
      ...(sandboxState ? { "codex/sandbox-state-meta": sandboxState } : {}),
      ...(turnMetadata ? { "x-codex-turn-metadata": turnMetadata } : {}),
    },
  };
}

function assertWorkerArtifactEnvironment(
  args: string[],
  expectedPluginRoot: string,
  expectedPython: string,
) {
  const override = args.find((value) => value.startsWith("mcp_servers="));
  assert.ok(override);
  const env = JSON.parse(JSON.stringify(parseToml(override))).mcp_servers
    .cs_artifacts.env;
  assert.equal(env.CODEX_SECURITY_PLUGIN_ROOT, expectedPluginRoot);
  assert.equal(env.CODEX_SECURITY_PYTHON_COMMAND, expectedPython);
}

function assertReadOnlyWorkerInvocation(args: string[], deniedHome: string) {
  assert.equal(args.includes("--sandbox"), false);
  assert.equal(args.includes("--add-dir"), false);
  assert.equal(
    args.includes("--dangerously-bypass-approvals-and-sandbox"),
    false,
  );
  assert.deepEqual(
    args.filter((arg) => arg.startsWith("approval_policy=")),
    ['approval_policy="never"'],
  );
  assert.equal(
    args.some((arg) =>
      /^sandbox_workspace_write\.network_access\s*=\s*true$/.test(arg),
    ),
    false,
  );
  assert.equal(
    args.includes('default_permissions="codex_security_deep_scan_worker"'),
    true,
  );
  const overrides = args.filter((arg) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker="),
  );
  assert.deepEqual(
    overrides.map((value) => parseToml(value)),
    [
      parseToml(
        `permissions.codex_security_deep_scan_worker={extends=":read-only",filesystem={":root"="read",${JSON.stringify(deniedHome)}={"."="deny"}},network={enabled=false}}`,
      ),
    ],
  );
}

async function waitForScanId({
  server,
  requestId = 10,
  excludedScanIds = [],
}: {
  server: ReturnType<typeof startServer>;
  requestId?: number;
  excludedScanIds?: string[];
}): Promise<string> {
  let scanId!: string;
  const excluded = new Set(excludedScanIds);
  await waitFor(async () => {
    const startResponse = server.response(requestId);
    if (startResponse) {
      throw new Error(
        `Target-based Deep Scan start returned early: ${JSON.stringify(startResponse)}`,
      );
    }
    const coordinatorStarted = server
      .stderrEvents()
      .find(
        (event) =>
          event.event === "coordinator_started" && !excluded.has(event.scanId),
      );
    scanId = coordinatorStarted?.scanId!;
    return typeof scanId === "string";
  }, "target-based Deep Scan bootstrap");
  return scanId;
}

async function getDeepScan({
  environment,
  scanId,
  threadId,
}: {
  environment: NodeJS.ProcessEnv;
  scanId: string;
  threadId: string;
}) {
  const result = await runWorkbench(environment, [
    "get-deep-scan",
    "--scan-id",
    scanId,
    "--thread-id",
    threadId,
  ]);
  return result.deepScan;
}

async function waitForDeepScanWorker(input: Parameters<typeof getDeepScan>[0]) {
  await waitFor(async () => {
    const deepScan = await getDeepScan(input);
    const worker = deepScan.workers.find(
      (candidate: PersistedDeepScanWorker) =>
        candidate.kind === "discovery" && candidate.status === "running",
    );
    return worker !== undefined;
  }, "active Standard scan worker");
}

function discoveryPromptContext(prompt: string) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/u);
  assert.ok(
    match,
    "the discovery worker must receive its typed Standard artifact context",
  );
  return JSON.parse(match[1]);
}

async function runWorkbench(environment: NodeJS.ProcessEnv, args: string[]) {
  const python = process.env.PYTHON?.trim() || "python3";
  const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
    cwd: pluginRoot,
    env: environment,
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000,
  });
  return JSON.parse(stdout);
}

async function writeFakeCodex(executablePath: string) {
  await writeFile(
    executablePath,
    `#!/usr/bin/env node
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parse as parseToml } from ${JSON.stringify(import.meta.resolve("smol-toml"))};
if (process.argv.includes('app-server')) {
  const permissionOverride = process.argv.find((arg) => arg.startsWith("permissions.") && parseToml(arg).permissions?.codex_security_deep_scan_worker);
  const effectiveProfile = parseToml(permissionOverride).permissions.codex_security_deep_scan_worker;
  let buffer = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buffer += chunk;
    while (true) {
      const newline = buffer.indexOf('\\n');
      if (newline < 0) return;
      const line = buffer.slice(0, newline).trim();
      buffer = buffer.slice(newline + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      if (message.method === 'initialized') continue;
      let result;
      if (message.method === 'initialize') {
        result = { userAgent: 'fixture', codexHome: '/fixture', platformFamily: 'unix', platformOs: 'macos' };
      } else if (message.method === 'config/read') {
        result = { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: effectiveProfile } }, origins: {}, layers: null };
      } else if (message.method === 'permissionProfile/list') {
        result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: true }], nextCursor: null };
      } else if (message.method === 'account/read') {
        result = { account: null, requiresOpenaiAuth: true };
      } else {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }) + '\\n');
        continue;
      }
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');
    }
  });
  process.stdin.on('end', () => process.exit(0));
} else {
const stdin = (await process.stdin.toArray()).join('');
const context = JSON.parse(stdin.match(/\`\`\`json\\n([\\s\\S]*?)\\n\`\`\`/u)[1]);
const root = process.argv[process.argv.indexOf('--cd') + 1];
const readCoreScanReference = !context.workerLabel || readFileSync(path.join(context.pluginRoot, 'references', 'core-scan.md'), 'utf8').length > 0;
appendFileSync(process.env.FAKE_CODEX_START_LOG, JSON.stringify({ pid: process.pid, argv: process.argv.slice(2), stdin, readCoreScanReference, hasExpectedApiKey: process.env.CODEX_API_KEY === 'synthetic-stdio-key' }) + '\\n');
console.log(JSON.stringify({ type: 'thread.started', thread_id: \`stdio-fixture-\${process.pid}\` }));
while (existsSync(process.env.FAKE_CODEX_RESTART_CONTROL) && readFileSync(process.env.FAKE_CODEX_RESTART_CONTROL, 'utf8') === 'wait-for-completion') {
  await new Promise((resolve) => setTimeout(resolve, 25));
}
if (existsSync(process.env.FAKE_CODEX_RESTART_CONTROL)) {
  const phase = readFileSync(process.env.FAKE_CODEX_RESTART_CONTROL, 'utf8');
  if (phase === 'after-restart' || context.workerLabel === 'discovery-0001') {
    const coverage = { completeness: 'complete', surfaces: [], explicitExclusions: [], deferred: [] };
    if (context.claimedWorkerIds) {
      const output = path.join(root, 'deep_discovery', 'dedup', context.reducerLabel, 'output');
      const firstResult = JSON.parse(readFileSync(path.join(root, 'deep_discovery', 'workers', 'discovery-0001', 'output', 'result.json'), 'utf8'));
      writeFileSync(path.join(output, 'result.json'), JSON.stringify({ scanId: firstResult.scanId, findings: [], coverage }));
    } else {
      writeFileSync(path.join(root, 'result.json'), JSON.stringify({ scanId: context.scanId, findings: [], coverage }));
    }
    console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture completed' } }));
    console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
    process.exit(0);
  }
}
setInterval(() => {}, 1_000);
const stop = (signal) => {
  if (existsSync(process.env.FAKE_CODEX_SIGNAL_CHECKPOINT_CONTROL)) {
    const coverage = { completeness: 'complete', surfaces: [], explicitExclusions: [], deferred: [] };
    const checkpointDir = path.join(root, 'checkpoints');
    mkdirSync(checkpointDir, { recursive: true });
    writeFileSync(path.join(checkpointDir, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'), JSON.stringify({ scanId: context.scanId, findings: [], coverage }));
  }
  appendFileSync(process.env.FAKE_CODEX_EXIT_LOG, JSON.stringify({ pid: process.pid, signal }) + '\\n');
  process.exit(0);
};
process.once('SIGINT', () => stop('SIGINT'));
process.once('SIGTERM', () => stop('SIGTERM'));
}
`,
  );
  await chmod(executablePath, 0o755);
}

async function writePythonWrapper(executablePath: string) {
  await writeFile(
    executablePath,
    [
      "#!/usr/bin/env node",
      'import { appendFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";',
      'import { spawnSync } from "node:child_process";',
      "const args = process.argv.slice(2);",
      "const input = Buffer.concat(await process.stdin.toArray());",
      "const codeIndex = args.indexOf('-c');",
      "const framed = codeIndex !== -1 && args[codeIndex + 1].includes('json.loads(sys.stdin.buffer.readline())');",
      "const workbenchArgs = framed ? JSON.parse(input.subarray(0, input.indexOf(10)).toString('utf8')) : args.slice(1);",
      "appendFileSync(process.env.FAKE_WORKBENCH_LAUNCH_LOG, JSON.stringify({ args, workbenchArgs, cwd: process.cwd() }) + '\\n');",
      "const control = process.env.FAKE_WORKBENCH_CANCEL_FAILURE_CONTROL;",
      "if (workbenchArgs[0] === 'cancel-scan') {",
      "  appendFileSync(process.env.FAKE_WORKBENCH_CANCEL_LOG, JSON.stringify(args) + '\\n');",
      "}",
      "if (workbenchArgs[0] === 'cancel-scan' && control && existsSync(control)) {",
      "  unlinkSync(control);",
      "  console.error('injected cancel-scan failure');",
      "  process.exit(1);",
      "}",
      "let finalizerMode;",
      "if (workbenchArgs[0] === 'complete-scan' && process.env.FAKE_WORKBENCH_FINALIZER_LOG) {",
      "  appendFileSync(process.env.FAKE_WORKBENCH_FINALIZER_LOG, JSON.stringify(args) + '\\n');",
      "  const finalizerControl = process.env.FAKE_WORKBENCH_FINALIZER_CONTROL;",
      "  const readFinalizerControl = () => {",
      "    try { return readFileSync(finalizerControl, 'utf8'); }",
      "    catch (error) { if (error.code !== 'ENOENT') throw error; }",
      "  };",
      "  while ((finalizerMode = readFinalizerControl()) === 'wait') {",
      "    await new Promise((resolve) => setTimeout(resolve, 25));",
      "  }",
      "  if (finalizerMode !== undefined) {",
      "    unlinkSync(finalizerControl);",
      "  }",
      "  if (finalizerMode === 'failure') { console.error('injected complete-scan failure'); process.exit(1); }",
      "}",
      "const result = spawnSync(process.env.REAL_PYTHON || 'python3', args, { input, stdio: ['pipe', 'inherit', 'inherit'] });",
      "const committedControl = process.env.FAKE_WORKBENCH_COMMITTED_CONTROL;",
      "if (workbenchArgs[0] === 'complete-scan' && result.status === 0 && committedControl && existsSync(committedControl)) {",
      "  appendFileSync(process.env.FAKE_WORKBENCH_COMMITTED_LOG, JSON.stringify({ pid: process.pid, committed: true }) + '\\n');",
      "  while (existsSync(committedControl)) await new Promise((resolve) => setTimeout(resolve, 25));",
      "}",
      "if (result.error) throw result.error;",
      "if (result.status === 0 && finalizerMode === 'lost-response') { console.error('injected lost completion response'); process.exit(1); }",
      "process.exit(result.status ?? 1);",
      "",
    ].join("\n"),
  );
  await chmod(executablePath, 0o755);
}

function assertCanceled(
  response: Awaited<ReturnType<ReturnType<typeof startServer>["request"]>>,
  scanId: string,
  scanDir: string,
) {
  assertNoError(response);
  const instructions = response.result.structuredContent.instructions;
  assert.match(
    instructions,
    /Saved findings and pending candidates remain available/,
  );
  assert.match(
    instructions,
    /Do not start additional scan work or claim complete coverage/,
  );
  assert.deepEqual(response.result.structuredContent, {
    status: "canceled",
    scanId,
    scanDir,
    instructions,
  });
  assert.deepEqual(response.result.content, [
    { type: "text", text: instructions },
  ]);
}

function assertProcessAlive(pid: number) {
  assert.doesNotThrow(
    () => process.kill(pid, 0),
    `expected fake Codex process ${pid} to remain alive`,
  );
}

async function waitForJsonLines(filePath: string, count: number) {
  let lines: Awaited<ReturnType<typeof readLogLines>> = [];
  await waitFor(
    async () => {
      lines = await readLogLines(filePath);
      return lines.length >= count;
    },
    `${count} record(s) in ${path.basename(filePath)}`,
  );
  return lines;
}

function readLogLines(filePath: string) {
  return readJsonLines(filePath).catch((error) => {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw error;
  });
}

async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  label: string,
) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(25);
  }
  throw new Error(`Timed out waiting for ${label}.`);
}
