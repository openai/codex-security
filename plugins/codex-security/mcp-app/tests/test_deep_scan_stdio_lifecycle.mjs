import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const execFileAsync = promisify(execFile);
const mcpAppRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pluginRoot = path.resolve(mcpAppRoot, "..");
const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
const parentSandboxState = {
  permissionProfile: {
    type: "managed",
    file_system: {
      type: "restricted",
      entries: [{
        path: { type: "special", value: { kind: "root" } },
        access: "read"
      }]
    },
    network: "restricted"
  },
  sandboxCwd: pathToFileURL(pluginRoot).href
};

if (process.platform === "win32") {
  console.log("deep scan stdio lifecycle test skipped on Windows (POSIX fake Codex executable)");
} else {
  await testDeepScanStdioLifecycle();
}

async function testDeepScanStdioLifecycle() {
  const fixtureRoot = await mkdtemp(path.join(tmpdir(), "codex-security-deep-stdio-"));
  const targetPath = path.join(fixtureRoot, "target");
  const failedTargetPath = path.join(fixtureRoot, "failed-target");
  const stateDir = path.join(fixtureRoot, "state");
  const scanRoot = path.join(fixtureRoot, "scans");
  const codexHome = path.join(fixtureRoot, "codex-home");
  const startLogPath = path.join(fixtureRoot, "fake-codex-started.jsonl");
  const exitLogPath = path.join(fixtureRoot, "fake-codex-exited.jsonl");
  const restartControlPath = path.join(fixtureRoot, "fake-codex-restart-control.txt");
  const signalCheckpointControlPath = path.join(
    fixtureRoot,
    "fake-codex-signal-checkpoint-control.txt"
  );
  const fakeCodexPath = path.join(fixtureRoot, "fake-codex.mjs");
  const pythonWrapperPath = path.join(fixtureRoot, "python-wrapper.mjs");
  const cancelFailureControlPath = path.join(fixtureRoot, "fail-next-cancel-scan");
  const cancelLogPath = path.join(fixtureRoot, "cancel-scan-calls.jsonl");
  const serverBundlePath = path.join(
    pluginRoot,
    "mcp",
    `.deep-scan-stdio-test-${randomUUID()}.cjs`
  );
  const threadId = "deep-scan-stdio-lifecycle-thread";

  await mkdir(targetPath, { recursive: true });
  await mkdir(failedTargetPath, { recursive: true });
  await mkdir(stateDir, { recursive: true });
  await mkdir(scanRoot, { recursive: true });
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  await writeFile(path.join(targetPath, "fixture.py"), "print('fixture')\n");
  await writeFile(path.join(failedTargetPath, "fixture.py"), "print('failure fixture')\n");
  await writeFile(
    path.join(codexHome, "codex-security", "config.toml"),
    [
      "[deep_scan]",
      "workers = 1",
      "subagents = 0",
      "stop_after_no_new = 1",
      "max_discovery_runs = 2",
      ""
    ].join("\n")
  );
  await writeFakeCodex(fakeCodexPath);
  await writePythonWrapper(pythonWrapperPath);
  await bundleServer(serverBundlePath);

  const environment = {
    ...process.env,
    CODEX_CLI_PATH: fakeCodexPath,
    CODEX_HOME: codexHome,
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_SECURITY_STATE_DIR: stateDir,
    PYTHON: pythonWrapperPath,
    REAL_PYTHON: process.env.PYTHON?.trim() || "python3",
    FAKE_WORKBENCH_CANCEL_FAILURE_CONTROL: cancelFailureControlPath,
    FAKE_WORKBENCH_CANCEL_LOG: cancelLogPath,
    FAKE_CODEX_EXIT_LOG: exitLogPath,
    FAKE_CODEX_RESTART_CONTROL: restartControlPath,
    FAKE_CODEX_SIGNAL_CHECKPOINT_CONTROL: signalCheckpointControlPath,
    FAKE_CODEX_START_LOG: startLogPath
  };
  const server = startServer(serverBundlePath, environment);

  try {
    const initialized = await server.request(1, "initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "deep-scan-stdio-lifecycle", version: "0.1.0" }
    });
    assertNoError(initialized);
    assert.deepEqual(
      initialized.result.capabilities.experimental["codex/sandbox-state-meta"],
      {}
    );
    assert.deepEqual(initialized.result.capabilities.extensions["com.openai"], {});
    assert.deepEqual(initialized.result.capabilities.logging, {});

    const missingParentSandbox = await server.request(2, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { targetPath, scope: ".", userContext: "missing parent sandbox fixture" },
      threadId,
      undefined,
      null
    ));
    assert.equal(missingParentSandbox.result?.isError, true);
    assert.match(
      missingParentSandbox.result.content.map((item) => item.text).join(" "),
      /parent.*sandbox|sandbox.*metadata|permission/i
    );

    const unsupportedParentSandbox = await server.request(3, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { targetPath, scope: ".", userContext: "unsupported parent sandbox fixture" },
      threadId,
      undefined,
      {
        permissionProfile: { type: "disabled" },
        sandboxCwd: pathToFileURL(pluginRoot).href
      }
    ));
    assert.equal(unsupportedParentSandbox.result?.isError, true);
    assert.match(
      unsupportedParentSandbox.result.content.map((item) => item.text).join(" "),
      /parent.*sandbox|sandbox.*metadata|permission/i
    );
    assert.deepEqual(await readJsonLines(startLogPath), []);

    server.sendRequest(10, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { targetPath, scope: ".", userContext: "stdio lifecycle fixture" },
      threadId,
      { model: "gpt-5.5", reasoning_effort: "xhigh" }
    ));

    const scanId = await waitForScanId({ server });
    await waitForDeepScanWorker({ environment, scanId, threadId });
    const [startedWorker] = await waitForJsonLines(startLogPath, 1);
    const workerContext = discoveryPromptContext(startedWorker.stdin);
    assert.match(startedWorker.stdin, /record_codex_security_scan_draft/);
    const startedState = await getDeepScan({ environment, scanId, threadId });
    const startedArtifactRoot = startedState.workers
      .find((worker) => worker.kind === "discovery")?.artifactDir;
    assert.equal(typeof startedArtifactRoot, "string");
    assert.equal(workerContext.pluginRoot, pluginRoot);
    assert.equal(workerContext.targetPath, await realpath(targetPath));
    assert.equal(workerContext.scope, ".");
    assert.equal(workerContext.scanId, scanId);
    for (const field of [
      "artifactDir",
      "threatModelPath",
      "inScopeFilesPath",
      "candidateLedgerPath"
    ]) {
      assert.equal(Object.hasOwn(workerContext, field), false);
    }
    await assert.rejects(readFile(path.join(
      startedArtifactRoot,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt"
    )), { code: "ENOENT" });
    assertFlagPair(startedWorker.argv, "--model", "gpt-5.5");
    assert.equal(startedWorker.argv.includes('model_reasoning_effort="xhigh"'), true);
    assertReadOnlyWorkerInvocation(startedWorker.argv);

    // Discovery progress is admitted once the first complete Standard worker is active.
    const discoveryProgress = await server.request(15, "tools/call", toolCall(
      "update_codex_security_scan_progress",
      { scanId, phase: "discovery", reviewItemsTotal: 6, reviewItemsCompleted: 0 },
      threadId
    ));
    assertNoError(discoveryProgress);
    const discoveryScan = await runWorkbench(environment, ["get-scan", "--scan-id", scanId]);
    assert.equal(discoveryScan.scan.progress.phase, "discovery");
    assert.equal(discoveryScan.scan.progress.coverage.worklistRows, 6);

    // Stopping the original model response detaches only that long-poll waiter.
    server.notify("notifications/cancelled", {
      requestId: 10,
      reason: "detach the first Deep Scan waiter"
    });
    await delay(150);

    const stillRunning = await getDeepScan({ environment, scanId, threadId });
    assert.equal(stillRunning.status, "running");
    assert.equal(stillRunning.cancelRequested, false);
    assert.equal(stillRunning.workers.some((worker) => worker.kind === "setup"), false);
    assert.equal(stillRunning.workers.length, 1);
    assert.equal(stillRunning.workers[0].kind, "discovery");
    assert.equal(stillRunning.workers[0].status, "running");
    assertProcessAlive(startedWorker.pid);
    assert.equal((await readJsonLines(startLogPath)).length, 1);

    // Two live calls with the persisted scanId must join the one coordinator.
    server.sendRequest(11, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { scanId },
      threadId
    ));
    server.sendRequest(12, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { scanId },
      threadId
    ));
    await waitFor(() => server.stderrEvents().filter((event) => (
      event.event === "coordinator_joined" && event.scanId === scanId
    )).length >= 2, "both scanId callers to join the coordinator");
    assert.equal((await readJsonLines(startLogPath)).length, 1);

    const rejectedWrongThreadCancel = await server.request(1312, "tools/call", toolCall(
      "cancel_codex_security_scan",
      { scanId },
      "another-thread"
    ));
    assert.equal(rejectedWrongThreadCancel.result?.isError, true);
    assert.match(
      rejectedWrongThreadCancel.result.content.map((item) => item.text).join(" "),
      /owned by another continuation|owning Codex thread/
    );
    assertProcessAlive(startedWorker.pid);

    await writeFile(signalCheckpointControlPath, "write-on-signal\n");
    await writeFile(cancelFailureControlPath, "fail\n");
    const failedCancel = await server.request(1313, "tools/call", toolCall(
      "cancel_codex_security_scan",
      { scanId },
      threadId
    ));
    assert.equal(failedCancel.result?.isError, true);
    assert.match(
      failedCancel.result.content.map((item) => item.text).join(" "),
      /injected cancel-scan failure/
    );
    await delay(150);
    const [failedFirstJoin, failedSecondJoin] = await Promise.all([
      server.waitForResponse(11),
      server.waitForResponse(12)
    ]);
    for (const failedJoin of [failedFirstJoin, failedSecondJoin]) {
      const failureText = failedJoin.result?.content?.map((item) => item.text).join(" ") ?? "";
      assert.equal(failedJoin.result?.isError, true);
      assert.equal(failedJoin.result?.structuredContent, undefined);
      assert.match(failureText, /injected cancel-scan failure/);
    }
    const stillDurablyRunning = await runWorkbench(environment, [
      "get-scan", "--scan-id", scanId
    ]);
    assert.equal(stillDurablyRunning.scan.progress.status, "running");
    assert.equal((await getDeepScan({ environment, scanId, threadId })).cancelRequested, false);

    const cancelResponse = await server.request(1314, "tools/call", toolCall(
      "cancel_codex_security_scan",
      { scanId },
      threadId
    ));
    assertNoError(cancelResponse);
    assert.equal(
      (await readJsonLines(cancelLogPath)).length,
      2,
      "each cancellation request must invoke the durable transition exactly once",
    );

    const [exitedWorker] = await waitForJsonLines(exitLogPath, 1);
    assert.equal(exitedWorker.pid, startedWorker.pid);
    assert.match(exitedWorker.signal, /^SIG(?:INT|TERM)$/);
    await waitFor(() => server.stderrEvents().some((event) => (
      event.event === "coordinator_unhandled_error" && event.scanId === scanId
    )), "cancellation persistence failure to reach the coordinator");
    const canceledManifest = JSON.parse(await readFile(path.join(
      startedState.scanDir,
      "scan-manifest.json"
    ), "utf8"));
    assert.equal(
      Object.keys(canceledManifest.scan.preservedSources ?? {}).some((source) => (
        source.endsWith(`deep_discovery/workers/discovery-0001/output/checkpoints/${"a".repeat(64)}.json`)
      )),
      true,
      "cancellation must retain a checkpoint committed while the worker exits"
    );
    await rm(signalCheckpointControlPath, { force: true });

    const canceledState = await getDeepScan({ environment, scanId, threadId });
    assert.equal(canceledState.status, "canceled");
    assert.equal(canceledState.cancelRequested, true);
    assert.equal(canceledState.workers.some((worker) => worker.kind === "setup"), false);
    assert.equal(canceledState.workers.every((worker) => worker.status === "canceled"), true);

    const lateJoin = await server.request(14, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { scanId },
      threadId
    ));
    assertCanceled(lateJoin, scanId);
    assert.equal((await readJsonLines(startLogPath)).length, 1);

    const failureThreadId = "deep-scan-stdio-failure-thread";
    server.sendRequest(20, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { targetPath: failedTargetPath, scope: ".", userContext: "stdio failure fixture" },
      failureThreadId,
      { model: "gpt-5.6-sol", reasoning_effort: "high" }
    ));
    const failedScanId = await waitForScanId({
      server,
      requestId: 20,
      excludedScanIds: [scanId]
    });
    await waitForDeepScanWorker({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId
    });
    const startedWorkers = await waitForJsonLines(startLogPath, 2);
    const failedWorker = startedWorkers[1];
    const failedWorkerContext = discoveryPromptContext(failedWorker.stdin);
    const activeFailureState = await getDeepScan({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId
    });
    const failedArtifactRoot = activeFailureState.workers
      .find((worker) => worker.kind === "discovery")?.artifactDir;
    assert.equal(typeof failedArtifactRoot, "string");
    assert.equal(failedWorkerContext.pluginRoot, pluginRoot);
    assert.equal(failedWorkerContext.targetPath, await realpath(failedTargetPath));
    assert.equal(failedWorkerContext.scanId, failedScanId);
    assert.equal(Object.hasOwn(failedWorkerContext, "inScopeFilesPath"), false);
    await assert.rejects(readFile(path.join(
      failedArtifactRoot,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt"
    )), { code: "ENOENT" });
    assertFlagPair(failedWorker.argv, "--model", "gpt-5.6-sol");
    assert.equal(failedWorker.argv.includes('model_reasoning_effort="high"'), true);
    assertReadOnlyWorkerInvocation(failedWorker.argv);
    assert.equal(activeFailureState.workers.some((worker) => worker.kind === "setup"), false);
    assert.equal(activeFailureState.workers.length, 1);
    assert.equal(activeFailureState.workers[0].kind, "discovery");
    assert.equal(activeFailureState.workers[0].status, "running");
    assertProcessAlive(failedWorker.pid);

    const failureMessage = "fixture unrecoverable failure";
    const failureResponse = await server.request(21, "tools/call", toolCall(
      "fail_codex_security_scan",
      { scanId: failedScanId, message: failureMessage },
      failureThreadId
    ));
    assertNoError(failureResponse);

    const failedWaiter = await server.waitForResponse(20);
    const failureText =
      failedWaiter.result?.content?.map((item) => item.text).join(" ") ?? "";
    assert.equal(failedWaiter.result?.isError, true);
    assert.equal(failedWaiter.result?.structuredContent, undefined);
    assert.match(failureText, /fixture unrecoverable failure/);
    assert.match(failureText, /no successful discovery manifest was returned/);
    const failedContext = await server.request(211, "tools/call", toolCall(
      "get_codex_security_scan_context", { scanId: failedScanId }, failureThreadId
    ));
    assertNoError(failedContext);
    assert.equal(failedContext.result.structuredContent.scan.progress.status, "failed");
    const exitedWorkers = await waitForJsonLines(exitLogPath, 2);
    assert.equal(exitedWorkers[1].pid, failedWorker.pid);
    assert.match(exitedWorkers[1].signal, /^SIG(?:INT|TERM)$/);
    await waitFor(() => server.stderrEvents().some((event) => (
      event.event === "coordinator_cleanup_settled" && event.scanId === failedScanId
    )), "externally failed coordinator cleanup to settle");

    const failedState = await getDeepScan({
      environment,
      scanId: failedScanId,
      threadId: failureThreadId
    });
    assert.equal(failedState.status, "failed");
    assert.equal(failedState.error, failureMessage);
    assert.equal(failedState.workers.some((worker) => worker.kind === "setup"), false);
    assert.equal(
      failedState.workers.every((worker) => !["queued", "running"].includes(worker.status)),
      true
    );

    const failedLateJoin = await server.request(22, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { scanId: failedScanId },
      failureThreadId
    ));
    const failedLateJoinText =
      failedLateJoin.result?.content?.map((item) => item.text).join(" ") ?? "";
    assert.equal(failedLateJoin.result?.isError, true);
    assert.equal(failedLateJoin.result?.structuredContent, undefined);
    assert.match(failedLateJoinText, /fixture unrecoverable failure/);
    assert.match(failedLateJoinText, /Do not call complete_codex_security_scan/);

    const toolList = await server.request(23, "tools/list");
    assertNoError(toolList);
    assert.equal(
      toolList.result.tools.some((tool) => tool.name === "start_codex_security_deep_scan"),
      true,
      "the MCP server must remain responsive after canceling one scan"
    );

    const resumedThreadId = "deep-scan-stdio-resumed-thread";
    const opened = await server.request(24, "tools/call", toolCall(
      "open_codex_security_workspace",
      { targetPath, scope: ".", mode: "deep" },
      resumedThreadId
    ));
    assertNoError(opened);
    const sessionId = opened.result.structuredContent.workspace.id;
    assertNoError(await server.request(25, "tools/call", toolCall(
      "submit_codex_security_setup",
      { sessionId, targetPath, scope: ".", mode: "deep" },
      resumedThreadId
    )));
    const started = await server.request(26, "tools/call", toolCall(
      "start_codex_security_scan",
      { sessionId },
      resumedThreadId
    ));
    assertNoError(started);
    const resumedScan = started.result.structuredContent.workspace.results;
    const resumedScanId = resumedScan.scanId;
    const handoffClaimToken = randomUUID();
    for (const [id, name, arguments_] of [
      [27, "claim_codex_security_scan_handoff_delivery", {
        scanId: resumedScanId, claimToken: handoffClaimToken
      }],
      [28, "attach_codex_security_scan_continuation_thread", {
        scanId: resumedScanId, claimToken: handoffClaimToken, threadId: resumedThreadId
      }]
    ]) {
      assertNoError(await server.request(id, "tools/call", toolCall(
        name, arguments_, resumedThreadId
      )));
    }

    const restartStartIndex = (await readJsonLines(startLogPath)).length;
    await writeFile(restartControlPath, "before-restart");
    server.sendRequest(29, "tools/call", toolCall(
      "start_codex_security_deep_scan",
      { scanId: resumedScanId, handoffClaimToken },
      resumedThreadId
    ));
    let partial;
    await waitFor(async () => {
      if (!server.stderrEvents().some((event) => (
        event.event === "coordinator_started" && event.scanId === resumedScanId
      ))) return false;
      partial = await getDeepScan({ environment, scanId: resumedScanId, threadId: resumedThreadId });
      return partial.workers.some((worker) => worker.status === "succeeded")
        && partial.workers.some((worker) => worker.status === "running");
    }, "one completed discovery and one interrupted discovery");
    const completedWorker = partial.workers.find((worker) => worker.status === "succeeded");
    const completedDraft = JSON.parse(await readFile(completedWorker.resultManifestPath, "utf8"));
    assert.equal(completedDraft.scanId, resumedScanId);
    assert.deepEqual(completedDraft.findings, []);
    await server.stop();
    assert.throws(() => process.kill(server.pid, 0), "the original MCP server must have exited");
    const paused = await runWorkbench(environment, ["get-scan", "--scan-id", resumedScanId]);
    assert.deepEqual([paused.scan.progress.status, paused.scan.progress.phase], ["running", "discovery"]);
    assert.deepEqual(paused.scan.progress.independentReviews, {
      completed: 1,
      active: 0,
      consolidating: false
    });
    assert.deepEqual(
      [paused.scan.reportAvailable, paused.scan.findingCount, paused.scan.artifacts],
      [false, 0, {}]
    );
    const manifestPath = path.join(resumedScan.scanDir, "scan-manifest.json");
    await assert.rejects(readFile(manifestPath), { code: "ENOENT" });
    await rm(path.join(
      resumedScan.scanDir,
      "artifacts",
      "deep_discovery",
      `coordinator-heartbeat-${partial.coordinatorGeneration}.json`
    ), { force: true });
    await execFileAsync(process.env.PYTHON?.trim() || "python3", [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?', ('2000-01-01T00:00:00Z',sys.argv[2])); c.commit()",
      path.join(stateDir, "workbench.sqlite3"),
      resumedScanId
    ]);
    await writeFile(restartControlPath, "after-restart");

    const restartedServer = startServer(serverBundlePath, environment);
    try {
      assertNoError(await restartedServer.request(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "deep-scan-restarted-artifacts", version: "0.1.0" }
      }));
      const resumed = await restartedServer.request(2, "tools/call", toolCall(
        "start_codex_security_deep_scan",
        { scanId: resumedScanId, handoffClaimToken },
        resumedThreadId
      ));
      assertNoError(resumed);
      assert.equal(resumed.result.structuredContent.manifestPath, manifestPath);
      assert.equal(
        resumed.result.content.some((item) => item.text.includes(resumedScanId)),
        true,
        "the successful tool response must expose the authoritative scan ID for completion"
      );
      const finished = await getDeepScan({
        environment, scanId: resumedScanId, threadId: resumedThreadId
      });
      assert.equal(finished.status, "succeeded");
      assert.equal(finished.coordinatorGeneration, partial.coordinatorGeneration + 1);
      assert.equal(finished.dispatchedCount, 2);
      const successfulDiscoveries = finished.workers.filter((worker) => (
        worker.kind === "discovery" && worker.status === "succeeded"
      ));
      assert.equal(successfulDiscoveries.length, 2);
      assert.equal(successfulDiscoveries[0].id, completedWorker.id);
      assert.equal(finished.workers.some((worker) => (
        worker.kind === "dedup" && worker.status === "succeeded"
      )), true);
      await assert.rejects(readFile(path.join(
        resumedScan.scanDir, "artifacts", "02_discovery", "in_scope_files.txt"
      )), { code: "ENOENT" });
      assert.deepEqual(
        JSON.parse(await readFile(path.join(resumedScan.scanDir, "findings.json"), "utf8")).findings,
        []
      );
      const executions = (await readJsonLines(startLogPath)).slice(restartStartIndex);
      assert.equal(executions.filter((execution) => (
        discoveryPromptContext(execution.stdin).workerLabel === "discovery-0001"
      )).length, 1);
    } finally {
      await restartedServer.stop();
    }
  } catch (error) {
    error.message += `\nMCP stderr:\n${server.stderrText()}`;
    throw error;
  } finally {
    await server.stop();
    await rm(serverBundlePath, { force: true });
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

async function bundleServer(outfile) {
  await build({
    bundle: true,
    define: { "import.meta.url": "__filename" },
    entryPoints: [path.join(mcpAppRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile,
    platform: "node",
    target: "node20"
  });
}

function startServer(serverPath, env) {
  const child = spawn(process.execPath, [serverPath, "--stdio"], {
    cwd: pluginRoot,
    env,
    stdio: ["pipe", "pipe", "pipe"]
  });
  const responses = new Map();
  const waiters = new Map();
  const stderrEvents = [];
  const stderrLines = [];
  let stdoutBuffer = "";
  let stderrBuffer = "";

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdoutBuffer += chunk;
    stdoutBuffer = consumeLines(stdoutBuffer, (line) => {
      const response = JSON.parse(line);
      responses.set(response.id, response);
      waiters.get(response.id)?.(response);
      waiters.delete(response.id);
    });
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderrBuffer += chunk;
    stderrBuffer = consumeLines(stderrBuffer, (line) => {
      stderrLines.push(line);
      try {
        const event = JSON.parse(line);
        if (event.component === "codex_security_deep_scan") stderrEvents.push(event);
      } catch {
        // Non-structured diagnostics remain available in the child process on test failure.
      }
    });
  });

  return {
    pid: child.pid,
    notify(method, params = {}) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
    },
    sendRequest(id, method, params = {}) {
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    },
    request(id, method, params = {}) {
      this.sendRequest(id, method, params);
      return this.waitForResponse(id);
    },
    waitForResponse(id, timeoutMs = 15_000) {
      const existing = responses.get(id);
      if (existing) return Promise.resolve(existing);
      return withTimeout(new Promise((resolve) => waiters.set(id, resolve)), timeoutMs, (
        `JSON-RPC response ${id}`
      ));
    },
    stderrEvents() {
      return [...stderrEvents];
    },
    stderrText() {
      return stderrLines.join("\n");
    },
    response(id) {
      return responses.get(id);
    },
    async stop() {
      if (child.exitCode !== null) return;
      child.stdin.end();
      const exited = new Promise((resolve) => child.once("exit", resolve));
      const graceful = await Promise.race([exited.then(() => true), delay(2_000).then(() => false)]);
      if (!graceful && child.exitCode === null) child.kill("SIGKILL");
      await exited;
    }
  };
}

function toolCall(name, args, threadId, turnMetadata, sandboxState = parentSandboxState) {
  return {
    name,
    arguments: args,
    _meta: {
      "openai/threadId": threadId,
      ...(sandboxState ? { "codex/sandbox-state-meta": sandboxState } : {}),
      ...(turnMetadata ? { "x-codex-turn-metadata": turnMetadata } : {})
    }
  };
}

function assertFlagPair(args, flag, value) {
  const index = args.indexOf(flag);
  assert.notEqual(index, -1, `missing ${flag}`);
  assert.equal(args[index + 1], value);
}

function assertReadOnlyWorkerInvocation(args) {
  assert.equal(args.includes("--sandbox"), false);
  assert.equal(args.includes("--add-dir"), false);
  assert.equal(args.includes("--dangerously-bypass-approvals-and-sandbox"), false);
  assert.deepEqual(
    args.filter((arg) => arg.startsWith("approval_policy=")),
    ['approval_policy="never"']
  );
  assert.equal(
    args.some((arg) => /^sandbox_workspace_write\.network_access\s*=\s*true$/.test(arg)),
    false
  );
  assert.equal(
    args.includes('default_permissions="codex_security_deep_scan_worker"'),
    true
  );
  const overrides = args.filter((arg) =>
    arg.startsWith("permissions.codex_security_deep_scan_worker=")
  );
  assert.deepEqual(overrides, [
    'permissions.codex_security_deep_scan_worker={extends=":read-only",filesystem={":root"="read"},network={enabled=false}}'
  ]);
}

async function waitForScanId({
  server,
  requestId = 10,
  excludedScanIds = []
}) {
  let scanId;
  const excluded = new Set(excludedScanIds);
  await waitFor(async () => {
    const startResponse = server.response(requestId);
    if (startResponse) {
      throw new Error(`Target-based Deep Scan start returned early: ${JSON.stringify(startResponse)}`);
    }
    const coordinatorStarted = server.stderrEvents().find((event) => (
      event.event === "coordinator_started" && !excluded.has(event.scanId)
    ));
    scanId = coordinatorStarted?.scanId;
    return typeof scanId === "string";
  }, "target-based Deep Scan bootstrap");
  return scanId;
}

async function getDeepScan({ environment, scanId, threadId }) {
  const result = await runWorkbench(environment, [
    "get-deep-scan",
    "--scan-id",
    scanId,
    "--thread-id",
    threadId
  ]);
  return result.deepScan;
}

async function waitForDeepScanWorker({ environment, scanId, threadId }) {
  let worker;
  await waitFor(async () => {
    const deepScan = await getDeepScan({ environment, scanId, threadId });
    worker = deepScan.workers.find((candidate) => (
      candidate.kind === "discovery" && candidate.status === "running"
    ));
    return worker !== undefined;
  }, "active Standard scan worker");
  return worker;
}

function discoveryPromptContext(prompt) {
  const match = prompt.match(/```json\n([\s\S]*?)\n```/u);
  assert.ok(match, "the discovery worker must receive its typed Standard artifact context");
  return JSON.parse(match[1]);
}

async function runWorkbench(environment, args) {
  const python = process.env.PYTHON?.trim() || "python3";
  const { stdout } = await execFileAsync(python, [workbenchPath, ...args], {
    cwd: pluginRoot,
    env: environment,
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000
  });
  return JSON.parse(stdout);
}

async function writeFakeCodex(executablePath) {
  await writeFile(executablePath, [
    "#!/usr/bin/env node",
    'import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";',
    'import path from "node:path";',
    "if (process.argv.includes('app-server')) {",
    "  let buffer = '';",
    "  process.stdin.setEncoding('utf8');",
    "  process.stdin.on('data', (chunk) => {",
    "    buffer += chunk;",
    "    while (true) {",
    "      const newline = buffer.indexOf('\\n');",
    "      if (newline < 0) return;",
    "      const line = buffer.slice(0, newline).trim();",
    "      buffer = buffer.slice(newline + 1);",
    "      if (!line) continue;",
    "      const message = JSON.parse(line);",
    "      if (message.method === 'initialized') continue;",
    "      let result;",
    "      if (message.method === 'initialize') {",
    "        result = { userAgent: 'fixture', codexHome: '/fixture', platformFamily: 'unix', platformOs: 'macos' };",
    "      } else if (message.method === 'config/read') {",
    "        result = { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: { extends: ':read-only', filesystem: { ':root': 'read' }, network: { enabled: false } } } }, origins: {}, layers: null };",
    "      } else if (message.method === 'permissionProfile/list') {",
    "        result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: true }], nextCursor: null };",
    "      } else {",
    "        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }) + '\\n');",
    "        continue;",
    "      }",
    "      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');",
    "    }",
    "  });",
    "  process.stdin.on('end', () => process.exit(0));",
    "} else {",
    "let stdin = '';",
    "for await (const chunk of process.stdin) stdin += chunk;",
    "const context = JSON.parse(stdin.match(/```json\\n([\\s\\S]*?)\\n```/u)[1]);",
    "const root = process.argv[process.argv.indexOf('--cd') + 1];",
    "appendFileSync(process.env.FAKE_CODEX_START_LOG, JSON.stringify({ pid: process.pid, argv: process.argv.slice(2), stdin }) + '\\n');",
    "console.log(JSON.stringify({ type: 'thread.started', thread_id: `stdio-fixture-${process.pid}` }));",
    "if (existsSync(process.env.FAKE_CODEX_RESTART_CONTROL)) {",
    "  const phase = readFileSync(process.env.FAKE_CODEX_RESTART_CONTROL, 'utf8');",
    "  if (phase === 'after-restart' || context.workerLabel === 'discovery-0001') {",
    "    const coverage = { completeness: 'complete', surfaces: [], explicitExclusions: [], deferred: [] };",
    "    if (context.claimedWorkerIds) {",
    "      const output = path.join(root, 'deep_discovery', 'dedup', context.reducerLabel, 'output');",
    "      const firstResult = JSON.parse(readFileSync(path.join(root, 'deep_discovery', 'workers', 'discovery-0001', 'output', 'result.json'), 'utf8'));",
    "      writeFileSync(path.join(output, 'result.json'), JSON.stringify({ scanId: firstResult.scanId, findings: [], coverage }));",
    "    } else {",
    "      writeFileSync(path.join(root, 'result.json'), JSON.stringify({ scanId: context.scanId, findings: [], coverage }));",
    "    }",
    "    console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture completed' } }));",
    "    console.log(JSON.stringify({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));",
    "    process.exit(0);",
    "  }",
    "}",
    "const timer = setInterval(() => {}, 1_000);",
    "const stop = (signal) => {",
    "  clearInterval(timer);",
    "  if (existsSync(process.env.FAKE_CODEX_SIGNAL_CHECKPOINT_CONTROL)) {",
    "    const coverage = { completeness: 'complete', surfaces: [], explicitExclusions: [], deferred: [] };",
    "    const checkpointDir = path.join(root, 'checkpoints');",
    "    mkdirSync(checkpointDir, { recursive: true });",
    "    writeFileSync(path.join(checkpointDir, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json'), JSON.stringify({ scanId: context.scanId, findings: [], coverage }));",
    "  }",
    "  appendFileSync(process.env.FAKE_CODEX_EXIT_LOG, JSON.stringify({ pid: process.pid, signal }) + '\\n');",
    "  process.exit(0);",
    "};",
    "process.once('SIGINT', () => stop('SIGINT'));",
    "process.once('SIGTERM', () => stop('SIGTERM'));",
    "}",
    ""
  ].join("\n"));
  await chmod(executablePath, 0o755);
}

async function writePythonWrapper(executablePath) {
  await writeFile(executablePath, [
    "#!/usr/bin/env node",
    'import { appendFileSync, existsSync, unlinkSync } from "node:fs";',
    'import { spawnSync } from "node:child_process";',
    "const args = process.argv.slice(2);",
    "const control = process.env.FAKE_WORKBENCH_CANCEL_FAILURE_CONTROL;",
    "if (args[1] === 'cancel-scan') {",
    "  appendFileSync(process.env.FAKE_WORKBENCH_CANCEL_LOG, JSON.stringify(args) + '\\n');",
    "}",
    "if (args[1] === 'cancel-scan' && control && existsSync(control)) {",
    "  unlinkSync(control);",
    "  console.error('injected cancel-scan failure');",
    "  process.exit(1);",
    "}",
    "const result = spawnSync(process.env.REAL_PYTHON || 'python3', args, { stdio: 'inherit' });",
    "if (result.error) throw result.error;",
    "process.exit(result.status ?? 1);",
    "",
  ].join("\n"));
  await chmod(executablePath, 0o755);
}

function assertNoError(response) {
  assert.equal(response.error, undefined, response.error?.message);
  assert.equal(
    response.result?.isError,
    undefined,
    response.result?.content?.map((item) => item.text).join(" ")
  );
}

function assertCanceled(response, scanId) {
  assertNoError(response);
  assert.deepEqual(response.result.structuredContent, { status: "canceled", scanId });
}

function assertProcessAlive(pid) {
  assert.doesNotThrow(() => process.kill(pid, 0), `expected fake Codex process ${pid} to remain alive`);
}

async function waitForJsonLines(filePath, count) {
  let lines = [];
  await waitFor(async () => {
    lines = await readJsonLines(filePath);
    return lines.length >= count;
  }, `${count} record(s) in ${path.basename(filePath)}`);
  return lines;
}

async function readJsonLines(filePath) {
  try {
    return (await readFile(filePath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

async function waitFor(predicate, label, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(25);
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function withTimeout(promise, timeoutMs, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label}.`)), timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function consumeLines(buffer, consume) {
  let newlineIndex = buffer.indexOf("\n");
  while (newlineIndex >= 0) {
    const line = buffer.slice(0, newlineIndex).trim();
    buffer = buffer.slice(newlineIndex + 1);
    if (line) consume(line);
    newlineIndex = buffer.indexOf("\n");
  }
  return buffer;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
