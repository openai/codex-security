import childProcess from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { mock } from "bun:test";

if (process.argv[2] === "exec") {
  const { readDeepScanRuntimeConfig } =
    await import("../../../../plugins/codex-security/mcp-app/src/deep-scan/permission-profile-preflight.ts");
  const args = process.argv.slice(2);
  process.stdin.resume();
  await once(process.stdin, "end");
  // Resolve the launched worker's actual home and overrides with native Codex,
  // before thread.started lets the wrapper release its configuration lock.
  // Only turn events are synthetic: this test does not require an OS sandbox.
  const config = await readDeepScanRuntimeConfig({
    codexPath: process.env.CODEX_CLI_PATH,
    cwd: args[args.indexOf("--cd") + 1],
    configOverrides: args.flatMap((arg, index) =>
      arg === "--config" || arg === "-c" ? [args[index + 1]] : [],
    ),
    env: process.env,
    signal: new AbortController().signal,
  });
  const threadId = args.includes("resume")
    ? args[args.indexOf("resume") + 1]
    : randomUUID();
  for (const event of [
    { type: "thread.started", thread_id: threadId },
    {
      type: "item.completed",
      item: {
        id: "native-config",
        type: "agent_message",
        text: JSON.stringify({
          config,
          codexHome: process.env.CODEX_HOME,
          codexPath: process.env.CODEX_CLI_PATH,
          apiKey: process.env.CODEX_API_KEY,
          resumed: args.includes("resume"),
        }),
      },
    },
    {
      type: "turn.completed",
      usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 },
    },
  ])
    process.stdout.write(JSON.stringify(event) + "\n");
} else {
  const spawn = childProcess.spawn;
  let workerCommand;
  // Preserve the SDK's worker argv and environment at the child-process boundary.
  // Native app-server launches, including permission preflight, remain untouched.
  const recordedSpawn = (command, args, options) => {
    if (args[0] !== "exec") return spawn(command, args, options);
    workerCommand = command;
    return spawn(
      process.execPath,
      [fileURLToPath(import.meta.url), ...args],
      options,
    );
  };
  for (const name of ["node:child_process", "child_process"])
    mock.module(name, () => ({ ...childProcess, spawn: recordedSpawn }));
  const {
    createExecutionCodex,
    nativeScanConfiguration,
    prepareDiscoveryExecution,
    prepareExecutionSource,
    prepareMergeExecution,
  } = await import("../../src/execution-preparation.ts");
  const { scanRuntimeCodexConfig } = await import("../../src/api.ts");
  const { preparedRuntime } = await import("../support/api-events.ts");
  let session;
  for await (const line of createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    workerCommand = undefined;
    if (session === undefined) {
      const configuration = await nativeScanConfiguration(
        process.env,
        { model: "gpt-test" },
        0,
      );
      const source = prepareExecutionSource({
        command: { command: process.env.CODEX_CLI_PATH },
        configuration,
        environment: process.env,
        auth: "api-key",
      });
      const home = process.env.CODEX_HOME;
      /** @type {import("../../src/execution-preparation.ts").PreparedExecution} */
      const prepared = {
        policy: "ordinary",
        source,
        runtime: preparedRuntime(home),
        runtimeHome: home,
        effectiveConfig: configuration,
        preflightConfig: {},
        sessionConfig: scanRuntimeCodexConfig(configuration, home),
        runtimeConfig: {},
        authentication: source.authentication,
        approvalPolicy: "never",
        python: process.execPath,
        releaseCredentialHome: null,
      };
      session = prepared;
    }
    const worker =
      request.kind === "discovery"
        ? prepareDiscoveryExecution(session)
        : prepareMergeExecution(session, 0);
    const { codex } = await createExecutionCodex(
      { surface: "sdk", command: "scan", mode: "deep" },
      worker,
      {},
    );
    const threadOptions = {
      model: "gpt-test",
      workingDirectory: process.cwd(),
      skipGitRepoCheck: true,
    };
    const thread = request.resumeThreadId
      ? codex.resumeThread(request.resumeThreadId, threadOptions)
      : codex.startThread(threadOptions);
    const { events } = await thread.runStreamed(
      await readFile(process.argv[2], "utf8"),
      {
        signal: new AbortController().signal,
      },
    );
    let receipt;
    for await (const event of events) {
      if (event.type === "turn.failed") throw new Error(event.error.message);
      if (
        event.type === "item.completed" &&
        event.item.type === "agent_message"
      )
        receipt = JSON.parse(event.item.text);
    }
    if (!receipt || !workerCommand)
      throw new Error("Worker configuration was not captured");
    const { config, ...launch } = receipt;
    process.stdout.write(
      JSON.stringify({
        ...launch,
        executable: workerCommand,
        threadId: thread.id,
        daybreak: config.daybreak ?? null,
        daybreakFeatures: Object.fromEntries(
          [
            "cli_daybreak",
            "api_key_cyber_access_programs",
            "api_key_model_discovery",
          ].map((key) => [key, config.features?.[key] ?? null]),
        ),
        permissionProfile: config.default_permissions,
        permissions: config.permissions?.[config.default_permissions],
      }) + "\n",
    );
  }
}
