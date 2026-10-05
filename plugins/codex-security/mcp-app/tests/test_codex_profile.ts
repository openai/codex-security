import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import type { ThreadEvent } from "@openai/codex-sdk";
import { createCodexProfileClient } from "../../scripts/codex_profile.mjs";

async function fixture(mode = "success") {
  const directory = await mkdtemp(path.join(tmpdir(), "codex-profile-test-"));
  const script = path.join(directory, "native-fixture.mjs");
  const marker = path.join(directory, "marker.json");
  await writeFile(
    script,
    String.raw`
    import { readFile, writeFile } from "node:fs/promises";
    let input = "";
    for await (const chunk of process.stdin) input += chunk;
    const args = process.argv.slice(1);
    const schemaPath = args[args.indexOf("--output-schema") + 1];
    await writeFile(process.env.PROFILE_TEST_MARKER, JSON.stringify({
      args, input, pid: process.pid,
      schemaPath: args.includes("--output-schema") ? schemaPath : null,
      schema: args.includes("--output-schema") ? JSON.parse(await readFile(schemaPath, "utf8")) : null,
      environment: {
        CODEX_HOME: process.env.CODEX_HOME,
        CODEX_API_KEY: process.env.CODEX_API_KEY,
        CODEX_INTERNAL_ORIGINATOR_OVERRIDE: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE,
        PROFILE_CLIENT_SHOULD_NOT_LEAK: process.env.PROFILE_CLIENT_SHOULD_NOT_LEAK,
      },
    }));
    const emit = (event) => process.stdout.write(JSON.stringify(event) + "\n");
    if (process.env.PROFILE_TEST_MODE === "error") {
      process.stderr.write("synthetic token=fixture-secret: upstream diagnostic\n");
      process.exit(3);
    }
    if (process.env.PROFILE_TEST_MODE === "malformed") {
      process.stdout.write("synthetic malformed token=fixture-secret\n");
      process.exit(0);
    }
    emit({ type: "thread.started", thread_id: args.includes("resume") ? args[args.indexOf("resume") + 1] : "fixture-thread", native_field: "preserved" });
    if (process.env.PROFILE_TEST_MODE === "turn_failed") {
      emit({ type: "turn.failed", error: { message: "synthetic token=fixture-secret: upstream turn failure" } });
      process.exit(0);
    } else if (process.env.PROFILE_TEST_MODE === "wait") {
      setInterval(() => {}, 1000);
    } else {
      emit({ type: "item.completed", item: { type: "agent_message", id: "fixture-item", text: "synthetic token=fixture-secret" } });
      emit({ type: "turn.completed", usage: { input_tokens: 2, cached_input_tokens: 1, output_tokens: 3, reasoning_output_tokens: 0, ...(args.includes("resume") ? { cache_write_input_tokens: 9 } : {}) } });
      process.exit(0);
    }
  `,
  );
  const options = {
    codexPathOverride: process.execPath,
    profileName: "scan_fixture_1",
    apiKey: "synthetic-api-key",
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([key]) =>
          [
            "PATH",
            "Path",
            "SystemRoot",
            "WINDIR",
            "HOME",
            "USERPROFILE",
            "TEMP",
            "TMP",
          ].includes(key),
        ),
      ),
      NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
      PROFILE_TEST_MARKER: marker,
      PROFILE_TEST_MODE: mode,
      CODEX_HOME: path.join(directory, "credential home"),
      CODEX_API_KEY: "replaced-synthetic-key",
    },
  };
  return {
    directory,
    options,
    record: async () => JSON.parse(await readFile(marker, "utf8")),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

test("native profile turns preserve settings, JSON events, schema cleanup, and resume identity", async () => {
  const f = await fixture();
  const previousEnvironment = process.env.PROFILE_CLIENT_SHOULD_NOT_LEAK;
  process.env.PROFILE_CLIENT_SHOULD_NOT_LEAK = "synthetic-parent-only-value";
  try {
    const client = createCodexProfileClient<ThreadEvent>({
      ...f.options,
      baseUrl: "https://provider.example.test/v1",
      config: {
        features: { plugins: true },
        empty: {},
        values: [1, { "dotted.key": "value" }],
      },
      configOverrides: ["features.plugins=false"],
    });
    const thread = client.startThread({
      model: "fixture-model",
      threadSource: "sdk",
      sandboxMode: "read-only",
      workingDirectory: path.join(f.directory, "scan workspace"),
      additionalDirectories: [path.join(f.directory, "extra workspace")],
      skipGitRepoCheck: true,
      modelReasoningEffort: "medium",
      networkAccessEnabled: false,
      webSearchMode: "cached",
      approvalPolicy: "never",
    });
    const schema = {
      type: "object",
      properties: { answer: { type: "string" } },
    };
    const { events } = await thread.runStreamed("first synthetic prompt", {
      outputSchema: schema,
      cyberAccessProgram: "standard",
    });
    const received = [];
    for await (const event of events) received.push(event);
    assert.deepEqual(received[0], {
      type: "thread.started",
      thread_id: "fixture-thread",
      native_field: "preserved",
    });
    assert.equal(thread.id, "fixture-thread");
    assert.deepEqual(received.at(-1), {
      type: "turn.completed",
      usage: {
        input_tokens: 2,
        cached_input_tokens: 1,
        cache_write_input_tokens: 0,
        output_tokens: 3,
        reasoning_output_tokens: 0,
      },
    });
    const first = await f.record();
    assert.equal(path.basename(first.args[0]), "exec");
    assert.deepEqual(first.args.slice(1), [
      "--experimental-json",
      "--profile",
      "scan_fixture_1",
      "--config",
      "features.plugins=true",
      "--config",
      "empty={}",
      "--config",
      'values=[1, {"dotted.key" = "value"}]',
      "--config",
      "features.plugins=false",
      "--config",
      'openai_base_url="https://provider.example.test/v1"',
      "--model",
      "fixture-model",
      "--thread-source",
      "sdk",
      "--sandbox",
      "read-only",
      "--cd",
      path.join(f.directory, "scan workspace"),
      "--add-dir",
      path.join(f.directory, "extra workspace"),
      "--skip-git-repo-check",
      "--output-schema",
      first.schemaPath,
      "--cyber-access-program",
      "standard",
      "--config",
      'model_reasoning_effort="medium"',
      "--config",
      "sandbox_workspace_write.network_access=false",
      "--config",
      'web_search="cached"',
      "--config",
      'approval_policy="never"',
    ]);
    assert.equal(first.input, "first synthetic prompt");
    assert.deepEqual(first.schema, schema);
    assert.deepEqual(first.environment, {
      CODEX_HOME: f.options.env.CODEX_HOME,
      CODEX_API_KEY: "synthetic-api-key",
      CODEX_INTERNAL_ORIGINATOR_OVERRIDE: "codex_sdk_ts",
    });
    assert.ok(!first.args.join(" ").includes("synthetic-api-key"));
    await assert.rejects(readFile(first.schemaPath), { code: "ENOENT" });
    const result = await thread.run("second synthetic prompt");
    assert.equal(result.finalResponse, "synthetic token=fixture-secret");
    assert.equal(result.items.length, 1);
    assert.equal(result.usage?.cache_write_input_tokens, 9);
    const second = await f.record();
    assert.ok(!second.args.includes("--thread-source"));
    assert.deepEqual(second.args.slice(-2), ["resume", "fixture-thread"]);
    const resumed = client.resumeThread("existing-fixture", {
      webSearchEnabled: false,
    });
    await resumed.run("resumed synthetic prompt");
    const third = await f.record();
    assert.deepEqual(third.args.slice(-4), [
      "--config",
      'web_search="disabled"',
      "resume",
      "existing-fixture",
    ]);
    assert.equal(resumed.id, "existing-fixture");
  } finally {
    if (previousEnvironment === undefined)
      delete process.env.PROFILE_CLIENT_SHOULD_NOT_LEAK;
    else process.env.PROFILE_CLIENT_SHOULD_NOT_LEAK = previousEnvironment;
    await f.cleanup();
  }
});

test("native profile failures preserve upstream diagnostics and remove schema files", async () => {
  for (const mode of ["error", "malformed", "turn_failed"]) {
    const f = await fixture(mode);
    try {
      const thread = createCodexProfileClient(f.options).startThread();
      await assert.rejects(
        thread.run("synthetic prompt", { outputSchema: { type: "object" } }),
        mode === "error"
          ? /code 3: synthetic token=fixture-secret: upstream diagnostic/
          : mode === "malformed"
            ? /Failed to parse item: synthetic malformed token=fixture-secret/
            : /synthetic token=fixture-secret: upstream turn failure/,
      );
      const record = await f.record();
      await assert.rejects(readFile(record.schemaPath), { code: "ENOENT" });
    } finally {
      await f.cleanup();
    }
  }
});

test("native profile abort and abandoned streams close the actual child", async () => {
  for (const abort of [true, false]) {
    const f = await fixture("wait");
    try {
      const controller = new AbortController();
      const thread = createCodexProfileClient(f.options).startThread();
      const { events } = await thread.runStreamed("synthetic prompt", {
        signal: controller.signal,
      });
      assert.equal((await events.next()).value.type, "thread.started");
      const record = await f.record();
      if (abort) {
        controller.abort();
        await assert.rejects(events.next(), { name: "AbortError" });
      } else {
        await events.return(undefined);
      }
      assert.throws(() => process.kill(record.pid, 0), { code: "ESRCH" });
    } finally {
      await f.cleanup();
    }
  }
});

test("native profile launch failures do not hang the stream", async () => {
  const f = await fixture();
  try {
    const thread = createCodexProfileClient({
      ...f.options,
      codexPathOverride: path.join(f.directory, "missing-native"),
    }).startThread();
    await assert.rejects(thread.run("synthetic prompt"), { code: "ENOENT" });
  } finally {
    await f.cleanup();
  }
});
