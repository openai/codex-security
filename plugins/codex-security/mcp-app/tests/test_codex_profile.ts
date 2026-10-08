import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { mock, test } from "node:test";
import { pathToFileURL } from "node:url";
import type { ThreadEvent } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import {
  createCodexProfileClient,
  preflightProviderDefinitions,
  profileConfigOverrides,
} from "../../scripts/codex_profile.mjs";

test("native startup provider metadata preserves identity and auth without private configuration", () => {
  const providers = {
    "custom.provider": {
      name: "Synthetic managed provider",
      wire_api: "responses",
      requires_openai_auth: false,
      base_url: "https://synthetic-provider.example.test/v1",
      http_headers: { Authorization: "synthetic-private-header" },
      env_http_headers: { Authorization: "SYNTHETIC_PRIVATE_ENV" },
      env_key: "SYNTHETIC_PRIVATE_KEY",
      experimental_bearer_token: "synthetic-private-token",
      auth: { env: { SYNTHETIC_PRIVATE_SECRET: "synthetic-secret-value" } },
    },
    "account-provider": {
      name: "Synthetic account provider",
      requires_openai_auth: true,
    },
    "default-auth-provider": {
      name: "Synthetic default auth provider",
      wire_api: "responses",
    },
    "amazon-bedrock": { aws: { region: "us-east-1" } },
    "omitted-provider": null,
  };
  const before = structuredClone(providers);
  assert.deepEqual(preflightProviderDefinitions(providers), {
    "custom.provider": {
      name: "Synthetic managed provider",
      wire_api: "responses",
      requires_openai_auth: false,
    },
    "account-provider": {
      name: "Synthetic account provider",
      requires_openai_auth: true,
    },
    "default-auth-provider": {
      name: "Synthetic default auth provider",
      wire_api: "responses",
    },
    "amazon-bedrock": {},
  });
  assert.deepEqual(providers, before);
});

test("native overrides preserve literal paths, prototype keys, and TOML control escapes", () => {
  const profile = {
    extends: ":read-only",
    filesystem: Object.fromEntries([
      ["/synthetic/.env\u007f", { ".": "deny" }],
      [String.raw`C:\Users\synthetic\credentials`, { ".": "deny" }],
      ["__proto__", "deny"],
    ]),
    network: { enabled: false },
  };
  const overrides = profileConfigOverrides({
    "permissions.synthetic_worker": profile,
    model_instructions_file: "/synthetic/instructions\u007f.md",
  }).join("\n");
  assert.equal(overrides.includes("\u007f"), false);
  assert.deepEqual(JSON.parse(JSON.stringify(parseToml(overrides))), {
    permissions: { synthetic_worker: profile },
    model_instructions_file: "/synthetic/instructions\u007f.md",
  });
});

test("native overrides reject null array elements", () => {
  assert.throws(
    () => profileConfigOverrides({ values: [null] }),
    /must contain finite TOML values/,
  );
});

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
    if (process.env.PROFILE_TEST_MODE === "slow_completion")
      process.once("SIGTERM", () => setTimeout(() => process.exit(0), 50));
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
      await new Promise(() => {});
    } else if (process.env.PROFILE_TEST_MODE.startsWith("fallback_")) {
      emit({ type: "item.completed", item: { type: "agent_message", id: "discarded-item", text: "discarded synthetic response" } });
      const message = "Configured value for \u0060permission_profile\u0060 is disallowed by requirements; falling back from \u0060synthetic_read_only\u0060 to required value \u0060:workspace\u0060.";
      emit(process.env.PROFILE_TEST_MODE === "fallback_item"
        ? { type: "item.completed", item: { type: "error", message } }
        : { type: "error", message });
      setInterval(() => {}, 1000);
      await new Promise(() => {});
    } else {
      emit({ type: "item.completed", item: { type: "agent_message", id: "fixture-item", text: "synthetic token=fixture-secret" } });
      const completion = { type: "turn.completed" };
      if (process.env.PROFILE_TEST_MODE === "null_usage") completion.usage = null;
      else if (process.env.PROFILE_TEST_MODE !== "missing_usage") completion.usage = { input_tokens: 2, cached_input_tokens: 1, output_tokens: 3, reasoning_output_tokens: 0, ...(args.includes("resume") ? { cache_write_input_tokens: 9 } : {}) };
      emit(completion);
      if (process.env.PROFILE_TEST_MODE === "slow_completion") {
        setInterval(() => {}, 1000);
        await new Promise(() => {});
      } else process.exit(0);
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

async function npmLauncherFixture() {
  const f = await fixture("slow_completion");
  const codexRequire = createRequire(import.meta.resolve("@openai/codex-sdk"));
  const packageRoot = path.dirname(
    codexRequire.resolve("@openai/codex/package.json"),
  );
  const launcherRoot = path.join(f.directory, "npm-codex");
  const targetTriple = new Map([
    ["linux-x64", "x86_64-unknown-linux-musl"],
    ["linux-arm64", "aarch64-unknown-linux-musl"],
    ["darwin-x64", "x86_64-apple-darwin"],
    ["darwin-arm64", "aarch64-apple-darwin"],
  ]).get(`${process.platform}-${process.arch}`);
  assert.ok(targetTriple);
  const launcher = path.join(launcherRoot, "bin", "codex.js");
  const native = path.join(
    launcherRoot,
    "vendor",
    targetTriple,
    "bin",
    "codex",
  );
  await mkdir(path.dirname(launcher), { recursive: true });
  await mkdir(path.dirname(native), { recursive: true });
  await copyFile(
    path.join(packageRoot, "package.json"),
    path.join(launcherRoot, "package.json"),
  );
  await copyFile(path.join(packageRoot, "bin", "codex.js"), launcher);
  await chmod(launcher, 0o755);
  await writeFile(
    native,
    "#!/usr/bin/env node\n" +
      (
        await readFile(path.join(f.directory, "native-fixture.mjs"), "utf8")
      ).replace("process.argv.slice(1)", "process.argv.slice(2)"),
  );
  await chmod(native, 0o755);
  const { NODE_OPTIONS: _fixtureImport, ...env } = f.options.env;
  return { ...f, options: { ...f.options, codexPathOverride: launcher, env } };
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
        features: { plugins: true, optional: null },
        service_tier: null,
        empty: {},
        values: [1, { "dotted.key": "value", optional: null }],
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
      "features={plugins = true}",
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

test("native profile children hide Windows console windows", async () => {
  const f = await fixture();
  const originalSpawn = childProcess.spawn;
  let launched = false;
  childProcess.spawn = ((
    command: string,
    args: readonly string[],
    options: SpawnOptions,
  ) => {
    launched = true;
    assert.equal(options?.windowsHide, true);
    return originalSpawn(command, args, options);
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  try {
    await createCodexProfileClient(f.options)
      .startThread()
      .run("synthetic prompt");
    assert.equal(launched, true);
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

for (const mode of ["null_usage", "missing_usage"]) {
  for (const resumed of [false, true]) {
    for (const streamed of [false, true]) {
      test(`native profile ${resumed ? "resumed" : "fresh"} ${streamed ? "streamed" : "collected"} turns preserve ${mode}`, async () => {
        const f = await fixture(mode);
        try {
          const client = createCodexProfileClient(f.options);
          const thread = resumed
            ? client.resumeThread("existing-fixture")
            : client.startThread();
          const turnOptions = { outputSchema: { type: "object" } };
          if (streamed) {
            const { events } = await thread.runStreamed(
              "synthetic prompt",
              turnOptions,
            );
            const received = [];
            for await (const event of events) received.push(event);
            assert.equal(received.length, 3);
            assert.deepEqual(received.at(-1), {
              type: "turn.completed",
              ...(mode === "null_usage" ? { usage: null } : {}),
            });
          } else {
            const result = await thread.run("synthetic prompt", turnOptions);
            assert.equal(
              result.finalResponse,
              "synthetic token=fixture-secret",
            );
            assert.equal(result.items.length, 1);
            assert.equal(
              result.usage,
              mode === "null_usage" ? null : undefined,
            );
          }
          assert.equal(
            thread.id,
            resumed ? "existing-fixture" : "fixture-thread",
          );
          const record = await f.record();
          assert.equal(record.args.includes("resume"), resumed);
          await assert.rejects(readFile(record.schemaPath), { code: "ENOENT" });
        } finally {
          await f.cleanup();
        }
      });
    }
  }
}

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

function captureChildClose() {
  let closed: Promise<void> | undefined;
  let isClosed = false;
  let pid: number | undefined;
  const originalSpawn = childProcess.spawn;
  const spawnSpy = mock.method(
    childProcess,
    "spawn",
    (command: string, args: readonly string[], options: SpawnOptions) => {
      const child = originalSpawn(command, args, options);
      pid = child.pid;
      closed = new Promise((resolve) =>
        child.once("close", () => {
          isClosed = true;
          resolve();
        }),
      );
      return child;
    },
  );
  syncBuiltinESMExports();
  return {
    isClosed: () => isClosed,
    pid: () => pid,
    wait: () => {
      assert.ok(closed);
      return closed;
    },
    restore: () => {
      spawnSpy.mock.restore();
      syncBuiltinESMExports();
    },
  };
}

for (const resumed of [false, true]) {
  test(`native profile ${resumed ? "resumed" : "fresh"} completion waits for its slow child to close`, async () => {
    const f = await fixture("slow_completion");
    const childClose = captureChildClose();
    try {
      const client = createCodexProfileClient(f.options);
      const thread = resumed
        ? client.resumeThread("existing-fixture")
        : client.startThread();
      const { events } = await thread.runStreamed("synthetic prompt");
      for await (const event of events) {
        if (event.type === "turn.completed") break;
      }
      assert.equal(childClose.isClosed(), true);
      const record = await f.record();
      assert.throws(() => process.kill(record.pid, 0), { code: "ESRCH" });
    } finally {
      await childClose.wait();
      childClose.restore();
      await f.cleanup();
    }
  });
}

for (const resumed of [false, true]) {
  test(
    `native profile ${resumed ? "resumed" : "fresh"} completion releases npm launcher inherited output`,
    { skip: process.platform === "win32" },
    async () => {
      const f = await npmLauncherFixture();
      const childClose = captureChildClose();
      let completion: Promise<void> | undefined;
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        const client = createCodexProfileClient(f.options);
        const thread = resumed
          ? client.resumeThread("existing-fixture")
          : client.startThread();
        const { events } = await thread.runStreamed("synthetic prompt", {
          outputSchema: { type: "object" },
        });
        completion = (async () => {
          for await (const event of events) {
            if (event.type === "turn.completed") break;
          }
        })();
        await Promise.race([
          completion,
          new Promise((_, reject) => {
            timeout = setTimeout(() => {
              reject(
                new Error(
                  "Completed profile turn did not release npm launcher output.",
                ),
              );
            }, 1_000);
          }),
        ]);
        clearTimeout(timeout);
        assert.equal(childClose.isClosed(), true);
        assert.ok(childClose.pid());
        assert.throws(() => process.kill(childClose.pid()!, 0), {
          code: "ESRCH",
        });
        const record = await f.record();
        assert.equal(record.args.includes("resume"), resumed);
        assert.equal(record.environment.CODEX_HOME, f.options.env.CODEX_HOME);
        assert.equal(record.environment.CODEX_API_KEY, "synthetic-api-key");
        assert.doesNotThrow(() => process.kill(record.pid, 0));
        await assert.rejects(readFile(record.schemaPath), { code: "ENOENT" });
      } finally {
        clearTimeout(timeout);
        const record = await f.record().catch(() => undefined);
        if (record?.pid) {
          try {
            process.kill(record.pid, "SIGKILL");
          } catch {}
        }
        await completion?.catch(() => {});
        await childClose.wait();
        childClose.restore();
        await f.cleanup();
      }
    },
  );
}

test("native profile abort and abandoned streams close the actual child", async () => {
  for (const abort of [true, false]) {
    const f = await fixture("wait");
    const childClose = captureChildClose();
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
      await childClose.wait();
      assert.throws(() => process.kill(record.pid, 0), { code: "ESRCH" });
    } finally {
      childClose.restore();
      await f.cleanup();
    }
  }
});

test("a late native permission fallback discards the turn and closes the actual child", async () => {
  for (const mode of ["fallback_item", "fallback_event"]) {
    const f = await fixture(mode);
    const childClose = captureChildClose();
    try {
      const thread = createCodexProfileClient({
        ...f.options,
        requestedPermissionProfile: "synthetic_read_only",
      }).startThread();
      await assert.rejects(
        thread.run("synthetic prompt", { outputSchema: { type: "object" } }),
        /results were discarded[\s\S]*falling back from `synthetic_read_only` to required value `:workspace`\./,
      );
      const record = await f.record();
      await childClose.wait();
      assert.throws(() => process.kill(record.pid, 0), { code: "ESRCH" });
      await assert.rejects(readFile(record.schemaPath), { code: "ENOENT" });
    } finally {
      childClose.restore();
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
