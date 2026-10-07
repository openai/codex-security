import { temporaryDirectory } from "../../plugins/codex-security/mcp-app/tests/support/temporary-directories.ts";
import { readJson } from "../../plugins/codex-security/mcp-app/tests/support/json.ts";
import assert from "node:assert/strict";
import { once } from "node:events";
import childProcess, { spawn } from "node:child_process";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { delimiter, dirname, join, win32 } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import {
  codexSettings,
  preflightEval,
  prepareEval,
  runPreparedEval,
} from "./harness.mts";
import {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  withEvalState,
} from "./runtime.mts";

const unixOnly = { skip: process.platform === "win32", timeout: 15000 };
const sdkUrl = new URL(
  "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js",
  import.meta.url,
).href;
const tomlUrl = new URL(
  "../../sdk/typescript/node_modules/smol-toml/dist/index.js",
  import.meta.url,
).href;
const harnessUrl = new URL("./harness.mts", import.meta.url).href;
const runtimeUrl = new URL("./runtime.mts", import.meta.url).href;

type RpcCall = { method: string; params: Record<string, unknown> };
async function readCalls(directory: string): Promise<RpcCall[]> {
  return (await readFile(join(directory, "rpc.jsonl"), "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

const createHome = (root = tmpdir()) => mkdtemp(join(root, "eval-home-test-"));

test("saved login refresh survives cleanup without importing config or changing permissions", async (t) => {
  const ambient = await mkdtemp(join(tmpdir(), "eval-login-test-"));
  t.after(() => rm(ambient, { recursive: true, force: true }));
  const auth = join(ambient, "auth.json");
  await writeFile(auth, '{"tokens":{"refresh_token":"synthetic-original"}}');
  if (process.platform !== "win32") await chmod(auth, 0o640);
  const originalMode = (await stat(auth)).mode;
  await writeFile(
    join(ambient, "config.toml"),
    '[mcp_servers.unrelated]\ncommand="unused"\n',
  );
  let home: string | undefined;
  await withEvalState(createHome, ambient, async (state) => {
    home = state.home;
    assert.equal(dirname(home), await realpath(ambient));
    assert.deepEqual(await readdir(home), ["auth.json"]);
    assert.equal(
      (await stat(join(home, "auth.json"))).ino,
      (await stat(auth)).ino,
    );
    assert.equal((await stat(auth)).mode, originalMode);
    const env = { OPENAI_API_KEY: "synthetic-env-key" };
    assert.equal(codexSettings(home, "/tmp/bin/codex", env).apiKey, undefined);
    const explicit = codexSettings(home, "/tmp/bin/codex", {
      ...env,
      CODEX_API_KEY: "synthetic-explicit-key",
    });
    assert.equal(explicit.env.CODEX_API_KEY, "synthetic-explicit-key");
    // The pinned native file store truncates and writes the existing auth file.
    await writeFile(
      join(home, "auth.json"),
      '{"tokens":{"refresh_token":"synthetic-refreshed"}}',
    );
  });
  assert.equal(
    (await readJson(auth)).tokens.refresh_token,
    "synthetic-refreshed",
  );
  assert.equal((await stat(auth)).mode, originalMode);
  await assert.rejects(access(home!), { code: "ENOENT" });
  assert.equal(
    await readFile(join(ambient, "config.toml"), "utf8"),
    '[mcp_servers.unrelated]\ncommand="unused"\n',
  );
});

test("missing file login creates an empty temporary home", async (t) => {
  const ambient = await mkdtemp(join(tmpdir(), "eval-login-test-"));
  t.after(() => rm(ambient, { recursive: true, force: true }));
  await withEvalState(createHome, ambient, async ({ home }) => {
    assert.deepEqual(await readdir(home), []);
  });
});

test(
  "symlink-backed login creates its private home beside the canonical file",
  unixOnly,
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "eval-login-test-"));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const ambient = join(directory, "ambient");
    const store = join(directory, "store");
    await mkdir(ambient);
    await mkdir(store);
    const auth = join(store, "saved.json");
    await writeFile(auth, '{"OPENAI_API_KEY":"synthetic-file-key"}');
    await symlink(auth, join(ambient, "auth.json"));
    await withEvalState(createHome, ambient, async ({ home }) => {
      assert.equal(dirname(home), await realpath(store));
      assert.equal(
        (await stat(join(home, "auth.json"))).ino,
        (await stat(auth)).ino,
      );
    });
    await access(auth);
  },
);

test("an eval does not overwrite a later replacement login", async (t) => {
  const ambient = await mkdtemp(join(tmpdir(), "eval-login-test-"));
  t.after(() => rm(ambient, { recursive: true, force: true }));
  const auth = join(ambient, "auth.json");
  await writeFile(auth, '{"OPENAI_API_KEY":"synthetic-original-key"}');
  await withEvalState(createHome, ambient, async ({ home }) => {
    await rename(auth, join(ambient, "old-auth.json"));
    await writeFile(auth, '{"OPENAI_API_KEY":"synthetic-replacement-key"}');
    await writeFile(
      join(home, "auth.json"),
      '{"OPENAI_API_KEY":"synthetic-refreshed-key"}',
    );
  });
  assert.equal(
    (await readJson(auth)).OPENAI_API_KEY,
    "synthetic-replacement-key",
  );
});

test("the SDK launches long Windows paths with the native namespace prefix", async (t) => {
  const executable = win32.join(
    "C:\\synthetic",
    ...Array(12).fill("nested executable directory"),
    "bin",
    "codex.exe",
  );
  assert.ok(executable.length > 260);
  const platform = Object.getOwnPropertyDescriptor(process, "platform");
  let settings;
  try {
    Object.defineProperty(process, "platform", { value: "win32" });
    settings = codexSettings("C:\\synthetic-home", executable, {});
  } finally {
    Object.defineProperty(process, "platform", platform!);
  }
  assert.equal(settings.env.CODEX_CLI_PATH, executable);

  const intercepted = new Error("Synthetic launch intercepted");
  let launched;
  const spawn = t.mock.method(childProcess, "spawn", (file: string) => {
    launched = file;
    throw intercepted;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      async () => {
        const { events } = await new Codex(settings)
          .startThread({ skipGitRepoCheck: true })
          .runStreamed("Offline synthetic launch check");
        for await (const event of events) void event;
      },
      (error) => error === intercepted,
    );
    assert.equal(spawn.mock.callCount(), 1);
    assert.equal(launched, win32.toNamespacedPath(executable));
  } finally {
    spawn.mock.restore();
    syncBuiltinESMExports();
  }
});

test("the SDK executable override preserves bundled tools at the child boundary", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "eval-tools-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const executable = join(directory, "bin", "codex");
  const tools = join(directory, "codex-path");
  await mkdir(tools);
  const inherited = {
    Path: [tools, join(directory, "other tools"), tools].join(delimiter),
    PATH: [tools, join(directory, "unix tools"), tools].join(delimiter),
  };
  const original = { ...inherited };
  const intercepted = new Error("Synthetic launch intercepted");
  const environments: NodeJS.ProcessEnv[] = [];
  const spawn = t.mock.method(
    childProcess,
    "spawn",
    (
      _file: string,
      _args: string[],
      options: import("node:child_process").SpawnOptions,
    ) => {
      environments.push(options.env!);
      throw intercepted;
    },
  );
  syncBuiltinESMExports();
  try {
    for (const environment of [{}, inherited]) {
      await assert.rejects(
        async () => {
          const settings = codexSettings(directory, executable, environment);
          const { events } = await new Codex(settings)
            .startThread({ skipGitRepoCheck: true })
            .runStreamed("Offline synthetic launch check");
          for await (const event of events) void event;
        },
        (error) => error === intercepted,
      );
    }
    assert.deepEqual(
      environments.map((environment) =>
        Object.fromEntries(
          Object.entries(environment).filter(
            ([key]) => key.toLowerCase() === "path",
          ),
        ),
      ),
      [
        { PATH: tools },
        process.platform === "win32"
          ? { Path: [tools, join(directory, "other tools")].join(delimiter) }
          : {
              ...inherited,
              PATH: [tools, join(directory, "unix tools")].join(delimiter),
            },
      ],
    );
    assert.deepEqual(inherited, original);
  } finally {
    spawn.mock.restore();
    syncBuiltinESMExports();
  }
});

async function waitForFile(path: string) {
  for (let attempt = 0; attempt < 500; attempt++) {
    try {
      await access(path);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await delay(20);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

async function nativeFixture(
  t: import("node:test").TestContext,
  mode = "complete",
  account: { type: string } | null = null,
) {
  const directory = await temporaryDirectory("eval-runtime-test-", true);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await prepareEval(join(directory, "eval"));
  const home = join(directory, "home[private]");
  await mkdir(home);
  const executable = join(directory, "native[local]", "bin", "codex.mjs");
  await mkdir(dirname(executable), { recursive: true });
  const tools = join(dirname(dirname(executable)), "codex-path");
  await mkdir(tools);
  await writeFile(
    join(tools, "rg"),
    `#!${process.execPath}\nconsole.log("synthetic rg");\n`,
    { mode: 0o755 },
  );
  const result = {
    findings: prepared.fixture.positives.map((expected) => ({
      taxonomy: { category: "hardcoded-credentials", cwe: [expected.cwes[0]] },
      locations: [
        { path: expected.path, startLine: expected.line, role: "root_control" },
      ],
      codeEvidence: [
        {
          id: expected.id,
          label: "Credential declaration",
          path: expected.path,
          startLine: expected.line,
          code: prepared.fixture.files[expected.path]
            .split("\n")
            .slice(expected.line - 1, expected.endLine)
            .join("\n"),
          explanation: "Source-backed credential declaration.",
        },
      ],
    })),
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  // Fixed, offline app-server and exec protocol; only generated source and auth exist here.
  await writeFile(
    executable,
    `#!${process.execPath}
import { existsSync, writeFileSync, appendFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { parse } from ${JSON.stringify(tomlUrl)};
const scenario = ${JSON.stringify({ directory, mode, result, account })};
const args = process.argv.slice(2);
const kind = args.includes("app-server") ? "preflight" : "exec";
const cwd = args.includes("--cd") ? args[args.indexOf("--cd") + 1] : process.cwd();
// Last repeated CLI keys win; parse dotted sibling keys together.
const overrides = new Map(args.flatMap((arg, index) => {
  if (arg !== "--config") return [];
  const value = args[index + 1];
  return [[value.slice(0, value.indexOf("=")), value]];
}));
const config = parse([...overrides.values()].join("\\n"));
const record = (name, value) => writeFileSync(join(scenario.directory, name + ".json"), JSON.stringify(value));
const bundledTool = execFileSync("rg", ["--version"], { encoding: "utf8" }).trim();
record(kind, { args, cwd: process.cwd(), effectiveCwd: cwd, config, env: process.env, pid: process.pid, bundledTool });
process.on("SIGTERM", () => {
  setTimeout(() => {
    record(kind + "-stopped", { sourceExists: existsSync(cwd), homeExists: existsSync(process.env.CODEX_HOME) });
    process.exit(0);
  }, 75);
});
const send = (event) => process.stdout.write(JSON.stringify(event) + "\\n");
if (kind === "preflight") {
  setInterval(() => {}, 1000);
  const lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    const request = JSON.parse(line);
    appendFileSync(join(scenario.directory, "rpc.jsonl"), JSON.stringify(request) + "\\n");
    if (request.method === "initialized") return;
    if (request.method === "account/read" && scenario.mode === "account-error") {
      send({ jsonrpc: "2.0", id: request.id, error: { code: -32603, message: "Synthetic account lookup failure" } });
      return;
    }
    let result = {};
    if (request.method === "config/read") result = { config };
    if (request.method === "permissionProfile/list") result = {
      data: [{ id: config.default_permissions, allowed: scenario.mode !== "managed-rejection" }], nextCursor: null,
    };
    if (request.method === "configRequirements/read") result = { requirements: null };
    if (request.method === "account/read") result = { account: scenario.account, requiresOpenaiAuth: true };
    send({ jsonrpc: "2.0", id: request.id, result });
  });
} else {
  process.stdin.resume();
  process.stdin.on("end", () => {
    record("ready", {});
    if (scenario.mode === "block") {
      writeFileSync(join(process.env.CODEX_HOME, "auth.json"), '{"tokens":{"refresh_token":"synthetic-refreshed"}}');
      setInterval(() => {}, 1000); return;
    }
    send({ type: "item.completed", item: { id: "final", type: "agent_message", text: JSON.stringify(scenario.result) } });
    if (scenario.mode.startsWith("fallback-")) {
      const message = "Configured value for \x60permission_profile\x60 is disallowed by requirements; falling back from \x60" + config.default_permissions + "\x60 to required value \x60:read-only\x60.";
      send(scenario.mode === "fallback-item"
        ? { type: "item.completed", item: { id: "warning", type: "error", message } }
        : { type: "error", message });
      setInterval(() => {}, 1000);
    } else {
      send({ type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } });
    }
  });
}
`,
    { mode: 0o755 },
  );
  const settings = codexSettings(home, executable, {
    PATH: dirname(process.execPath),
    Path: join(directory, "unrelated alias"),
    HOME: home,
    OPENAI_API_KEY: "synthetic-env-key",
    DATABASE_URL: "synthetic-unrelated-secret",
  });
  return { directory, prepared, settings, executable, result };
}

test(
  "native preflight and SDK exec share effective settings and fallback auth",
  unixOnly,
  async (t) => {
    const {
      directory,
      prepared,
      settings: original,
      result,
    } = await nativeFixture(t);
    const settings = await preflightEval(
      prepared,
      original,
      new AbortController().signal,
    );
    const { report, semanticResult } = await runPreparedEval(
      prepared,
      new Codex(settings),
    );
    assert.equal(report.passed, true);
    assert.deepEqual(semanticResult, result);
    const preflight = await readJson(join(directory, "preflight.json"));
    const exec = await readJson(join(directory, "exec.json"));
    assert.equal(preflight.cwd, prepared.repo);
    assert.equal(exec.effectiveCwd, prepared.repo);
    assert.equal(exec.config.model_provider, undefined);
    assert.deepEqual(preflight.config, exec.config);
    assert.deepEqual(exec.config.features, {
      memories: false,
      apps: false,
      plugins: false,
      multi_agent: false,
      shell_snapshot: false,
    });
    assert.deepEqual(exec.config.shell_environment_policy, {
      inherit: "core",
      ignore_default_excludes: false,
    });
    assert.equal(exec.config.allow_login_shell, false);
    assert.equal(exec.config.windows.sandbox, "elevated");
    assert.equal(exec.config.approval_policy, "never");
    assert.equal(exec.config.model_reasoning_effort, "xhigh");
    assert.equal(exec.config.web_search, "disabled");
    assert.equal(
      exec.config.default_permissions,
      DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
    );
    assert.equal(
      exec.config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID].network
        .enabled,
      false,
    );
    assert.deepEqual(
      exec.config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID]
        .filesystem[settings.env.CODEX_HOME],
      { ".": "deny" },
    );
    assert.deepEqual(
      exec.config.permissions[DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID]
        .filesystem[dirname(dirname(settings.env.CODEX_CLI_PATH))],
      { ".": "read" },
    );
    assert.equal(exec.args.includes("--sandbox"), false);
    assert.equal(
      exec.args[exec.args.indexOf("--add-dir") + 1],
      prepared.runtime,
    );
    for (const entry of [preflight, exec])
      assert.equal(entry.bundledTool, "synthetic rg");
    assert.equal(exec.env.CODEX_HOME, settings.env.CODEX_HOME);
    assert.equal(exec.env.CODEX_SQLITE_HOME, settings.env.CODEX_HOME);
    assert.equal(exec.env.DATABASE_URL, undefined);
    assert.equal(exec.env.CODEX_API_KEY, "synthetic-env-key");
    assert.equal(original.apiKey, undefined);
    const {
      CODEX_INTERNAL_ORIGINATOR_OVERRIDE,
      CODEX_API_KEY,
      ...execEnvironment
    } = exec.env;
    assert.deepEqual(execEnvironment, preflight.env);
    const calls = await readCalls(directory);
    assert.deepEqual(
      calls.map((call) => call.method),
      [
        "initialize",
        "initialized",
        "config/read",
        "permissionProfile/list",
        "account/read",
      ],
    );
    for (const call of calls.slice(2, 4))
      assert.equal(call.params.cwd, prepared.repo);
    assert.deepEqual(calls[4].params, { refreshToken: false });
  },
);

for (const {
  name,
  authFile,
  account,
  codexApiKey,
  openAiApiKey = " synthetic-env-key \n ",
  expectedKey,
} of [
  {
    name: "missing file login",
    account: null,
    expectedKey: "synthetic-env-key",
  },
  {
    name: "empty auth file",
    authFile: "",
    account: null,
    expectedKey: "synthetic-env-key",
  },
  {
    name: "malformed auth file",
    authFile: "{",
    account: null,
    expectedKey: "synthetic-env-key",
  },
  {
    name: "auth file without an account",
    authFile: "{}",
    account: null,
    expectedKey: "synthetic-env-key",
  },
  {
    name: "native-recognized saved API key",
    authFile: '{"OPENAI_API_KEY":"synthetic-file-key"}',
    account: { type: "apiKey" },
  },
  {
    name: "native-recognized saved ChatGPT login",
    authFile: '{"tokens":{"refresh_token":"synthetic-saved"}}',
    account: { type: "chatgpt" },
  },
  {
    name: "blank Codex key",
    account: null,
    codexApiKey: " \t ",
    expectedKey: "synthetic-env-key",
  },
  {
    name: "explicit Codex key with a malformed auth file",
    authFile: "{",
    account: { type: "apiKey" },
    codexApiKey: "synthetic-codex-key",
    expectedKey: "synthetic-codex-key",
  },
  { name: "blank OpenAI key", account: null, openAiApiKey: " \t " },
]) {
  test(`native auth precedence with ${name}`, unixOnly, async (t) => {
    const {
      directory,
      prepared,
      settings: original,
    } = await nativeFixture(t, "complete", account);
    const ambient = original.env.CODEX_HOME;
    if (authFile !== undefined)
      await writeFile(join(ambient, "auth.json"), authFile);
    await withEvalState(createHome, ambient, async ({ home }) => {
      const initialSettings = codexSettings(home, original.codexPathOverride, {
        ...original.env,
        CODEX_API_KEY: codexApiKey,
        OPENAI_API_KEY: openAiApiKey,
      });
      const settings = await preflightEval(
        prepared,
        initialSettings,
        new AbortController().signal,
      );
      const { report } = await runPreparedEval(prepared, new Codex(settings));
      assert.equal(report.passed, true);
      assert.equal(initialSettings.apiKey, undefined);
      const preflight = await readJson(join(directory, "preflight.json"));
      const exec = await readJson(join(directory, "exec.json"));
      assert.equal(preflight.env.CODEX_API_KEY, codexApiKey);
      assert.equal(exec.env.CODEX_API_KEY, expectedKey);
      assert.equal(preflight.env.CODEX_HOME, home);
      assert.equal(exec.env.CODEX_HOME, home);
      const calls = await readCalls(directory);
      const accountCalls = calls.filter(
        (call) => call.method === "account/read",
      );
      assert.equal(
        accountCalls.length,
        openAiApiKey.trim() && !codexApiKey?.trim() ? 1 : 0,
      );
      if (accountCalls.length)
        assert.deepEqual(accountCalls[0].params, { refreshToken: false });
      if (authFile !== undefined) {
        assert.equal(await readFile(join(home, "auth.json"), "utf8"), authFile);
        assert.equal(
          await readFile(join(ambient, "auth.json"), "utf8"),
          authFile,
        );
      }
    });
  });
}

for (const codexApiKey of [undefined, "synthetic-explicit-key"]) {
  test(
    `Windows mixed-case auth snapshot with ${codexApiKey ? "explicit" : "fallback"} key`,
    unixOnly,
    async (t) => {
      const {
        directory,
        prepared,
        settings: original,
      } = await nativeFixture(t);
      const {
        OPENAI_API_KEY,
        Path: ignoredPathAlias,
        ...environment
      } = original.env;
      environment.OpenAI_API_Key = " synthetic-fallback-key ";
      if (codexApiKey) environment.CodeX_Api_Key = codexApiKey;
      const platform = Object.getOwnPropertyDescriptor(process, "platform");
      let settings;
      try {
        Object.defineProperty(process, "platform", { value: "win32" });
        const snapshot = codexSettings(
          original.env.CODEX_HOME,
          original.codexPathOverride,
          environment,
        );
        assert.equal(snapshot.env.OPENAI_API_KEY, undefined);
        assert.equal(snapshot.env.OpenAI_API_Key, environment.OpenAI_API_Key);
        settings = await preflightEval(
          prepared,
          snapshot,
          new AbortController().signal,
        );
      } finally {
        Object.defineProperty(process, "platform", platform!);
      }
      await runPreparedEval(prepared, new Codex(settings));
      const exec = await readJson(join(directory, "exec.json"));
      assert.equal(
        exec.env.CODEX_API_KEY,
        codexApiKey ? undefined : "synthetic-fallback-key",
      );
      assert.equal(exec.env.CodeX_Api_Key, codexApiKey);
      const calls = await readCalls(directory);
      assert.equal(
        calls.filter((call) => call.method === "account/read").length,
        codexApiKey ? 0 : 1,
      );
    },
  );
}

for (const [mode, expectedError] of [
  ["managed-rejection", /managed Codex policy rejected/],
  ["account-error", /account\/read/],
] as const) {
  test(`${mode} prevents starting the SDK exec turn`, unixOnly, async (t) => {
    const { directory, prepared, settings } = await nativeFixture(t, mode);
    await assert.rejects(async () => {
      const resolved = await preflightEval(
        prepared,
        settings,
        new AbortController().signal,
      );
      await runPreparedEval(prepared, new Codex(resolved));
    }, expectedError);
    await assert.rejects(access(join(directory, "exec.json")), {
      code: "ENOENT",
    });
    await access(join(directory, "preflight-stopped.json"));
  });
}

for (const mode of ["fallback-item", "fallback-error"]) {
  test(
    `${mode} aborts the real SDK turn and discards its response`,
    unixOnly,
    async (t) => {
      const { directory, prepared, settings } = await nativeFixture(t, mode);
      const resolved = await preflightEval(
        prepared,
        settings,
        new AbortController().signal,
      );
      await assert.rejects(
        runPreparedEval(prepared, new Codex(resolved)),
        /results were discarded/,
      );
      await access(join(directory, "exec-stopped.json"));
    },
  );
}

for (const [signal, exitCode] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const) {
  test(
    `${signal} awaits the SDK child before cleanup and preserves refreshed login`,
    unixOnly,
    async (t) => {
      const { directory, executable } = await nativeFixture(t, "block");
      const ambient = join(directory, "ambient");
      await mkdir(ambient);
      await writeFile(
        join(ambient, "auth.json"),
        '{"tokens":{"refresh_token":"synthetic-original"}}',
      );
      const driver = join(directory, "driver.mjs");
      await writeFile(
        driver,
        `
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Codex } from ${JSON.stringify(sdkUrl)};
import { codexSettings, preflightEval, prepareEval, runPreparedEval } from ${JSON.stringify(harnessUrl)};
import { withEvalState } from ${JSON.stringify(runtimeUrl)};
await withEvalState(
  (base) => mkdtemp(join(base, "signal-home-")),
  ${JSON.stringify(ambient)},
async ({ root, home, signal }) => {
  await writeFile(join(${JSON.stringify(directory)}, "state.json"), JSON.stringify({ root, home }));
  const prepared = await prepareEval(root);
  const settings = await preflightEval(prepared,
    codexSettings(home, ${JSON.stringify(executable)}, { PATH: ${JSON.stringify(dirname(process.execPath))}, HOME: home }), signal);
  await runPreparedEval(prepared, new Codex(settings), { signal });
});
`,
      );
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", driver],
        {
          env: {
            PATH: dirname(process.execPath),
            HOME: directory,
            TMPDIR: directory,
          },
          stdio: ["ignore", "ignore", "pipe"],
        },
      );
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      t.after(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      });
      const exited: Promise<unknown> = once(child, "exit");
      await Promise.race([
        waitForFile(join(directory, "ready.json")),
        exited.then(() => {
          throw new Error(`Driver exited before exec was ready: ${stderr}`);
        }),
      ]);
      child.kill(signal);
      assert.deepEqual(await exited, [exitCode, null], stderr);
      const stopped = await readJson(join(directory, "exec-stopped.json"));
      assert.deepEqual(stopped, { sourceExists: true, homeExists: true });
      const state = await readJson(join(directory, "state.json"));
      for (const path of [state.root, state.home]) {
        await assert.rejects(access(path), { code: "ENOENT" });
      }
      assert.equal(
        (await readJson(join(ambient, "auth.json"))).tokens.refresh_token,
        "synthetic-refreshed",
      );
    },
  );
}
