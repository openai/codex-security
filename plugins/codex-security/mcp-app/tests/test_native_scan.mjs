import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { parse as parseToml } from "smol-toml";

const bundle = await build({
  bundle: true,
  stdin: {
    contents: `export * from ${JSON.stringify(fileURLToPath(new URL("../src/native-scan.ts", import.meta.url)))};
      export { createPermissionCheckedCodex } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/permission-profile.ts", import.meta.url)))};
      export { scanRuntimeCodexConfig } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/api.ts", import.meta.url)))};`,
    resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
  },
  define: {
    "import.meta.url": JSON.stringify(
      new URL("../src/native-scan.ts", import.meta.url).href,
    ),
  },
  format: "cjs",
  platform: "node",
  write: false,
  plugins: [
    {
      name: "capture-ordinary-client",
      setup(build) {
        build.onResolve({ filter: /sdk\/typescript\/src\/api\.js$/ }, () => ({
          path: "client",
          namespace: "fixture",
        }));
        build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
          resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
          contents: `export { selectedScanEnvironment } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/api.ts", import.meta.url)))};
             export class CodexSecurity { constructor(config, dependencies) { this.config = config; this.dependencies = dependencies; } }`,
        }));
      },
    },
  ],
});
const module = { exports: {} };
new Function("require", "module", "exports", bundle.outputFiles[0].text)(
  createRequire(import.meta.url),
  module,
  module.exports,
);
const {
  NativeScanHost,
  prepareNativeScan,
  nativeScanConfiguration,
  scanRuntimeCodexConfig,
  createPermissionCheckedCodex,
} = module.exports;

async function collectNativeEvents(thread, prompt, options) {
  const { events } = await thread.runStreamed(prompt, options);
  const collected = [];
  for await (const event of events) collected.push(event);
  return collected;
}

function syntheticPermissionAppServer() {
  return `function servePermissionProfiles() {
  const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
  const config = {};
  const argv = process.argv.slice(2);
  function merge(target, value) {
    for (const [key, child] of Object.entries(value)) {
      if (child && typeof child === "object" && !Array.isArray(child)) {
        target[key] = merge(target[key] ?? {}, child);
      } else target[key] = child;
    }
    return target;
  }
  for (let index = 0; index < argv.length; index++) {
    if (argv[index] === "--config" || argv[index] === "-c") merge(config, parse(argv[++index]));
  }
  const scenario = process.env.NATIVE_PROFILE_SCENARIO
    ? fs.readFileSync(process.env.NATIVE_PROFILE_SCENARIO, "utf8").trim() : "valid";
  const selected = config.default_permissions;
  const profile = config.permissions[selected];
  profile.description = "Synthetic profile description";
  profile.network.fixtureNull = null;
  if (scenario === "substituted-default") config.default_permissions = ":read-only";
  if (scenario === "substituted-profile") {
    for (const [key, value] of Object.entries(profile.filesystem)) {
      if (value === "deny") delete profile.filesystem[key];
    }
  }
  const capture = (value) => {
    if (process.env.NATIVE_PROFILE_CAPTURE) fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify(value) + "\\n");
  };
  capture({ kind: "preflight", argv, cwd: process.cwd(), marker: process.env.NATIVE_PROFILE_MARKER,
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY });
  require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {
    const request = JSON.parse(line);
    capture({ kind: "request", method: request.method, params: request.params });
    if (request.id === undefined) return;
    let result;
    if (request.method === "initialize") result = {};
    else if (request.method === "config/read") result = { config };
    else if (request.method === "permissionProfile/list") result = request.params?.cursor === "selected-page"
      ? { data: [{ id: selected, allowed: scenario !== "disallowed" }], nextCursor: null }
      : { data: [{ id: "other-profile", allowed: true }], nextCursor: "selected-page" };
    else throw new Error("Unexpected app-server request " + request.method);
    console.log(JSON.stringify({ id: request.id, result }));
  });
}`;
}

function input(id = "parent") {
  return {
    scan: {
      scanId: id,
      scanDir: join(tmpdir(), id),
      targetPath: tmpdir(),
      userContext: "Review the boundary.",
    },
    threadId: "native-owner",
    pluginRoot: tmpdir(),
    pythonPath: process.execPath,
    parentSandbox: { filesystemDenies: [] },
  };
}

test("native waiters join one ordinary scan and detaching leaves it running", async () => {
  const started = Promise.withResolvers();
  const completed = Promise.withResolvers();
  let preparations = 0;
  let closes = 0;
  let signal;
  const host = new NativeScanHost(async () => {
    preparations++;
    return {
      options: { mode: "deep" },
      client: {
        run(_repository, options) {
          signal = options.signal;
          started.resolve();
          return completed.promise;
        },
        async close() {
          closes++;
        },
      },
    };
  });
  const waiter = new AbortController();
  const first = host.run(input(), waiter.signal);
  const joined = host.run(input());
  await started.promise;
  const rejected = assert.rejects(first, /detached/);
  waiter.abort(new Error("detached"));
  await rejected;
  assert.equal(signal.aborted, false);
  completed.resolve({ scanDir: "sealed-parent" });
  assert.deepEqual(await joined, { scanDir: "sealed-parent" });
  assert.equal(preparations, 1);
  assert.equal(closes, 1);
});

for (const outcome of ["completed", "failed"]) {
  test(`native cleanup preserves the ${outcome} scan outcome and drains before rejoining`, async (t) => {
    const closing = Promise.withResolvers();
    const releaseClose = Promise.withResolvers();
    const primaryError = new Error("Synthetic startup failure");
    const cleanupError = new Error("Synthetic bootstrap cleanup failure");
    const result = { scanDir: "sealed-parent" };
    const warnings = [];
    t.mock.method(console, "warn", (...args) => {
      warnings.push(args);
      if (warnings.length === 2) throw new Error("Synthetic warning failure");
    });
    let preparations = 0;
    const host = new NativeScanHost(async () => {
      preparations++;
      return {
        options: { mode: "deep" },
        client: {
          async run() {
            if (outcome === "failed") throw primaryError;
            return result;
          },
          async close() {
            closing.resolve();
            await releaseClose.promise;
          },
        },
      };
    });
    const first = host.run(input());
    const joined = host.run(input());
    let settled = false;
    void first.then(() => { settled = true; }, () => { settled = true; });
    await closing.promise;
    assert.equal(settled, false);
    assert.equal(preparations, 1);
    releaseClose.reject(cleanupError);
    for (const pending of [first, joined]) {
      if (outcome === "failed") await assert.rejects(pending, (error) => error === primaryError);
      else assert.equal(await pending, result);
    }
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0][1], cleanupError);
    const next = host.run(input());
    if (outcome === "failed") await assert.rejects(next, (error) => error === primaryError);
    else assert.equal(await next, result);
    assert.equal(preparations, 2);
    assert.equal(warnings.length, 2);
  });
}

test("native cancellation drains only its parent; shutdown drains the rest", async () => {
  const started = new Map();
  const closed = [];
  const closing = Promise.withResolvers();
  const releaseClose = Promise.withResolvers();
  const host = new NativeScanHost(async ({ scan }) => ({
    options: { mode: "deep" },
    client: {
      run(_repository, { signal }) {
        started.set(scan.scanId, signal);
        return new Promise((_resolve, reject) =>
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          }),
        );
      },
      async close() {
        if (scan.scanId === "second") {
          closing.resolve();
          await releaseClose.promise;
        }
        closed.push(scan.scanId);
      },
    },
  }));
  const first = host.run(input("first"));
  const second = host.run(input("second"));
  const firstRejected = assert.rejects(first, /user_canceled_scan/);
  const secondRejected = assert.rejects(second, (error) => {
    assert.equal(error.constructor.name, "ScanTransportClosedError");
    assert.equal(error.message, "mcp_transport_closed");
    return true;
  });
  await Promise.resolve();
  await Promise.resolve();
  await host.cancel("first");
  await firstRejected;
  assert.equal(started.get("first").reason.constructor, Error);
  assert.equal(started.get("second").aborted, false);
  assert.deepEqual(closed, ["first"]);
  let drained = false;
  const shutdown = host.close().then(() => {
    drained = true;
  });
  await closing.promise;
  assert.equal(drained, false);
  assert.deepEqual(closed, ["first"]);
  releaseClose.resolve();
  await shutdown;
  await secondRejected;
  assert.deepEqual(closed, ["first", "second"]);
});

test("native scans preserve selected Codex homes and saved settings", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-codex-home-")),
  );
  const defaultHome = join(root, ".codex");
  const explicitHome = join(root, "explicit");
  const spacedHome = join(root, "explicit ");
  const pluginRoot = join(root, "plugin");
  const keys = [
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ];
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, {
      HOME: root,
      USERPROFILE: root,
      CODEX_CLI_PATH: process.execPath,
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
    await writeFile(
      join(pluginRoot, ".codex-plugin/plugin.json"),
      JSON.stringify({ name: "codex-security", version: "0.0.0" }),
    );
    const homes = [
      [defaultHome, "synthetic-default", 2],
      [explicitHome, "synthetic-explicit", 4],
      ...(process.platform === "win32"
        ? []
        : [[spacedHome, "synthetic-spaced", 3]]),
    ];
    for (const [home, model, workers] of homes) {
      await mkdir(join(home, "codex-security"), { recursive: true });
      await writeFile(join(home, "config.toml"), `model = "${model}"\n`);
      await writeFile(
        join(home, "codex-security/config.toml"),
        `[deep_scan]\nworkers = ${workers}\n`,
      );
    }
    const nested = join(explicitHome, "nested");
    const link = join(defaultHome, "link");
    await mkdir(nested);
    await symlink(
      nested,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const linkedHome = `${link}${sep}..`;
    const physicalHome = await realpath(linkedHome);
    const linkedSettings = homes.find(([home]) => home === physicalHome);
    assert.ok(linkedSettings);
    for (const [override, home, model, workers] of [
      [undefined, defaultHome, "synthetic-default", 2],
      ["", defaultHome, "synthetic-default", 2],
      [" \t\n", defaultHome, "synthetic-default", 2],
      [explicitHome, explicitHome, "synthetic-explicit", 4],
      ...(process.platform === "win32"
        ? []
        : [[spacedHome, spacedHome, "synthetic-spaced", 3]]),
      [linkedHome, ...linkedSettings],
    ]) {
      if (override === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = override;
      for (const saved of [false, true]) {
        const prepared = await prepareNativeScan({
          ...input(),
          pluginRoot,
          recipe: {
            auth: "api-key",
            ...(saved
              ? {
                  config: { model: "synthetic-saved" },
                  deepScan: { workers: 6 },
                }
              : {}),
          },
        });
        assert.equal(
          prepared.client.config.codexOverrides.model,
          saved ? "synthetic-saved" : model,
        );
        assert.equal(prepared.options.workers, saved ? 6 : workers);
        const runtime = await prepared.client.dependencies.prepareRuntime({});
        try {
          const expectedHome = await realpath(home);
          assert.equal(runtime.codexHome, expectedHome);
          assert.equal(runtime.environment.CODEX_HOME, expectedHome);
          assert.equal(process.env.CODEX_HOME, override);
        } finally {
          await rm(runtime.bootstrapWorkspace, {
            recursive: true,
            force: true,
          });
        }
      }
    }
  } finally {
    for (const key of keys) {
      if (before[key] === undefined) delete process.env[key];
      else process.env[key] = before[key];
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("native blank Codex homes reach fresh and resumed SDK children", {
  skip: process.platform === "win32" ? "Synthetic executable uses a POSIX shebang." : false,
}, async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "native-blank-home-")));
  const home = join(root, ".codex");
  const repository = join(root, "repository");
  const pluginRoot = join(root, "plugin");
  const executable = join(root, "codex");
  const capture = join(root, "child.json");
  const keys = [
    "HOME", "USERPROFILE", "CODEX_HOME", "CODEX_CLI_PATH", "CODEX_API_KEY",
    "OPENAI_API_KEY", "CODEX_SECURITY_CONFIG_PATH", "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ];
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  try {
    await Promise.all([
      mkdir(home), mkdir(repository), mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true }),
    ]);
    await writeFile(join(home, "config.toml"), 'model = "synthetic-current"\n');
    await writeFile(join(pluginRoot, ".codex-plugin/plugin.json"), JSON.stringify({ name: "codex-security", version: "0.0.0" }));
    await writeFile(executable, `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) {
  servePermissionProfiles();
} else {
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ home: process.env.CODEX_HOME, argv: process.argv.slice(2) }));
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-home-thread" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`, { mode: 0o700 });
    Object.assign(process.env, {
      HOME: root, USERPROFILE: root, CODEX_HOME: " \t\n",
      CODEX_CLI_PATH: executable, CODEX_API_KEY: "synthetic-home-key",
    });
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    for (const resumed of [false, true]) {
      const prepared = await prepareNativeScan({
        ...input(), pluginRoot, model: "synthetic-current", reasoningEffort: "ultra",
        recipe: { auth: "api-key", ...(resumed ? { config: { model: "synthetic-saved" } } : {}) },
      });
      const runtime = await prepared.client.dependencies.prepareRuntime({});
      try {
        const sdk = prepared.client.dependencies.createCodex({
          codexPathOverride: executable,
          config: scanRuntimeCodexConfig(prepared.client.config.codexOverrides, repository, prepared.client.dependencies.inheritedPermissions),
          env: runtime.environment,
        });
        const options = { workingDirectory: repository, skipGitRepoCheck: true, approvalPolicy: "never" };
        const thread = resumed ? sdk.resumeThread("synthetic-home-thread", options) : sdk.startThread(options);
        const events = await collectNativeEvents(thread, "Synthetic home selection only.");
        assert.equal(events.at(-1).type, "turn.completed");
        const observed = JSON.parse(await readFile(capture, "utf8"));
        assert.equal(observed.home, await realpath(home));
        assert.equal(observed.argv.includes("resume"), resumed);
        assert.ok(observed.argv.includes(`model=${JSON.stringify(resumed ? "synthetic-saved" : "synthetic-current")}`));
        assert.equal(process.env.CODEX_HOME, " \t\n");
      } finally {
        await rm(runtime.bootstrapWorkspace, { recursive: true, force: true });
      }
    }
  } finally {
    for (const key of keys) {
      if (before[key] === undefined) delete process.env[key];
      else process.env[key] = before[key];
    }
    await rm(root, { recursive: true, force: true });
  }
});

test("native launches snapshot safety identifiers and prefer saved recipes", async () => {
  const root = await mkdtemp(join(tmpdir(), "native-safety-identifier-"));
  const keys = [
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SAFETY_IDENTIFIER",
  ];
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, {
      CODEX_HOME: root,
      CODEX_CLI_PATH: process.execPath,
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    await writeFile(
      join(root, "config.toml"),
      'model_provider = "synthetic"\n[model_providers.synthetic]\nbase_url = "https://example.invalid"\n',
    );
    const launches = [
      ["synthetic-fresh", undefined, "synthetic-fresh"],
      ["synthetic-resumed", {}, "synthetic-resumed"],
      [
        "synthetic-current",
        { safetyIdentifier: "synthetic-saved" },
        "synthetic-saved",
      ],
      [undefined, undefined, undefined],
    ].map(([ambient, recipe, expected], index) => {
      if (ambient === undefined) delete process.env.CODEX_SAFETY_IDENTIFIER;
      else process.env.CODEX_SAFETY_IDENTIFIER = ambient;
      return prepareNativeScan({ ...input(`parent-${index}`), recipe }).then(
        ({ client, options }) => {
          assert.equal(options.safetyIdentifier, expected);
          assert.equal(
            client.dependencies.environment.CODEX_SAFETY_IDENTIFIER,
            ambient,
          );
        },
      );
    });
    await Promise.all(launches);
    assert.equal(process.env.CODEX_SAFETY_IDENTIFIER, undefined);
  } finally {
    for (const key of keys) {
      if (before[key] === undefined) delete process.env[key];
      else process.env[key] = before[key];
    }
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "native worker turns verify the selected permissions before fresh and resumed execution",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-permission-child-")),
    );
    const executable = join(root, "codex");
    const capture = join(root, "capture.jsonl");
    const scenario = join(root, "scenario");
    const fallback =
      "Configured value for `permission_profile` is disallowed by requirements; falling back from `codex_security_scan` to required value `:read-only`.";
    const observations = async () =>
      (await readFile(capture, "utf8"))
        .trim()
        .split("\n")
        .filter(Boolean)
        .map(JSON.parse);
    const rawConfig = (argv) =>
      argv.flatMap((value, index) =>
        value === "--config" || value === "-c" ? [argv[index + 1]] : [],
      );
    const permissionError = (error) => {
      assert.equal(error.constructor.name, "ScanPermissionError");
      return true;
    };
    try {
      await writeFile(
        executable,
        `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) {
  servePermissionProfiles();
} else {
  const capture = (value) => fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify(value) + "\\n");
  capture({ kind: "exec", argv: process.argv.slice(2), marker: process.env.NATIVE_PROFILE_MARKER,
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY });
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-worker-thread" }));
  const scenario = fs.readFileSync(process.env.NATIVE_PROFILE_SCENARIO, "utf8").trim();
  if (scenario.startsWith("late-fallback")) {
    process.on("SIGTERM", () => { capture({ kind: "aborted" }); process.exit(0); });
    console.log(JSON.stringify(scenario === "late-fallback-error"
      ? { type: "error", message: ${JSON.stringify(fallback)} }
      : { type: "item.completed", item: { type: "error", message: ${JSON.stringify(fallback)} } }));
    setTimeout(() => {
      console.log(JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "must not be consumed" } }));
      console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
      process.exit(0);
    }, 500);
  } else {
    console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
  }
}
`,
        { mode: 0o700 },
      );
      for (const role of ["discovery", "merge", "comparison"]) {
        const cwd = join(root, role);
        await mkdir(cwd);
        const config = scanRuntimeCodexConfig(
          { approval_policy: "on-request" },
          root,
          {
            filesystem: {
              [join(root, "private")]: "deny",
              glob_scan_max_depth: 3,
            },
            network: { enabled: false },
          },
        );
        const profileId =
          role === "comparison"
            ? "codex_security_comparison"
            : "codex_security_scan";
        const configOverrides = [
          `default_permissions=${JSON.stringify(profileId)}`,
        ];
        if (role === "comparison") {
          configOverrides.push(
            `permissions.codex_security_comparison={extends=":read-only",filesystem={${JSON.stringify(join(root, "private"))}="deny"},network={enabled=false}}`,
          );
        }
        const sdk = createPermissionCheckedCodex({
          codexPathOverride: executable,
          config: { ...config, default_permissions: ":read-only" },
          configOverrides,
          apiKey: "synthetic-final-key",
          env: {
            CODEX_HOME: root,
            CODEX_API_KEY: "synthetic-stale-key",
            NATIVE_PROFILE_CAPTURE: capture,
            NATIVE_PROFILE_SCENARIO: scenario,
            NATIVE_PROFILE_MARKER: role,
          },
        });
        for (const resumed of [false, true]) {
          const options = {
            workingDirectory: cwd,
            skipGitRepoCheck: true,
            approvalPolicy: "never",
            ...(role === "comparison"
              ? { networkAccessEnabled: false, webSearchMode: "disabled" }
              : {}),
          };
          const thread = resumed
            ? sdk.resumeThread(`synthetic-${role}-thread`, options)
            : sdk.startThread(options);
          await writeFile(scenario, "valid");
          await writeFile(capture, "");
          const events = await collectNativeEvents(
            thread,
            "Synthetic permission verification.",
          );
          assert.equal(events.at(-1).type, "turn.completed");
          assert.equal(thread.id, "synthetic-worker-thread");
          const observed = await observations();
          const preflight = observed.find(
            (entry) => entry.kind === "preflight",
          );
          const executed = observed.find((entry) => entry.kind === "exec");
          assert.equal(preflight.cwd, cwd);
          assert.equal(executed.argv[executed.argv.indexOf("--cd") + 1], cwd);
          assert.equal(executed.argv.includes("resume"), resumed);
          assert.deepEqual(rawConfig(preflight.argv), rawConfig(executed.argv));
          assert.equal(
            rawConfig(preflight.argv).at(-1),
            'approval_policy="never"',
          );
          for (const process of [preflight, executed]) {
            assert.equal(process.marker, role);
            assert.equal(process.codex, "synthetic-final-key");
            assert.equal(process.openai, undefined);
          }
          const requests = observed.filter((entry) => entry.kind === "request");
          assert.deepEqual(
            requests.map((entry) => entry.method),
            [
              "initialize",
              "initialized",
              "config/read",
              "permissionProfile/list",
              "permissionProfile/list",
            ],
          );
          for (const request of requests.slice(2))
            assert.equal(request.params.cwd, cwd);
          assert.equal(requests.at(-1).params.cursor, "selected-page");
          if (role === "comparison") break;

          for (const rejectedScenario of [
            "disallowed",
            "substituted-default",
            "substituted-profile",
          ]) {
            await writeFile(scenario, rejectedScenario);
            await writeFile(capture, "");
            await assert.rejects(
              collectNativeEvents(thread, "Recheck the same worker turn."),
              permissionError,
            );
            assert.equal(
              (await observations()).filter((entry) => entry.kind === "exec")
                .length,
              0,
            );
          }
          for (const lateScenario of [
            "late-fallback-item",
            "late-fallback-error",
          ]) {
            await writeFile(scenario, lateScenario);
            await writeFile(capture, "");
            const streamed = await thread.runStreamed(
              "Stop on a late permission fallback.",
            );
            const yielded = [];
            await assert.rejects(async () => {
              for await (const event of streamed.events) yielded.push(event);
            }, permissionError);
            assert.deepEqual(
              yielded.map((event) => event.type),
              ["thread.started"],
            );
            for (let attempt = 0; attempt < 100; attempt += 1) {
              if (
                (await observations()).some((entry) => entry.kind === "aborted")
              )
                break;
              await delay(10);
            }
            assert.ok(
              (await observations()).some((entry) => entry.kind === "aborted"),
            );
          }
        }
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test(
  "native-selected credentials reach actual SDK child processes",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await mkdtemp(join(tmpdir(), "native-auth-child-"));
    const executable = join(root, "codex");
    const capture = join(root, "capture.json");
    const keys = [
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
    ];
    const before = Object.fromEntries(
      keys.map((key) => [key, process.env[key]]),
    );
    try {
      await writeFile(
        executable,
        `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) {
  servePermissionProfiles();
} else {
if (process.argv.includes("login")) {
  fs.writeFileSync(${JSON.stringify(join(root, "login.json"))}, JSON.stringify({
    codex: process.env.CODEX_API_KEY,
    openai: process.env.OPENAI_API_KEY,
    argv: process.argv.slice(2),
  }));
  if (fs.existsSync(${JSON.stringify(join(root, "account-error"))})) {
    console.error("Could not access the selected keyring");
    process.exit(2);
  }
  const authenticated = fs.existsSync(${JSON.stringify(join(root, "account-present"))});
  console.error(authenticated ? "Logged in using ChatGPT" : "Not logged in");
  process.exit(authenticated ? 0 : 1);
}
fs.writeFileSync(process.env.NATIVE_AUTH_CAPTURE, JSON.stringify({
  codex: process.env.CODEX_API_KEY,
  openai: process.env.OPENAI_API_KEY,
  executable: process.execPath,
  argv: process.argv.slice(2),
}));
console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-auth-thread" }));
console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
      );
      await chmod(executable, 0o700);
      Object.assign(process.env, {
        CODEX_HOME: root,
        CODEX_CLI_PATH: executable,
        CODEX_API_KEY: "synthetic-native-selected",
        OPENAI_API_KEY: "synthetic-competing-key",
      });
      delete process.env.CODEX_SECURITY_CONFIG_PATH;
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      for (const [provider, modelProvider] of [
        [undefined, undefined],
        [{ env_key: "OPENAI_API_KEY" }, "custom"],
        [
          { auth: { type: "command", command: "synthetic-auth-provider" } },
          "custom",
        ],
        [{ requires_openai_auth: true }, "custom"],
        [{ env_key: "OPENAI_API_KEY" }, undefined],
        [
          { auth: { type: "command", command: "synthetic-auth-provider" } },
          undefined,
        ],
      ]) {
        const selected = provider !== undefined;
        const providerName = modelProvider ?? "openai";
        const configured = selected && provider.requires_openai_auth !== true;
        const config = {
          model: "saved-model",
          model_reasoning_effort: "ultra",
          approval_policy: "on-request",
          ...(selected
            ? {
                ...(modelProvider === undefined
                  ? {}
                  : { model_provider: modelProvider }),
                model_providers: { [providerName]: provider },
              }
            : {}),
        };
        await writeFile(
          join(root, "config.toml"),
          selected
            ? 'approval_policy = "on-request"\n' +
                (modelProvider === undefined
                  ? ""
                  : `model_provider = "${modelProvider}"\n`) +
                `[model_providers.${providerName}]\n` +
                (provider.auth
                  ? `[model_providers.${providerName}.auth]\ntype = "command"\ncommand = "synthetic-auth-provider"\n`
                  : provider.requires_openai_auth
                    ? "requires_openai_auth = true\n"
                    : 'env_key = "OPENAI_API_KEY"\n')
            : "",
        );
        for (const recipe of [undefined, { auth: "api-key", config }]) {
          const prepared = await prepareNativeScan({
            ...input(),
            recipe,
            model: "current-model",
            reasoningEffort: "low",
          });
          assert.equal(
            prepared.options.preserveProviderEnvironment,
            configured ? true : undefined,
          );
          assert.equal(
            prepared.client.config.codexOverrides.model_provider,
            selected ? providerName : undefined,
          );
          const sdk = prepared.client.dependencies.createCodex({
            codexPathOverride: executable,
            config: scanRuntimeCodexConfig(
              prepared.client.config.codexOverrides,
              root,
              {
                filesystem: { [join(root, "private")]: "deny" },
                network: { enabled: false },
              },
            ),
            env: {
              ...prepared.client.dependencies.environment,
              NATIVE_AUTH_CAPTURE: capture,
            },
          });
          await collectNativeEvents(
            sdk.startThread({ workingDirectory: root, skipGitRepoCheck: true }),
            "Synthetic credential launch only.",
          );
          const observed = JSON.parse(await readFile(capture, "utf8"));
          assert.ok(observed.argv.includes('approval_policy="never"'));
          assert.equal(observed.codex, "synthetic-native-selected");
          assert.equal(
            observed.openai,
            configured ? "synthetic-competing-key" : undefined,
          );
          assert.ok(
            observed.argv.includes(
              `model=${JSON.stringify(recipe ? "saved-model" : "current-model")}`,
            ),
          );
          assert.ok(
            observed.argv.includes(
              `model_reasoning_effort=${JSON.stringify(recipe ? "ultra" : "low")}`,
            ),
          );
          assert.equal(observed.executable, process.execPath);
          assert.equal(process.env.CODEX_API_KEY, "synthetic-native-selected");
          assert.equal(process.env.OPENAI_API_KEY, "synthetic-competing-key");
          if (!selected) {
            await collectNativeEvents(
              sdk.resumeThread("synthetic-auth-thread", {
                workingDirectory: root,
                skipGitRepoCheck: true,
              }),
              "Synthetic resumed launch only.",
            );
            const resumed = JSON.parse(await readFile(capture, "utf8"));
            assert.ok(resumed.argv.includes('approval_policy="never"'));
            assert.equal(
              resumed.argv.includes('approval_policy="on-request"'),
              false,
            );
          }
        }
      }
      const prepared = await prepareNativeScan(input());
      const executionConfig = {
        model: "native-config-model",
        mcp_servers: {
          "synthetic.server": {
            command: "synthetic-command",
            env: { "SYNTHETIC.SETTING": "selected" },
          },
        },
        shell_environment_policy: { set: { "SYNTHETIC.SETTING": "selected" } },
        features: { plugins: false },
      };
      const configuredSdk = prepared.client.dependencies.createCodex({
        codexPathOverride: executable,
        env: {
          ...prepared.client.dependencies.environment,
          NATIVE_AUTH_CAPTURE: capture,
        },
        config: scanRuntimeCodexConfig(executionConfig, root, {
          filesystem: { [join(root, "private")]: "deny" },
          network: { enabled: false },
        }),
        configOverrides: ['model="explicit-model"'],
      });
      await collectNativeEvents(
        configuredSdk.startThread({
          workingDirectory: root,
          skipGitRepoCheck: true,
        }),
        "Synthetic config launch only.",
      );
      const configArguments = JSON.parse(await readFile(capture, "utf8")).argv;
      for (const name of [
        "mcp_servers",
        "shell_environment_policy",
        "features",
      ]) {
        assert.deepEqual(
          parseToml(
            configArguments.find((argument) => argument.startsWith(`${name}=`)),
          )[name],
          executionConfig[name],
        );
      }
      assert.ok(
        configArguments.indexOf('model="explicit-model"') >
          configArguments.indexOf('model="native-config-model"'),
      );
      const accountConfig = {
        cli_auth_credentials_store: "file",
        forced_chatgpt_workspace_id: "synthetic-workspace",
      };
      await writeFile(
        join(root, "config.toml"),
        'cli_auth_credentials_store = "file"\nforced_chatgpt_workspace_id = "synthetic-workspace"\n',
      );
      delete process.env.CODEX_API_KEY;
      for (const authenticated of [true, false]) {
        if (authenticated)
          await writeFile(join(root, "account-present"), "synthetic");
        else await rm(join(root, "account-present"));
        for (const recipe of [
          undefined,
          { auth: "auto", config: accountConfig },
        ]) {
          const prepared = await prepareNativeScan({ ...input(), recipe });
          const login = JSON.parse(
            await readFile(join(root, "login.json"), "utf8"),
          );
          assert.equal(login.codex, undefined);
          assert.equal(login.openai, undefined);
          assert.ok(login.argv.includes('cli_auth_credentials_store="file"'));
          assert.ok(
            login.argv.includes(
              'forced_chatgpt_workspace_id="synthetic-workspace"',
            ),
          );
          assert.equal(
            prepared.options.auth,
            authenticated ? "chatgpt" : recipe?.auth,
          );
          assert.equal(
            prepared.client.dependencies.environment.OPENAI_API_KEY,
            authenticated ? undefined : "synthetic-competing-key",
          );
          assert.equal(process.env.OPENAI_API_KEY, "synthetic-competing-key");
        }
      }
      await writeFile(join(root, "account-error"), "synthetic");
      for (const [provider, providerToml] of [
        [undefined, ""],
        [{ requires_openai_auth: true }, "requires_openai_auth = true\n"],
        [
          { requires_openai_auth: true, env_key: "OPENAI_API_KEY" },
          'requires_openai_auth = true\nenv_key = "OPENAI_API_KEY"\n',
        ],
        [
          { auth: { type: "command", command: "synthetic-auth-provider" } },
          '[model_providers.custom.auth]\ntype = "command"\ncommand = "synthetic-auth-provider"\n',
        ],
      ]) {
        const config = {
          ...accountConfig,
          ...(provider && {
            model_provider: "custom",
            model_providers: { custom: provider },
          }),
        };
        await writeFile(
          join(root, "config.toml"),
          'cli_auth_credentials_store = "file"\nforced_chatgpt_workspace_id = "synthetic-workspace"\n' +
            (provider
              ? 'model_provider = "custom"\n[model_providers.custom]\n' +
                providerToml
              : ""),
        );
        for (const recipe of [undefined, { auth: "auto", config }]) {
          await rm(join(root, "login.json"), { force: true });
          if (provider?.env_key || provider?.auth) {
            const prepared = await prepareNativeScan({ ...input(), recipe });
            assert.equal(prepared.options.preserveProviderEnvironment, true);
            assert.equal(
              prepared.client.dependencies.environment.OPENAI_API_KEY,
              "synthetic-competing-key",
            );
            await assert.rejects(readFile(join(root, "login.json")), {
              code: "ENOENT",
            });
          } else {
            await assert.rejects(prepareNativeScan({ ...input(), recipe }), {
              name: "CodexSecurityError",
              message: "Could not access the selected keyring",
            });
            const login = JSON.parse(
              await readFile(join(root, "login.json"), "utf8"),
            );
            assert.ok(login.argv.includes('cli_auth_credentials_store="file"'));
            assert.ok(
              login.argv.includes(
                'forced_chatgpt_workspace_id="synthetic-workspace"',
              ),
            );
            assert.equal(login.openai, undefined);
            assert.equal(login.codex, undefined);
          }
          assert.equal(process.env.OPENAI_API_KEY, "synthetic-competing-key");
        }
      }
      await rm(join(root, "account-error"));
      await writeFile(join(root, "account-present"), "synthetic");
      await writeFile(
        join(root, "config.toml"),
        'model_provider = "custom"\n[model_providers.custom]\nrequires_openai_auth = true\n',
      );
      for (const recipe of [
        undefined,
        {
          auth: "auto",
          config: {
            model_provider: "custom",
            model_providers: { custom: { requires_openai_auth: true } },
          },
        },
      ]) {
        await rm(join(root, "login.json"), { force: true });
        const prepared = await prepareNativeScan({ ...input(), recipe });
        assert.equal(prepared.options.preserveProviderEnvironment, undefined);
        assert.equal(prepared.options.auth, "chatgpt");
        assert.equal(
          prepared.client.dependencies.environment.OPENAI_API_KEY,
          undefined,
        );
        const login = JSON.parse(
          await readFile(join(root, "login.json"), "utf8"),
        );
        assert.equal(login.openai, undefined);
        assert.equal(process.env.OPENAI_API_KEY, "synthetic-competing-key");
      }
      await rm(join(root, "login.json"));
      const forced = await prepareNativeScan({
        ...input(),
        recipe: { auth: "auto", config: { forced_login_method: "chatgpt" } },
      });
      assert.equal(forced.options.auth, "chatgpt");
      assert.equal(
        forced.client.dependencies.environment.OPENAI_API_KEY,
        undefined,
      );
      await assert.rejects(readFile(join(root, "login.json")), {
        code: "ENOENT",
      });
    } finally {
      for (const key of keys) {
        if (before[key] === undefined) delete process.env[key];
        else process.env[key] = before[key];
      }
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("native saved scans retain settings, auth environment, permissions and identity", async () => {
  const root = await mkdtemp(join(tmpdir(), "native-scan-settings-"));
  const keys = [
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  ];
  const before = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  try {
    await writeFile(
      join(root, "config.toml"),
      'model_provider = "synthetic"\n[model_providers.synthetic]\nbase_url = "https://example.invalid"\nwire_api = "responses"\n[plugins]\nfixture = true\n',
    );
    await writeFile(
      join(root, "selected.toml"),
      'model = "selected-model"\nmodel_reasoning_summary = "detailed"\n[agents]\nmax_threads = 20\nmax_depth = 2\n[features]\nenable_fanout = false\n[features.multi_agent_v2]\nenabled = false\n',
    );
    Object.assign(process.env, {
      CODEX_HOME: root,
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_CONFIG_PATH: join(root, "selected.toml"),
      CODEX_API_KEY: "synthetic-key",
      OPENAI_API_KEY: "synthetic-other-key",
      OPENROUTER_API_KEY: "synthetic-provider-key",
    });
    delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    const request = {
      ...input(),
      model: "active-model",
      reasoningEffort: "ultra",
      stateDirectory: join(root, "state"),
      parentSandbox: {
        filesystemDenies: ["/fixture/.env"],
        globScanMaxDepth: 3,
      },
      scan: { ...input().scan, handoffClaimToken: "saved-claim" },
      recipe: {
        auth: "api-key",
        target: { kind: "paths", paths: ["src/auth", "src/data"] },
        deepScan: { workers: 4, subagents: 3 },
        maxCostUsd: 10,
        postScanPrompt: "Publish once.",
      },
    };
    const { client, options } = await prepareNativeScan(request);
    assert.equal(client.config.pluginPath, request.pluginRoot);
    assert.equal(client.config.codexOverrides.model, "active-model");
    assert.equal(client.config.codexOverrides.model_reasoning_effort, "ultra");
    assert.equal(
      client.config.codexOverrides.model_reasoning_summary,
      "detailed",
    );
    assert.equal(
      client.config.codexOverrides.model_providers.synthetic.base_url,
      "https://example.invalid",
    );
    assert.equal(client.config.codexOverrides.plugins, undefined);
    assert.deepEqual(client.config.codexOverrides.agents, { max_depth: 2 });
    assert.deepEqual(client.config.codexOverrides.features, {
      enable_fanout: false,
      multi_agent_v2: { enabled: true, max_concurrent_threads_per_session: 4 },
    });
    assert.equal(
      client.dependencies.environment.CODEX_API_KEY,
      "synthetic-key",
    );
    assert.equal(
      client.dependencies.environment.OPENAI_API_KEY,
      "synthetic-other-key",
    );
    assert.equal(process.env.OPENAI_API_KEY, "synthetic-other-key");
    assert.equal(process.env.CODEX_API_KEY, "synthetic-key");
    for (const [auth, modelProvider] of [
      ["auto", "openai"],
      ["chatgpt", "openai"],
      ["api-key", "openrouter"],
    ]) {
      const selected = await prepareNativeScan({
        ...request,
        recipe: {
          ...request.recipe,
          auth,
          config: { model_provider: modelProvider },
        },
      });
      assert.equal(
        selected.client.dependencies.environment.OPENAI_API_KEY,
        modelProvider === "openrouter" ? "synthetic-other-key" : undefined,
      );
      assert.equal(
        selected.client.dependencies.environment.CODEX_API_KEY,
        auth === "chatgpt" ? undefined : "synthetic-key",
      );
      assert.equal(
        selected.client.dependencies.environment.OPENROUTER_API_KEY,
        "synthetic-provider-key",
      );
      assert.equal(process.env.OPENAI_API_KEY, "synthetic-other-key");
      assert.equal(process.env.CODEX_API_KEY, "synthetic-key");
    }
    assert.equal(
      client.dependencies.environment.CODEX_CLI_PATH,
      process.execPath,
    );
    assert.equal(
      client.dependencies.environment.CODEX_SECURITY_STATE_DIR,
      request.stateDirectory,
    );
    assert.deepEqual(client.dependencies.inheritedPermissions, {
      filesystem: { "/fixture/.env": "deny", glob_scan_max_depth: 3 },
      network: { enabled: false },
    });
    assert.equal(options.workers, 4);
    assert.equal(options.subagents, 3);
    assert.equal(options.auth, "api-key");
    assert.equal(options.maxCostUsd, 10);
    assert.equal(options.postScanPrompt, "Publish once.");
    const withoutContext = await prepareNativeScan({
      ...request,
      scan: { ...request.scan, userContext: null },
    });
    assert.equal(withoutContext.options.scanPrompt, undefined);
    for (const [savedDepth, currentDepth] of [
      [3, 10],
      [10, 3],
      [3, undefined],
    ]) {
      const savedPermissions = await prepareNativeScan({
        ...request,
        parentSandbox: {
          ...request.parentSandbox,
          globScanMaxDepth: currentDepth,
        },
        recipe: {
          ...request.recipe,
          inheritedPermissions: {
            filesystem: {
              "/saved/.env": "deny",
              glob_scan_max_depth: savedDepth,
            },
            network: { enabled: false },
          },
        },
      });
      assert.deepEqual(savedPermissions.options.inheritedPermissions, {
        filesystem: {
          "/saved/.env": "deny",
          "/fixture/.env": "deny",
          glob_scan_max_depth: 3,
        },
        network: { enabled: false },
      });
      assert.deepEqual(
        savedPermissions.client.dependencies.inheritedPermissions,
        savedPermissions.options.inheritedPermissions,
      );
    }
    assert.deepEqual(options.target, ["src/auth", "src/data"]);
    assert.deepEqual(options.registeredScan, {
      scanId: "parent",
      scanDir: input().scan.scanDir,
      threadId: "native-owner",
      handoffClaimToken: "saved-claim",
    });
    assert.equal(process.env.CODEX_HOME, root);
    const resumed = await nativeScanConfiguration(
      process.env,
      {
        recipe: {
          config: { model: "saved-model", model_reasoning_summary: "none" },
        },
      },
      3,
    );
    assert.equal(resumed.model, "saved-model");
    assert.equal(resumed.model_reasoning_summary, "none");
    const savedDeepScanSettings = {
      workers: 2,
      subagents: 1,
      stopAfterNoNew: 3,
      stopAfterConsecutiveErrors: 4,
      maxDiscoveryRuns: 7,
      maxTimeHours: 0.5,
    };
    process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = join(root, "deep.toml");
    await writeFile(
      process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
      "[invalid",
    );
    for (const recipe of [
      undefined,
      { deepScan: { workers: 3, subagents: 2 } },
    ]) {
      const restored = await prepareNativeScan({
        ...request,
        recipe,
        savedDeepScanSettings,
      });
      const expected = { ...savedDeepScanSettings, ...recipe?.deepScan };
      for (const [key, value] of Object.entries(expected)) {
        assert.equal(restored.options[key], value);
      }
      assert.equal(
        restored.client.config.codexOverrides.features.multi_agent_v2
          .max_concurrent_threads_per_session,
        expected.subagents + 1,
      );
    }
  } finally {
    for (const [key, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
});
