import { captureEnvironment } from "../../../../sdk/typescript/tests-support/process-environment.mjs";
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
import { delimiter, dirname, join, relative, sep } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

let onNativeSealRead;

const bundle = await build({
  bundle: true,
  stdin: {
    contents: `export * from ${JSON.stringify(fileURLToPath(new URL("../src/native-scan.ts", import.meta.url)))};
      export { resolveNativeParentSandbox } from ${JSON.stringify(fileURLToPath(new URL("../src/native-permissions.ts", import.meta.url)))};
      export { saveScanKnowledge, scanInputIdentity } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/scan-inputs.ts", import.meta.url)))};
      export { readKnowledgeBaseSnapshot, prepareKnowledgeBase } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/knowledge-base.ts", import.meta.url)))};
      export { acquireScanExecution } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/scan-execution.ts", import.meta.url)))};
      export { prepareAmbientRuntime, prepareExecutionSource, createExecutionCodex, prepareDiscoveryExecution, prepareMergeExecution, resolveExecutionPaths } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/execution-preparation.ts", import.meta.url)))};
      export { createPermissionCheckedCodex } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/permission-profile.ts", import.meta.url)))};
      export { createProviderProfile, createReplayProfile } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/provider-profile.ts", import.meta.url)))};
      export { scanRuntimeCodexConfig, scanPreflightCodexConfig } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/api.ts", import.meta.url)))};`,
    resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
  },
  define: {
    "import.meta.url": JSON.stringify(
      new URL("../../mcp/server.mjs", import.meta.url).href,
    ),
  },
  format: "cjs",
  platform: "node",
  write: false,
  plugins: [
    {
      name: "observe-native-seal-boundary",
      setup(build) {
        build.onResolve(
          { filter: /sdk\/typescript\/src\/scan-publication\.js$/ },
          (args) =>
            args.importer.replaceAll("\\", "/").endsWith("/native-scan.ts")
              ? { path: "seal", namespace: "native-seal-fixture" }
              : undefined,
        );
        build.onLoad(
          { filter: /.*/, namespace: "native-seal-fixture" },
          () => ({
            resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
            contents: `import { hasSealedScanArtifacts as original } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/scan-publication.ts", import.meta.url)))};
            export async function hasSealedScanArtifacts(...args) {
              const sealed = await original(...args);
              await afterNativeSealRead();
              return sealed;
            }`,
          }),
        );
      },
    },
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
new Function(
  "require",
  "module",
  "exports",
  "afterNativeSealRead",
  bundle.outputFiles[0].text,
)(createRequire(import.meta.url), module, module.exports, () =>
  onNativeSealRead?.(),
);
const {
  NativeScanHost,
  resolveNativeParentSandbox,
  saveScanKnowledge,
  scanInputIdentity,
  readKnowledgeBaseSnapshot,
  prepareKnowledgeBase,
  acquireScanExecution,
  prepareNativeScan,
  readNativeScanSemanticInputs,
  nativeScanConfiguration,
  scanRuntimeCodexConfig,
  scanPreflightCodexConfig,
  createReplayProfile,
  createProviderProfile,
  createPermissionCheckedCodex,
  prepareAmbientRuntime,
  prepareExecutionSource,
  createExecutionCodex,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  resolveExecutionPaths,
} = module.exports;

const fixtureRepository = await realpath(
  await mkdtemp(join(tmpdir(), "native-scan-repository-")),
);
after(() => rm(fixtureRepository, { recursive: true, force: true }));

async function collectNativeEvents(thread, prompt, options) {
  const { events } = await thread.runStreamed(prompt, options);
  const collected = [];
  for await (const event of events) collected.push(event);
  return collected;
}

function syntheticPermissionAppServer(parentPath) {
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
  const profile = config.permissions?.[selected] ?? { filesystem: {}, network: {} };
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
  capture({ kind: "preflight", executable: process.argv[1], argv, modelProvider: config.model_provider, provider: config.model_providers?.[config.model_provider], cwd: process.cwd(), marker: process.env.NATIVE_PROFILE_MARKER,
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY,
    gitEnvironment: Object.fromEntries(["PATH", "CODEX_SECURITY_GIT", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL"].map(name => [name, process.env[name]])) });
  require("node:readline").createInterface({ input: process.stdin }).on("line", (line) => {
    const request = JSON.parse(line);
    capture({ kind: "request", method: request.method, params: request.params });
    if (request.id === undefined) return;
    let result;
    if (request.method === "initialize") result = {};
    else if (request.method === "config/read") result = { config };
    else if (request.method === "thread/read") result = { thread: { id: request.params.threadId, path: ${JSON.stringify(parentPath ?? null)} } };
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
      targetPath: fixtureRepository,
      targetProtectionRoots: [fixtureRepository],
      userContext: "Review the boundary.",
    },
    threadId: "native-owner",
    pluginRoot: tmpdir(),
    pythonPath: process.execPath,
    parentSandbox: { workspaceAccess: "write", filesystemDenies: [] },
  };
}

test("native preparation protects enclosing repositories for fresh and resumed clients", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-executable-selection-")),
  );
  const worktree = join(root, "repository");
  const repository = join(worktree, "src");
  const bin = join(worktree, "bin");
  const alias = join(root, "bin-alias");
  const executable = join(
    bin,
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  const externalBin = join(root, "external bin");
  const externalExecutable = join(
    externalBin,
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  const keys = [
    ...new Set([
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_MANAGED_PACKAGE_ROOT",
      "LOCALAPPDATA",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      "PATH",
      ...Object.keys(process.env).filter((key) => key.toUpperCase() === "PATH"),
    ]),
  ];
  const restoreEnvironment = captureEnvironment(keys);
  try {
    await Promise.all([
      mkdir(bin, { recursive: true }),
      mkdir(repository, { recursive: true }),
      mkdir(join(worktree, ".git"), { recursive: true }),
    ]);
    await writeFile(executable, "inert executable fixture");
    await chmod(executable, 0o700);
    await mkdir(externalBin);
    await writeFile(externalExecutable, "inert executable fixture");
    await chmod(externalExecutable, 0o700);
    const installations = [
      { bin: externalBin, executable: externalExecutable },
    ];
    await symlink(
      bin,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    for (const key of keys) delete process.env[key];
    process.env.CODEX_HOME = root;
    process.env.LOCALAPPDATA = root;
    for (const resumed of [false, true]) {
      if (resumed)
        await writeFile(join(repository, ".git"), "gitdir: ../.git\n");
      const request = {
        ...input(),
        scan: { ...input().scan, targetPath: repository },
        recipe: {
          auth: "api-key",
          ...(resumed ? { config: {}, deepScan: { workers: 2 } } : {}),
        },
      };
      for (const searchPath of [bin, alias]) {
        delete process.env.CODEX_CLI_PATH;
        process.env.PATH = searchPath;
        await assert.rejects(
          prepareNativeScan(request),
          /outside the scan target/,
        );
      }
      process.env.CODEX_CLI_PATH = executable;
      await assert.rejects(
        prepareNativeScan(request),
        /outside the scan target/,
      );

      for (const installation of installations) {
        for (const quoted of process.platform === "win32"
          ? [false, true]
          : [false]) {
          process.env.PATH = [bin, alias, installation.bin]
            .map((directory) => (quoted ? `"${directory}"` : directory))
            .join(delimiter);
          process.env.CODEX_CLI_PATH = executable;
          await assert.rejects(
            prepareNativeScan(request),
            /outside the scan target/,
          );
          for (const configured of [undefined, "  ", "codex"]) {
            if (configured === undefined) delete process.env.CODEX_CLI_PATH;
            else process.env.CODEX_CLI_PATH = configured;
            const originalPath = process.env.PATH;
            const prepared = await prepareNativeScan(request);
            const environment = prepared.client.dependencies.environment;
            assert.equal(environment.CODEX_CLI_PATH, installation.executable);
            assert.equal(environment.PATH, installation.bin);
            assert.equal(process.env.PATH, originalPath);
          }
        }
      }

      process.env.CODEX_CLI_PATH = process.execPath;
      process.env.PATH = [bin, alias, dirname(process.execPath)].join(
        delimiter,
      );
      const originalPath = process.env.PATH;
      const prepared = await prepareNativeScan(request);
      const environment = prepared.client.dependencies.environment;
      assert.equal(
        await realpath(environment.CODEX_CLI_PATH),
        await realpath(process.execPath),
      );
      assert.equal(environment.PATH, await realpath(dirname(process.execPath)));
      assert.equal(process.env.PATH, originalPath);
    }
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

for (const scenario of [
  { saved: false, form: "absolute" },
  { saved: true, form: "absolute" },
  { saved: false, form: "relative" },
  { saved: true, form: "relative" },
  { saved: false, form: "home", captured: true },
  { saved: true, form: "home" },
  { saved: true, form: "relative", provider: true },
  { saved: true, form: "absolute", noGit: true },
]) {
  test(`native executable selection protects selected instruction Git roots: ${JSON.stringify(scenario)}`, async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-instruction-root-")),
    );
    const target = join(root, "target");
    const instructions = join(root, "instructions");
    const inactive = join(root, "inactive");
    const home = join(root, "home");
    const scanDir = join(root, "output", "parent");
    const filename = process.platform === "win32" ? "codex.exe" : "codex";
    const instructionExecutable = join(instructions, "bin", filename);
    const outsideExecutable = join(inactive, "bin", filename);
    const targetExecutable = join(target, "bin", filename);
    const instructionFile = join(instructions, "docs", "guide.md");
    const inactiveFile = join(inactive, "guide.md");
    const restore = captureEnvironment([
      "HOME",
      "USERPROFILE",
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_MANAGED_PACKAGE_ROOT",
      "LOCALAPPDATA",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      "CODEX_SECURITY_KNOWLEDGE_BASE",
      "CODEX_SECURITY_STATE_DIR",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
      "SYNTHETIC_PROVIDER_KEY",
      ...new Set([
        "PATH",
        ...Object.keys(process.env).filter(
          (key) => key.toUpperCase() === "PATH",
        ),
      ]),
    ]);
    try {
      for (const directory of [
        home,
        scanDir,
        dirname(instructionFile),
        join(target, ".git"),
        join(inactive, ".git"),
      ])
        await mkdir(directory, { recursive: true, mode: 0o700 });
      if (!scenario.noGit) await mkdir(join(instructions, ".git"));
      for (const executable of [
        instructionExecutable,
        outsideExecutable,
        targetExecutable,
      ]) {
        await mkdir(dirname(executable), { recursive: true });
        await writeFile(executable, "inert executable fixture", {
          mode: 0o700,
        });
      }
      await writeFile(instructionFile, "Selected synthetic instructions.\n");
      await writeFile(inactiveFile, "Inactive synthetic instructions.\n");
      for (const key of [
        "CODEX_CLI_PATH",
        "CODEX_MANAGED_PACKAGE_ROOT",
        "LOCALAPPDATA",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_SECURITY_KNOWLEDGE_BASE",
        "CODEX_SECURITY_STATE_DIR",
        "OPENAI_API_KEY",
        ...Object.keys(process.env).filter(
          (key) => key.toUpperCase() === "PATH",
        ),
      ])
        delete process.env[key];
      Object.assign(process.env, {
        HOME: root,
        USERPROFILE: root,
        CODEX_HOME: home,
        CODEX_API_KEY: "synthetic-instruction-root-key",
        SYNTHETIC_PROVIDER_KEY: "synthetic-selected-provider-key",
      });
      const selected =
        scenario.form === "absolute"
          ? instructionFile
          : scenario.form === "relative"
            ? relative(scanDir, instructionFile)
            : "~/instructions/docs/guide.md";
      const configuration = {
        model: "synthetic-instruction-model",
        ...(scenario.form === "absolute"
          ? { model_instructions_file: selected }
          : {
              profile: "scan",
              model_instructions_file: inactiveFile,
              profiles: { scan: { model_instructions_file: selected } },
            }),
        ...(scenario.provider
          ? {
              model_provider: "custom",
              model_providers: {
                custom: {
                  env_key: "SYNTHETIC_PROVIDER_KEY",
                  experimental_bearer_token: "synthetic-provider-token",
                  wire_api: "responses",
                },
              },
            }
          : {}),
      };
      const ambient = { model_instructions_file: inactiveFile };
      await writeFile(
        join(home, "config.toml"),
        stringifyToml(scenario.saved ? ambient : configuration),
      );
      const replay = scenario.provider
        ? await createReplayProfile(home, configuration)
        : undefined;
      const savedConfig = structuredClone(configuration);
      if (replay) delete savedConfig.model_providers;
      const request = {
        ...input(),
        scan: {
          ...input().scan,
          targetPath: target,
          targetProtectionRoots: [target],
          scanDir,
        },
        ...(scenario.provider
          ? { stateDirectory: join(root, "selected-state") }
          : {}),
        ...(scenario.saved
          ? {
              recipe: {
                auth: "api-key",
                config: savedConfig,
                ...(replay
                  ? { replayProfile: { name: replay.name, home: "ambient" } }
                  : {}),
              },
            }
          : {}),
      };
      if (scenario.captured) {
        request.semanticInputs = await readNativeScanSemanticInputs();
        await writeFile(join(home, "config.toml"), stringifyToml(ambient));
      }
      assert.equal(
        resolveExecutionPaths(configuration, scanDir, process.env)
          .model_instructions_file,
        instructionFile,
      );

      // An overridden top-level instruction path does not protect its tools.
      process.env.PATH = [
        dirname(instructionExecutable),
        dirname(outsideExecutable),
      ].join(delimiter);
      process.env.CODEX_CLI_PATH = outsideExecutable;
      const prepared = await prepareNativeScan(request);
      assert.equal(
        prepared.client.dependencies.environment.CODEX_CLI_PATH,
        outsideExecutable,
      );
      assert.equal(
        resolveExecutionPaths(
          prepared.client.config.codexOverrides,
          scanDir,
          prepared.client.dependencies.environment,
        ).model_instructions_file,
        instructionFile,
      );
      if (scenario.provider) {
        assert.deepEqual(
          prepared.client.config.codexOverrides.model_providers,
          configuration.model_providers,
        );
        assert.equal(prepared.options.preserveProviderEnvironment, true);
        assert.equal(
          prepared.client.dependencies.environment.SYNTHETIC_PROVIDER_KEY,
          "synthetic-selected-provider-key",
        );
        assert.equal(
          prepared.client.dependencies.environment.CODEX_SECURITY_STATE_DIR,
          request.stateDirectory,
        );
      }
      process.env.CODEX_CLI_PATH = targetExecutable;
      await assert.rejects(
        prepareNativeScan(request),
        /outside the scan target/,
      );

      delete process.env.CODEX_CLI_PATH;
      process.env.PATH = dirname(instructionExecutable);
      if (scenario.noGit) {
        const colocated = await prepareNativeScan(request);
        assert.equal(
          colocated.client.dependencies.environment.CODEX_CLI_PATH,
          instructionExecutable,
        );
      } else {
        await assert.rejects(
          prepareNativeScan(request),
          /outside the scan target/,
        );
        process.env.CODEX_CLI_PATH = instructionExecutable;
        await assert.rejects(
          prepareNativeScan(request),
          /outside the scan target/,
        );
        delete process.env.CODEX_CLI_PATH;
        process.env.PATH = [
          dirname(instructionExecutable),
          dirname(outsideExecutable),
        ].join(delimiter);
        const originalPath = process.env.PATH;
        const fallback = await prepareNativeScan(request);
        assert.equal(
          fallback.client.dependencies.environment.CODEX_CLI_PATH,
          outsideExecutable,
        );
        assert.equal(
          fallback.client.dependencies.environment.PATH,
          dirname(outsideExecutable),
        );
        assert.equal(process.env.PATH, originalPath);
      }
    } finally {
      restore();
      await rm(root, { recursive: true, force: true });
    }
  });
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
  let joinedPolicyReads = 0;
  const joined = host.run({
    ...input(),
    parentSandbox: () => {
      joinedPolicyReads++;
      return resolveNativeParentSandbox({});
    },
  });
  await started.promise;
  const rejected = assert.rejects(first, /detached/);
  waiter.abort(new Error("detached"));
  await rejected;
  assert.equal(signal.aborted, false);
  completed.resolve({ scanDir: "sealed-parent" });
  assert.deepEqual(await joined, { scanDir: "sealed-parent" });
  assert.equal(preparations, 1);
  assert.equal(joinedPolicyReads, 0);
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
    void first.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await closing.promise;
    assert.equal(settled, false);
    assert.equal(preparations, 1);
    releaseClose.reject(cleanupError);
    for (const pending of [first, joined]) {
      if (outcome === "failed")
        await assert.rejects(pending, (error) => error === primaryError);
      else assert.equal(await pending, result);
    }
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0][1], cleanupError);
    const next = host.run(input());
    if (outcome === "failed")
      await assert.rejects(next, (error) => error === primaryError);
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

test("native shutdown prevents an in-flight request from starting a new scan", async () => {
  const registered = Promise.withResolvers();
  let preparations = 0;
  const host = new NativeScanHost(async () => {
    preparations++;
    throw new Error("A closed host must not prepare another scan.");
  });
  // A tool request can be registering its scan when the MCP transport closes.
  const request = registered.promise.then(() => host.run(input()));
  await host.close();
  registered.resolve();
  await assert.rejects(request, (error) => {
    assert.equal(error.constructor.name, "ScanTransportClosedError");
    assert.equal(error.message, "mcp_transport_closed");
    return true;
  });
  assert.equal(preparations, 0);
});

test("native scans preserve selected Codex homes and saved settings", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-codex-home-")),
  );
  const defaultHome = join(root, ".codex");
  const explicitHome = join(root, "explicit");
  const spacedHome = join(root, " spaced ");
  const pluginRoot = join(root, "plugin");
  const keys = [
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ];
  const restoreEnvironment = captureEnvironment(keys);
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
      ["~/.codex/link/..", ...linkedSettings],
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
        const runtime = await prepareAmbientRuntime(
          prepared.client.dependencies.ambientExecution,
        );
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
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "native blank config overrides reach fresh and resumed SDK children",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-blank-home-")),
    );
    const home = join(root, ".codex");
    const deepConfig = join(root, "selected-deep.toml");
    const repository = join(root, "repository");
    const pluginRoot = join(root, "plugin");
    const executable = join(root, "codex");
    const capture = join(root, "child.json");
    const keys = [
      "HOME",
      "USERPROFILE",
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ];
    const restoreEnvironment = captureEnvironment(keys);
    try {
      await Promise.all([
        mkdir(join(home, "codex-security"), { recursive: true }),
        mkdir(repository),
        mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true }),
      ]);
      await writeFile(
        join(home, "config.toml"),
        'model = "synthetic-current"\n',
      );
      await writeFile(
        join(home, "codex-security/config.toml"),
        "[deep_scan]\nworkers = 2\nsubagents = 1\n",
      );
      await writeFile(deepConfig, "[deep_scan]\nworkers = 3\nsubagents = 2\n");
      await writeFile(
        join(pluginRoot, ".codex-plugin/plugin.json"),
        JSON.stringify({ name: "codex-security", version: "0.0.0" }),
      );
      await writeFile(
        executable,
        `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) {
  servePermissionProfiles();
} else {
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ home: process.env.CODEX_HOME, argv: process.argv.slice(2) }));
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-home-thread" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
        { mode: 0o700 },
      );
      Object.assign(process.env, {
        HOME: root,
        USERPROFILE: root,
        CODEX_HOME: " \t\n",
        CODEX_CLI_PATH: executable,
        CODEX_API_KEY: "synthetic-home-key",
      });
      delete process.env.OPENAI_API_KEY;
      delete process.env.CODEX_SECURITY_CONFIG_PATH;
      for (const [override, workers, subagents] of [
        [undefined, 2, 1],
        ["", 2, 1],
        [" \t\n", 2, 1],
        [` ${deepConfig} `, 3, 2],
      ]) {
        if (override === undefined)
          delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        else process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH = override;
        for (const resumed of [false, true]) {
          const prepared = await prepareNativeScan({
            ...input(),
            pluginRoot,
            model: "synthetic-current",
            reasoningEffort: "ultra",
            recipe: {
              auth: "api-key",
              ...(resumed
                ? {
                    config: { model: "synthetic-saved" },
                    deepScan: { workers: 6, subagents: 4 },
                  }
                : {}),
            },
          });
          assert.equal(prepared.options.workers, resumed ? 6 : workers);
          const runtime = await prepareAmbientRuntime(
            prepared.client.dependencies.ambientExecution,
          );
          try {
            const sdk = createPermissionCheckedCodex({
              codexPathOverride: executable,
              config: scanRuntimeCodexConfig(
                prepared.client.config.codexOverrides,
                repository,
                prepared.client.dependencies.inheritedPermissions,
              ),
              env: runtime.environment,
            });
            const options = {
              workingDirectory: repository,
              skipGitRepoCheck: true,
              approvalPolicy: "never",
            };
            const thread = resumed
              ? sdk.resumeThread("synthetic-home-thread", options)
              : sdk.startThread(options);
            const events = await collectNativeEvents(
              thread,
              "Synthetic home selection only.",
            );
            assert.equal(events.at(-1).type, "turn.completed");
            const observed = JSON.parse(await readFile(capture, "utf8"));
            assert.equal(observed.home, await realpath(home));
            assert.equal(observed.argv.includes("resume"), resumed);
            assert.equal(
              parseToml(
                observed.argv.find((arg) => arg.startsWith("features=")),
              ).features.multi_agent_v2.max_concurrent_threads_per_session,
              (resumed ? 4 : subagents) + 1,
            );
            assert.ok(
              observed.argv.includes(
                `model=${JSON.stringify(resumed ? "synthetic-saved" : "synthetic-current")}`,
              ),
            );
            assert.equal(process.env.CODEX_HOME, " \t\n");
            assert.equal(
              process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
              override,
            );
          } finally {
            await rm(runtime.bootstrapWorkspace, {
              recursive: true,
              force: true,
            });
          }
        }
      }
    } finally {
      restoreEnvironment();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("native relative home stays bound when cwd changes during seal inspection", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-relative-home-")),
  );
  const originalCwd = process.cwd();
  const first = join(root, "first");
  const second = join(root, "second");
  const restore = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  ]);
  try {
    for (const directory of [first, second]) {
      await mkdir(join(directory, "actual", "nested"), { recursive: true });
      await mkdir(join(directory, "actual", "home"));
      await mkdir(join(directory, "home"));
      await symlink(
        join(directory, "actual", "nested"),
        join(directory, "alias"),
        process.platform === "win32" ? "junction" : "dir",
      );
    }
    Object.assign(process.env, {
      CODEX_HOME: ["alias", "..", "home"].join(sep),
      CODEX_CLI_PATH: process.execPath,
      CODEX_API_KEY: "synthetic-relative-home-key",
    });
    delete process.env.OPENAI_API_KEY;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
    for (const sealed of [false, true]) {
      const scanDir = join(root, String(sealed));
      await mkdir(scanDir, { mode: 0o700 });
      if (sealed)
        await writeFile(
          join(scanDir, "scan-manifest.json"),
          JSON.stringify({ scan: { sealedAt: "2026-01-01T00:00:00Z" } }),
        );
      onNativeSealRead = () => {
        process.chdir(second);
      };
      process.chdir(first);
      const expectedHome = await realpath(process.env.CODEX_HOME);
      const prepared = await prepareNativeScan({
        ...input(),
        scan: { ...input().scan, scanDir },
        recipe: { auth: "api-key", config: {} },
      });
      assert.equal(process.cwd(), second);
      assert.equal(
        prepared.client.dependencies.environment.CODEX_HOME,
        expectedHome,
      );
    }
  } finally {
    onNativeSealRead = undefined;
    process.chdir(originalCwd);
    restore();
    await rm(root, { recursive: true, force: true });
  }
});

test("native launches snapshot safety identifiers and prefer saved recipes", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-safety-identifier-")),
  );
  const codexExecutable = await realpath(process.execPath);
  const repositories = [join(root, "first"), join(root, "second")];
  for (const repository of repositories) {
    await mkdir(join(repository, "src"), { recursive: true });
    await mkdir(join(repository, ".git"));
    await mkdir(join(repository, "bin"));
  }
  const searchDirectories = repositories.map((repository) =>
    join(repository, "bin"),
  );
  const keys = [
    "PATH",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SAFETY_IDENTIFIER",
  ];
  const restoreEnvironment = captureEnvironment(keys);
  try {
    Object.assign(process.env, {
      CODEX_HOME: root,
      CODEX_CLI_PATH: codexExecutable,
      PATH: searchDirectories.join(delimiter),
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    await writeFile(
      join(root, "config.toml"),
      'model_provider = "synthetic"\n[model_providers.synthetic]\nbase_url = "https://example.invalid"\n',
    );
    const launches = [
      ["synthetic-fresh", undefined, "synthetic-fresh"],
      ["synthetic-resumed", {}, undefined],
      [
        "synthetic-current",
        { safetyIdentifier: "synthetic-saved" },
        "synthetic-saved",
      ],
      [undefined, undefined, undefined],
    ].map(([ambient, recipe, expected], index) => {
      if (ambient === undefined) delete process.env.CODEX_SAFETY_IDENTIFIER;
      else process.env.CODEX_SAFETY_IDENTIFIER = ambient;
      return prepareNativeScan({
        ...input(`parent-${index}`),
        scan: {
          ...input(`parent-${index}`).scan,
          targetPath: join(repositories[index % 2], "src"),
        },
        recipe,
      }).then(({ client, options }) => {
        assert.equal(
          client.dependencies.environment.PATH,
          searchDirectories[1 - (index % 2)],
        );
        assert.equal(
          client.dependencies.environment.CODEX_CLI_PATH,
          codexExecutable,
        );
        assert.equal(options.safetyIdentifier, expected);
        assert.equal(
          client.dependencies.environment.CODEX_SAFETY_IDENTIFIER,
          ambient,
        );
      });
    });
    await Promise.all(launches);
    assert.equal(process.env.CODEX_SAFETY_IDENTIFIER, undefined);
    assert.equal(process.env.PATH, searchDirectories.join(delimiter));
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "native discovery and merge workers inherit safe paths and selected cyber programs on fresh and resumed launches",
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
    const repository = join(root, "repository");
    const target = join(repository, "src");
    const repositoryBin = join(repository, "bin");
    const selectedTools = join(root, "selected tools");
    const knowledge = join(root, "knowledge");
    const knowledgeBin = join(knowledge, "bin");
    const document = join(knowledge, "architecture.md");
    const scanDir = join(root, "scan");
    const keys = [
      "PATH",
      "HOME",
      "USERPROFILE",
      "CODEX_HOME",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
      "CODEX_CLI_PATH",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_KNOWLEDGE_BASE",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ];
    const before = Object.fromEntries(
      keys.map((key) => [key, process.env[key]]),
    );
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
    try {
      await mkdir(target, { recursive: true });
      await Promise.all([
        mkdir(repositoryBin),
        mkdir(join(repository, ".git")),
        mkdir(selectedTools),
        mkdir(join(knowledge, ".git"), { recursive: true }),
        mkdir(knowledgeBin, { recursive: true }),
        mkdir(scanDir, { mode: 0o700 }),
        mkdir(join(root, "alias")),
        mkdir(join(root, "real-child")),
      ]);
      await symlink(join(root, "real-child"), join(root, "alias", "link"));
      await writeFile(
        join(root, "alias", "codex"),
        "inert lexical-path decoy",
        { mode: 0o700 },
      );
      await writeFile(
        join(repositoryBin, "codex"),
        "inert executable fixture",
        { mode: 0o700 },
      );
      await writeFile(document, "Synthetic architecture context.\n");
      await writeFile(
        join(knowledgeBin, "codex"),
        "inert knowledge-source executable",
        { mode: 0o700 },
      );
      const knowledgeSnapshot = await readKnowledgeBaseSnapshot([document]);
      await saveScanKnowledge(scanDir, knowledgeSnapshot);
      const savedKnowledge = {
        knowledgeBasePaths: [document],
        scanInputs: scanInputIdentity(
          input().scan.userContext,
          knowledgeSnapshot,
        ),
      };
      Object.assign(process.env, {
        CODEX_HOME: root,
        CODEX_SECURITY_KNOWLEDGE_BASE: document,
        HOME: root,
        USERPROFILE: root,
        CODEX_API_KEY: "synthetic-source-key",
        OPENAI_API_KEY: "synthetic-other-key",
        PATH: [
          repositoryBin,
          knowledgeBin,
          `${root}/alias/link/..`,
          selectedTools,
        ].join(delimiter),
      });
      delete process.env.CODEX_CLI_PATH;
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      const selectedConfig = join(root, "selected.toml");
      await writeFile(
        selectedConfig,
        '[codex_security]\ncyber_access_program = "daybreak_blue"\n',
      );
      process.env.CODEX_SECURITY_CONFIG_PATH = selectedConfig;
      await writeFile(
        join(root, "parent.jsonl"),
        JSON.stringify({
          type: "turn_context",
          payload: {
            turn_id: "synthetic-parent-turn",
            cyber_access_program: "daybreak_red",
          },
        }) + "\n",
      );
      await writeFile(
        executable,
        `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer(join(root, "parent.jsonl"))}
if (process.argv.includes("app-server")) {
  servePermissionProfiles();
} else {
  const capture = (value) => fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify(value) + "\\n");
  capture({ kind: "exec", executable: process.argv[1], argv: process.argv.slice(2), marker: process.env.NATIVE_PROFILE_MARKER,
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY,
    gitEnvironment: Object.fromEntries(["PATH", "CODEX_SECURITY_GIT", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL"].map(name => [name, process.env[name]])) });
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-worker-thread" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
        { mode: 0o700 },
      );
      for (const [role, programSource] of [
        ["discovery", "recipe"],
        ["discovery", "config"],
        ["discovery", "parent"],
        ["merge", "recipe"],
        ["merge", "config"],
        ["merge", "parent"],
        ["discovery", "home-slash"],
        ["merge", "home-backslash"],
      ]) {
        if (programSource === "recipe") {
          process.env.CODEX_CLI_PATH = `${relative(process.cwd(), root)}/alias/link/../codex`;
        } else if (programSource.startsWith("home-")) {
          process.env.CODEX_CLI_PATH =
            programSource === "home-slash"
              ? "~/alias/link/../codex"
              : "~\\alias\\link\\..\\codex";
        } else {
          delete process.env.CODEX_CLI_PATH;
        }
        const selectedProgram =
          programSource === "config" ? "daybreak_blue" : "daybreak_red";
        const cwd = join(root, `${role}-${programSource}`);
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
        const native = await prepareNativeScan({
          ...input(),
          scan: { ...input().scan, scanDir, targetPath: target },
          ...(programSource === "parent"
            ? {
                parentTurn: {
                  threadId: "synthetic-parent-thread",
                  turnId: "synthetic-parent-turn",
                },
                recipe: {
                  ...savedKnowledge,
                  auth: "api-key",
                  cyberAccessProgram: "daybreak_blue",
                },
              }
            : {}),
          ...(programSource === "recipe" || programSource.startsWith("home-")
            ? {
                recipe: {
                  ...savedKnowledge,
                  auth: "api-key",
                  cyberAccessProgram: selectedProgram,
                },
              }
            : {}),
        });
        if (programSource === "parent") {
          assert.equal(native.options.cyberAccessProgram, "daybreak_red");
          assert.equal(
            native.client.config.codexOverrides.features
              .api_key_cyber_access_programs,
            true,
          );
        }
        const selectedEnvironment = native.client.dependencies.environment;
        assert.equal(selectedEnvironment.CODEX_CLI_PATH, executable);
        assert.equal(
          selectedEnvironment.PATH,
          [root, selectedTools].join(delimiter),
        );
        assert.equal(
          process.env.PATH,
          [
            repositoryBin,
            knowledgeBin,
            `${root}/alias/link/..`,
            selectedTools,
          ].join(delimiter),
        );
        const gitEnvironment = {
          PATH: selectedEnvironment.PATH,
          CODEX_SECURITY_GIT: join(root, "selected tools", "git"),
          GIT_SSH_COMMAND: "synthetic-ssh --fixture",
          GIT_CONFIG_GLOBAL: join(root, "operator.gitconfig"),
        };
        const sdk = createPermissionCheckedCodex({
          codexPathOverride: selectedEnvironment.CODEX_CLI_PATH,
          config: { ...config, default_permissions: ":read-only" },
          configOverrides: ['default_permissions="codex_security_scan"'],
          apiKey: "synthetic-final-key",
          env: {
            ...selectedEnvironment,
            CODEX_HOME: root,
            OPENAI_API_KEY: "synthetic-other-key",
            CODEX_API_KEY: "synthetic-stale-key",
            NATIVE_PROFILE_CAPTURE: capture,
            NATIVE_PROFILE_MARKER: role,
            ...gitEnvironment,
          },
        });
        for (const resumed of [false, true]) {
          const options = {
            workingDirectory: cwd,
            skipGitRepoCheck: true,
            approvalPolicy: "never",
          };
          const thread = resumed
            ? sdk.resumeThread(`synthetic-${role}-thread`, options)
            : sdk.startThread(options);
          await writeFile(capture, "");
          const events = await collectNativeEvents(
            thread,
            "Synthetic worker path verification.",
            { cyberAccessProgram: native.options.cyberAccessProgram },
          );
          assert.equal(events.at(-1).type, "turn.completed");
          assert.equal(thread.id, "synthetic-worker-thread");
          const observed = await observations();
          const preflight = observed.find(
            (entry) => entry.kind === "preflight",
          );
          const executed = observed.find((entry) => entry.kind === "exec");
          assert.equal(executed.executable, executable);
          assert.equal(
            executed.argv[executed.argv.indexOf("--cyber-access-program") + 1],
            selectedProgram,
          );
          assert.equal(preflight.cwd, cwd);
          assert.equal(executed.argv[executed.argv.indexOf("--cd") + 1], cwd);
          assert.equal(executed.argv.includes("resume"), resumed);
          assert.deepEqual(rawConfig(preflight.argv), rawConfig(executed.argv));
          assert.equal(
            rawConfig(preflight.argv).at(-1),
            'approval_policy="never"',
          );
          for (const process of [preflight, executed]) {
            assert.deepEqual(process.gitEnvironment, gitEnvironment);
            assert.equal(process.marker, role);
            assert.equal(process.codex, "synthetic-final-key");
            assert.equal(process.openai, "synthetic-other-key");
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
    const restoreEnvironment = captureEnvironment(keys);
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
          const sdk = createPermissionCheckedCodex({
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
      const configuredSdk = createPermissionCheckedCodex({
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
          JSON.parse(
            JSON.stringify(
              parseToml(
                configArguments.find((argument) =>
                  argument.startsWith(`${name}=`),
                ),
              )[name],
            ),
          ),
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
      restoreEnvironment();
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
  const restoreEnvironment = captureEnvironment(keys);
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
        workspaceAccess: "write",
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
      filesystem: {
        ":workspace_roots": "write",
        "/fixture/.env": "deny",
        glob_scan_max_depth: 3,
      },
      network: { enabled: false },
    });
    const ownedDirectory = join(root, "owned-scan");
    await mkdir(ownedDirectory, { mode: 0o700 });
    const nativePlugin = fileURLToPath(
      new URL("../../../../sdk/typescript/_bundled_plugin/", import.meta.url),
    );
    const releaseOwner = await acquireScanExecution(
      root,
      ownedDirectory,
      nativePlugin,
    );
    let acquired = false;
    const joined = client.dependencies
      .acquireScanExecution(root, ownedDirectory, nativePlugin)
      .then((release) => {
        acquired = true;
        return release;
      });
    try {
      await new Promise((resolve) => setTimeout(resolve, 150));
      assert.equal(acquired, false);
    } finally {
      releaseOwner();
    }
    const releaseJoined = await joined;
    assert.equal(acquired, true);
    releaseJoined();
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
    for (const [savedDepth, currentDepth, expectedDepth] of [
      [3, 10, 10],
      [10, 3, 10],
      [3, undefined, 3],
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
              ":workspace_roots": "read",
              "/saved/.env": "deny",
              glob_scan_max_depth: savedDepth,
            },
            network: { enabled: false },
          },
        },
      });
      assert.deepEqual(savedPermissions.options.inheritedPermissions, {
        filesystem: {
          ":workspace_roots": "read",
          "/saved/.env": "deny",
          "/fixture/.env": "deny",
          glob_scan_max_depth: expectedDepth,
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
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

async function writeNativeWorkerExecutable(executable, capture) {
  await writeFile(
    executable,
    `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) servePermissionProfiles();
else {
  const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
  const argv = process.argv.slice(2);
  const path = require("node:path");
  const effective = parse(fs.readFileSync(path.join(process.env.CODEX_HOME, "config.toml"), "utf8"));
  const merge = (target, value) => { for (const [key, child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {}, child) : child; return target; };
  const profile = argv.includes("--profile") ? parse(fs.readFileSync(path.join(process.env.CODEX_HOME, argv[argv.indexOf("--profile") + 1] + ".config.toml"), "utf8")) : {};
  merge(effective, profile);
  for (let i = 0; i < argv.length; i++) if (["--config", "-c"].includes(argv[i])) merge(effective, parse(argv[++i]));
  const provider = effective.model_providers?.[effective.model_provider];
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ argv, path: process.env.PATH, codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY, home: process.env.CODEX_HOME, state: process.env.CODEX_SECURITY_STATE_DIR, executable: process.argv[1], knowledge: process.env.CODEX_SECURITY_KNOWLEDGE_BASE,
    knowledgeDocuments: process.env.CODEX_SECURITY_KNOWLEDGE_BASE && Object.fromEntries(fs.readdirSync(process.env.CODEX_SECURITY_KNOWLEDGE_BASE).map(name => [name, fs.readFileSync(path.join(process.env.CODEX_SECURITY_KNOWLEDGE_BASE, name), "utf8")])),
    model: effective.model,
    reasoningEffort: effective.model_reasoning_effort,
    modelProvider: effective.model_provider,
    safetyIdentifier: process.env.CODEX_SAFETY_IDENTIFIER,
    provider,
    profileProvider: profile.model_providers?.[effective.model_provider],
    providerToken: provider && (provider.experimental_bearer_token ?? process.env[provider.env_key]),
    providerHeaders: provider && {...provider.http_headers, ...Object.fromEntries(Object.entries(provider.env_http_headers ?? {}).map(([header, key]) => [header, process.env[key]]))},
    literalCredentialInEnvironment: ["synthetic-provider-token", "synthetic-provider-header"].some(value => Object.values(process.env).includes(value)),
  }));
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-merged-worker" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
    { mode: 0o700 },
  );
}

async function nativeWorkerSession(prepared, repository) {
  const ambient = prepared.client.dependencies.ambientExecution;
  const runtime = await prepareAmbientRuntime(ambient);
  runtime.providerProfile = await createProviderProfile(
    runtime.codexHome,
    ambient.configuration,
  );
  const source = prepareExecutionSource(ambient);
  return {
    runtime,
    session: {
      policy: "ordinary",
      source,
      runtime,
      runtimeHome: runtime.codexHome,
      effectiveConfig: ambient.configuration,
      preflightConfig: {},
      sessionConfig: scanRuntimeCodexConfig(
        prepared.client.config.codexOverrides,
        repository,
        prepared.options.inheritedPermissions,
      ),
      inheritedPermissions: prepared.options.inheritedPermissions,
      safetyIdentifier: prepared.options.safetyIdentifier,
      authentication: source.authentication,
      approvalPolicy: "never",
      python: process.execPath,
      releaseCredentialHome: null,
    },
  };
}

for (const scenario of [
  "saved-uncapped",
  "lexical-target-protection",
  "legacy-explicit-executable",
  "current-uncapped",
  "both-finite",
  "saved-literal",
  "current-literal",
  "saved-glob-current-literal",
  "saved-literal-current-glob",
  "repeated-literal",
  "read-only-parent",
  "saved-absent-knowledge",
  "saved-present-knowledge",
  "saved-developer-instructions",
  "fresh-whitespace-knowledge",
  "tilde-home-and-selected-config",
  "explicit-state-directory",
  "fresh-safety-identifier",
  "saved-absent-safety-identifier",
  "saved-explicit-safety-identifier",
  "openrouter-env-key",
  "openrouter-selected-env-key",
  "fireworks-env-key",
  "openrouter-bearer",
  "fireworks-bearer",
  "openrouter-http-headers",
  "fireworks-http-headers",
  "openrouter-env-http-headers",
  "fireworks-env-http-headers",
]) {
  test(
    `native merged settings reach every worker: ${scenario}`,
    {
      skip:
        process.platform === "win32"
          ? "Synthetic executable uses a POSIX shebang."
          : false,
    },
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "native-merged-worker-")),
      );
      const home = join(root, "home");
      const repository = join(root, "repository");
      const pluginRoot = join(root, "plugin");
      const executable = join(root, "codex");
      const capture = join(root, "worker.json");
      const preflights = join(root, "preflights.jsonl");
      const lexicalTarget = [
        "lexical-target-protection",
        "legacy-explicit-executable",
      ].includes(scenario);
      const lexicalRepository = join(root, "lexical-repository");
      const lexicalBin = join(lexicalRepository, "bin");
      const decoyLaunch = join(root, "decoy-launched.jsonl");
      const externalProvider = scenario.startsWith("openrouter-")
        ? "openrouter"
        : scenario.startsWith("fireworks-")
          ? "fireworks"
          : undefined;
      const selectedConfiguration = scenario === "openrouter-selected-env-key";
      const safetyScenario = scenario.endsWith("-safety-identifier");
      const expectedSafetyIdentifier =
        scenario === "fresh-safety-identifier"
          ? "synthetic-current-attribution"
          : scenario === "saved-explicit-safety-identifier"
            ? "synthetic-saved-attribution"
            : undefined;
      const restore = captureEnvironment([
        "PATH",
        "HOME",
        "USERPROFILE",
        "CODEX_SECURITY_KNOWLEDGE_BASE",
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "FIREWORKS_API_KEY",
        "NATIVE_PROFILE_CAPTURE",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_SECURITY_STATE_DIR",
        "CODEX_SAFETY_IDENTIFIER",
      ]);
      try {
        await mkdir(home);
        await mkdir(repository);
        await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
        await writeFile(
          join(pluginRoot, ".codex-plugin/plugin.json"),
          JSON.stringify({ name: "codex-security", version: "0.0.0" }),
        );
        await writeNativeWorkerExecutable(executable, capture);
        if (lexicalTarget) {
          await writeFile(preflights, "");
          await mkdir(lexicalBin, { recursive: true });
          await mkdir(join(lexicalRepository, ".git"));
          await symlink(repository, join(lexicalRepository, "selected"), "dir");
          await writeFile(
            join(lexicalBin, "codex"),
            (await readFile(executable, "utf8")).replace(
              'const fs = require("node:fs");',
              `const fs = require("node:fs"); fs.appendFileSync(${JSON.stringify(decoyLaunch)}, JSON.stringify(process.argv.slice(2)) + "\\n");`,
            ),
            { mode: 0o700 },
          );
        }
        Object.assign(process.env, {
          CODEX_HOME: home,
          CODEX_CLI_PATH: executable,
          OPENAI_API_KEY: "synthetic-selected-key",
        });
        delete process.env.CODEX_API_KEY;
        delete process.env.OPENROUTER_API_KEY;
        delete process.env.FIREWORKS_API_KEY;
        delete process.env.NATIVE_PROFILE_CAPTURE;
        if (lexicalTarget) {
          process.env.PATH = [lexicalBin, root].join(delimiter);
          process.env.NATIVE_PROFILE_CAPTURE = preflights;
          if (scenario === "lexical-target-protection")
            delete process.env.CODEX_CLI_PATH;
        }
        if (externalProvider) {
          process.env.CODEX_API_KEY = "synthetic-competing-key";
          process.env.NATIVE_PROFILE_CAPTURE = preflights;
        }
        delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
        delete process.env.CODEX_SECURITY_CONFIG_PATH;
        delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        delete process.env.CODEX_SECURITY_STATE_DIR;
        delete process.env.CODEX_SAFETY_IDENTIFIER;
        if (safetyScenario)
          process.env.CODEX_SAFETY_IDENTIFIER =
            scenario === "fresh-safety-identifier"
              ? "synthetic-current-attribution"
              : "synthetic-later-attribution";
        if (scenario === "explicit-state-directory")
          process.env.CODEX_SECURITY_STATE_DIR = join(root, "ambient-state");
        const credential = scenario.endsWith("-env-key")
          ? { env_key: "OPENAI_API_KEY" }
          : scenario.endsWith("-bearer")
            ? { experimental_bearer_token: "synthetic-provider-token" }
            : scenario.endsWith("-env-http-headers")
              ? { env_http_headers: { Authorization: "OPENAI_API_KEY" } }
              : {
                  http_headers: { Authorization: "synthetic-provider-header" },
                };
        const configuration = {
          model: "ambient-model",
          model_provider: externalProvider ?? "openai",
          model_providers: {
            [externalProvider ?? "openai"]: externalProvider
              ? {
                  name: "Synthetic provider",
                  wire_api: "responses",
                  base_url: "https://example.invalid/custom",
                  ...credential,
                }
              : { env_key: "OPENAI_API_KEY", requires_openai_auth: true },
          },
        };
        if (scenario === "saved-developer-instructions")
          configuration.developer_instructions = "Saved synthetic guidance.";
        let ambientConfiguration = configuration;
        if (scenario === "saved-developer-instructions")
          ambientConfiguration = {
            ...configuration,
            developer_instructions: "Later ambient guidance.",
          };
        let selectedConfigText;
        let selectedConfigPath;
        if (selectedConfiguration) {
          Object.assign(configuration.model_providers[externalProvider], {
            name: "Selected synthetic provider",
            request_max_retries: 7,
          });
          configuration.features = {
            goals: true,
            api_key_model_discovery: true,
            api_key_cyber_access_programs: true,
          };
          configuration.model_reasoning_summary = "auto";
          ambientConfiguration = structuredClone(configuration);
          Object.assign(
            ambientConfiguration.model_providers[externalProvider],
            {
              name: "Ambient synthetic provider",
              request_max_retries: 2,
            },
          );
          delete ambientConfiguration.model_providers[externalProvider]
            .wire_api;
          ambientConfiguration.features.api_key_model_discovery = false;
          delete ambientConfiguration.features.api_key_cyber_access_programs;
          selectedConfigText = stringifyToml({
            model_providers: {
              [externalProvider]: {
                name: "Selected synthetic provider",
                wire_api: "responses",
                request_max_retries: 7,
              },
            },
            features: {
              api_key_model_discovery: true,
              api_key_cyber_access_programs: true,
            },
          });
          selectedConfigPath = join(root, "selected.toml");
          await writeFile(selectedConfigPath, selectedConfigText);
          process.env.CODEX_SECURITY_CONFIG_PATH = selectedConfigPath;
        }
        const configText = stringifyToml(ambientConfiguration);
        await writeFile(join(home, "config.toml"), configText);
        const replay = externalProvider
          ? await createReplayProfile(home, configuration)
          : undefined;
        const replayText = replay
          ? await readFile(replay.path, "utf8")
          : undefined;
        const scanDir = join(root, "scan");
        await mkdir(scanDir, { mode: 0o700 });
        const document = join(root, "knowledge.txt");
        let savedKnowledge;
        if (scenario === "fresh-whitespace-knowledge")
          process.env.CODEX_SECURITY_KNOWLEDGE_BASE = " \t\n ";
        if (scenario.startsWith("saved-") && scenario.endsWith("-knowledge")) {
          await writeFile(document, "Original synthetic knowledge.\n");
          if (scenario === "saved-present-knowledge") {
            savedKnowledge = await readKnowledgeBaseSnapshot([document]);
            await saveScanKnowledge(scanDir, savedKnowledge);
          }
          await writeFile(document, "Late synthetic knowledge.\n");
          process.env.CODEX_SECURITY_KNOWLEDGE_BASE = document;
        }
        if (scenario === "tilde-home-and-selected-config") {
          await mkdir(join(root, "real-child"));
          await mkdir(join(root, "alias", "home"), { recursive: true });
          await symlink(join(root, "real-child"), join(root, "alias", "link"));
          await writeFile(
            join(root, "alias", "home", "config.toml"),
            'model="lexical-decoy"\n',
          );
          await writeFile(
            join(root, "selected-deep.toml"),
            "[deep_scan]\nworkers=3\nsubagents=4\nmax_discovery_runs=5\n",
          );
          await writeFile(
            join(root, "alias", "selected-deep.toml"),
            "[deep_scan]\nworkers=7\nsubagents=8\nmax_discovery_runs=9\n",
          );
          Object.assign(process.env, {
            HOME: root,
            USERPROFILE: root,
            CODEX_HOME: "~/alias/link/../home",
            CODEX_SECURITY_CONFIG_PATH: " \t\n",
            CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH:
              "~/alias/link/../selected-deep.toml",
          });
        }
        const invokingEnvironment = Object.fromEntries(
          [
            "PATH",
            "HOME",
            "USERPROFILE",
            "CODEX_HOME",
            "CODEX_CLI_PATH",
            "OPENAI_API_KEY",
            "CODEX_API_KEY",
            "OPENROUTER_API_KEY",
            "FIREWORKS_API_KEY",
            "CODEX_SECURITY_KNOWLEDGE_BASE",
            "CODEX_SECURITY_CONFIG_PATH",
            "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
            "CODEX_SECURITY_STATE_DIR",
            "CODEX_SAFETY_IDENTIFIER",
          ].map((name) => [name, process.env[name]]),
        );
        const samePath = [
          "saved-glob-current-literal",
          "saved-literal-current-glob",
          "repeated-literal",
        ].includes(scenario);
        const savedLiteral = [
          "saved-literal-current-glob",
          "repeated-literal",
        ].includes(scenario);
        const currentLiteral = [
          "saved-glob-current-literal",
          "repeated-literal",
        ].includes(scenario);
        const savedPath = samePath
          ? join(repository, "private[0]")
          : scenario === "saved-literal"
            ? join(repository, "saved.env")
            : join(repository, "**", "saved.env");
        const currentPath = samePath
          ? savedPath
          : scenario === "current-literal"
            ? join(repository, "current.env")
            : join(repository, "**", "current.env");
        const savedDepth = ["saved-uncapped", "saved-literal"].includes(
          scenario,
        )
          ? undefined
          : 3;
        const currentDepth = ["current-uncapped", "current-literal"].includes(
          scenario,
        )
          ? undefined
          : 7;
        const expectedDepth = ["saved-uncapped", "current-uncapped"].includes(
          scenario,
        )
          ? undefined
          : scenario === "current-literal"
            ? 3
            : 7;
        const knowledgeMismatches = [];
        for (const resumed of [false, true]) {
          const request = {
            ...input(),
            pluginRoot,
            ...(scenario === "explicit-state-directory"
              ? { stateDirectory: join(root, "selected-state") }
              : {}),
            scan: {
              ...input().scan,
              targetPath: repository,
              targetProtectionRoots:
                scenario === "legacy-explicit-executable"
                  ? undefined
                  : lexicalTarget
                    ? [lexicalRepository]
                    : [repository],
              scanDir,
            },
            model: "explicit-current-model",
            reasoningEffort: "ultra",
            parentSandbox: {
              workspaceAccess:
                scenario === "read-only-parent" ? "read" : "write",
              filesystemDenies: currentLiteral ? [] : [currentPath],
              ...(currentLiteral
                ? { literalFilesystemDenies: [currentPath] }
                : {}),
              ...(currentDepth === undefined
                ? {}
                : { globScanMaxDepth: currentDepth }),
            },
            recipe: {
              auth: "api-key",
              ...(scenario === "saved-developer-instructions"
                ? {
                    config: {
                      ...configuration,
                      model: "explicit-current-model",
                      model_reasoning_effort: "ultra",
                    },
                  }
                : {}),
              ...(resumed && replay
                ? {
                    config: scanPreflightCodexConfig({
                      ...configuration,
                      model: "explicit-current-model",
                      model_reasoning_effort: "ultra",
                    }),
                    replayProfile: { name: replay.name, home: "ambient" },
                  }
                : {}),
              scanInputs: scanInputIdentity(
                input().scan.userContext,
                savedKnowledge,
              ),
              ...(savedKnowledge ? { knowledgeBasePaths: [document] } : {}),
              inheritedPermissions: {
                filesystem: {
                  ...(scenario === "read-only-parent"
                    ? {
                        ":workspace_roots": "write",
                        [join(repository, "saved-write")]: { ".": "write" },
                      }
                    : {}),
                  [savedPath]: savedLiteral ? { ".": "deny" } : "deny",
                  ...(savedDepth === undefined
                    ? {}
                    : { glob_scan_max_depth: savedDepth }),
                },
                network: { enabled: false },
              },
            },
          };
          if (
            ["fresh-safety-identifier", "fresh-whitespace-knowledge"].includes(
              scenario,
            )
          )
            delete request.recipe;
          else if (scenario === "saved-explicit-safety-identifier")
            request.recipe.safetyIdentifier = expectedSafetyIdentifier;
          if (samePath && savedLiteral !== currentLiteral) {
            await assert.rejects(
              prepareNativeScan(request),
              /literal.*glob|glob.*literal/u,
            );
            await assert.rejects(readFile(capture), { code: "ENOENT" });
            continue;
          }
          if (scenario === "lexical-target-protection") {
            const priorPreflights = await readFile(preflights, "utf8");
            await assert.rejects(
              prepareNativeScan({
                ...request,
                scan: { ...request.scan, targetProtectionRoots: undefined },
              }),
              /does not record its original target paths/u,
            );
            assert.equal(await readFile(preflights, "utf8"), priorPreflights);
            await assert.rejects(readFile(decoyLaunch), { code: "ENOENT" });
          }
          const prepared = await prepareNativeScan(request);
          if (scenario.endsWith("-knowledge")) {
            assert.deepEqual(
              prepared.options.knowledgeBaseSnapshot,
              savedKnowledge,
            );
            assert.deepEqual(
              prepared.options.knowledgeBasePaths,
              savedKnowledge ? [document] : undefined,
            );
          }
          if (scenario === "tilde-home-and-selected-config") {
            assert.equal(prepared.options.workers, 3);
            assert.equal(prepared.options.subagents, 4);
            assert.equal(prepared.options.maxDiscoveryRuns, 5);
          }
          const knowledge = prepared.options.knowledgeBaseSnapshot
            ? await prepareKnowledgeBase(prepared.options.knowledgeBaseSnapshot)
            : undefined;
          const { runtime, session } = await nativeWorkerSession(
            prepared,
            repository,
          );
          try {
            for (const role of ["discovery", "merge"]) {
              const worker =
                role === "discovery"
                  ? prepareDiscoveryExecution(session)
                  : prepareMergeExecution(session, 2);
              const { codex } = await createExecutionCodex(
                { surface: "sdk", command: "scan" },
                worker,
                {
                  ...(knowledge
                    ? { CODEX_SECURITY_KNOWLEDGE_BASE: knowledge.path }
                    : {}),
                  ...(prepared.client.dependencies.stateDirectory === undefined
                    ? {}
                    : {
                        CODEX_SECURITY_STATE_DIR:
                          prepared.client.dependencies.stateDirectory,
                      }),
                },
              );
              const options = {
                workingDirectory: repository,
                skipGitRepoCheck: true,
                approvalPolicy: "never",
              };
              const thread = resumed
                ? codex.resumeThread("synthetic-merged-worker", options)
                : codex.startThread(options);
              const events = await collectNativeEvents(
                thread,
                "Synthetic worker settings only.",
                {},
              );
              assert.equal(events.at(-1).type, "turn.completed");
              const observed = JSON.parse(await readFile(capture, "utf8"));
              const fragments = [];
              for (let i = 0; i < observed.argv.length; i++)
                if (["-c", "--config"].includes(observed.argv[i]))
                  fragments.push(parseToml(observed.argv[++i]));
              const config = Object.assign({}, ...fragments);
              assert.equal(observed.argv.includes("resume"), resumed);
              assert.equal(observed.home, home);
              assert.equal(
                observed.state,
                request.stateDirectory ??
                  join(home, "state", "plugins", "codex-security"),
              );
              assert.equal(observed.executable, executable);
              if (lexicalTarget) {
                assert.equal(
                  observed.path,
                  scenario === "lexical-target-protection"
                    ? root
                    : [lexicalBin, root].join(delimiter),
                );
                await assert.rejects(readFile(decoyLaunch), { code: "ENOENT" });
              }
              assert.equal(observed.openai, "synthetic-selected-key");
              assert.equal(observed.safetyIdentifier, expectedSafetyIdentifier);
              assert.equal(
                observed.codex,
                externalProvider ? "synthetic-competing-key" : undefined,
              );
              if (externalProvider) {
                assert.equal(observed.modelProvider, externalProvider);
                assert.deepEqual(
                  observed.provider,
                  configuration.model_providers[externalProvider],
                );
                assert.deepEqual(
                  observed.profileProvider,
                  configuration.model_providers[externalProvider],
                );
                assert.equal(config.model_provider, externalProvider);
                assert.equal(config.model_providers, undefined);
                if (
                  scenario.endsWith("-env-key") ||
                  scenario.endsWith("-bearer")
                )
                  assert.equal(
                    observed.providerToken,
                    scenario.endsWith("-env-key")
                      ? "synthetic-selected-key"
                      : "synthetic-provider-token",
                  );
                else
                  assert.equal(
                    observed.providerHeaders.Authorization,
                    scenario.endsWith("-env-http-headers")
                      ? "synthetic-selected-key"
                      : "synthetic-provider-header",
                  );
                assert.equal(observed.literalCredentialInEnvironment, false);
                for (const value of [
                  "synthetic-provider-token",
                  "synthetic-provider-header",
                ])
                  assert.equal(
                    observed.argv.some((argument) => argument.includes(value)),
                    false,
                  );
              }
              if (observed.knowledge !== knowledge?.path)
                knowledgeMismatches.push({
                  role,
                  resumed,
                  actual: observed.knowledge,
                  expected: knowledge?.path,
                });
              if (knowledge) {
                assert.equal(
                  await readFile(
                    join(observed.knowledge, "0-knowledge.txt.txt"),
                    "utf8",
                  ),
                  "Original synthetic knowledge.\n",
                );
              }
              if (scenario === "saved-developer-instructions")
                assert.equal(
                  config.developer_instructions,
                  "Saved synthetic guidance.",
                );
              assert.equal(config.model, "explicit-current-model");
              assert.equal(config.model_reasoning_effort, "ultra");
              if (selectedConfiguration) {
                for (const [key, value] of Object.entries(
                  configuration.features,
                ))
                  assert.equal(config.features[key], value);
                assert.equal(config.model_reasoning_summary, "auto");
                assert.equal(
                  await readFile(selectedConfigPath, "utf8"),
                  selectedConfigText,
                );
                assert.equal(await readFile(replay.path, "utf8"), replayText);
              }
              assert.equal(
                config.features.multi_agent_v2
                  .max_concurrent_threads_per_session,
                (role === "merge" ? 2 : prepared.options.subagents) + 1,
              );
              assert.equal(
                config.permissions[config.default_permissions].network.enabled,
                false,
              );
              for (const [name, value] of Object.entries(invokingEnvironment))
                assert.equal(process.env[name], value, name);
              const filesystem =
                config.permissions[config.default_permissions].filesystem;
              assert.equal(
                savedLiteral
                  ? filesystem[savedPath]["."]
                  : filesystem[savedPath],
                request.recipe ? "deny" : undefined,
              );
              assert.equal(
                currentLiteral
                  ? filesystem[currentPath]["."]
                  : filesystem[currentPath],
                "deny",
              );
              assert.equal(filesystem.glob_scan_max_depth, expectedDepth);
              assert.equal(
                filesystem[":workspace_roots"],
                scenario === "read-only-parent" ? "read" : "write",
              );
              if (scenario === "read-only-parent")
                assert.equal(
                  filesystem[join(repository, "saved-write")]["."],
                  "read",
                );
              assert.equal(
                await readFile(join(home, "config.toml"), "utf8"),
                configText,
              );
              assert.equal(
                process.env.OPENAI_API_KEY,
                "synthetic-selected-key",
              );
            }
          } finally {
            await knowledge?.cleanup();
            await runtime.providerProfile.cleanup();
            await rm(runtime.bootstrapWorkspace, {
              recursive: true,
              force: true,
            });
          }
        }
        assert.deepEqual(knowledgeMismatches, []);
        if (lexicalTarget) {
          const rows = (await readFile(preflights, "utf8"))
            .trim()
            .split("\n")
            .map(JSON.parse)
            .filter((row) => row.kind === "preflight");
          assert.equal(rows.length, 4);
          for (const row of rows) {
            assert.equal(row.executable, executable);
            assert.equal(
              row.gitEnvironment.PATH,
              scenario === "lexical-target-protection"
                ? root
                : [lexicalBin, root].join(delimiter),
            );
          }
          await assert.rejects(readFile(decoyLaunch), { code: "ENOENT" });
        }
        if (externalProvider) {
          const rows = (await readFile(preflights, "utf8"))
            .trim()
            .split("\n")
            .map(JSON.parse)
            .filter((row) => row.kind === "preflight");
          assert.equal(rows.length, 4);
          for (const row of rows) {
            assert.equal(row.openai, "synthetic-selected-key");
            assert.equal(row.codex, "synthetic-competing-key");
            assert.equal(row.modelProvider, externalProvider);
            assert.deepEqual(row.provider, {
              name: configuration.model_providers[externalProvider].name,
              wire_api: "responses",
            });
            for (const value of [
              "synthetic-provider-token",
              "synthetic-provider-header",
            ])
              assert.equal(
                row.argv.some((argument) => argument.includes(value)),
                false,
              );
          }
        }
      } finally {
        restore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

test(
  "native target protection, selected configuration and captured semantic inputs stay isolated across concurrent worker launches",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-concurrent-targets-")),
    );
    const restore = captureEnvironment([
      "PATH",
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
      "NATIVE_PROFILE_CAPTURE",
      "NATIVE_PROFILE_MARKER",
      "CODEX_SAFETY_IDENTIFIER",
      "CODEX_SECURITY_KNOWLEDGE_BASE",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      "CODEX_SECURITY_STATE_DIR",
    ]);
    const fixtures = [];
    try {
      const pluginRoot = join(root, "plugin");
      await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
      await writeFile(
        join(pluginRoot, ".codex-plugin/plugin.json"),
        JSON.stringify({ name: "codex-security", version: "0.0.0" }),
      );
      for (const id of ["a", "b", "c", "d"]) {
        const capturedInputs = id === "c" || id === "d";
        const fixture = {
          id,
          repository: join(root, `target-${id}`),
          lexicalRepository: join(root, `repository-${id}`),
          home: join(root, `home-${id}`),
          toolBin: join(root, `tools-${id}`),
          scanDir: join(root, `scan-${id}`),
          stateDirectory: join(
            root,
            `selected-state-${id}${process.platform === "win32" ? "" : " "}`,
          ),
          capture: join(root, `worker-${id}.json`),
          preflights: join(root, `preflights-${id}.jsonl`),
          decoyLaunch: join(root, `decoy-${id}.jsonl`),
          selectedConfigPath: join(root, `selected-${id}.toml`),
          instructionsFile: join(
            root,
            `instructions-${id}-${capturedInputs ? "B" : "A"}.md`,
          ),
          laterInstructionsFile: join(
            root,
            `instructions-${id}-${capturedInputs ? "A" : "B"}.md`,
          ),
          compactPromptFile: join(
            root,
            `compact-${id}-${capturedInputs ? "B" : "A"}.md`,
          ),
          laterCompactPromptFile: join(
            root,
            `compact-${id}-${capturedInputs ? "A" : "B"}.md`,
          ),
          developerInstructions: `Selected synthetic guidance ${id}.`,
          parentAccess: id === "a" || id === "c" ? "read" : "write",
          parentDeniedPath: join(root, `parent-private-${id}`),
          savedWritePath: join(root, `saved-write-${id}`),
          parentPolicyReads: 0,
          model: capturedInputs
            ? `${id === "c" ? "selected" : "ambient"}-model-${id}`
            : `synthetic-model-${id}`,
          reasoningEffort: capturedInputs
            ? `${id === "c" ? "selected" : "ambient"}-effort-${id}`
            : `synthetic-effort-${id}`,
          safetyIdentifier: capturedInputs
            ? `synthetic-later-${id}`
            : id === "a"
              ? undefined
              : "synthetic-saved-b",
        };
        fixture.lexicalBin = join(fixture.lexicalRepository, "bin");
        fixture.executable = join(fixture.toolBin, "codex");
        await Promise.all([
          mkdir(fixture.repository),
          mkdir(fixture.lexicalBin, { recursive: true }),
          mkdir(fixture.home, { mode: 0o700 }),
          mkdir(fixture.toolBin),
          mkdir(fixture.scanDir, { mode: 0o700 }),
        ]);
        await mkdir(join(fixture.lexicalRepository, ".git"));
        await symlink(
          fixture.repository,
          join(fixture.lexicalRepository, "selected"),
          "dir",
        );
        fixture.provider = {
          name: `Selected synthetic provider ${id}`,
          base_url: `https://example.invalid/${id}`,
          env_key: "OPENAI_API_KEY",
          requires_openai_auth: true,
          wire_api: "responses",
          request_max_retries: id === "a" ? 3 : 7,
        };
        fixture.features = {
          goals: true,
          api_key_model_discovery: id === "a",
          api_key_cyber_access_programs: true,
        };
        fixture.configText = stringifyToml({
          model: `ambient-model-${id}`,
          model_reasoning_effort: `ambient-effort-${id}`,
          model_provider: "openai",
          model_reasoning_summary: "auto",
          model_providers: {
            openai: {
              name: `Ambient synthetic provider ${id}`,
              base_url: fixture.provider.base_url,
              env_key: "OPENAI_API_KEY",
              requires_openai_auth: true,
              request_max_retries: 1,
            },
          },
          features: { goals: true, api_key_model_discovery: id !== "a" },
        });
        fixture.selectedConfigText = stringifyToml({
          developer_instructions: fixture.developerInstructions,
          model_instructions_file: fixture.instructionsFile,
          experimental_compact_prompt_file: fixture.compactPromptFile,
          ...(id === "c"
            ? {
                model: fixture.model,
                model_reasoning_effort: fixture.reasoningEffort,
              }
            : {}),
          model_providers: {
            openai: {
              name: fixture.provider.name,
              wire_api: "responses",
              request_max_retries: fixture.provider.request_max_retries,
            },
          },
          features: {
            api_key_model_discovery: fixture.features.api_key_model_discovery,
            api_key_cyber_access_programs: true,
          },
        });
        await writeFile(join(fixture.home, "config.toml"), fixture.configText);
        await writeFile(fixture.selectedConfigPath, fixture.selectedConfigText);
        await Promise.all(
          [
            fixture.instructionsFile,
            fixture.laterInstructionsFile,
            fixture.compactPromptFile,
            fixture.laterCompactPromptFile,
          ].map((path) =>
            writeFile(path, `Synthetic instruction-file guidance ${id}.\n`),
          ),
        );
        if (!capturedInputs) {
          fixture.savedConfiguration = await nativeScanConfiguration(
            {
              ...process.env,
              CODEX_HOME: fixture.home,
              CODEX_SECURITY_CONFIG_PATH: fixture.selectedConfigPath,
            },
            { model: fixture.model, reasoningEffort: fixture.reasoningEffort },
            2,
          );
          const laterSelectedConfig = parseToml(fixture.selectedConfigText);
          laterSelectedConfig.model_instructions_file =
            fixture.laterInstructionsFile;
          laterSelectedConfig.experimental_compact_prompt_file =
            fixture.laterCompactPromptFile;
          fixture.selectedConfigText = stringifyToml(laterSelectedConfig);
          await writeFile(
            fixture.selectedConfigPath,
            fixture.selectedConfigText,
          );
        }
        if (capturedInputs) {
          const knowledgeDirectory = join(root, `knowledge-${id}`);
          await mkdir(knowledgeDirectory);
          fixture.document = join(knowledgeDirectory, `knowledge ${id}.txt`);
          fixture.knowledgeText = `Captured synthetic knowledge ${id}.\n`;
          fixture.deepConfigPath = join(root, `deep-${id}.toml`);
          fixture.subagents = id === "c" ? 3 : 5;
          await writeFile(fixture.document, fixture.knowledgeText);
          await writeFile(
            fixture.deepConfigPath,
            `[deep_scan]\nworkers=${id === "c" ? '"auto"' : 4}\nsubagents=${fixture.subagents}\nmax_discovery_runs=7\n`,
          );
          Object.assign(process.env, {
            CODEX_HOME: fixture.home,
            CODEX_SECURITY_CONFIG_PATH: fixture.selectedConfigPath,
            CODEX_SECURITY_KNOWLEDGE_BASE:
              id === "c" ? ` \t${fixture.document}\n ` : " \t\n ",
            CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: fixture.deepConfigPath,
          });
          fixture.semanticInputs = await readNativeScanSemanticInputs();
          assert.deepEqual(fixture.semanticInputs.modelSettings, {
            model: fixture.model,
            reasoningEffort: fixture.reasoningEffort,
          });
          assert.equal(
            Object.hasOwn(fixture.semanticInputs.config, "windows"),
            false,
          );
          assert.equal(
            typeof fixture.semanticInputs.deepScanSettings.workers,
            "number",
          );
          if (id === "d")
            assert.equal(fixture.semanticInputs.deepScanSettings.workers, 4);
          assert.equal(
            fixture.semanticInputs.deepScanSettings.subagents,
            fixture.subagents,
          );
          assert.equal(
            fixture.semanticInputs.deepScanSettings.maxDiscoveryRuns,
            7,
          );
          await writeFile(
            fixture.document,
            `Later synthetic knowledge ${id}.\n`,
          );
          await writeFile(
            fixture.deepConfigPath,
            "[deep_scan]\nworkers=8\nsubagents=9\nmax_discovery_runs=10\n",
          );
          const laterConfig = parseToml(fixture.configText);
          laterConfig.model = `later-ambient-model-${id}`;
          laterConfig.model_reasoning_effort = `later-ambient-effort-${id}`;
          laterConfig.model_reasoning_summary = "detailed";
          laterConfig.features.goals = false;
          fixture.configText = stringifyToml(laterConfig);
          const laterSelectedConfig = parseToml(fixture.selectedConfigText);
          laterSelectedConfig.developer_instructions = `Later synthetic guidance ${id}.`;
          laterSelectedConfig.model_instructions_file =
            fixture.laterInstructionsFile;
          laterSelectedConfig.experimental_compact_prompt_file =
            fixture.laterCompactPromptFile;
          laterSelectedConfig.model = `later-selected-model-${id}`;
          laterSelectedConfig.model_reasoning_effort = `later-selected-effort-${id}`;
          laterSelectedConfig.model_providers.openai.name = `Later synthetic provider ${id}`;
          laterSelectedConfig.features.api_key_cyber_access_programs = false;
          fixture.selectedConfigText = stringifyToml(laterSelectedConfig);
          await writeFile(
            join(fixture.home, "config.toml"),
            fixture.configText,
          );
          await writeFile(
            fixture.selectedConfigPath,
            fixture.selectedConfigText,
          );
        }
        await writeNativeWorkerExecutable(fixture.executable, fixture.capture);
        await writeFile(
          join(fixture.lexicalBin, "codex"),
          (await readFile(fixture.executable, "utf8")).replace(
            'const fs = require("node:fs");',
            `const fs = require("node:fs"); fs.appendFileSync(${JSON.stringify(fixture.decoyLaunch)}, JSON.stringify(process.argv.slice(2)) + "\\n");`,
          ),
          { mode: 0o700 },
        );
        fixtures.push(fixture);
      }
      for (const key of [
        "CODEX_CLI_PATH",
        "CODEX_API_KEY",
        "CODEX_SECURITY_KNOWLEDGE_BASE",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_SECURITY_STATE_DIR",
      ])
        delete process.env[key];
      const pending = fixtures.map((fixture, index) => {
        const other = fixtures[index ^ 1];
        fixture.path = [
          fixture.lexicalBin,
          fixture.toolBin,
          other.lexicalBin,
          other.toolBin,
        ].join(delimiter);
        fixture.expectedPath = [
          fixture.toolBin,
          other.lexicalBin,
          other.toolBin,
        ].join(delimiter);
        Object.assign(process.env, {
          PATH: fixture.path,
          CODEX_HOME: fixture.home,
          CODEX_SECURITY_CONFIG_PATH: fixture.selectedConfigPath,
          CODEX_SECURITY_STATE_DIR: join(root, "ambient-state"),
          OPENAI_API_KEY: `synthetic-key-${fixture.id}`,
          NATIVE_PROFILE_CAPTURE: fixture.preflights,
          NATIVE_PROFILE_MARKER: fixture.id,
          CODEX_SAFETY_IDENTIFIER: `synthetic-later-${fixture.id}`,
        });
        if (fixture.semanticInputs) {
          process.env.CODEX_SECURITY_KNOWLEDGE_BASE = fixture.document;
          process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH =
            fixture.deepConfigPath;
        } else {
          fixture.savedDeepScanSettings = {
            ...fixtures[index + 2].semanticInputs.deepScanSettings,
            workers: 1,
            subagents: 2,
          };
        }
        return prepareNativeScan({
          ...input(`synthetic-${fixture.id}`),
          parentSandbox: () => {
            fixture.parentPolicyReads++;
            return resolveNativeParentSandbox({
              _meta: {
                "codex/sandbox-state-meta": {
                  permissionProfile: {
                    type: "managed",
                    file_system: {
                      type: "restricted",
                      entries: [
                        {
                          access: "read",
                          path: { type: "special", value: { kind: "root" } },
                        },
                        {
                          access: fixture.parentAccess,
                          path: {
                            type: "special",
                            value: { kind: "project_roots" },
                          },
                        },
                        {
                          access: "deny",
                          path: {
                            type: "path",
                            path: fixture.parentDeniedPath,
                          },
                        },
                      ],
                    },
                  },
                },
              },
            });
          },
          pluginRoot,
          stateDirectory: fixture.stateDirectory,
          ...(fixture.semanticInputs
            ? {}
            : {
                model: fixture.model,
                reasoningEffort: fixture.reasoningEffort,
              }),
          semanticInputs:
            fixture.semanticInputs ?? fixtures[index + 2].semanticInputs,
          scan: {
            ...input(`synthetic-${fixture.id}`).scan,
            targetPath: fixture.repository,
            targetProtectionRoots: [fixture.lexicalRepository],
            scanDir: fixture.scanDir,
          },
          ...(fixture.semanticInputs
            ? {}
            : {
                recipe: {
                  auth: "api-key",
                  config: fixture.savedConfiguration,
                  inheritedPermissions: {
                    filesystem: { [fixture.savedWritePath]: "write" },
                    network: { enabled: false },
                  },
                  deepScan: fixture.savedDeepScanSettings,
                  ...(fixture.safetyIdentifier === undefined
                    ? {}
                    : { safetyIdentifier: fixture.safetyIdentifier }),
                },
              }),
        });
      });
      const prepared = await Promise.all(pending);
      await Promise.all(
        fixtures.map(async (fixture, index) => {
          assert.equal(fixture.parentPolicyReads, 1);
          for (const [name, value] of Object.entries(
            fixture.semanticInputs?.deepScanSettings ??
              fixture.savedDeepScanSettings,
          ))
            assert.equal(prepared[index].options[name], value);
          const knowledge = fixture.semanticInputs?.knowledgeBaseSnapshot
            ? await prepareKnowledgeBase(
                prepared[index].options.knowledgeBaseSnapshot,
              )
            : undefined;
          if (fixture.semanticInputs) {
            assert.deepEqual(
              prepared[index].options.knowledgeBasePaths,
              fixture.id === "c" ? [fixture.document] : undefined,
            );
            assert.deepEqual(
              prepared[index].options.knowledgeBaseSnapshot,
              fixture.semanticInputs.knowledgeBaseSnapshot,
            );
          } else {
            assert.equal(prepared[index].options.knowledgeBasePaths, undefined);
            assert.equal(
              prepared[index].options.knowledgeBaseSnapshot,
              undefined,
            );
          }
          const { runtime, session } = await nativeWorkerSession(
            prepared[index],
            fixture.repository,
          );
          try {
            for (const resumed of [false, true]) {
              for (const role of ["discovery", "merge"]) {
                const worker =
                  role === "discovery"
                    ? prepareDiscoveryExecution(session)
                    : prepareMergeExecution(
                        session,
                        fixture.semanticInputs
                          ? prepared[index].options.subagents
                          : 2,
                      );
                const { codex } = await createExecutionCodex(
                  { surface: "sdk", command: "scan" },
                  worker,
                  {
                    ...(knowledge
                      ? { CODEX_SECURITY_KNOWLEDGE_BASE: knowledge.path }
                      : {}),
                    ...(prepared[index].client.dependencies.stateDirectory ===
                    undefined
                      ? {}
                      : {
                          CODEX_SECURITY_STATE_DIR:
                            prepared[index].client.dependencies.stateDirectory,
                        }),
                  },
                );
                const options = {
                  workingDirectory: fixture.repository,
                  skipGitRepoCheck: true,
                  approvalPolicy: "never",
                };
                const thread = resumed
                  ? codex.resumeThread("synthetic-merged-worker", options)
                  : codex.startThread(options);
                const events = await collectNativeEvents(
                  thread,
                  "Synthetic isolated worker settings.",
                  {},
                );
                assert.equal(events.at(-1).type, "turn.completed");
                const observed = JSON.parse(
                  await readFile(fixture.capture, "utf8"),
                );
                assert.equal(observed.executable, fixture.executable);
                assert.equal(observed.path, fixture.expectedPath);
                assert.equal(observed.home, fixture.home);
                assert.equal(observed.model, fixture.model);
                assert.equal(observed.reasoningEffort, fixture.reasoningEffort);
                assert.equal(observed.openai, `synthetic-key-${fixture.id}`);
                assert.equal(
                  observed.safetyIdentifier,
                  fixture.safetyIdentifier,
                );
                assert.deepEqual(observed.provider, fixture.provider);
                assert.deepEqual(observed.profileProvider, fixture.provider);
                const fragments = [];
                for (let i = 0; i < observed.argv.length; i++)
                  if (["-c", "--config"].includes(observed.argv[i]))
                    fragments.push(parseToml(observed.argv[++i]));
                const config = Object.assign({}, ...fragments);
                const permission =
                  config.permissions[config.default_permissions];
                assert.equal(permission.network.enabled, false);
                assert.equal(
                  permission.filesystem[":workspace_roots"],
                  fixture.parentAccess,
                );
                assert.equal(
                  permission.filesystem[fixture.parentDeniedPath],
                  "deny",
                );
                assert.equal(
                  permission.filesystem[fixture.savedWritePath],
                  fixture.semanticInputs ? undefined : fixture.parentAccess,
                );
                for (const other of fixtures)
                  if (other !== fixture)
                    assert.equal(
                      permission.filesystem[other.parentDeniedPath],
                      undefined,
                    );
                assert.equal(
                  config.developer_instructions,
                  fixture.developerInstructions,
                );
                assert.equal(
                  config.model_instructions_file,
                  fixture.instructionsFile,
                );
                assert.equal(
                  config.experimental_compact_prompt_file,
                  fixture.compactPromptFile,
                );
                if (knowledge) {
                  assert.equal(observed.knowledge, knowledge.path);
                  assert.deepEqual(observed.knowledgeDocuments, {
                    [`0-knowledge ${fixture.id}.txt.txt`]:
                      fixture.knowledgeText,
                  });
                  assert.equal(
                    config.features.multi_agent_v2
                      .max_concurrent_threads_per_session,
                    fixture.subagents + 1,
                  );
                } else {
                  assert.equal(observed.knowledge, undefined);
                  assert.equal(
                    config.features.multi_agent_v2
                      .max_concurrent_threads_per_session,
                    fixture.semanticInputs ? fixture.subagents + 1 : 3,
                  );
                }
                for (const [key, value] of Object.entries(fixture.features))
                  assert.equal(config.features[key], value);
                assert.equal(config.model_reasoning_summary, "auto");
                assert.equal(observed.argv.includes("resume"), resumed);
                assert.ok(observed.argv.includes(`model="${fixture.model}"`));
                assert.equal(observed.state, fixture.stateDirectory);
                await assert.rejects(readFile(fixture.decoyLaunch), {
                  code: "ENOENT",
                });
              }
            }
            const preflights = (await readFile(fixture.preflights, "utf8"))
              .trim()
              .split("\n")
              .map(JSON.parse)
              .filter((row) => row.kind === "preflight");
            assert.equal(preflights.length, 4);
            assert.equal(
              await readFile(join(fixture.home, "config.toml"), "utf8"),
              fixture.configText,
            );
            assert.equal(
              await readFile(fixture.selectedConfigPath, "utf8"),
              fixture.selectedConfigText,
            );
            for (const observed of preflights) {
              assert.equal(observed.executable, fixture.executable);
              assert.equal(observed.gitEnvironment.PATH, fixture.expectedPath);
              assert.equal(observed.marker, fixture.id);
              assert.equal(observed.openai, `synthetic-key-${fixture.id}`);
            }
            assert.equal(fixture.parentPolicyReads, 1);
          } finally {
            await knowledge?.cleanup();
            await runtime.providerProfile.cleanup();
            await rm(runtime.bootstrapWorkspace, {
              recursive: true,
              force: true,
            });
          }
        }),
      );
      assert.equal(process.env.PATH, fixtures[3].path);
      assert.equal(process.env.CODEX_HOME, fixtures[3].home);
      assert.equal(
        process.env.CODEX_SECURITY_CONFIG_PATH,
        fixtures[3].selectedConfigPath,
      );
      assert.equal(process.env.OPENAI_API_KEY, "synthetic-key-d");
      assert.equal(process.env.NATIVE_PROFILE_MARKER, "d");
      assert.equal(process.env.CODEX_SAFETY_IDENTIFIER, "synthetic-later-d");
      assert.equal(
        process.env.CODEX_SECURITY_KNOWLEDGE_BASE,
        fixtures[3].document,
      );
      assert.equal(
        process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
        fixtures[3].deepConfigPath,
      );
      assert.equal(
        process.env.CODEX_SECURITY_STATE_DIR,
        join(root, "ambient-state"),
      );
    } finally {
      restore();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test(
  "native preflight rejects executables from fresh and saved knowledge sources",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-knowledge-preflight-")),
    );
    const knowledge = join(root, "knowledge");
    const document = join(knowledge, "architecture.md");
    const executable = join(knowledge, "codex");
    const external = join(root, "codex");
    const marker = join(root, "launched.json");
    const scanDir = join(root, "scan");
    const restore = captureEnvironment([
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_SECURITY_KNOWLEDGE_BASE",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
    ]);
    try {
      await mkdir(join(knowledge, ".git"), { recursive: true });
      await mkdir(scanDir, { mode: 0o700 });
      await writeFile(document, "Synthetic architecture.\n");
      const script = `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify(process.argv.slice(2))); console.log("Not logged in"); process.exitCode = 1;\n`;
      await writeFile(executable, script, { mode: 0o700 });
      await writeFile(external, script, { mode: 0o700 });
      Object.assign(process.env, {
        CODEX_HOME: root,
        CODEX_CLI_PATH: executable,
        CODEX_SECURITY_KNOWLEDGE_BASE: document,
        OPENAI_API_KEY: "synthetic-preflight-key",
      });
      delete process.env.CODEX_API_KEY;
      delete process.env.CODEX_SECURITY_CONFIG_PATH;
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      const snapshot = await readKnowledgeBaseSnapshot([document]);
      await saveScanKnowledge(scanDir, snapshot);
      const request = { ...input(), scan: { ...input().scan, scanDir } };
      const recipe = {
        knowledgeBasePaths: [document],
        scanInputs: scanInputIdentity(request.scan.userContext, snapshot),
      };
      for (const state of ["fresh", "resumed", "deleted-source", "legacy"]) {
        if (state === "deleted-source") await rm(document);
        let savedRecipe = recipe;
        if (state === "legacy") {
          const { protectedRoots, ...legacy } = snapshot;
          await rm(join(scanDir, ".scan-knowledge.json"));
          await saveScanKnowledge(scanDir, legacy);
          savedRecipe = {
            ...recipe,
            scanInputs: scanInputIdentity(request.scan.userContext, legacy),
          };
        }
        await assert.rejects(
          prepareNativeScan({
            ...request,
            ...(state === "fresh" ? {} : { recipe: savedRecipe }),
          }),
          /outside the scan target or knowledge base/,
        );
        await assert.rejects(readFile(marker), { code: "ENOENT" });
      }
      await rm(join(scanDir, ".scan-knowledge.json"));
      await saveScanKnowledge(scanDir, snapshot);
      process.env.CODEX_CLI_PATH = external;
      const trusted = await prepareNativeScan({ ...request, recipe });
      assert.equal(
        trusted.client.dependencies.ambientExecution.command.command,
        external,
      );
      assert.deepEqual(JSON.parse(await readFile(marker, "utf8")), [
        "login",
        "status",
      ]);
      await rm(marker);
      await writeFile(
        join(scanDir, ".scan-knowledge.json"),
        JSON.stringify({
          ...snapshot,
          documents: { "architecture.txt": "Changed synthetic context." },
        }),
      );
      await assert.rejects(
        prepareNativeScan({ ...request, recipe }),
        /saved knowledge-base snapshot changed/,
      );
      await assert.rejects(readFile(marker), { code: "ENOENT" });
    } finally {
      restore();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("native rejoin restores bound knowledge without overwriting its snapshot", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-knowledge-resume-")),
  );
  const document = join(root, "architecture.md");
  const scanDir = join(root, "scan");
  const home = join(root, "home");
  await mkdir(scanDir, { mode: 0o700 });
  await mkdir(home);
  await writeFile(document, "Original synthetic architecture.\n");
  const restoreEnvironment = captureEnvironment([
    "CODEX_HOME",
    "CODEX_API_KEY",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ]);
  try {
    Object.assign(process.env, {
      CODEX_HOME: home,
      CODEX_API_KEY: "synthetic-knowledge-key",
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_KNOWLEDGE_BASE: document,
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    const request = { ...input(), scan: { ...input().scan, scanDir } };
    const fresh = await prepareNativeScan(request);
    assert.equal(fresh.options.resumeScanId, undefined);
    assert.deepEqual(
      fresh.options.knowledgeBaseSnapshot,
      await readKnowledgeBaseSnapshot([document]),
    );
    assert.deepEqual(fresh.options.knowledgeBasePaths, [document]);
    const snapshot = await readKnowledgeBaseSnapshot([document]);
    await saveScanKnowledge(scanDir, snapshot);
    const recipe = {
      knowledgeBasePaths: [document],
      scanInputs: scanInputIdentity(request.scan.userContext, snapshot),
    };
    const snapshotPath = join(scanDir, ".scan-knowledge.json");
    const original = await readFile(snapshotPath, "utf8");
    for (const state of ["edited", "deleted"]) {
      if (state === "edited")
        await writeFile(document, "Changed architecture.");
      else await rm(document);
      const rejoined = await prepareNativeScan({ ...request, recipe });
      assert.equal(rejoined.options.resumeScanId, request.scan.scanId);
      assert.equal(rejoined.options.registeredScan.scanId, request.scan.scanId);
      assert.deepEqual(rejoined.options.knowledgeBaseSnapshot, snapshot);
      assert.equal(await readFile(snapshotPath, "utf8"), original);
    }
    const modified = JSON.parse(original);
    modified.documents["0-architecture.md.txt"] = "Changed snapshot.";
    await writeFile(snapshotPath, JSON.stringify(modified));
    await assert.rejects(
      prepareNativeScan({ ...request, recipe }),
      /saved knowledge-base snapshot changed/,
    );
    assert.equal(
      await readFile(snapshotPath, "utf8"),
      JSON.stringify(modified),
    );
    await rm(snapshotPath);
    await assert.rejects(
      prepareNativeScan({ ...request, recipe }),
      /Cannot restore the original scan knowledge base/,
    );
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test("native selected configuration preserves home traversal and blank selectors", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-selected-path-")),
  );
  const restore = captureEnvironment([
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
  ]);
  try {
    delete process.env.CODEX_API_KEY;
    delete process.env.OPENAI_API_KEY;
    await mkdir(join(root, "target", "nested"), { recursive: true });
    await symlink(
      join(root, "target", "nested"),
      join(root, "link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await writeFile(
      join(root, "target", "deep.toml"),
      "[deep_scan]\nworkers=1\nmax_discovery_runs=2\n",
    );
    await writeFile(
      join(root, "deep.toml"),
      "[deep_scan]\nworkers=7\nmax_discovery_runs=9\n",
    );
    Object.assign(process.env, {
      HOME: root,
      USERPROFILE: root,
      CODEX_HOME: root,
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_CONFIG_PATH: " \t\n",
      CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: "~/link/../deep.toml",
    });
    const prepared = await prepareNativeScan(input());
    assert.equal(prepared.options.workers, 1);
    assert.equal(prepared.options.maxDiscoveryRuns, 2);
    const selected = join(
      root,
      process.platform === "win32" ? "selected.toml" : " selected.toml ",
    );
    await writeFile(selected, 'model="synthetic-selected"\n');
    process.env.CODEX_SECURITY_CONFIG_PATH = selected;
    assert.equal(
      (await prepareNativeScan(input())).client.config.codexOverrides.model,
      "synthetic-selected",
    );
  } finally {
    restore();
    await rm(root, { recursive: true, force: true });
  }
});

test("native resume preserves absent knowledge instead of importing ambient context", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-absent-knowledge-")),
  );
  const restore = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
  ]);
  try {
    delete process.env.CODEX_API_KEY;
    delete process.env.OPENAI_API_KEY;
    const document = join(root, "late.txt");
    await writeFile(document, "Late synthetic context.");
    Object.assign(process.env, {
      CODEX_HOME: root,
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_KNOWLEDGE_BASE: document,
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    for (const sealed of [false, true]) {
      const scanDir = join(root, String(sealed));
      await mkdir(scanDir, { mode: 0o700 });
      if (sealed)
        await writeFile(
          join(scanDir, "scan-manifest.json"),
          JSON.stringify({ scan: { sealedAt: "2026-01-01T00:00:00Z" } }),
        );
      const request = { ...input(), scan: { ...input().scan, scanDir } };
      assert.deepEqual(
        (await prepareNativeScan(request)).options.knowledgeBasePaths,
        [document],
      );
      const prepared = await prepareNativeScan({
        ...request,
        recipe: {
          config: {},
          scanInputs: scanInputIdentity(request.scan.userContext),
        },
      });
      assert.equal(prepared.options.knowledgeBasePaths, undefined);
      assert.equal(prepared.options.knowledgeBaseSnapshot, undefined);
      assert.equal(
        prepared.client.dependencies.ambientExecution.environment
          .CODEX_SECURITY_KNOWLEDGE_BASE,
        undefined,
      );
      assert.equal(process.env.CODEX_SECURITY_KNOWLEDGE_BASE, document);
      assert.equal(prepared.options.resumeScanId, request.scan.scanId);
    }
  } finally {
    restore();
    await rm(root, { recursive: true, force: true });
  }
});

test("sealed native publication defers executable selection while retaining ambient context", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-sealed-executable-")),
  );
  const restore = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
  ]);
  try {
    const scanDir = join(root, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(
      join(scanDir, "scan-manifest.json"),
      JSON.stringify({ scan: { sealedAt: "2026-01-01T00:00:00Z" } }),
    );
    const missing = join(root, "missing-codex");
    Object.assign(process.env, { CODEX_HOME: root, CODEX_CLI_PATH: missing });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
    const request = {
      ...input(),
      scan: { ...input().scan, scanDir, targetProtectionRoots: undefined },
      recipe: {
        auth: "api-key",
        config: {
          model: "synthetic-saved",
          model_instructions_file: join(
            root,
            "missing-instructions",
            "guide.md",
          ),
          experimental_compact_prompt_file: join(
            root,
            "missing-compact-prompt",
            "guide.md",
          ),
        },
        preserveProviderEnvironment: true,
      },
    };
    const prepared = await prepareNativeScan(request);
    assert.equal(
      prepared.client.dependencies.ambientExecution.environment.CODEX_HOME,
      root,
    );
    assert.equal(
      prepared.client.dependencies.ambientExecution.pluginRoot,
      request.pluginRoot,
    );
    assert.equal(
      prepared.client.dependencies.ambientExecution.command,
      undefined,
    );
    assert.equal(
      prepared.client.config.codexOverrides.model,
      "synthetic-saved",
    );
    assert.equal(prepared.options.preserveProviderEnvironment, true);
    await assert.rejects(
      prepareNativeScan({
        ...request,
        recipe: {
          ...request.recipe,
          postScanPrompt: "Run synthetic follow-up.",
        },
      }),
      /Could not resolve a Codex executable/,
    );
    process.env.CODEX_CLI_PATH = process.execPath;
    await assert.rejects(
      prepared.client.dependencies.resolveCodexCommand(),
      /prepared for sealed-result publication only/,
    );
    const executing = await prepareNativeScan({
      ...request,
      recipe: { ...request.recipe, postScanPrompt: "Run synthetic follow-up." },
    });
    assert.equal(
      executing.client.dependencies.ambientExecution.command.command,
      await realpath(process.execPath),
    );
  } finally {
    restore();
    await rm(root, { recursive: true, force: true });
  }
});

for (const scenario of [
  "missing-home",
  "missing-home-traversal",
  "denial-collision",
  "missing-parent-sandbox",
  "invalid-parent-sandbox",
]) {
  test(
    `sealed native publication skips execution preparation: ${scenario}`,
    {
      skip:
        scenario === "missing-home-traversal" && process.platform === "win32"
          ? "POSIX symlink parent traversal differs from Windows path resolution."
          : false,
    },
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "native-sealed-read-")),
      );
      const restore = captureEnvironment([
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_SECURITY_KNOWLEDGE_BASE",
      ]);
      try {
        const scanDir = join(root, "scan");
        await mkdir(scanDir, { mode: 0o700 });
        await writeFile(
          join(scanDir, "scan-manifest.json"),
          JSON.stringify({ scan: { sealedAt: "2026-01-01T00:00:00Z" } }),
        );
        let home =
          scenario === "missing-home" ? join(root, "missing-home") : root;
        let expectedHome = home;
        if (scenario === "missing-home-traversal") {
          await mkdir(join(root, "actual", "nested"), { recursive: true });
          await mkdir(join(root, "absent", "deeper", "home"), {
            recursive: true,
          });
          await symlink(
            join(root, "actual", "nested"),
            join(root, "alias"),
            process.platform === "win32" ? "junction" : "dir",
          );
          home = `${root}${sep}alias${sep}..${sep}absent${sep}deeper${sep}home`;
          expectedHome = join(root, "actual", "absent", "deeper", "home");
        }
        Object.assign(process.env, {
          CODEX_HOME: home,
          CODEX_CLI_PATH: process.execPath,
        });
        delete process.env.CODEX_SECURITY_CONFIG_PATH;
        delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
        const denied = join(root, "[private]");
        const savedPermissions = {
          filesystem: { [denied]: "deny" },
          network: { enabled: false },
        };
        const deferredPolicy = scenario.endsWith("parent-sandbox");
        let parentPolicyReads = 0;
        const request = {
          ...input(),
          scan: { ...input().scan, scanDir },
          parentSandbox: deferredPolicy
            ? () => {
                parentPolicyReads++;
                return resolveNativeParentSandbox(
                  scenario === "missing-parent-sandbox"
                    ? {}
                    : {
                        _meta: {
                          "codex/sandbox-state-meta": {
                            permissionProfile: { type: "external" },
                          },
                        },
                      },
                );
              }
            : {
                workspaceAccess: "read",
                filesystemDenies: [],
                ...(scenario === "denial-collision"
                  ? { literalFilesystemDenies: [denied] }
                  : {}),
              },
          recipe: {
            config: { model: "synthetic-saved" },
            inheritedPermissions: savedPermissions,
          },
        };
        const prepared = await prepareNativeScan(request);
        assert.equal(parentPolicyReads, 0);
        assert.equal(
          prepared.client.dependencies.ambientExecution.environment.CODEX_HOME,
          expectedHome,
        );
        assert.deepEqual(
          prepared.options.inheritedPermissions,
          savedPermissions,
        );
        await assert.rejects(
          prepareNativeScan({
            ...request,
            recipe: {
              ...request.recipe,
              postScanPrompt: "Synthetic follow-up.",
            },
          }),
          scenario.startsWith("missing-home")
            ? { code: "ENOENT" }
            : deferredPolicy
              ? /cannot preserve the parent sandbox/u
              : /glob.*literal/u,
        );
        if (deferredPolicy) assert.equal(parentPolicyReads, 1);
        await rm(join(scanDir, "scan-manifest.json"));
        await assert.rejects(
          prepared.client.dependencies.resolveCodexCommand(),
          /prepared for sealed-result publication only/u,
        );
        await assert.rejects(
          prepareNativeScan(request),
          scenario.startsWith("missing-home")
            ? { code: "ENOENT" }
            : deferredPolicy
              ? /cannot preserve the parent sandbox/u
              : /glob.*literal/u,
        );
        if (deferredPolicy) {
          assert.equal(parentPolicyReads, 2);
          await assert.rejects(
            prepareNativeScan({ ...request, recipe: undefined }),
            /cannot preserve the parent sandbox/u,
          );
          assert.equal(parentPolicyReads, 3);
        }
      } finally {
        restore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}
