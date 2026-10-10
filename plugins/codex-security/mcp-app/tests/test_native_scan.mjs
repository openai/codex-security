import { captureEnvironment } from "../../../../sdk/typescript/tests-support/process-environment.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, sep } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";

const pluginVersion = JSON.parse(
  await readFile(
    new URL("../../.codex-plugin/plugin.json", import.meta.url),
    "utf8",
  ),
).version;

const bundle = await build({
  bundle: true,
  stdin: {
    contents: `export * from ${JSON.stringify(fileURLToPath(new URL("../src/native-scan.ts", import.meta.url)))};
      export { saveScanKnowledge, scanInputIdentity } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/scan-inputs.ts", import.meta.url)))};
      export { readKnowledgeBaseSnapshot } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/knowledge-base.ts", import.meta.url)))};
      export { acquireScanExecution } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/scan-execution.ts", import.meta.url)))};
      export { prepareAmbientExecution, prepareAmbientRuntime, prepareExecutionSource, createExecutionCodex, prepareDiscoveryExecution, prepareMergeExecution } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/execution-preparation.ts", import.meta.url)))};
      export { resolveDeepScanConfig } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/deep-config.ts", import.meta.url)))};
      export { createPermissionCheckedCodex } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/permission-profile.ts", import.meta.url)))};
      export { scanRuntimeCodexConfig, scanPreflightCodexConfig } from ${JSON.stringify(fileURLToPath(new URL("../../../../sdk/typescript/src/api.ts", import.meta.url)))};`,
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
  saveScanKnowledge,
  scanInputIdentity,
  readKnowledgeBaseSnapshot,
  acquireScanExecution,
  prepareNativeScan,
  nativeScanConfiguration,
  scanPreflightCodexConfig,
  createExecutionCodex,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  scanRuntimeCodexConfig,
  createPermissionCheckedCodex,
  prepareAmbientExecution,
  prepareAmbientRuntime,
  prepareExecutionSource,
  resolveDeepScanConfig,
} = module.exports;

async function prepareNativeExecution(input) {
  const prepared = await prepareNativeScan(input);
  const ambient = await prepareAmbientExecution(
    prepared.client.dependencies.ambientExecution,
  );
  prepared.client.config = {
    ...prepared.client.config,
    codexOverrides: ambient.configuration,
  };
  prepared.client.dependencies = {
    ...prepared.client.dependencies,
    environment: ambient.environment,
    ambientExecution: ambient,
  };
  prepared.options = {
    ...prepared.options,
    auth: ambient.auth,
    ...(ambient.preserveProviderEnvironment
      ? { preserveProviderEnvironment: true }
      : {}),
  };
  return prepared;
}

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
  const selectedProvider = config.model_providers?.[config.model_provider];
  capture({ kind: "preflight", argv, cwd: process.cwd(), home: process.env.CODEX_HOME, marker: process.env.NATIVE_PROFILE_MARKER,
    literalCredentialInEnvironment: ["synthetic-provider-token", "synthetic-provider-header"].some(value => Object.values(process.env).includes(value)),
    providerToken: selectedProvider && process.env[selectedProvider.env_key],
    providerHeaders: selectedProvider && Object.fromEntries(Object.entries(selectedProvider.env_http_headers ?? {}).map(([header, key]) => [header, process.env[key]])),
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY,
    gitEnvironment: Object.fromEntries(["PATH", "CODEX_SECURITY_GIT", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL"].map(name => [name, process.env[name]])) });
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
      targetPath: fixtureRepository,
      userContext: "Review the boundary.",
    },
    threadId: "native-owner",
    pluginRoot: tmpdir(),
    pythonPath: process.execPath,
    parentSandbox: { filesystemDenies: [] },
  };
}

for (const scenario of [
  "provider",
  "credential-store",
  "nested-settings",
  "literal-home",
  "openrouter-env-key",
  "fireworks-env-key",
  "openrouter-bearer",
  "fireworks-bearer",
  "openrouter-command",
  "fireworks-command",
  "openrouter-http-headers",
  "fireworks-http-headers",
  "openrouter-env-http-headers",
  "fireworks-env-http-headers",
]) {
  test(
    `native ${scenario} settings survive projected recipes at fresh and resumed worker boundaries`,
    {
      skip:
        process.platform === "win32"
          ? "Synthetic executable uses a POSIX shebang."
          : false,
    },
    async () => {
      const createdRoot = await realpath(
        await mkdtemp(join(tmpdir(), "native-config-merge-")),
      );
      const root =
        scenario === "literal-home" ? `${createdRoot} ` : createdRoot;
      if (root !== createdRoot) await rename(createdRoot, root);
      const executable = join(root, "codex");
      const capture = join(root, "observations.jsonl");
      const externalProvider = scenario.startsWith("openrouter-")
        ? "openrouter"
        : scenario.startsWith("fireworks-")
          ? "fireworks"
          : undefined;
      const restore = captureEnvironment([
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "FIREWORKS_API_KEY",
        "NATIVE_PROFILE_CAPTURE",
      ]);
      try {
        const config =
          externalProvider !== undefined
            ? `model_provider = "${externalProvider}"\n[model_providers.${externalProvider}]\n` +
              (scenario.endsWith("-env-key")
                ? 'base_url = "https://example.invalid/custom"\nenv_key = "OPENAI_API_KEY"\n'
                : scenario.endsWith("-bearer")
                  ? 'experimental_bearer_token = "synthetic-provider-token"\n'
                  : scenario.endsWith("-env-http-headers")
                    ? 'env_http_headers = { Authorization = "OPENAI_API_KEY" }\n'
                    : scenario.endsWith("-http-headers")
                      ? 'http_headers = { Authorization = "synthetic-provider-header" }\n'
                      : 'auth = { command = "synthetic-auth", args = ["synthetic-account"] }\n')
            : scenario === "provider"
              ? 'model_provider = "synthetic_provider"\n[model_providers.synthetic_provider]\nenv_key = "OPENAI_API_KEY"\n'
              : scenario === "credential-store"
                ? 'cli_auth_credentials_store = "file"\n'
                : "[features]\ngoals = false\n";
        await writeFile(join(root, "config.toml"), config);
        await writeFile(
          join(root, "selected.toml"),
          "[features]\napi_key_model_discovery = false\n",
        );
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
  if (argv.includes("--profile")) merge(effective, parse(fs.readFileSync(path.join(process.env.CODEX_HOME, argv[argv.indexOf("--profile") + 1] + ".config.toml"), "utf8")));
  for (let i = 0; i < argv.length; i++) if (["--config", "-c"].includes(argv[i])) merge(effective, parse(argv[++i]));
  const selectedProvider = effective.model_providers?.[effective.model_provider];
  fs.appendFileSync(process.env.NATIVE_PROFILE_CAPTURE, JSON.stringify({
    kind: process.argv.includes("login") ? "login" : "exec", argv, home: process.env.CODEX_HOME,
    providerAuth: selectedProvider?.auth,
    providerToken: selectedProvider && (selectedProvider.experimental_bearer_token ?? process.env[selectedProvider.env_key]),
    providerHeaders: selectedProvider && {...selectedProvider.http_headers, ...Object.fromEntries(Object.entries(selectedProvider.env_http_headers ?? {}).map(([header, key]) => [header, process.env[key]]))},
    literalCredentialInEnvironment: ["synthetic-provider-token", "synthetic-provider-header"].some(value => Object.values(process.env).includes(value)),
    codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY,
  }) + "\\n");
  if (process.argv.includes("login")) { console.error("Logged in using ChatGPT"); process.exit(0); }
  console.log(JSON.stringify({type:"thread.started",thread_id:"synthetic-native-config"}));
  console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));
}
`,
          { mode: 0o700 },
        );
        Object.assign(process.env, {
          CODEX_HOME: root,
          CODEX_CLI_PATH: executable,
          NATIVE_PROFILE_CAPTURE: capture,
          OPENAI_API_KEY: "synthetic-openai-selected",
        });
        delete process.env.OPENROUTER_API_KEY;
        delete process.env.FIREWORKS_API_KEY;
        if (scenario === "credential-store") delete process.env.CODEX_API_KEY;
        else process.env.CODEX_API_KEY = "synthetic-codex-competing";
        delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        if (scenario === "nested-settings")
          process.env.CODEX_SECURITY_CONFIG_PATH = join(root, "selected.toml");
        else delete process.env.CODEX_SECURITY_CONFIG_PATH;
        // Saved recipes contain the preflight projection, not provider credentials or storage settings.
        const saved = scanPreflightCodexConfig(
          {
            ...parseToml(config),
            model: "synthetic-saved-model",
            features: { api_key_model_discovery: false },
          },
          true,
        );
        if (externalProvider !== undefined)
          await writeFile(join(root, "selected.toml"), stringifyToml(saved));
        for (const recipe of [
          undefined,
          {
            auth: "auto",
            config: saved,
            inheritedPermissions: {
              filesystem: { "/saved/private": "deny" },
              network: { enabled: false },
            },
          },
          {
            auth: "auto",
            config: saved,
            inheritedPermissions: {
              filesystem: {
                ":workspace_roots": "read",
                "/saved/private": "deny",
              },
              network: { enabled: false },
            },
          },
        ]) {
          if (externalProvider !== undefined) {
            if (recipe) delete process.env.CODEX_SECURITY_CONFIG_PATH;
            else
              process.env.CODEX_SECURITY_CONFIG_PATH = join(
                root,
                "selected.toml",
              );
          }
          await writeFile(capture, "");
          const prepared = await prepareNativeExecution({
            ...input(),
            recipe,
            parentSandbox: {
              filesystemDenies: ["/current/private"],
              ...(scenario === "nested-settings"
                ? { literalFilesystemDenies: ["/current/[private]"] }
                : {}),
            },
            model: "synthetic-current-model",
          });
          const ambient = prepared.client.dependencies.ambientExecution;
          const source = prepareExecutionSource({
            ...ambient,
            auth: prepared.options.auth,
          });
          const permissions = prepared.options.inheritedPermissions;
          const selected = prepared.client.config.codexOverrides;
          const session = {
            policy: "ordinary",
            source,
            inheritedPermissions: permissions,
            runtime: { codexHome: root, plugin: { version: pluginVersion } },
            runtimeHome: root,
            effectiveConfig: selected,
            preflightConfig: {},
            sessionConfig: scanRuntimeCodexConfig(selected, root, permissions),
            authentication: source.authentication,
            approvalPolicy: "never",
            python: process.execPath,
            releaseCredentialHome: null,
          };
          for (const role of ["discovery", "merge"]) {
            const worker =
              role === "discovery"
                ? prepareDiscoveryExecution(session)
                : prepareMergeExecution(session, 2);
            const { codex } = createExecutionCodex(
              { surface: "sdk", command: "scan" },
              worker,
              {
                NATIVE_PROFILE_CAPTURE: capture,
              },
            );
            for (const resumed of [false, true]) {
              const options = {
                workingDirectory: root,
                skipGitRepoCheck: true,
              };
              const thread = resumed
                ? codex.resumeThread("synthetic-native-config", options)
                : codex.startThread(options);
              await collectNativeEvents(
                thread,
                "Synthetic native configuration check.",
                {},
              );
            }
          }
          const rows = (await readFile(capture, "utf8"))
            .trim()
            .split("\n")
            .map(JSON.parse);
          const executions = rows.filter((row) => row.kind === "exec");
          assert.equal(executions.length, 4);
          assert.equal(
            rows.filter((row) => row.kind === "preflight").length,
            4,
          );
          for (const row of rows.filter((row) =>
            ["exec", "preflight", "login"].includes(row.kind),
          )) {
            const effective = Object.assign(
              {},
              ...row.argv.flatMap((arg, i) =>
                ["--config", "-c"].includes(arg)
                  ? [parseToml(row.argv[i + 1])]
                  : [],
              ),
            );
            if (scenario === "credential-store")
              assert.equal(effective.cli_auth_credentials_store, "file");
            if (row.kind === "login") continue;
            assert.equal(
              effective.model,
              recipe ? "synthetic-saved-model" : "synthetic-current-model",
            );
            if (scenario === "provider") {
              assert.equal(row.openai, "synthetic-openai-selected");
              assert.equal(
                effective.model_providers.synthetic_provider.env_key,
                "OPENAI_API_KEY",
              );
            }
            if (externalProvider !== undefined) {
              assert.equal(effective.model_provider, externalProvider);
              const provider = effective.model_providers[externalProvider];
              if (scenario.endsWith("-env-key")) {
                assert.equal(
                  provider.base_url,
                  "https://example.invalid/custom",
                );
                assert.equal(provider.env_key, "OPENAI_API_KEY");
              } else if (scenario.endsWith("-bearer")) {
                assert.equal(provider.experimental_bearer_token, undefined);
                assert.equal(row.literalCredentialInEnvironment, false);
                if (row.kind === "exec")
                  assert.equal(row.providerToken, "synthetic-provider-token");
                assert.equal(
                  row.argv.some((argument) =>
                    argument.includes("synthetic-provider-token"),
                  ),
                  false,
                );
              } else if (scenario.endsWith("-http-headers")) {
                assert.equal(provider.env_key, undefined);
                assert.equal(row.literalCredentialInEnvironment, false);
                if (
                  row.kind === "exec" ||
                  scenario.endsWith("-env-http-headers")
                )
                  assert.equal(
                    row.providerHeaders.Authorization,
                    scenario.endsWith("-env-http-headers")
                      ? "synthetic-openai-selected"
                      : "synthetic-provider-header",
                  );
                assert.equal(
                  row.argv.some((argument) =>
                    argument.includes("synthetic-provider-header"),
                  ),
                  false,
                );
              } else {
                assert.equal(provider.auth, undefined);
                if (row.kind === "exec") {
                  assert.equal(row.providerAuth.command, "synthetic-auth");
                  assert.deepEqual(row.providerAuth.args, [
                    "synthetic-account",
                  ]);
                }
                assert.equal(provider.env_key, undefined);
              }
            }
            if (scenario === "nested-settings") {
              assert.equal(effective.features.goals, false);
              assert.equal(effective.features.api_key_model_discovery, false);
            }
            if (scenario === "literal-home") assert.equal(row.home, root);
            const filesystem =
              effective.permissions[effective.default_permissions].filesystem;
            assert.equal(
              filesystem[":workspace_roots"],
              recipe?.inheritedPermissions?.filesystem[":workspace_roots"] ??
                "write",
            );
            assert.equal(filesystem[":root"], "read");
            assert.equal(filesystem["/current/private"], "deny");
            if (scenario === "nested-settings")
              assert.deepEqual(
                { ...filesystem["/current/[private]"] },
                {
                  ".": "deny",
                },
              );
            if (recipe) assert.equal(filesystem["/saved/private"], "deny");
            assert.equal(effective.approval_policy, "never");
          }
          assert.deepEqual(
            executions.map((row) => row.argv.includes("resume")),
            [false, true, false, true],
          );
        }
        assert.equal(await readFile(join(root, "config.toml"), "utf8"), config);
      } finally {
        restore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

test(
  "native workers can write their output while inherited deny globs and outside writes stay restricted",
  {
    skip:
      process.platform !== "linux"
        ? "Exercises Linux deny-glob expansion."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-deny-glob-")),
    );
    const target = join(root, "target");
    const home = join(root, "home");
    const output = join(root, "output");
    const denied = join(target, "a", "b", "c", "d", "private.txt");
    const sdkRequire = createRequire(
      new URL("../../../../sdk/typescript/package.json", import.meta.url),
    );
    const packageRequire = createRequire(
      sdkRequire.resolve("@openai/codex/package.json"),
    );
    const packageRoot = dirname(
      packageRequire.resolve(
        `@openai/codex-linux-${process.arch}/package.json`,
      ),
    );
    const executable = join(
      packageRoot,
      "vendor",
      process.arch === "arm64"
        ? "aarch64-unknown-linux-musl"
        : "x86_64-unknown-linux-musl",
      "bin",
      "codex",
    );
    const restore = captureEnvironment([
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ]);
    try {
      await mkdir(home, { mode: 0o700 });
      await mkdir(output, { mode: 0o700 });
      await mkdir(dirname(denied), { recursive: true });
      await writeFile(denied, "synthetic denied content");
      Object.assign(process.env, {
        CODEX_HOME: home,
        CODEX_CLI_PATH: executable,
      });
      delete process.env.CODEX_SECURITY_CONFIG_PATH;
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      for (const [savedDepth, currentDepth] of [
        [3, 10],
        [10, 3],
        [undefined, 3],
        [3, undefined],
      ]) {
        const prepared = await prepareNativeExecution({
          ...input(),
          scan: { ...input().scan, targetPath: target, scanDir: output },
          parentSandbox: {
            filesystemDenies: [join(target, "**", "private.txt")],
            globScanMaxDepth: currentDepth,
          },
          recipe: {
            auth: "api-key",
            inheritedPermissions: {
              filesystem: {
                [join(target, "**", "private.txt")]: "deny",
                ...(savedDepth === undefined
                  ? {}
                  : { glob_scan_max_depth: savedDepth }),
              },
              network: { enabled: false },
            },
          },
        });
        const config = scanRuntimeCodexConfig(
          {},
          home,
          prepared.options.inheritedPermissions,
        );
        await writeFile(join(home, "config.toml"), stringifyToml(config));
        const child = spawnSync(
          executable,
          [
            "sandbox",
            "-P",
            config.default_permissions,
            "--config",
            `permissions.${config.default_permissions}.network.enabled=true`,
            "-C",
            target,
            "--",
            "/bin/cat",
            denied,
          ],
          {
            cwd: target,
            env: { PATH: process.env.PATH, CODEX_HOME: home },
            encoding: "utf8",
          },
        );
        assert.equal(child.status, 1, child.stderr);
        assert.match(child.stderr, /Permission denied/);
        assert.equal(child.stdout, "");
        const write = spawnSync(
          executable,
          [
            "sandbox",
            "-P",
            config.default_permissions,
            "--config",
            `permissions.${config.default_permissions}.network.enabled=true`,
            "-C",
            output,
            "--",
            process.execPath,
            "-e",
            `const fs = require("node:fs");
           fs.writeFileSync(${JSON.stringify(join(output, "findings.json"))}, "{}");
           try { fs.writeFileSync(${JSON.stringify(join(target, "outside.txt"))}, "blocked"); process.exit(2); }
           catch (error) { if (error.code !== "EACCES" && error.code !== "EPERM" && error.code !== "EROFS") throw error; }`,
          ],
          {
            cwd: output,
            env: { PATH: process.env.PATH, CODEX_HOME: home },
            encoding: "utf8",
          },
        );
        assert.equal(write.status, 0, write.stderr);
        assert.equal(
          await readFile(join(output, "findings.json"), "utf8"),
          "{}",
        );
      }
    } finally {
      restore();
      await rm(root, { recursive: true, force: true });
    }
  },
);

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
          prepareNativeExecution(request),
          /outside the scan target/,
        );
      }
      process.env.CODEX_CLI_PATH = executable;
      await assert.rejects(
        prepareNativeExecution(request),
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
            prepareNativeExecution(request),
            /outside the scan target/,
          );
          for (const configured of [undefined, "  ", "codex"]) {
            if (configured === undefined) delete process.env.CODEX_CLI_PATH;
            else process.env.CODEX_CLI_PATH = configured;
            const originalPath = process.env.PATH;
            const prepared = await prepareNativeExecution(request);
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
      const prepared = await prepareNativeExecution(request);
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

test("native preparation excludes scan output and knowledge sources from executable selection", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "native-inputs-")));
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const knowledgeRoot = join(root, "knowledge");
  const documents = join(knowledgeRoot, "docs");
  const external = join(root, "external");
  const name = process.platform === "win32" ? "codex.exe" : "codex";
  const restoreEnvironment = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ]);
  try {
    for (const directory of [repository, scanDir, documents, external]) {
      await mkdir(directory, { recursive: true });
    }
    await mkdir(join(knowledgeRoot, ".git"));
    await writeFile(
      join(documents, "architecture.md"),
      "Synthetic architecture.",
    );
    const snapshot = await readKnowledgeBaseSnapshot([documents]);
    await saveScanKnowledge(scanDir, snapshot);
    for (const directory of [scanDir, knowledgeRoot, external]) {
      await writeFile(join(directory, name), "inert executable fixture");
      await chmod(join(directory, name), 0o700);
    }
    process.env.CODEX_HOME = root;
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    for (const saved of [false, true]) {
      if (saved) delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;
      else process.env.CODEX_SECURITY_KNOWLEDGE_BASE = documents;
      const request = {
        ...input(),
        scan: { ...input().scan, targetPath: repository, scanDir },
        ...(saved
          ? {
              recipe: {
                auth: "api-key",
                knowledgeBasePaths: [documents],
                scanInputs: scanInputIdentity(
                  input().scan.userContext,
                  snapshot,
                ),
                config: {},
              },
            }
          : {}),
      };
      for (const directory of [scanDir, knowledgeRoot]) {
        process.env.CODEX_CLI_PATH = join(directory, name);
        await assert.rejects(
          prepareNativeExecution(request),
          /outside the scan target/,
        );
      }
      delete process.env.CODEX_CLI_PATH;
      process.env.PATH = [scanDir, knowledgeRoot, external].join(delimiter);
      const prepared = await prepareNativeExecution(request);
      const environment = prepared.client.dependencies.environment;
      assert.equal(environment.CODEX_CLI_PATH, join(external, name));
      assert.equal(environment.PATH, external);
    }
  } finally {
    restoreEnvironment();
    await rm(root, { recursive: true, force: true });
  }
});

test("pre-aborted native waiters leave the accepted scan running", async () => {
  const started = Promise.withResolvers();
  const completed = Promise.withResolvers();
  let preparations = 0;
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
        async close() {},
      },
    };
  });
  const reason = new Error("detached before waiting");
  const waiter = AbortSignal.abort(reason);
  assert.throws(
    () => host.run(input(), waiter),
    (error) => error === reason,
  );
  await started.promise;
  const joined = host.run(input());
  assert.throws(
    () => host.run(input(), waiter),
    (error) => error === reason,
  );
  assert.equal(preparations, 1);
  assert.equal(signal.aborted, false);
  completed.resolve({ scanDir: "sealed-parent" });
  assert.deepEqual(await joined, { scanDir: "sealed-parent" });
});

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

for (const action of ["cancel", "close"]) {
  test(`native ${action} during preparation closes the client without starting it`, async () => {
    const preparing = Promise.withResolvers();
    const ready = Promise.withResolvers();
    let runs = 0;
    let closes = 0;
    const host = new NativeScanHost(async () => {
      preparing.resolve();
      await ready.promise;
      return {
        options: { mode: "deep" },
        client: {
          async run() {
            runs++;
          },
          async close() {
            closes++;
          },
        },
      };
    });
    const request = host.run(input());
    const rejected = assert.rejects(
      request,
      action === "cancel" ? /user_canceled_scan/ : /mcp_transport_closed/,
    );
    await preparing.promise;
    const stopped =
      action === "cancel" ? host.cancel(input().scan.scanId) : host.close();
    ready.resolve();
    await stopped;
    await rejected;
    assert.equal(runs, 0);
    assert.equal(closes, 1);
  });
}

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
  const spacedHome = join(root, "home with spaces");
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
      ["~/explicit", explicitHome, "synthetic-explicit", 4],
      ...(process.platform === "win32"
        ? []
        : [[spacedHome, spacedHome, "synthetic-spaced", 3]]),
      [linkedHome, ...linkedSettings],
    ]) {
      if (override === undefined) delete process.env.CODEX_HOME;
      else process.env.CODEX_HOME = override;
      for (const saved of [false, true]) {
        const prepared = await prepareNativeExecution({
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

test("native API-key preparation creates a missing default Codex home", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-new-home-")),
  );
  const pluginRoot = join(root, "plugin");
  const restoreEnvironment = captureEnvironment([
    "HOME",
    "USERPROFILE",
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ]);
  let runtime;
  try {
    await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
    await writeFile(
      join(pluginRoot, ".codex-plugin/plugin.json"),
      JSON.stringify({ name: "codex-security", version: "0.0.0" }),
    );
    Object.assign(process.env, {
      HOME: root,
      USERPROFILE: root,
      CODEX_CLI_PATH: process.execPath,
      CODEX_API_KEY: "synthetic-new-home-key",
    });
    for (const key of [
      "CODEX_HOME",
      "OPENAI_API_KEY",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ])
      delete process.env[key];
    const prepared = await prepareNativeExecution({
      ...input(),
      pluginRoot,
      recipe: { auth: "api-key" },
    });
    runtime = await prepareAmbientRuntime(
      prepared.client.dependencies.ambientExecution,
    );
    assert.equal(runtime.codexHome, join(root, ".codex"));
    assert.equal(runtime.environment.CODEX_API_KEY, "synthetic-new-home-key");
    assert.equal(runtime.environment.CODEX_HOME, runtime.codexHome);
    const metadata = await stat(runtime.codexHome);
    assert.ok(metadata.isDirectory());
    if (process.platform !== "win32")
      assert.equal(metadata.mode & 0o777, 0o700);
    await assert.rejects(readFile(join(runtime.codexHome, "config.toml")), {
      code: "ENOENT",
    });
  } finally {
    restoreEnvironment();
    if (runtime)
      await rm(runtime.bootstrapWorkspace, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

test(
  "native missing symlink homes select matching config for fresh and resumed children",
  {
    skip:
      process.platform === "win32"
        ? "Synthetic executable uses a POSIX shebang."
        : false,
  },
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "native-missing-home-")),
    );
    const repository = join(root, "repository");
    const pluginRoot = join(root, "plugin");
    const executable = join(root, "codex");
    const capture = join(root, "child.json");
    const restoreEnvironment = captureEnvironment([
      "HOME",
      "USERPROFILE",
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_API_KEY",
      "OPENAI_API_KEY",
      "CODEX_SECURITY_CONFIG_PATH",
      "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    ]);
    try {
      await mkdir(repository);
      await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
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
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-new-home-thread" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
        { mode: 0o700 },
      );
      Object.assign(process.env, {
        HOME: root,
        USERPROFILE: root,
        CODEX_CLI_PATH: executable,
        CODEX_API_KEY: "synthetic-new-home-key",
      });
      for (const key of [
        "OPENAI_API_KEY",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      ])
        delete process.env[key];
      for (const resumed of [false, true]) {
        const base = join(root, resumed ? "resumed" : "fresh", "base");
        const target = join(root, resumed ? "resumed" : "fresh", "target");
        const decoy = join(base, "missing", "home");
        await mkdir(join(target, "nested"), { recursive: true });
        await mkdir(join(decoy, "codex-security"), { recursive: true });
        await symlink(join(target, "nested"), join(base, "link"), "dir");
        const home = `${base}${sep}link${sep}..${sep}missing${sep}home`;
        const expectedHome = join(target, "missing", "home");
        await writeFile(
          join(decoy, "config.toml"),
          'model = "synthetic-wrong"\n',
        );
        await writeFile(
          join(decoy, "codex-security", "config.toml"),
          "[deep_scan]\nworkers = 7\nsubagents = 5\n",
        );
        process.env.CODEX_HOME = home;
        await assert.rejects(stat(home), { code: "ENOENT" });
        const prepared = await prepareNativeExecution({
          ...input(),
          pluginRoot,
          recipe: {
            auth: "api-key",
            ...(resumed
              ? {
                  config: { model: "synthetic-saved" },
                  deepScan: { workers: 3, subagents: 2 },
                }
              : {}),
          },
        });
        await assert.rejects(stat(home), { code: "ENOENT" });
        const defaults = await resolveDeepScanConfig(
          {},
          join(expectedHome, "codex-security", "config.toml"),
        );
        assert.equal(
          prepared.options.workers,
          resumed ? 3 : defaults.settings.workers,
        );
        assert.equal(
          prepared.client.config.codexOverrides.model,
          resumed ? "synthetic-saved" : undefined,
        );
        const runtime = await prepareAmbientRuntime(
          prepared.client.dependencies.ambientExecution,
        );
        try {
          for (const role of ["discovery", "merge"]) {
            const workerDirectory = join(root, role);
            await mkdir(workerDirectory, { recursive: true });
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
              workingDirectory: workerDirectory,
              skipGitRepoCheck: true,
              approvalPolicy: "never",
            };
            const thread = resumed
              ? sdk.resumeThread("synthetic-new-home-thread", options)
              : sdk.startThread(options);
            const events = await collectNativeEvents(
              thread,
              "Synthetic home selection.",
            );
            assert.equal(events.at(-1).type, "turn.completed");
            const observed = JSON.parse(await readFile(capture, "utf8"));
            assert.equal(observed.home, expectedHome);
            assert.equal(observed.home, await realpath(home));
            assert.equal(
              observed.argv.includes('model="synthetic-wrong"'),
              false,
            );
            if (resumed)
              assert.ok(observed.argv.includes('model="synthetic-saved"'));
            assert.equal(
              parseToml(
                observed.argv.find((arg) => arg.startsWith("features=")),
              ).features.multi_agent_v2.max_concurrent_threads_per_session,
              (resumed ? 2 : defaults.settings.subagents) + 1,
            );
            assert.equal(
              observed.argv[observed.argv.indexOf("--cd") + 1],
              workerDirectory,
            );
            assert.equal(observed.argv.includes("resume"), resumed);
            assert.equal(process.env.CODEX_HOME, home);
          }
        } finally {
          await rm(runtime.bootstrapWorkspace, {
            recursive: true,
            force: true,
          });
        }
      }
    } finally {
      restoreEnvironment();
      await rm(root, { recursive: true, force: true });
    }
  },
);

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
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ home: process.env.CODEX_HOME, argv: process.argv.slice(2), deepConfigPath: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH, deepConfig: fs.readFileSync(process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH?.trim() || require("node:path").join(process.env.CODEX_HOME, "codex-security/config.toml"), "utf8") }));
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
          const prepared = await prepareNativeExecution({
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
            const perScan = await resolveDeepScanConfig(
              prepared.options,
              deepConfig,
            );
            assert.equal(perScan.settings.workers, resumed ? 6 : workers);
            assert.equal(perScan.settings.subagents, resumed ? 4 : subagents);
            for (const role of ["discovery", "merge"]) {
              const sdk = createPermissionCheckedCodex({
                codexPathOverride: executable,
                config: scanRuntimeCodexConfig(
                  prepared.client.config.codexOverrides,
                  repository,
                  prepared.client.dependencies.inheritedPermissions,
                ),
                env: runtime.environment,
              });
              const workerDirectory = join(root, role);
              await mkdir(workerDirectory, { recursive: true });
              const options = {
                workingDirectory: workerDirectory,
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
                observed.argv[observed.argv.indexOf("--cd") + 1],
                workerDirectory,
              );
              assert.equal(observed.deepConfigPath, override);
              assert.equal(
                parseToml(observed.deepConfig).deep_scan.workers,
                workers,
              );
              assert.equal(
                parseToml(observed.deepConfig).deep_scan.subagents,
                subagents,
              );
              assert.equal(
                await readFile(deepConfig, "utf8"),
                "[deep_scan]\nworkers = 3\nsubagents = 2\n",
              );
              assert.equal(
                await readFile(
                  join(home, "codex-security/config.toml"),
                  "utf8",
                ),
                "[deep_scan]\nworkers = 2\nsubagents = 1\n",
              );
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
            }
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
      return prepareNativeExecution({
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
  "native discovery and merge workers inherit safe executable paths on fresh and resumed launches",
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
    const keys = [
      "HOME",
      "USERPROFILE",
      "OPENAI_API_KEY",
      "CODEX_API_KEY",
      "PATH",
      "CODEX_HOME",
      "CODEX_CLI_PATH",
      "CODEX_SECURITY_CONFIG_PATH",
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
      ]);
      await writeFile(
        join(repositoryBin, "codex"),
        "inert executable fixture",
        { mode: 0o700 },
      );
      process.env.OPENAI_API_KEY = "synthetic-native-key";
      delete process.env.CODEX_API_KEY;
      Object.assign(process.env, {
        CODEX_HOME: root,
        HOME: root,
        USERPROFILE: root,
        PATH: [repositoryBin, root, selectedTools].join(delimiter),
      });
      delete process.env.CODEX_CLI_PATH;
      delete process.env.CODEX_SECURITY_CONFIG_PATH;
      delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
      await writeFile(
        executable,
        `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
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
      for (const role of ["discovery", "merge"]) {
        process.env.CODEX_CLI_PATH =
          role === "discovery" ? "~/codex" : "~\\codex";
        const cwd = join(root, role);
        await mkdir(cwd);
        const config = scanRuntimeCodexConfig(
          { approval_policy: "on-request", forced_login_method: "api" },
          root,
          {
            filesystem: {
              [join(root, "private")]: "deny",
              glob_scan_max_depth: 3,
            },
            network: { enabled: false },
          },
        );
        const selectedProgram =
          role === "discovery" ? "daybreak_blue" : "daybreak_red";
        const settingsPath = join(root, `${role}-settings.toml`);
        await writeFile(
          settingsPath,
          `forced_login_method = "api"\n[codex_security]\ncyber_access_program = "${selectedProgram}"\n`,
        );
        process.env.CODEX_SECURITY_CONFIG_PATH = settingsPath;
        const nativeCases = await Promise.all(
          [
            undefined,
            {
              auth: "auto",
              config: { forced_login_method: "api" },
              cyberAccessProgram:
                role === "discovery" ? "daybreak_red" : "daybreak_blue",
            },
          ].map(async (recipe) => ({
            native: await prepareNativeExecution({
              ...input(),
              scan: { ...input().scan, targetPath: target },
              recipe,
            }),
            expectedProgram: recipe?.cyberAccessProgram ?? selectedProgram,
          })),
        );
        for (const { native, expectedProgram } of nativeCases) {
          assert.equal(native.options.auth, "api-key");
          assert.equal(native.options.cyberAccessProgram, expectedProgram);
          const selectedEnvironment = native.client.dependencies.environment;
          assert.equal(
            selectedEnvironment.OPENAI_API_KEY,
            "synthetic-native-key",
          );
          assert.equal(selectedEnvironment.CODEX_CLI_PATH, executable);
          assert.equal(
            selectedEnvironment.PATH,
            [root, selectedTools].join(delimiter),
          );
          assert.equal(
            process.env.PATH,
            [repositoryBin, root, selectedTools].join(delimiter),
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
            assert.equal(preflight.cwd, cwd);
            assert.equal(executed.argv[executed.argv.indexOf("--cd") + 1], cwd);
            assert.equal(executed.argv.includes("resume"), resumed);
            assert.equal(
              executed.argv[
                executed.argv.indexOf("--cyber-access-program") + 1
              ],
              native.options.cyberAccessProgram,
            );
            assert.deepEqual(
              rawConfig(preflight.argv),
              rawConfig(executed.argv),
            );
            assert.equal(
              rawConfig(preflight.argv).at(-1),
              'approval_policy="never"',
            );
            for (const process of [preflight, executed]) {
              assert.deepEqual(process.gitEnvironment, gitEnvironment);
              assert.equal(process.marker, role);
              assert.equal(process.codex, "synthetic-final-key");
              assert.equal(process.openai, "synthetic-native-key");
            }
          }
          assert.equal(process.env.CODEX_SECURITY_CONFIG_PATH, settingsPath);
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
  storedApi: fs.existsSync(${JSON.stringify(join(root, "auth.json"))}),
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
      for (const [provider, modelProvider, forcedLogin, storedApi] of [
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
        [undefined, undefined, "api"],
        [undefined, undefined, "api", true],
      ]) {
        if (storedApi) {
          delete process.env.OPENAI_API_KEY;
          await writeFile(
            join(root, "auth.json"),
            JSON.stringify({
              auth_mode: "apikey",
              OPENAI_API_KEY: "synthetic-stored-api-key",
            }),
            { mode: 0o600 },
          );
        } else process.env.OPENAI_API_KEY = "synthetic-competing-key";
        if (forcedLogin) {
          delete process.env.CODEX_API_KEY;
          await writeFile(join(root, "account-present"), "synthetic");
        } else process.env.CODEX_API_KEY = "synthetic-native-selected";
        const selected = provider !== undefined;
        const providerName = modelProvider ?? "openai";
        const configured =
          selected &&
          provider.requires_openai_auth !== true &&
          (providerName !== "openai" || provider.auth !== undefined);
        const config = {
          model: "saved-model",
          model_reasoning_effort: "ultra",
          approval_policy: "on-request",
          ...(forcedLogin ? { forced_login_method: forcedLogin } : {}),
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
        if (forcedLogin)
          await writeFile(
            join(root, "config.toml"),
            'forced_login_method = "api"\n',
          );
        for (const recipe of [
          undefined,
          { auth: forcedLogin ? "auto" : "api-key", config },
        ]) {
          await rm(join(root, "login.json"), { force: true });
          const prepared = await prepareNativeExecution({
            ...input(),
            recipe,
            model: "current-model",
            reasoningEffort: "low",
          });
          if (forcedLogin) {
            assert.equal(
              prepared.options.auth,
              storedApi ? recipe?.auth : "api-key",
            );
            const source = prepareExecutionSource({
              ...prepared.client.dependencies.ambientExecution,
              auth: prepared.options.auth,
            });
            assert.equal(
              source.authentication.method,
              storedApi ? "stored_credentials" : "api_key",
            );
            await assert.rejects(readFile(join(root, "login.json")), {
              code: "ENOENT",
            });
          }
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
          assert.equal(
            observed.codex,
            forcedLogin ? undefined : "synthetic-native-selected",
          );
          assert.equal(
            observed.argv.includes('forced_login_method="api"'),
            Boolean(forcedLogin),
          );
          assert.equal(
            observed.openai,
            !storedApi && (configured || forcedLogin)
              ? "synthetic-competing-key"
              : undefined,
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
          assert.equal(observed.storedApi, Boolean(storedApi));
          assert.equal(
            process.env.CODEX_API_KEY,
            forcedLogin ? undefined : "synthetic-native-selected",
          );
          assert.equal(
            process.env.OPENAI_API_KEY,
            storedApi ? undefined : "synthetic-competing-key",
          );
          if (!selected) {
            await collectNativeEvents(
              sdk.resumeThread("synthetic-auth-thread", {
                workingDirectory: root,
                skipGitRepoCheck: true,
              }),
              "Synthetic resumed launch only.",
            );
            const resumed = JSON.parse(await readFile(capture, "utf8"));
            assert.equal(resumed.codex, observed.codex);
            assert.equal(resumed.storedApi, Boolean(storedApi));
            assert.equal(resumed.openai, observed.openai);
            assert.equal(
              resumed.argv.includes('forced_login_method="api"'),
              Boolean(forcedLogin),
            );
            assert.ok(resumed.argv.includes('approval_policy="never"'));
            assert.equal(
              resumed.argv.includes('approval_policy="on-request"'),
              false,
            );
          }
        }
      }
      process.env.OPENAI_API_KEY = "synthetic-competing-key";
      await rm(join(root, "auth.json"));
      const prepared = await prepareNativeExecution(input());
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
              ),
            ),
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
          const prepared = await prepareNativeExecution({ ...input(), recipe });
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
            const prepared = await prepareNativeExecution({
              ...input(),
              recipe,
            });
            assert.equal(prepared.options.preserveProviderEnvironment, true);
            assert.equal(
              prepared.client.dependencies.environment.OPENAI_API_KEY,
              "synthetic-competing-key",
            );
            await assert.rejects(readFile(join(root, "login.json")), {
              code: "ENOENT",
            });
          } else {
            await assert.rejects(
              prepareNativeExecution({ ...input(), recipe }),
              {
                name: "CodexSecurityError",
                message: "Could not access the selected keyring",
              },
            );
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
        const prepared = await prepareNativeExecution({ ...input(), recipe });
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
      const forced = await prepareNativeExecution({
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
    const { client, options } = await prepareNativeExecution(request);
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
      const selected = await prepareNativeExecution({
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
    const nativePlugin = join(root, "native-plugin");
    await mkdir(join(nativePlugin, "mcp"), { recursive: true });
    const nativeDirectory = await realpath(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/native/",
        import.meta.url,
      ),
    ).catch((error) => {
      if (error.code !== "ENOENT") throw error;
      return fileURLToPath(new URL("../../native/dist/", import.meta.url));
    });
    await symlink(
      nativeDirectory,
      join(nativePlugin, "mcp", "native"),
      process.platform === "win32" ? "junction" : "dir",
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
    const documents = join(root, "ambient-documents");
    await mkdir(documents);
    process.env.CODEX_SECURITY_KNOWLEDGE_BASE = documents;
    const savedWithoutDocuments = await prepareNativeExecution(request);
    assert.equal(savedWithoutDocuments.options.knowledgeBasePaths, undefined);
    assert.equal(
      savedWithoutDocuments.client.dependencies.environment
        .CODEX_SECURITY_KNOWLEDGE_BASE,
      undefined,
    );
    const freshWithDocuments = await prepareNativeExecution({
      ...request,
      recipe: undefined,
    });
    assert.deepEqual(freshWithDocuments.options.knowledgeBasePaths, [
      documents,
    ]);
    delete process.env.CODEX_SECURITY_KNOWLEDGE_BASE;

    assert.equal(options.postScanPrompt, "Publish once.");
    const withoutContext = await prepareNativeExecution({
      ...request,
      scan: { ...request.scan, userContext: null },
    });
    assert.equal(withoutContext.options.scanPrompt, undefined);
    for (const [savedDepth, currentDepth, expectedDepth] of [
      [3, 10, 10],
      [10, 3, 10],
      [3, undefined, 3],
    ]) {
      const savedPermissions = await prepareNativeExecution({
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
          ":workspace_roots": "write",
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
    const restricted = await prepareNativeExecution({
      ...request,
      recipe: {
        ...request.recipe,
        inheritedPermissions: {
          filesystem: { ":workspace_roots": "read" },
          network: { enabled: false },
        },
      },
    });
    assert.equal(
      restricted.options.inheritedPermissions.filesystem[":workspace_roots"],
      "read",
    );
    assert.equal(
      restricted.options.inheritedPermissions.filesystem["/fixture/.env"],
      "deny",
    );
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
      const restored = await prepareNativeExecution({
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

for (const scenario of [
  "saved-profile",
  "builtin-chatgpt",
  "builtin-api-key",
  "saved-uncapped",
  "current-uncapped",
  "both-finite",
  "saved-literal",
  "current-literal",
  "saved-glob-current-literal",
  "saved-literal-current-glob",
  "repeated-literal",
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
      const restore = captureEnvironment([
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      ]);
      try {
        await mkdir(home);
        await mkdir(repository);
        await mkdir(join(pluginRoot, ".codex-plugin"), { recursive: true });
        await writeFile(
          join(pluginRoot, ".codex-plugin/plugin.json"),
          JSON.stringify({ name: "codex-security", version: "0.0.0" }),
        );
        await writeFile(
          executable,
          `#!${process.execPath}
const fs = require("node:fs");
${syntheticPermissionAppServer()}
if (process.argv.includes("app-server")) servePermissionProfiles();
else {
  fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ argv: process.argv.slice(2), codex: process.env.CODEX_API_KEY, openai: process.env.OPENAI_API_KEY }));
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-merged-worker" }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 0, cached_input_tokens: 0, output_tokens: 0 } }));
}
`,
          { mode: 0o700 },
        );
        Object.assign(process.env, {
          CODEX_HOME: home,
          CODEX_CLI_PATH: executable,
          OPENAI_API_KEY: "synthetic-selected-key",
        });
        delete process.env.CODEX_API_KEY;
        delete process.env.CODEX_SECURITY_CONFIG_PATH;
        delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
        const configuration =
          scenario === "saved-profile"
            ? {
                profile: "current",
                profiles: {
                  current: {
                    model: "ambient-model",
                    model_reasoning_effort: "low",
                    model_provider: "ambient-provider",
                  },
                },
                model_providers: {
                  "ambient-provider": { requires_openai_auth: false },
                },
              }
            : {
                model: "ambient-model",
                model_provider: "openai",
                model_providers: {
                  openai: {
                    env_key: "OPENAI_API_KEY",
                    requires_openai_auth: true,
                  },
                },
              };
        const configText = stringifyToml(configuration);
        await writeFile(join(home, "config.toml"), configText);
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
        const permissionsCase =
          !scenario.startsWith("builtin") && scenario !== "saved-profile";
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
        for (const resumed of [false, true]) {
          const request = {
            ...input(),
            pluginRoot,
            scan: {
              ...input().scan,
              targetPath: repository,
              scanDir: join(root, "scan"),
            },
            model: "explicit-current-model",
            reasoningEffort: "ultra",
            parentSandbox: permissionsCase
              ? {
                  filesystemDenies: currentLiteral ? [] : [currentPath],
                  ...(currentLiteral
                    ? { literalFilesystemDenies: [currentPath] }
                    : {}),
                  ...(currentDepth === undefined
                    ? {}
                    : { globScanMaxDepth: currentDepth }),
                }
              : { filesystemDenies: [] },
            recipe: {
              auth: scenario === "builtin-chatgpt" ? "chatgpt" : "api-key",
              ...(scenario === "saved-profile" && resumed
                ? {
                    config: {
                      model: "saved-model",
                      model_reasoning_effort: "high",
                      model_provider: "saved-provider",
                      model_providers: {
                        "saved-provider": { requires_openai_auth: false },
                      },
                    },
                  }
                : {}),
              ...(permissionsCase
                ? {
                    inheritedPermissions: {
                      filesystem: {
                        [savedPath]: savedLiteral ? { ".": "deny" } : "deny",
                        ...(savedDepth === undefined
                          ? {}
                          : { glob_scan_max_depth: savedDepth }),
                      },
                      network: { enabled: false },
                    },
                  }
                : {}),
            },
          };
          if (samePath && savedLiteral !== currentLiteral) {
            await assert.rejects(
              prepareNativeExecution(request),
              /literal.*glob|glob.*literal/u,
            );
            await assert.rejects(readFile(capture), { code: "ENOENT" });
            continue;
          }
          const prepared = await prepareNativeExecution(request);
          const ambient = prepared.client.dependencies.ambientExecution;
          const runtime = await prepareAmbientRuntime(ambient);
          try {
            const source = prepareExecutionSource(ambient);
            const sessionConfig = scanRuntimeCodexConfig(
              prepared.client.config.codexOverrides,
              repository,
              prepared.options.inheritedPermissions,
            );
            const session = {
              policy: "ordinary",
              source,
              runtime,
              runtimeHome: runtime.codexHome,
              effectiveConfig: ambient.configuration,
              preflightConfig: {},
              sessionConfig,
              inheritedPermissions: prepared.options.inheritedPermissions,
              authentication: source.authentication,
              approvalPolicy: "never",
              python: process.execPath,
              releaseCredentialHome: null,
            };
            for (const role of ["discovery", "merge"]) {
              const worker =
                role === "discovery"
                  ? prepareDiscoveryExecution(session)
                  : prepareMergeExecution(session, 2);
              const { codex } = createExecutionCodex(
                { surface: "sdk", command: "scan" },
                worker,
                {},
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
              if (scenario === "saved-profile") {
                assert.equal(
                  config.model,
                  resumed ? "saved-model" : "explicit-current-model",
                );
                assert.equal(
                  config.model_provider,
                  resumed ? "saved-provider" : "ambient-provider",
                );
                assert.equal(
                  config.model_reasoning_effort,
                  resumed ? "high" : "ultra",
                );
              } else if (scenario.startsWith("builtin")) {
                assert.equal(
                  observed.codex,
                  scenario === "builtin-chatgpt"
                    ? undefined
                    : "synthetic-selected-key",
                );
                assert.equal(observed.openai, undefined);
              } else {
                const filesystem =
                  config.permissions[config.default_permissions].filesystem;
                assert.equal(
                  savedLiteral
                    ? filesystem[savedPath]["."]
                    : filesystem[savedPath],
                  "deny",
                );
                assert.equal(
                  currentLiteral
                    ? filesystem[currentPath]["."]
                    : filesystem[currentPath],
                  "deny",
                );
                assert.equal(filesystem.glob_scan_max_depth, expectedDepth);
              }
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
            await rm(runtime.bootstrapWorkspace, {
              recursive: true,
              force: true,
            });
          }
        }
      } finally {
        restore();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

test("native rejoin restores bound knowledge without overwriting its snapshot", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-knowledge-resume-")),
  );
  const document = join(root, "architecture.md");
  const scanDir = join(root, "scan");
  const home = join(root, "home");
  await mkdir(scanDir);
  await mkdir(home);
  await writeFile(document, "Original synthetic architecture.\n");
  const restoreEnvironment = captureEnvironment([
    "CODEX_HOME",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_KNOWLEDGE_BASE",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
  ]);
  try {
    Object.assign(process.env, {
      CODEX_HOME: home,
      CODEX_CLI_PATH: process.execPath,
      CODEX_SECURITY_KNOWLEDGE_BASE: document,
    });
    delete process.env.CODEX_SECURITY_CONFIG_PATH;
    delete process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH;
    const request = { ...input(), scan: { ...input().scan, scanDir } };
    const fresh = await prepareNativeScan(request);
    assert.equal(fresh.options.resumeScanId, undefined);
    assert.equal(fresh.options.knowledgeBaseSnapshot, undefined);
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
