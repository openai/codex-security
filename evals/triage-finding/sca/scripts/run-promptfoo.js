#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");
const childProcess = require("node:child_process");
const runtimeVars = require("../../scripts/runtime-vars.mts").default;
const { CORPUS, FIXTURE_ROOT } = require("./sca-result.js");

const EVAL_ROOT = path.resolve(__dirname, "../..");

function codexPackageRequire() {
  const sdkRequire = createRequire(
    fs.realpathSync(
      path.join(EVAL_ROOT, "node_modules/@openai/codex-sdk/package.json"),
    ),
  );
  return createRequire(sdkRequire.resolve("@openai/codex/package.json"));
}

function nativeCodexRuntimeRoot() {
  const codexRequire = codexPackageRequire();
  return path.dirname(
    codexRequire.resolve(
      `@openai/codex-${process.platform}-${process.arch}/package.json`,
    ),
  );
}

function stageProviderConfig(
  runtime,
  codexHome,
  codexScript = path.join(
    path.dirname(codexPackageRequire().resolve("@openai/codex/package.json")),
    "bin/codex.js",
  ),
) {
  const { triage_node_path: nodePath, triage_runtime_root: pluginRoot } =
    runtimeVars({});
  // Match the SDK's read-only helpers: an empty table does not remove inherited servers.
  const inherited = JSON.parse(
    childProcess.execFileSync(
      nodePath,
      [
        codexScript,
        "-C",
        pluginRoot,
        "-c",
        "features.plugins=false",
        "-c",
        "features.apps=false",
        "mcp",
        "list",
        "--json",
      ],
      { env: { ...process.env, CODEX_HOME: codexHome }, encoding: "utf8" },
    ),
  );
  const provider = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../provider.json"), "utf8"),
  );
  // Promptfoo exposes SDK config, whose dotted-key flattening cannot retain
  // literal server names. Delegate through the existing launcher with one table.
  const mcpOverride = `mcp_servers={${inherited
    .map(({ name }) => `${JSON.stringify(name)}={enabled=false}`)
    .join(",")}}`;
  const adapter = path.join(runtime, "codex-launcher.mjs");
  const preload = `--import=${pathToFileURL(adapter).href}`;
  fs.writeFileSync(
    adapter,
    `const preload = ${JSON.stringify(preload)};
if (process.env.NODE_OPTIONS === preload) delete process.env.NODE_OPTIONS;
else if (process.env.NODE_OPTIONS?.endsWith(" " + preload))
  process.env.NODE_OPTIONS = process.env.NODE_OPTIONS.slice(0, -(preload.length + 1));
// Node resolves the SDK's exec argument as a main path before loading this module.
process.argv.splice(1, 1, ${JSON.stringify(codexScript)}, "--config", ${JSON.stringify(mcpOverride)}, "exec");
await import(${JSON.stringify(pathToFileURL(codexScript).href)});
`,
  );
  provider.config.codex_path_override = nodePath;
  provider.config.cli_env.CODEX_MCP_NODE_PATH = nodePath;
  provider.config.cli_env.NODE_OPTIONS = process.env.NODE_OPTIONS
    ? `${process.env.NODE_OPTIONS} ${preload}`
    : preload;
  const output = path.join(runtime, "provider.json");
  fs.writeFileSync(output, JSON.stringify(provider));
  return output;
}

function stageRuntime() {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "codex-security-sca-"));
  try {
    for (const testCase of CORPUS.cases) {
      fs.cpSync(
        path.join(FIXTURE_ROOT, testCase.case_id),
        path.join(runtime, "cases", testCase.case_id),
        { recursive: true },
      );
    }
    return runtime;
  } catch (error) {
    fs.rmSync(runtime, { recursive: true, force: true });
    throw error;
  }
}

function main(args = process.argv.slice(2)) {
  if (args.length === 0)
    throw new Error("Expected Promptfoo arguments (validate config or eval)");
  const runtime = stageRuntime();
  fs.mkdirSync(path.join(EVAL_ROOT, "artifacts"), { recursive: true });
  try {
    const codexHome =
      process.env.CODEX_HOME || path.join(os.homedir(), ".codex");
    const providerConfig = stageProviderConfig(runtime, codexHome);
    const promptfooPackage = path.join(
      EVAL_ROOT,
      "node_modules/promptfoo/package.json",
    );
    const { bin } = JSON.parse(fs.readFileSync(promptfooPackage, "utf8"));
    childProcess.execFileSync(
      runtimeVars({}).triage_node_path,
      [path.resolve(path.dirname(promptfooPackage), bin.promptfoo), ...args],
      {
        cwd: EVAL_ROOT,
        env: {
          ...process.env,
          SCA_EVAL_RUNTIME_ROOT: runtime,
          SCA_EVAL_CODEX_RUNTIME_ROOT: nativeCodexRuntimeRoot(),
          SCA_EVAL_CODEX_HOME: codexHome,
          SCA_EVAL_PROVIDER_CONFIG: providerConfig,
          PROMPTFOO_CONFIG_DIR: ".promptfoo",
          PROMPTFOO_DISABLE_WAL_MODE: "true",
        },
        stdio: "inherit",
      },
    );
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
}

if (require.main === module) main();
module.exports = {
  stageRuntime,
  stageProviderConfig,
  nativeCodexRuntimeRoot,
  main,
};
