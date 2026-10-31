import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import type { CodexOptions } from "@openai/codex-sdk";
import { parse } from "smol-toml";
import type { JsonObject, JsonValue } from "../src/config.js";
import {
  deepScanParentToolOverrides,
  readDeepScanParentConfig,
  type DirectDeepScanOptions,
} from "../src/deep-scan.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("a colliding MCP server leaves only the original coordinator's namespace direct", () => {
  const owner = "codex-security";
  const alias = "codex.security";
  const bare = "codex_security";
  const prefixed = "mcp__codex_security";
  const servers = { [owner]: { enabled: true }, [alias]: { enabled: true } };
  const selected = (...names: string[]) => ({
    enabled: true,
    server_names: names,
  });
  const direct = (...names: string[]) => ({
    direct_only_tool_namespaces: names,
  });
  const overrides = (
    prefix?: JsonValue,
    existing: string[] = ["audit"],
    registrations: JsonObject = servers,
  ) => {
    const config = {
      mcp_servers: registrations,
      features: {
        ...(prefix === undefined
          ? {}
          : { non_prefixed_mcp_tool_names: prefix }),
        code_mode: direct(...existing),
      },
    };
    return parse(deepScanParentToolOverrides(config, {}).join("\n"))[
      "features"
    ];
  };

  expect(overrides()).toEqual({
    non_prefixed_mcp_tool_names: selected(owner),
    code_mode: direct("audit", bare),
  });
  expect(overrides(selected("retained-tools"))).toEqual({
    non_prefixed_mcp_tool_names: selected("retained-tools", owner),
    code_mode: direct("audit", bare),
  });
  expect(overrides(selected(alias))).toEqual({
    code_mode: direct("audit", prefixed),
  });
  expect(overrides(selected(owner))).toEqual({
    code_mode: direct("audit", bare),
  });
  expect(
    overrides(undefined, ["audit"], {
      ...servers,
      [alias]: { enabled: false },
    }),
  ).toEqual({
    code_mode: direct("audit", prefixed, bare),
  });

  expect(
    overrides(false, ["audit"], { ...servers, [alias]: { enabled_tools: [] } }),
  ).toEqual({ code_mode: direct("audit", prefixed, bare) });
  expect(
    overrides(false, ["audit"], {
      ...servers,
      [alias]: { enabled_tools: ["peer_ping"] },
    }),
  ).toBeUndefined();
  expect(overrides(false)).toBeUndefined();
  expect(overrides(true)).toBeUndefined();
  expect(overrides(undefined, [prefixed])).toBeUndefined();
  const guardedPeer = `${prefixed}_9721dc6aa9d2`;
  expect(overrides(undefined, [guardedPeer])).toBeUndefined();
  expect(
    deepScanParentToolOverrides(
      { features: { code_mode: { excluded_tool_namespaces: [guardedPeer] } } },
      servers,
    ),
  ).toEqual([]);
  expect(
    overrides(undefined, [], { ...servers, [owner]: { enabled: false } }),
  ).toBeUndefined();
  expect(
    overrides(selected(bare), [], { ...servers, [bare]: { enabled: true } }),
  ).toBeUndefined();
});

test("a configured owner stays direct across native tool filtering without changing a sibling's routing", () => {
  const owner = "codex-security";
  const peer = "codex_security";
  const guarded = "mcp__codex_security_9721dc6aa9d2";
  const overrides = (transport: JsonObject, selected: string[]) =>
    parse(
      deepScanParentToolOverrides(
        {
          mcp_servers: {
            [owner]: transport,
            [peer]: { command: "peer", enabled_tools: selected },
          },
          features: {
            non_prefixed_mcp_tool_names: false,
            code_mode: { direct_only_tool_namespaces: [guarded] },
          },
        },
        {},
      ).join("\n"),
    );
  const transports: JsonObject[] = [
    { command: "coordinator", omit_tools_from: ["code_mode"] },
    { url: "https://coordinator.example/mcp" },
  ];
  for (const transport of transports) {
    for (const selected of [["peer_ping"], ["absent"]]) {
      expect(overrides(transport, selected)).toEqual({
        mcp_servers: {
          [owner]: { omit_tools_from: ["code_mode", "deferred"] },
        },
      });
    }
  }
  expect(
    overrides({ command: "coordinator", omit_tools_from: ["direct"] }, [
      "absent",
    ]),
  ).toEqual({});
});

test("native MCP registrations take precedence over the selected plugin's names and opt-outs", () => {
  const owner = "codex-security";
  const alias = "codex.security";
  const plugin = { [owner]: {}, [alias]: {} };
  const noDirect = { omit_tools_from: ["direct"] };
  const overrides = (servers: JsonObject, selected: JsonObject) =>
    parse(
      deepScanParentToolOverrides({ mcp_servers: servers }, selected).join(
        "\n",
      ),
    )["features"];
  const isolated = {
    non_prefixed_mcp_tool_names: { enabled: true, server_names: [owner] },
    code_mode: { direct_only_tool_namespaces: ["codex_security"] },
  };

  expect(overrides({}, plugin)).toEqual(isolated);
  expect(overrides({ [alias]: { enabled: false } }, plugin)).toEqual({
    code_mode: {
      direct_only_tool_namespaces: ["mcp__codex_security", "codex_security"],
    },
  });
  expect(overrides({}, { [alias]: {} })).toBeUndefined();
  expect(overrides({}, { ...plugin, [owner]: noDirect })).toBeUndefined();
  expect(overrides({ [owner]: noDirect }, plugin)).toBeUndefined();
  expect(overrides({ [owner]: {} }, { ...plugin, [owner]: noDirect })).toEqual(
    isolated,
  );
});

const parentWithNode = {
  dependencyNode: null,
  runtimeNode: "selected runtime",
  route: "parent",
} as const;

test.each([
  {
    name: "inherited Node override",
    dependencyNode: "configured runtime",
    runtimeNode: "configured runtime",
    route: "parent",
  },
  {
    name: "Node override supplied by the prepared runtime",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "prepared Node override replacing the dependency value",
    dependencyNode: "ambient runtime",
    runtimeNode: "selected runtime",
    route: "parent",
  },
  {
    name: "dependency Node override absent from the prepared runtime",
    dependencyNode: "unused runtime",
    runtimeNode: null,
    route: "direct",
  },
  {
    name: "no Node override",
    dependencyNode: null,
    runtimeNode: null,
    route: "direct",
  },
  {
    name: "installed plugin excludes the direct surface",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    pluginOmit: ["direct"],
    directOmitted: true,
  },
  {
    name: "configured server permits direct use despite the installed plugin exclusion",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    pluginOmit: ["direct"],
    configuredOmit: [],
  },
  {
    name: "configured server excludes the direct surface",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    configuredOmit: ["direct"],
    directOmitted: true,
  },
  {
    ...parentWithNode,
    name: "inline MCP declaration allowing direct calls",
    declaration: "inline",
    pluginOmit: [],
  },
  {
    ...parentWithNode,
    name: "inline MCP declaration excluding direct calls",
    declaration: "inline",
    pluginOmit: ["direct"],
    directOmitted: true,
  },
  {
    ...parentWithNode,
    name: "alternate MCP declaration allowing direct calls",
    declaration: "alternate",
    pluginOmit: [],
  },
  {
    ...parentWithNode,
    name: "alternate MCP declaration excluding direct calls",
    declaration: "alternate",
    pluginOmit: ["direct"],
    directOmitted: true,
  },
  {
    ...parentWithNode,
    name: "the installed default when an alternate MCP selector contains a parent component",
    declaration: "invalid",
    pluginOmit: ["direct"],
  },
  {
    ...parentWithNode,
    name: "an alternate MCP file reached through a link outside the installed plugin",
    declaration: "outside",
    pluginOmit: [],
    directOmitted: true,
  },
  {
    name: "invalid code mode supplied by the caller",
    dependencyNode: null,
    runtimeNode: "selected runtime",
    route: "parent",
    codeMode: "mistyped",
  },
])("Deep Scan respects $name", async (scenario) => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  const runtime = preparedRuntime(codexHome);
  if (scenario.pluginOmit) {
    const installed = join(root, "installed-plugin");
    await mkdir(join(installed, ".codex-plugin"), { recursive: true });
    const manifest = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
    );
    const servers = (omit: readonly string[]) => ({
      "codex-security": { command: "fixture", omit_tools_from: omit },
    });
    const declared = servers(scenario.pluginOmit);
    let defaults = declared;
    if ("declaration" in scenario) {
      // Only the installed manifest selects this declaration.
      defaults = servers(scenario.directOmitted ? [] : ["direct"]);
      if (scenario.declaration === "inline") {
        manifest.mcpServers = declared;
      } else {
        manifest.mcpServers = "./routing/servers.json";
        const routing = join(installed, "routing");
        const linked = scenario.declaration === "outside";
        const directory = linked ? join(root, "outside-plugin") : routing;
        await mkdir(directory);
        if (scenario.declaration === "invalid") {
          await mkdir(join(directory, "nested"));
          manifest.mcpServers = "./routing/nested/../servers.json";
          defaults = servers([]);
        }
        if (linked) {
          await symlink(
            directory,
            routing,
            process.platform === "win32" ? "junction" : "dir",
          );
        }
        await writeFile(
          join(directory, "servers.json"),
          JSON.stringify({ mcpServers: declared }),
        );
      }
    }
    await writeFile(
      join(installed, ".mcp.json"),
      JSON.stringify({ mcpServers: defaults }),
    );
    await writeFile(
      join(installed, ".codex-plugin", "plugin.json"),
      JSON.stringify(manifest),
    );
    runtime.plugin.installedRoot = installed;
  }
  const selectedNode =
    scenario.runtimeNode === null
      ? undefined
      : join(root, scenario.runtimeNode, "node");
  const runtimeEnvironment: Record<string, string> =
    selectedNode === undefined ? {} : { CODEX_MCP_NODE_PATH: selectedNode };
  const originalRuntimeEnvironment = { ...runtimeEnvironment };
  const codeMode = scenario.codeMode ?? {
    direct_only_tool_namespaces: ["existing_tools"],
  };
  const parentTurn = mock(async () => {
    throw new Error("parent route reached");
  });
  const directRun = mock(async function* (options: DirectDeepScanOptions) {
    expect(options.codexOptions.env?.["CODEX_MCP_NODE_PATH"]).toBe(
      selectedNode,
    );
    throw new Error("direct route reached");
  });
  const started: CodexOptions[] = [];
  const createCodex = mock((options: CodexOptions) => {
    expect(options.apiKey).toBe("synthetic-routing-key");
    expect(options.env?.["CODEX_MCP_NODE_PATH"]).toBe(selectedNode);
    expect(options.env?.["CODEX_SECURITY_SCAN_DIR"]).toBe(scanDir);
    expect(options.config).toMatchObject({
      model: "gpt-6.1-sol",
      model_reasoning_effort: "high",
      features: {
        shell_tool: false,
        code_mode: codeMode,
      },
    });
    return {
      startThread: () => {
        started.push(options);
        return { id: null, runStreamed: parentTurn };
      },
    };
  });
  const client = new TestClient(
    {
      codexOverrides: {
        ...(scenario.configuredOmit === undefined
          ? {}
          : {
              mcp_servers: {
                "codex-security": {
                  command: "test-server",
                  omit_tools_from: [...scenario.configuredOmit],
                },
              },
            }),
        model: "gpt-6.1-sol",
        model_reasoning_effort: "high",
        features: {
          shell_tool: false,
          code_mode: codeMode,
        },
      },
    },
    {
      ...scanRuntimeDependencies(codexHome, scanDir),
      environment: {
        CODEX_API_KEY: "synthetic-routing-key",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        ...(scenario.dependencyNode === null
          ? {}
          : {
              CODEX_MCP_NODE_PATH: join(root, scenario.dependencyNode, "node"),
            }),
      },
      prepareRuntime: async () => ({
        ...runtime,
        environment: runtimeEnvironment,
      }),
      // Keep the host's Bun fallback and account advisory out of this check.
      canRunDirectDeepScan: () => true,
      createCodex,
      runDeepScan: directRun,
    },
  );
  try {
    await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
      `${scenario.route} route reached`,
    );
    expect(started).toHaveLength(1);
    const rawRule =
      'mcp_servers.codex-security.omit_tools_from=["code_mode","deferred"]';
    const overrides = started[0]!.configOverrides?.filter(
      (value) =>
        value === rawRule ||
        value.startsWith("features.code_mode.direct_only_tool_namespaces="),
    );
    expect(overrides).toEqual(
      scenario.route === "parent" &&
        typeof codeMode !== "string" &&
        !scenario.directOmitted
        ? [
            scenario.configuredOmit !== undefined
              ? rawRule
              : 'features.code_mode.direct_only_tool_namespaces=["existing_tools","mcp__codex_security","codex_security"]',
          ]
        : [],
    );
    expect(parentTurn).toHaveBeenCalledTimes(
      scenario.route === "parent" ? 1 : 0,
    );
    expect(directRun).toHaveBeenCalledTimes(
      scenario.route === "direct" ? 1 : 0,
    );
    expect(runtimeEnvironment).toEqual(originalRuntimeEnvironment);
  } finally {
    await client.close();
  }
});

test("older app-servers retain supplied routing without starting in the caller project", async () => {
  const home = await temporaryDirectory();
  const scanDir = await temporaryDirectory();
  await writeFile(
    join(home, "config.toml"),
    '[features.code_mode]\ndirect_only_tool_namespaces = ["inherited_tools"]\n',
  );
  const read = (
    config: CodexOptions["config"],
    configOverrides: string[] = [],
  ) =>
    readDeepScanParentConfig({
      codexOptions: { config, configOverrides, env: { CODEX_HOME: home } },
      preflightCommand: resolveCodexCommand({}),
      scanDir,
      signal: new AbortController().signal,
    });
  const expected = (name: string) => ({
    features: { code_mode: { direct_only_tool_namespaces: [name] } },
  });
  expect(
    await read({ model_instructions_file: "missing-in-caller.md" }),
  ).toEqual({});
  expect(
    await read({
      features: { "code_mode.direct_only_tool_namespaces": ["first"] },
      "features.code_mode.direct_only_tool_namespaces": ["last"],
      model_auto_compact_token_limit: 2 ** 53,
    }),
  ).toEqual(expected("last"));
  expect(await read({ "features.code_mode": "invalid" })).toEqual({
    features: { code_mode: "invalid" },
  });
  const owner = { command: "fixture" };
  const explicit = { mcp_servers: { "codex-security": owner } };
  expect(await read(explicit)).toBeUndefined();
  expect(
    await read(explicit, [
      'mcp_servers.codex-security.omit_tools_from=["direct"]',
      "mcp_servers.codex-security.omit_tools_from=[]",
    ]),
  ).toEqual({
    mcp_servers: { "codex-security": { ...owner, omit_tools_from: [] } },
  });
  const leaf = await read({}, [
    "mcp_servers.codex-security.omit_tools_from=[]",
  ]);
  expect(deepScanParentToolOverrides(leaf!, {})).toEqual([
    'mcp_servers.codex-security.omit_tools_from=["code_mode","deferred"]',
  ]);
});

test("a capable app-server launches from the caller and reads the scan settings and selected plugin", async () => {
  const home = await temporaryDirectory();
  const scanDir = await temporaryDirectory();
  const script = join(home, "config-reader.mjs");
  const log = join(home, "requests.json");
  await writeFile(
    script,
    `import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
if (process.argv.includes("--help")) { console.log("  -C, --cd <DIR>"); process.exit(0); }
const startupCwd = process.argv[process.argv.indexOf("--cd") + 1];
const [log, replies] = process.argv.slice(2);
const responses = JSON.parse(replies);
const calls = [];
for await (const line of createInterface({ input: process.stdin })) {
  const { id, method, params } = JSON.parse(line);
  if (id === undefined) continue;
  if (method !== "initialize") {
    calls.push({ method, params });
    writeFileSync(log, JSON.stringify({ cwd: process.cwd(), startupCwd, calls }));
  }
  console.log(JSON.stringify({ id, ...(responses[method] ?? { result: {} }) }));
}`,
  );
  const plugin = {
    marketplacePath: join(home, "marketplace.json"),
    pluginName: "selected-security",
  };
  const owner = "codex-security";
  const alias = "codex.security";
  const noDirect = { omit_tools_from: ["direct"] };
  const config = { mcp_servers: { [owner]: noDirect } };
  const read = (
    detail: JsonObject,
    settings: JsonObject = { result: { config } },
  ) =>
    readDeepScanParentConfig({
      codexOptions: { env: { CODEX_HOME: home } },
      preflightCommand: {
        command: process.execPath,
        args: [
          script,
          log,
          JSON.stringify({ "config/read": settings, "plugin/read": detail }),
        ],
      },
      scanDir,
      signal: new AbortController().signal,
      plugin,
    });
  const requests = async () => JSON.parse(await readFile(log, "utf8"));
  const configRead = {
    method: "config/read",
    params: { cwd: scanDir, includeLayers: false },
  };
  const detail = {
    result: {
      plugin: {
        summary: { installed: true, enabled: true },
        mcpServers: [owner, alias],
      },
    },
  };
  expect(await read(detail)).toEqual({
    mcp_servers: { [owner]: noDirect, [alias]: {} },
  });
  expect(await requests()).toEqual({
    cwd: process.cwd(),
    startupCwd: scanDir,
    calls: [configRead, { method: "plugin/read", params: plugin }],
  });
  expect(
    await read({ error: { code: -32601, message: "Method not found" } }),
  ).toBeUndefined();
  await expect(
    read(detail, { error: { code: -32602, message: "invalid configuration" } }),
  ).rejects.toThrow(
    /Could not read the Deep Scan parent configuration[\s\S]*invalid configuration/u,
  );
  expect((await requests()).calls).toEqual([configRead]);
});
