import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import {
  cp,
  mkdir,
  readFile,
  readdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stringify } from "smol-toml";
import { main } from "../src/cli.js";
import {
  mergedCodexConfig,
  resolveCodexProfile,
  type JsonObject,
} from "../src/config.js";
import {
  createProviderProfile,
  privateReplayOverrides,
  restoreProviderProfile,
} from "../src/provider-profile.js";
import { codexSecurityCredentialHome, runWorkbench } from "../src/runtime.js";
import { dependencies, capture } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { rejecting } from "./support/errors.js";
import { pythonExecutable } from "./support/python.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "file-profile-replay-",
);
afterEach(cleanup);

test.each([
  "early",
  "precommit",
  "rejected",
  "postcommit",
  "unavailable-receipt",
  "success",
] as const)(
  "private replay ownership after %s registration",
  async (boundary) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const runtimeHome = join(root, "runtime");
    const scanDir = join(root, "scan");
    for (const path of [repository, home, runtimeHome, scanDir])
      await mkdir(path, { mode: 0o700 });
    await writeFile(join(repository, "fixture.txt"), "Synthetic scan input.\n");
    const profilePath = join(home, "review.config.toml");
    const fileProfile = (version: string) => ({
      model: "gpt-5.6-sol",
      model_provider: "openrouter",
      analytics: { enabled: true },
      shell_environment_policy: { set: { INHERITED: version } },
      model_providers: {
        openrouter: {
          name: "Synthetic provider",
          wire_api: "responses",
          request_max_retries: 4,
        },
      },
    });
    await writeFile(profilePath, stringify(fileProfile("first")));
    const explicit: JsonObject = {
      profile: "review",
      analytics: { enabled: false },
      shell_environment_policy: { inherit: "none", exclude: [] },
      model_providers: {
        openrouter: {
          base_url: "https://models.example.test/v1",
          env_key: "OPENROUTER_API_KEY",
          http_headers: { "X-Example": "synthetic-private-value" },
        },
      },
    };
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENROUTER_API_KEY: "synthetic-api-key",
    };
    const sockets = new Set<Socket>();
    const server = createServer((socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      socket.on("error", (error: NodeJS.ErrnoException) => {
        if (error.code !== "ECONNRESET") throw error;
      });
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Missing registration fixture port");
    const pluginRoot = join(root, "controlled-plugin");
    await cp(PLUGIN_ROOT, pluginRoot, { recursive: true });
    const paused = ["precommit", "postcommit", "unavailable-receipt"].includes(
      boundary,
    );
    await writeFile(
      join(pluginRoot, "scripts", "workbench_db.py"),
      [
        "import runpy, socket, sys",
        `workbench = runpy.run_path(${JSON.stringify(join(PLUGIN_ROOT, "scripts", "workbench_db.py"))})`,
        "namespace = workbench['main'].__globals__",
        ...(paused
          ? [
              `original = namespace[${JSON.stringify(boundary === "precommit" ? "insert_running_scan" : "register_cli_scan")}]`,
              "def pause():",
              `    with socket.create_connection(('127.0.0.1', ${address.port})) as connection:`,
              "        connection.sendall(b'ready')",
              "        connection.recv(1)",
              "def controlled(*args, **kwargs):",
              ...(boundary === "precommit" ? ["    pause()"] : []),
              "    result = original(*args, **kwargs)",
              ...(boundary === "precommit" ? [] : ["    pause()"]),
              "    return result",
              `namespace[${JSON.stringify(boundary === "precommit" ? "insert_running_scan" : "register_cli_scan")}] = controlled`,
            ]
          : []),
        "if __name__ == '__main__': workbench['main']()",
      ].join("\n"),
    );
    const python = pythonExecutable()!;
    const workbenchOptions = { python, pluginRoot: PLUGIN_ROOT, environment };
    const controller = new AbortController();
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), 10_000);
    const ready = paused
      ? once(server, "connection", { signal: deadline.signal }).then(
          async ([socket]) => {
            const [message] = await once(socket, "data", {
              signal: deadline.signal,
            });
            expect(String(message)).toBe("ready");
          },
        )
      : undefined;
    let submitted: JsonObject | undefined;
    const client = new TestClient(
      { pluginPath: pluginRoot, codexOverrides: explicit },
      {
        environment,
        resolvePluginPython: async () => python,
        prepareRuntime: async () => {
          const runtime = preparedRuntime(runtimeHome);
          runtime.plugin.pluginRoot = pluginRoot;
          return runtime;
        },
        prepareOutputDir: async () => scanDir,
        runWorkbench: async (options, args, input) => {
          if (args[0] === "register-cli-scan") {
            submitted = JSON.parse(input!).recipe;
            if (boundary === "rejected")
              args = [
                ...args,
                "--parent-scan-id",
                "00000000-0000-4000-8000-000000000001",
              ];
          }
          if (boundary === "unavailable-receipt" && args[0] === "list-scans")
            throw new Error("Synthetic unavailable registration receipt");
          return runWorkbench({ ...options, python }, args, input);
        },
        createCodex: async () => ({
          startThread: () => ({
            id: null,
            runStreamed: rejecting("synthetic stop after registration"),
          }),
        }),
      },
    );
    if (boundary === "early") controller.abort();
    const operation = client
      .run(repository, { signal: controller.signal })
      .catch((error: unknown) => error);
    try {
      if (ready !== undefined) {
        await Promise.race([
          ready,
          operation.then((error) => {
            throw error;
          }),
        ]);
        controller.abort();
      }
      const failure = await operation;
      expect(failure).toBeInstanceOf(Error);
      if (paused || boundary === "early")
        expect((failure as Error).message).toContain("interrupted");
      if (boundary === "success")
        expect((failure as Error).message).toContain(
          "synthetic stop after registration",
        );
      const { scans } = await runWorkbench(workbenchOptions, [
        "list-scans",
        "--scan-root",
        scanDir,
      ]);
      const committed = [
        "postcommit",
        "unavailable-receipt",
        "success",
      ].includes(boundary);
      expect(scans).toHaveLength(committed ? 1 : 0);
      if (!committed) {
        const names = await readdir(
          codexSecurityCredentialHome(environment),
        ).catch((error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return [];
          throw error;
        });
        expect(names.filter((name) => name.endsWith(".config.json"))).toEqual(
          [],
        );
        expect(submitted === undefined).toBe(boundary === "early");
        return;
      }
      const scanId = (scans as JsonObject[])[0]!["scanId"] as string;
      const { recipe } = await runWorkbench(workbenchOptions, [
        "get-scan-recipe",
        "--scan-id",
        scanId,
      ]);
      expect(recipe).toEqual(submitted!);
      expect(JSON.stringify(recipe)).not.toContain("synthetic-private-value");
      await writeFile(profilePath, stringify(fileProfile("reloaded")));
      let replay: JsonObject | undefined;
      const out = capture(),
        err = capture();
      const status = await main(
        ["scans", "rerun", scanId, "--json"],
        out.stream,
        err.stream,
        dependencies({
          currentDirectory: repository,
          environment,
          onWorkbench: (args, input) =>
            runWorkbench(workbenchOptions, args, input),
          onConfig: (config) => {
            replay = config.codexOverrides;
          },
        }),
      );
      expect(status, out.text() + err.text()).toBe(0);
      const restored = resolveCodexProfile(
        await mergedCodexConfig({ codexOverrides: replay }, home),
      );
      expect(restored).toMatchObject({
        analytics: { enabled: false },
        shell_environment_policy: {
          inherit: "none",
          exclude: [],
          set: { INHERITED: "reloaded" },
        },
        model_providers: {
          openrouter: {
            request_max_retries: 4,
            ...((explicit["model_providers"] as JsonObject)[
              "openrouter"
            ] as JsonObject),
          },
        },
      });
      const profile = submitted!["providerProfile"] as JsonObject;
      const privatePath = join(
        codexSecurityCredentialHome(environment),
        `${profile["name"]}.config.json`,
      );
      expect(await readFile(privatePath, "utf8")).toContain(
        "synthetic-private-value",
      );
      if (process.platform !== "win32")
        expect((await stat(privatePath)).mode & 0o777).toBe(0o600);
    } finally {
      clearTimeout(timer);
      controller.abort();
      for (const socket of sockets) socket.destroy();
      await operation;
      await client.close();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  },
);

test.each(
  (["rerun", "resume"] as const).flatMap((command) =>
    (["inherited", "explicit", "empty", "null"] as const).map(
      (skills) => [command, skills] as const,
    ),
  ),
)(
  "saved registration retains file-profile settings through CLI %s with %s skills",
  async (command, skills) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const runtimeHome = join(root, "runtime");
    const scanDir = join(root, "scan");
    for (const path of [repository, home, runtimeHome, scanDir])
      await mkdir(path, { mode: 0o700 });
    const profilePath = join(home, "review.config.toml");
    const fileProfile = (version: string) => ({
      model: version === "first" ? "initial-model" : "updated-model",
      model_reasoning_effort: version === "first" ? "low" : "high",
      analytics: { enabled: true },
      shell_environment_policy: {
        inherit: "all",
        exclude: ["FILE_SETTING"],
        set: { INHERITED: version },
      },
      otel: { exporter: "console", environment: version },
      agents: {
        reviewer: { config_file: "file-reviewer.toml", description: version },
      },
      skills: {
        config: [{ path: "file-skill", enabled: version === "first" }],
      },
      model_instructions_file: "file-instructions.md",
      model_catalog_json: "file-catalog.json",
      features: { view_image: true },
    });
    await writeFile(profilePath, stringify(fileProfile("first")));
    const explicit: JsonObject = {
      profile: "review",
      analytics: { enabled: false },
      shell_environment_policy: {
        inherit: "none",
        exclude: [],
        set: { EXPLICIT: "kept" },
      },
      otel: { exporter: "none" },
      agents: { reviewer: { config_file: "caller-reviewer.toml" } },
      model_instructions_file: null,
      model_catalog_json: "../caller-catalog.json",
      features: { view_image: false, shell_tool: false },
    };
    if (skills !== "inherited")
      explicit["skills"] =
        skills === "null"
          ? null
          : {
              config:
                skills === "empty"
                  ? []
                  : [{ path: "caller-skill", enabled: false }],
            };
    const environment = {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    let recipe: JsonObject | undefined;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, codexOverrides: explicit },
      {
        environment,
        resolvePluginPython: async () => "/managed/python",
        prepareRuntime: async () => preparedRuntime(runtimeHome),
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_runtime, args, input) => {
          if (args[0] === "register-cli-scan")
            recipe = JSON.parse(input!).recipe;
          return mockWorkbench(args, input);
        },
        createCodex: async () => ({
          startThread: () => ({
            id: null,
            runStreamed: rejecting("synthetic stop after registration"),
          }),
        }),
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        "synthetic stop after registration",
      );
      expect(recipe).toBeDefined();
      await writeFile(profilePath, stringify(fileProfile("reloaded")));
      let replay: JsonObject | undefined;
      const out = capture(),
        err = capture();
      const status = await main(
        ["scans", command, "saved", "--json"],
        out.stream,
        err.stream,
        dependencies({
          currentDirectory: repository,
          environment,
          onWorkbench: () => ({ scanId: "saved", scanDir, recipe: recipe! }),
          onConfig: (config) => {
            replay = config.codexOverrides;
          },
        }),
      );
      expect(status, out.text() + err.text()).toBe(0);
      const restored = resolveCodexProfile(
        await mergedCodexConfig({ codexOverrides: replay }, home),
      );
      expect(restored).toMatchObject({
        model: "updated-model",
        model_reasoning_effort: "high",
        analytics: { enabled: false },
        shell_environment_policy: {
          inherit: "none",
          exclude: [],
          set: { INHERITED: "reloaded", EXPLICIT: "kept" },
        },
        otel: { exporter: "none", environment: "reloaded" },
        agents: {
          reviewer: {
            config_file: join(scanDir, "caller-reviewer.toml"),
            description: "reloaded",
          },
        },
        model_catalog_json: resolve(scanDir, "../caller-catalog.json"),
        features: { view_image: false, shell_tool: false },
      });
      expect(restored["skills"]).toEqual(
        skills === "inherited"
          ? { config: [{ path: join(home, "file-skill"), enabled: false }] }
          : skills === "explicit"
            ? {
                config: [
                  { path: join(scanDir, "caller-skill"), enabled: false },
                ],
              }
            : skills === "empty"
              ? { config: [] }
              : undefined,
      );
      expect(restored).not.toHaveProperty("model_instructions_file");
      const workerResult = execFileSync(
        Bun.which("node")!,
        [
          "--experimental-strip-types",
          fileURLToPath(
            new URL("./support/replay-worker-boundary.ts", import.meta.url),
          ),
          root,
        ],
        { input: JSON.stringify(restored), encoding: "utf8" },
      );
      expect(JSON.parse(workerResult)).toEqual({ launches: 4 });
      const profile = recipe!["providerProfile"] as JsonObject;
      const privatePath = join(
        codexSecurityCredentialHome(environment),
        `${profile["name"]}.config.json`,
      );
      const saved = JSON.parse(await readFile(privatePath, "utf8"));
      expect(saved).not.toHaveProperty("model_catalog_json");
      expect(saved).not.toHaveProperty("features.shell_tool");
      expect(saved).toHaveProperty("model_instructions_file", null);
      expect(saved).not.toHaveProperty(
        "shell_environment_policy.set.INHERITED",
      );
      if (process.platform !== "win32")
        expect((await stat(privatePath)).mode & 0o777).toBe(0o600);
      expect(explicit["model_catalog_json"]).toBe("../caller-catalog.json");
    } finally {
      await client.close();
    }
  },
);

test("private replay preserves explicit clears over projected defaults and empty provider semantics", async () => {
  const home = await temporaryDirectory();
  const recipe: JsonObject = {
    model_provider: "openai",
    model_catalog_json: join(home, "original-catalog.json"),
    features: { shell_tool: true },
  };
  const providerCases: (JsonObject | null)[] = [
    null,
    {},
    { synthetic: { auth: null, http_headers: {} } },
  ];
  for (const providers of providerCases) {
    const overrides: JsonObject = {
      model_provider: null,
      model_catalog_json: "raw-relative-catalog.json",
      features: { shell_tool: null },
      shell_environment_policy: { exclude: [] },
      model_providers: providers,
    };
    const saved = await createProviderProfile(
      home,
      privateReplayOverrides(overrides, recipe),
      { replay: true },
    );
    try {
      const restored = await restoreProviderProfile(
        recipe,
        { name: saved.name, home: "ambient" },
        { CODEX_HOME: home },
      );
      expect(restored).toMatchObject({
        model_provider: null,
        model_catalog_json: recipe["model_catalog_json"],
        features: { shell_tool: null },
        shell_environment_policy: { exclude: [] },
      });
      if (providers === null || Object.keys(providers).length > 0)
        expect(restored["model_providers"]).toEqual(providers);
      else expect(restored).not.toHaveProperty("model_providers");
    } finally {
      await saved.cleanup();
    }
    await expect(readFile(saved.path)).rejects.toMatchObject({
      code: "ENOENT",
    });
  }
});
