import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import {
  parse as parseToml,
  stringify as stringifyToml,
  type TomlTable,
} from "smol-toml";
import {
  AuthenticationRequiredError,
  CodexSecurity,
  DiffTarget,
  InvalidTargetError,
  type ScanTarget,
  type DependencyIdentity,
} from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const TestClientBase = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
) => CodexSecurity;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-dependency-api-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

async function gitRepository(root: string): Promise<string> {
  const repository = join(root, "repository");
  await mkdir(repository);
  await writeFile(join(repository, "package.json"), '{"name":"fixture"}\n');
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repository, stdio: "pipe" });
  git("init", "-q");
  git("add", "package.json");
  git(
    "-c",
    "user.name=Codex Security",
    "-c",
    "user.email=codex-security@example.com",
    "commit",
    "-qm",
    "fixture",
  );
  return repository;
}

function mockWorkbench(args: readonly string[]): Record<string, unknown> {
  if (args[0] === "inspect-cli-dependencies") {
    const recipe = JSON.parse(
      args[args.indexOf("--recipe-json") + 1] ?? "{}",
    ) as Record<string, unknown>;
    return {
      repository: args[args.indexOf("--repository") + 1],
      target: recipe["target"],
      targetRevision: "deadbeef",
      snapshotDigest: null,
    };
  }
  if (args[0] === "register-cli-scan") {
    const recipe = JSON.parse(
      args[args.indexOf("--recipe-json") + 1] ?? "{}",
    ) as {
      target: { kind: string; paths: string[]; base?: string; head?: string };
    };
    const target = recipe.target;
    const isDiff = target.kind === "refs" || target.kind === "working_tree";
    return {
      scanId: "scan_dependency_fixture",
      targetId: "target_dependency_fixture",
      targetRevision: "deadbeef",
      scanDir: args[args.indexOf("--scan-dir") + 1],
      contract: {
        target: { allowedKinds: [isDiff ? "git_diff" : "git_revision"] },
        scope: {
          requiredIncludePaths:
            target.kind === "repository" ? ["."] : target.paths,
        },
        ...(isDiff
          ? {
              diffTarget: {
                baseRevision: target.base,
                headRevision: target.head,
              },
            }
          : {}),
      },
    };
  }
  if (args[0] === "get-scan-feedback") {
    return {
      scanId: "scan_dependency_fixture",
      targetId: "target_dependency_fixture",
      falsePositives: [],
    };
  }
  return {};
}

function dependencyArtifactResultEvent(
  overrides: {
    server?: string;
    scanId?: string;
    status?: string;
    operation?: string;
    toolStatus?: string;
    error?: string;
    findingsRecorded?: number;
    structuredResult?: boolean;
  } = {},
): Record<string, unknown> {
  return {
    type: "item.completed",
    item: {
      id: "dependency-result-1",
      type: "mcp_tool_call",
      server: overrides.server ?? "codex-security",
      tool: "record_codex_security_dependency_artifact_result",
      status: overrides.toolStatus ?? "completed",
      ...(overrides.error === undefined
        ? {}
        : { error: { message: overrides.error } }),
      result: {
        content: [],
        ...(overrides.structuredResult === false
          ? {}
          : {
              structured_content: {
                scanId: overrides.scanId ?? "scan_dependency_fixture",
                findingsRecorded: overrides.findingsRecorded ?? 1,
                operation: overrides.operation ?? "replace",
                status: overrides.status ?? "recorded",
              },
            }),
      },
    },
  };
}

async function createArtifactScanHarness(
  turns: ReadonlyArray<ReadonlyArray<Record<string, unknown>>>,
  options: {
    artifactMode?: boolean;
    cancelAfterTurn?: AbortController;
    registration?: Record<string, unknown>;
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = await gitRepository(root);
  const codexHome = join(root, "codex-home");
  const pluginRoot = join(root, "plugin");
  const scanDir = join(root, "scan");
  await mkdir(codexHome);
  await mkdir(scanDir, { mode: 0o700 });
  for (const skill of [
    "security-diff-scan",
    "security-scan",
    "dependency-update-scan",
  ]) {
    const skillDirectory = join(pluginRoot, "skills", skill);
    await mkdir(skillDirectory, { recursive: true });
    await writeFile(join(skillDirectory, "SKILL.md"), `# ${skill}\n`);
  }

  const commands: Array<readonly string[]> = [];
  const prompts: string[] = [];
  const targetPathSnapshots: unknown[] = [];
  const scanEnvironments: CodexOptions["env"][] = [];
  let threadsStarted = 0;
  const client = new TestClientBase(
    {},
    {
      environment:
        options.artifactMode === false
          ? {}
          : { CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN: "1" },
      prepareRuntime: async () => ({
        codexHome,
        plugin: {
          pluginRoot,
          marketplaceRoot: pluginRoot,
          installedRoot: pluginRoot,
          marketplaceName: "codex-security-sdk",
          name: "codex-security",
          version: "0.1.0",
        },
        environment: {},
        credentialsAvailable: true,
      }),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (
        _options: unknown,
        args: readonly string[],
        input?: string,
      ) => {
        if (input !== undefined)
          args = [
            ...args,
            "--recipe-json",
            JSON.stringify(JSON.parse(input).recipe),
          ];
        commands.push(args);
        if (args[0] === "prepare-scan-completion") {
          throw new Error("host preparation observed");
        }
        if (args[0] === "register-cli-scan") {
          return { ...mockWorkbench(args), ...options.registration };
        }
        return mockWorkbench(args);
      },
      createCodex: (codexOptions: CodexOptions) => ({
        startThread: () => {
          scanEnvironments.push(codexOptions.env);
          threadsStarted += 1;
          return {
            id: null,
            async runStreamed(input: string) {
              const turnIndex = prompts.length;
              prompts.push(input);
              const targetPathsFile =
                codexOptions.env?.["CODEX_SECURITY_TARGET_PATHS_FILE"];
              if (targetPathsFile !== undefined) {
                targetPathSnapshots.push(
                  JSON.parse(await readFile(targetPathsFile, "utf8")),
                );
              }
              const events = turns[turnIndex];
              if (events === undefined) {
                throw new Error("unexpected scanner continuation");
              }
              async function* streamedEvents(
                turnEvents: ReadonlyArray<Record<string, unknown>>,
              ) {
                yield { type: "thread.started", thread_id: "artifact-thread" };
                for (const event of turnEvents) yield event;
                yield {
                  type: "turn.completed",
                  usage: {
                    input_tokens: turnIndex + 1,
                    cached_input_tokens: 0,
                    output_tokens: turnIndex + 2,
                    reasoning_output_tokens: 0,
                  },
                };
                if (turnIndex === 0) options.cancelAfterTurn?.abort();
              }
              return { events: streamedEvents(events) };
            },
          };
        },
      }),
    },
  );

  return {
    client,
    repository,
    scanDir,
    commands,
    prompts,
    targetPathSnapshots,
    scanEnvironments,
    threadsStarted: () => threadsStarted,
  };
}

const nativeResolverOutput =
  JSON.stringify({
    dependencies: {
      first: {
        version: "1.0.0",
        dependencies: { transitive: { version: "2.0.0" } },
      },
      second: { version: "3.0.0" },
    },
  }) + "\n";

function calculationEvents(
  result: unknown = { depthCounts: [2, 1] },
): Record<string, unknown>[] {
  return [
    { type: "thread.started", thread_id: "calculation-fixture" },
    {
      type: "item.completed",
      item: {
        id: "calculation-result",
        type: "agent_message",
        text: JSON.stringify(result),
      },
    },
    {
      type: "turn.completed",
      usage: { input_tokens: 20, cached_input_tokens: 0, output_tokens: 10 },
    },
  ];
}

async function createCalculationHarness(
  options: {
    events?: readonly Record<string, unknown>[];
    writeGraph?: boolean;
    credentialsAvailable?: boolean;
    beforeEvents?: () => void;
    selectedProfile?: string;
    mcpServers?: readonly string[];
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = await gitRepository(root);
  const codexHome = join(root, "codex-home");
  const outputDir = join(root, "private calculation");
  const dependencyGraphPath = join(
    outputDir,
    "dependency-resolver-output.json",
  );
  await mkdir(codexHome);
  const configPath = join(codexHome, "config.toml");
  const effectiveConfig = {
    model: "gpt-5.6-sol",
    model_reasoning_effort: "xhigh",
    features: { apps: true, plugins: true, multi_agent_v2: { enabled: true } },
    agents: { fixture: { description: "A configured fixture role" } },
    mcp_servers: Object.fromEntries(
      (options.mcpServers ?? ["extra-tools"]).map((name) => [
        name,
        { command: "synthetic-extra-tool", enabled: true },
      ]),
    ),
    ...(options.selectedProfile === undefined
      ? {}
      : {
          profile: options.selectedProfile,
          profiles: {
            [options.selectedProfile]: {
              model: "gpt-5.6-sol",
              model_reasoning_effort: "xhigh",
              sandbox_mode: "danger-full-access",
              features: {
                apps: true,
                plugins: true,
                multi_agent_v2: { enabled: true },
              },
              web_search: "live",
            },
          },
        }),
  };
  const originalConfig = `# Fixture config: restore these exact bytes.\n${stringifyToml(effectiveConfig)}`;
  await writeFile(configPath, originalConfig, { mode: 0o600 });
  const commands: Array<readonly string[]> = [];
  const prompts: string[] = [];
  const codexOptions: CodexOptions[] = [];
  const runtimeConfigs: TomlTable[] = [];
  const threadOptions: Record<string, unknown>[] = [];
  const streamOptions: Record<string, unknown>[] = [];
  const inspectionOverrides: Record<string, unknown>[] = [];
  let runtimeCalls = 0;
  let outputCalls = 0;
  const client = new TestClientBase(
    {},
    {
      environment: {},
      prepareRuntime: async () => {
        runtimeCalls += 1;
        return {
          codexHome,
          plugin: {
            pluginRoot: PLUGIN_ROOT,
            marketplaceRoot: PLUGIN_ROOT,
            installedRoot: PLUGIN_ROOT,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {},
          credentialsAvailable: options.credentialsAvailable ?? true,
          effectiveConfig,
        };
      },
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => {
        outputCalls += 1;
        await mkdir(outputDir, { recursive: true, mode: 0o700 });
        return outputDir;
      },
      runWorkbench: async (
        _options: unknown,
        args: readonly string[],
        input?: string,
      ) => {
        if (input !== undefined)
          args = [
            ...args,
            "--recipe-json",
            JSON.stringify(JSON.parse(input).recipe),
          ];
        commands.push(args);
        if (args[0] !== "inspect-cli-dependencies") {
          throw new Error(
            "Calculation must not register or update a cloud scan",
          );
        }
        return { ...mockWorkbench(args), ...inspectionOverrides.shift() };
      },
      createCodex: (configuration: CodexOptions) => {
        codexOptions.push(configuration);
        const effective = { ...configuration.config } as TomlTable;
        for (const override of configuration.configOverrides ?? [])
          Object.assign(effective, parseToml(override));
        runtimeConfigs.push(effective);
        return {
          startThread: (configuration: Record<string, unknown>) => {
            threadOptions.push(configuration);
            return {
              id: null,
              async runStreamed(
                input: string,
                configuration: Record<string, unknown>,
              ) {
                prompts.push(input);
                streamOptions.push(configuration);
                if (options.writeGraph !== false) {
                  await writeFile(dependencyGraphPath, nativeResolverOutput);
                }
                async function* events() {
                  options.beforeEvents?.();
                  for (const event of options.events ?? calculationEvents())
                    yield event;
                }
                return { events: events() };
              },
            };
          },
        };
      },
    },
  );
  return {
    client,
    root,
    repository,
    outputDir,
    dependencyGraphPath,
    configPath,
    originalConfig,
    commands,
    prompts,
    codexOptions,
    runtimeConfigs,
    threadOptions,
    streamOptions,
    inspectionOverrides,
    runtimeCalls: () => runtimeCalls,
    outputCalls: () => outputCalls,
  };
}

const selectedPackage: DependencyIdentity = {
  ecosystem: "npm",
  registry: "https://registry.npmjs.org",
  package: "@example/library",
  oldVersion: null,
  newVersion: "1.2.3",
};

describe("CodexSecurity dependency scan API", () => {
  test.each([1, 20])(
    "preserves %i selected packages in registration, recipe and runtime",
    async (count) => {
      const harness = await createArtifactScanHarness([[]], {
        artifactMode: false,
      });
      const selectedDependencies = Array.from(
        { length: count },
        (_, index) => ({
          ...selectedPackage,
          package: index === 0 ? selectedPackage.package : `package-${index}`,
          newVersion:
            index === 0 ? selectedPackage.newVersion : "2.0.0-beta.1+build.01",
        }),
      );
      const preflight = await harness.client.preflight(harness.repository, {
        scanDependencies: true,
        selectedDependencies,
        target: ["package.json"],
      });
      expect(preflight.selectedDependencies).toEqual(selectedDependencies);
      expect(preflight).not.toHaveProperty("dependencyDepth");
      await expect(
        harness.client.scanDependencies(harness.repository, {
          selectedDependencies,
          target: ["package.json"],
        }),
      ).rejects.toThrow("host preparation observed");
      const registration = harness.commands.find(
        ([command]) => command === "register-cli-scan",
      )!;
      expect(
        JSON.parse(
          registration[registration.indexOf("--selected-dependencies") + 1]!,
        ),
      ).toEqual(selectedDependencies);
      const recipe = JSON.parse(
        registration[registration.indexOf("--recipe-json") + 1]!,
      );
      expect(recipe.selectedDependencies).toEqual(selectedDependencies);
      expect(recipe.dependencyMode).toBe("full_dependency");
      expect(recipe).not.toHaveProperty("dependencyDepth");
      expect(
        JSON.parse(
          harness.scanEnvironments[0]!["CODEX_SECURITY_SELECTED_DEPENDENCIES"]!,
        ),
      ).toEqual(selectedDependencies);
      await harness.client.close();
    },
  );

  test("rejects invalid selections and incompatible scan scopes before starting the runtime", async () => {
    const root = await temporaryDirectory();
    const repository = await gitRepository(root);
    let runtimeCalls = 0;
    const client = new TestClientBase(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeCalls += 1;
          throw new Error("runtime started");
        },
      },
    );
    for (const selectedDependencies of [
      [],
      [selectedPackage, selectedPackage],
      Array.from({ length: 21 }, (_, i) => ({
        ...selectedPackage,
        package: `package-${i}`,
      })),
      [{ ...selectedPackage, ecosystem: "pypi" }],
      [{ ...selectedPackage, registry: "https://private.example" }],
      [{ ...selectedPackage, registry: "https://registry.npmjs.org/" }],
      [{ ...selectedPackage, oldVersion: "1.0.0" }],
      [{ ...selectedPackage, newVersion: "^1.2.3" }],
      [{ ...selectedPackage, newVersion: "1.2.3-01" }],
      [{ ...selectedPackage, newVersion: "1.2.3-alpha.01" }],
      [{ ...selectedPackage, package: "@invalid" }],
    ]) {
      await expect(
        client.scanDependencies(repository, {
          selectedDependencies: selectedDependencies as DependencyIdentity[],
        }),
      ).rejects.toBeInstanceOf(InvalidTargetError);
    }
    for (const target of [
      DiffTarget.refs({ base: "HEAD", head: "HEAD" }),
      DiffTarget.workingTree({ base: "HEAD" }),
    ]) {
      await expect(
        client.scanDependencies(repository, {
          target,
          selectedDependencies: [selectedPackage],
        }),
      ).rejects.toBeInstanceOf(InvalidTargetError);
    }
    await expect(
      client.scanDependencies(repository, {
        dependencyDepth: 1,
        selectedDependencies: [selectedPackage],
      }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    await expect(
      client.run(repository, {
        scanDependencies: true,
        selectedDependencies: [selectedPackage],
      }),
    ).rejects.toBeInstanceOf(InvalidTargetError);
    expect(runtimeCalls).toBe(0);
    await client.close();
  });

  test("persists calculated selectable identities and returns them from the saved graph", async () => {
    const dependencies = [selectedPackage];
    const harness = await createCalculationHarness({
      events: calculationEvents({ depthCounts: [1], dependencies }),
    });
    const result = await harness.client.calculateDependencies(
      harness.repository,
    );
    expect(result.dependencies).toEqual(dependencies);
    expect(
      JSON.parse(
        await readFile(`${result.dependencyGraphPath}.setup.json`, "utf8"),
      ).dependencies,
    ).toEqual(dependencies);
    await expect(
      harness.client.calculateDependencies(harness.repository, {
        dependencyGraphPath: result.dependencyGraphPath,
      }),
    ).resolves.toEqual(result);
    expect(harness.prompts).toHaveLength(1);
    await harness.client.close();
  });

  test("rejects malformed calculation inventories instead of advertising them as selectable", async () => {
    for (const dependencies of [
      null,
      {},
      [selectedPackage, selectedPackage],
      [{ ...selectedPackage, registry: "https://private.example" }],
    ]) {
      const harness = await createCalculationHarness({
        events: calculationEvents({ depthCounts: [1], dependencies }),
      });
      await expect(
        harness.client.calculateDependencies(harness.repository),
      ).rejects.toThrow("invalid selectable dependency inventory");
      await expect(
        readFile(`${harness.dependencyGraphPath}.setup.json`, "utf8"),
      ).rejects.toThrow();
      await harness.client.close();
    }
  });

  test("the native calculation processor exposes only exact public npm artifact identities", async () => {
    const { buildDependencyCalculationPrompt } =
      await import("../../../plugins/codex-security/skills/dependency-resolution/dependency-calculation-prompt.mjs");
    const prompt = buildDependencyCalculationPrompt({
      targetPath: "/fixture",
      setup: {},
    });
    expect(prompt).toContain("npm ls --all --long --json --offline --silent");
    const processor = /node -e '([^']+)'/.exec(prompt)?.[1];
    expect(processor).toBeDefined();
    const result = JSON.parse(
      execFileSync(process.execPath, ["-e", processor!], {
        input: JSON.stringify({
          dependencies: {
            "@example/library": {
              name: "@example/library",
              version: "1.2.3",
              resolved:
                "https://registry.npmjs.org/@example/library/-/library-1.2.3.tgz",
            },
            "local-alias": {
              name: "example-aliased",
              version: "4.5.6",
              resolved:
                "https://registry.npmjs.org/example-aliased/-/example-aliased-4.5.6.tgz",
            },
            "another-alias": {
              name: "example-aliased",
              version: "4.5.6",
              resolved:
                "https://registry.npmjs.org/example-aliased/-/example-aliased-4.5.6.tgz",
            },
            private: {
              version: "2.0.0",
              resolved: "https://private.example/private/-/private-2.0.0.tgz",
            },
            unknown: { version: "3.0.0" },
            alias: {
              version: "1.2.3",
              resolved: "https://registry.npmjs.org/other/-/other-1.2.3.tgz",
            },
          },
        }),
        encoding: "utf8",
        timeout: 10000,
      }),
    );
    expect(result).toEqual({
      depthCounts: [5],
      dependencies: [
        selectedPackage,
        {
          ecosystem: "npm",
          registry: "https://registry.npmjs.org",
          package: "example-aliased",
          oldVersion: null,
          newVersion: "4.5.6",
        },
      ],
    });
  });

  test("rejects Deep dependency scans before preparing runtime", async () => {
    let runtimeInitialized = false;
    const client = new TestClientBase(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeInitialized = true;
          throw new Error("runtime should not initialize");
        },
      },
    );
    const options = { mode: "deep", scanDependencies: true } as const;
    for (const operation of [
      () => client.preflight(".", options),
      () => client.run(".", options),
      () => client.scanDependencies(".", { mode: "deep" }),
    ]) {
      await expect(operation()).rejects.toThrow(
        "Dependency scanning does not support Deep mode",
      );
    }
    expect(runtimeInitialized).toBe(false);
    await client.close();
  });

  test("preflights single, multiple, and file dependency scopes without initializing the runtime", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(join(repository, "packages", "client"), { recursive: true });
    await mkdir(join(repository, "packages", "server"), { recursive: true });
    await writeFile(join(repository, "package.json"), "{}\n");
    await writeFile(
      join(repository, "packages", "server", "package.json"),
      "{}\n",
    );
    const dependencyGraphPath = join(root, "calculated graph.json");
    let runtimeInitialized = false;
    const client = new TestClientBase(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeInitialized = true;
          throw new Error("runtime should not initialize");
        },
      },
    );

    for (const paths of [
      ["packages/client"],
      ["packages/client", "packages/server"],
      ["package.json"],
      ["packages/client", "packages/server/package.json"],
    ]) {
      await expect(
        client.preflight(repository, {
          target: paths,
          scanDependencies: true,
          dependencyGraphPath,
        }),
      ).resolves.toMatchObject({
        repository,
        target: { kind: "paths", paths },
        dependencyDepth: 1,
        dependencyGraphPath,
      });
    }
    await expect(
      client.preflight(repository, {
        target: ["./packages/client", join(repository, "packages", "client")],
        scanDependencies: true,
      }),
    ).resolves.toMatchObject({
      target: { kind: "paths", paths: ["packages/client"] },
    });
    expect(runtimeInitialized).toBe(false);
    await client.close();
  });

  test("preserves path containment for dedicated and combined dependency scans", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const outside = join(root, "outside");
    await mkdir(repository);
    await mkdir(outside);
    await writeFile(join(outside, "package.json"), "{}\n");
    await symlink(
      outside,
      join(repository, "linked-outside"),
      process.platform === "win32" ? "junction" : "dir",
    );
    let runtimeInitialized = false;
    const client = new TestClientBase(
      {},
      {
        environment: {},
        prepareRuntime: async () => {
          runtimeInitialized = true;
          throw new Error("runtime should not initialize");
        },
      },
    );
    for (const target of [
      ["../outside/package.json"],
      ["linked-outside/package.json"],
    ]) {
      await expect(
        client.preflight(repository, { target, scanDependencies: true }),
      ).rejects.toThrow(/outside the repository/i);
      await expect(
        client.run(repository, { target, scanDependencies: true }),
      ).rejects.toThrow(/outside the repository/i);
      await expect(
        client.scanDependencies(repository, { target }),
      ).rejects.toThrow(/outside the repository/i);
    }
    expect(runtimeInitialized).toBe(false);
    await client.close();
  });

  test.each([1, 3, null])(
    "reports dependency depth %p in local-only preflight",
    async (dependencyDepth) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      const client = new TestClientBase({}, { environment: {} });
      await expect(
        client.preflight(repository, {
          scanDependencies: true,
          dependencyDepth,
        }),
      ).resolves.toMatchObject({ dependencyDepth });
      const ordinary = await client.preflight(repository);
      expect(ordinary).not.toHaveProperty("dependencyDepth");
      expect(ordinary).not.toHaveProperty("dependencyGraphPath");
      await client.close();
    },
  );

  test.each([
    0,
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
  ])(
    "rejects invalid dependency depth %p before runtime initialization",
    async (dependencyDepth) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      await mkdir(repository);
      let runtimeInitialized = false;
      const client = new TestClientBase(
        {},
        {
          environment: {},
          prepareRuntime: async () => {
            runtimeInitialized = true;
            throw new Error("runtime should not initialize");
          },
        },
      );
      await expect(
        client.preflight(repository, {
          scanDependencies: true,
          dependencyDepth,
        }),
      ).rejects.toBeInstanceOf(InvalidTargetError);
      await expect(
        client.run(repository, { scanDependencies: true, dependencyDepth }),
      ).rejects.toBeInstanceOf(InvalidTargetError);
      await expect(
        client.scanDependencies(repository, { dependencyDepth }),
      ).rejects.toBeInstanceOf(InvalidTargetError);
      expect(runtimeInitialized).toBe(false);
      await client.close();
    },
  );

  test.each(["dedicated", "combined"] as const)(
    "preserves scoped dependency targets in %s prompts and saved recipes",
    async (mode) => {
      for (const target of [
        ["src"],
        ["src", "package.json"],
        ["package.json"],
      ]) {
        const { client, repository, commands, prompts, targetPathSnapshots } =
          await createArtifactScanHarness([[]], { artifactMode: false });
        await mkdir(join(repository, "src"));
        await writeFile(
          join(repository, "src", "index.js"),
          "export const value = 1;\n",
        );
        const options = {
          target,
          dependencyDepth: null,
          dependencyScanTarget: "malware" as const,
        };
        await expect(
          mode === "dedicated"
            ? client.scanDependencies(repository, options)
            : client.run(repository, { ...options, scanDependencies: true }),
        ).rejects.toThrow("host preparation observed");
        const registration =
          commands.find(([command]) => command === "register-cli-scan") ?? [];
        expect(
          registration[registration.indexOf("--dependency-depth") + 1],
        ).toBe("all");
        const recipe = JSON.parse(
          registration[registration.indexOf("--recipe-json") + 1] ?? "null",
        );
        expect(recipe).toMatchObject({
          scanDependencies: true,
          target: { kind: "paths", paths: target },
          dependencyDepth: null,
          dependencyScanTarget: "malware",
        });
        expect(recipe).not.toHaveProperty("dependencyGraphPath");
        if (mode === "dedicated") {
          expect(recipe.dependencyMode).toBe("full_dependency");
          expect(
            registration[registration.indexOf("--dependency-mode") + 1],
          ).toBe("full_dependency");
        } else {
          expect(recipe).not.toHaveProperty("dependencyMode");
          expect(registration).toContain("--scan-dependencies");
        }
        expect(prompts[0]).toContain("$codex-security:dependency-update-scan");
        expect(prompts[0]).toContain("CODEX_SECURITY_TARGET_PATHS_FILE");
        expect(targetPathSnapshots).toEqual([target]);
        await client.close();
      }
    },
  );

  test("rejects recursive dependency scans before authentication or runtime initialization", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository-that-must-not-be-read");
    const target = DiffTarget.refs({ base: "HEAD" });
    let runtimeInitialized = false;
    const client = new TestClientBase(
      {},
      {
        environment: {
          CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN: "1",
          OPENAI_API_KEY: "synthetic-artifact-service-key",
        },
        prepareRuntime: async () => {
          runtimeInitialized = true;
          throw new Error("runtime should not initialize");
        },
      },
    );

    await expect(
      client.run(repository, { target, scanDependencies: true }),
    ).rejects.toThrow(/recursive dependency scanning is disabled/i);
    await expect(
      client.preflight(repository, { target, scanDependencies: true }),
    ).rejects.toThrow(/recursive dependency scanning is disabled/i);
    await expect(
      client.scanDependencies(repository, { target }),
    ).rejects.toThrow(/recursive dependency scanning is disabled/i);

    expect(runtimeInitialized).toBe(false);
    await client.close();
  });

  test("keeps ordinary diff scans unchanged and selects combined or dedicated dependency skills", async () => {
    const root = await temporaryDirectory();
    const repository = await gitRepository(root);
    const codexHome = join(root, "codex-home");
    const pluginRoot = join(root, "plugin");
    const scanDir = join(root, "scan");
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    for (const skill of [
      "security-diff-scan",
      "security-scan",
      "dependency-update-scan",
    ]) {
      const directory = join(pluginRoot, "skills", skill);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "SKILL.md"), `# ${skill}\n`);
    }

    let prompt = "";
    let codexEnvironment: Record<string, string> = {};
    const registrationArguments: Array<readonly string[]> = [];
    const environment: Record<string, string> = {};
    const client = new TestClientBase(
      {},
      {
        environment,
        prepareRuntime: async () => ({
          codexHome,
          plugin: {
            pluginRoot,
            marketplaceRoot: pluginRoot,
            installedRoot: pluginRoot,
            marketplaceName: "codex-security-sdk",
            name: "codex-security",
            version: "0.1.0",
          },
          environment: {},
          credentialsAvailable: true,
        }),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (
          _options: unknown,
          args: readonly string[],
          input?: string,
        ) => {
          if (input !== undefined)
            args = [
              ...args,
              "--recipe-json",
              JSON.stringify(JSON.parse(input).recipe),
            ];
          if (args[0] === "register-cli-scan") registrationArguments.push(args);
          return mockWorkbench(args);
        },
        createCodex: (options: CodexOptions) => {
          codexEnvironment = options.env ?? {};
          return {
            startThread: () => ({
              id: null,
              async runStreamed(input: string) {
                prompt = input;
                throw new Error("prompt captured");
              },
            }),
          };
        },
      },
    );
    const target = DiffTarget.refs({ base: "HEAD" });

    await expect(client.run(repository, { target })).rejects.toThrow(
      "prompt captured",
    );
    expect(prompt).toContain("$codex-security:security-diff-scan");
    expect(prompt).not.toContain("$codex-security:dependency-update-scan");
    expect(prompt).not.toContain("published dependency artifact scan");
    expect(prompt).toContain(
      "Use record_codex_security_scan_draft and complete_codex_security_scan",
    );
    expect(prompt).toContain(
      "This exhaustive scan authorizes the delegated-worker phases",
    );
    expect(prompt).toContain("Every delegated review assignment must say:");
    expect(codexEnvironment).not.toHaveProperty(
      "CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS",
    );
    expect(registrationArguments.at(-1)).not.toContain("--dependency-mode");
    expect(registrationArguments.at(-1)).not.toContain("--scan-dependencies");
    expect(registrationArguments.at(-1)).not.toContain(
      "--dependency-scan-target",
    );

    await expect(
      client.run(repository, {
        target,
        scanDependencies: true,
        dependencyScanTarget: "malware-and-vulnerabilities",
      }),
    ).rejects.toThrow("prompt captured");
    expect(prompt).toContain("$codex-security:security-diff-scan");
    expect(prompt).toContain("$codex-security:dependency-update-scan");
    expect(prompt).toContain("before finalization");
    expect(prompt).toContain("no first-party candidates");
    expect(prompt).toContain(
      "This exhaustive scan authorizes the delegated-worker phases",
    );
    expect(prompt).toContain("Every delegated review assignment must say:");
    const combinedRegistration = registrationArguments.at(-1) ?? [];
    expect(combinedRegistration).toContain("--scan-dependencies");
    expect(combinedRegistration).not.toContain("--dependency-mode");
    expect(
      combinedRegistration[
        combinedRegistration.indexOf("--dependency-scan-target") + 1
      ],
    ).toBe("malware-and-vulnerabilities");

    await expect(
      client.run(repository, { scanDependencies: true }),
    ).rejects.toThrow("prompt captured");
    expect(prompt).toContain("$codex-security:security-scan");
    expect(prompt).toContain("$codex-security:dependency-update-scan");
    expect(prompt).not.toContain("Inspect the original Git diff");
    expect(registrationArguments.at(-1)).toContain("--scan-dependencies");

    await expect(client.scanDependencies(repository, {})).rejects.toThrow(
      "prompt captured",
    );
    expect(prompt).toContain("$codex-security:dependency-update-scan");
    expect(prompt).not.toContain("$codex-security:security-scan");
    expect(prompt).toContain("all current dependencies");
    const fullRegistration = registrationArguments.at(-1) ?? [];
    expect(
      fullRegistration[fullRegistration.indexOf("--dependency-mode") + 1],
    ).toBe("full_dependency");
    expect(fullRegistration).not.toContain("--dependency-scan-target");
    expect(
      JSON.parse(
        fullRegistration[fullRegistration.indexOf("--recipe-json") + 1] ??
          "null",
      ),
    ).toMatchObject({
      scanDependencies: true,
      dependencyMode: "full_dependency",
      dependencyDepth: 1,
      dependencyScanTarget: "malware-and-vulnerabilities",
      target: { kind: "repository", paths: [] },
    });

    const dependencyModelSettings = {
      acquisition: { model: "gpt-5.6-luna", reasoningEffort: "low" },
      scan: { model: "gpt-5.6-luna", reasoningEffort: "xhigh" },
      verification: { model: "gpt-5.6-sol", reasoningEffort: "high" },
      history: { model: "gpt-5.6-terra", reasoningEffort: "medium" },
    } as const;
    await expect(
      client.scanDependencies(repository, {
        target,
        dependencyDepth: 3,
        dependencyScanTarget: "malware",
        dependencyModelSettings,
      }),
    ).rejects.toThrow("prompt captured");
    expect(
      JSON.parse(
        codexEnvironment["CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS"] ?? "null",
      ),
    ).toEqual(dependencyModelSettings);
    const updateRegistration = registrationArguments.at(-1) ?? [];
    expect(
      updateRegistration[updateRegistration.indexOf("--dependency-mode") + 1],
    ).toBe("dependency_update");
    expect(
      updateRegistration[
        updateRegistration.indexOf("--dependency-scan-target") + 1
      ],
    ).toBe("malware");
    expect(
      updateRegistration[updateRegistration.indexOf("--dependency-depth") + 1],
    ).toBe("3");
    expect(
      JSON.parse(
        updateRegistration[updateRegistration.indexOf("--recipe-json") + 1] ??
          "null",
      ),
    ).toMatchObject({
      scanDependencies: true,
      dependencyMode: "dependency_update",
      dependencyDepth: 3,
      dependencyScanTarget: "malware",
      dependencyModelSettings,
    });
    expect(
      JSON.parse(
        updateRegistration[
          updateRegistration.indexOf("--model-settings") + 1
        ] ?? "null",
      ),
    ).toEqual(dependencyModelSettings);
    const mcpConfiguration = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
    ) as { mcpServers: Record<string, { env_vars: string[] }> };
    expect(mcpConfiguration.mcpServers["codex-security"]?.env_vars).toContain(
      "CODEX_SECURITY_DEPENDENCY_MODEL_SETTINGS",
    );

    let authenticationCallbacks = 0;
    await expect(
      client.scanDependencies(repository, {
        target,
        auth: "chatgpt",
        onAuthentication: () => {
          authenticationCallbacks += 1;
        },
      }),
    ).rejects.toThrow("prompt captured");
    expect(prompt).toContain("$codex-security:dependency-update-scan");
    expect(prompt).not.toContain("$codex-security:security-diff-scan");
    expect(prompt).toContain("directly in the parent agent");
    expect(prompt).toContain("Do not spawn local subagents");
    expect(prompt).toContain("existing Workbench MCP tools");
    expect(prompt).toContain("workers own concurrent artifact scans");
    expect(prompt).not.toContain("This exhaustive scan authorizes");
    expect(prompt).not.toContain("Every delegated review assignment");
    expect(prompt).not.toContain("After the file inventory");
    expect(authenticationCallbacks).toBe(1);

    await expect(
      client.scanDependencies(repository, {
        target: DiffTarget.workingTree({ base: "HEAD" }),
      }),
    ).rejects.toThrow("prompt captured");
    expect(prompt).toContain("$codex-security:dependency-update-scan");
    expect(prompt).toContain("working-tree changes");
    expect(prompt).toContain("Do not spawn local subagents");
    expect(prompt).not.toContain("This exhaustive scan authorizes");

    environment["CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN"] = "1";
    await expect(client.run(repository, { target })).rejects.toThrow(
      "prompt captured",
    );
    expect(prompt).toContain("$codex-security:security-diff-scan");
    expect(prompt).not.toContain("$codex-security:dependency-update-scan");
    expect(prompt).toContain("This is a published dependency artifact scan");
    expect(prompt).toContain("Never invoke the dependency-update-scan skill");
    expect(prompt).toContain("Never submit cloud dependency scan jobs");
    expect(prompt).toContain(
      "Never reconstruct the artifact's own dependency graph",
    );
    expect(prompt).toContain(
      "Scan only the current published artifact contents",
    );
    expect(
      prompt.match(/record_codex_security_dependency_artifact_result/g),
    ).toHaveLength(1);
    expect(prompt).toContain('"scanId":"$CODEX_SECURITY_SCAN_ID"');
    expect(prompt).toContain('"findings":[]');
    expect(prompt).toContain("exactly one successful");
    expect(prompt).toContain("only if the artifact is genuinely clean");
    expect(prompt).toContain("correct its arguments and retry");
    expect(prompt).toContain("Do not end your turn before the tool accepts");
    expect(prompt).not.toContain("introductionProbe");
    expect(prompt).not.toContain("vulnerableCode");
    expect(prompt).not.toContain("safeCode");
    expect(prompt).toContain("Do not finalize or complete the scan");
    expect(prompt).not.toContain("Write the complete canonical");
    expect(prompt).not.toContain("priorFindingAssessments");

    const priorFindings = join(root, "prior-findings.md");
    await writeFile(
      priorFindings,
      "# Prior findings\n- upstreamFindingId: upstream_fixture\n",
    );
    await expect(
      client.run(repository, {
        target,
        knowledgeBasePaths: [priorFindings],
      }),
    ).rejects.toThrow("prompt captured");
    expect(prompt).toContain('"$CODEX_SECURITY_KNOWLEDGE_BASE"');
    expect(prompt).toContain("Read every seeded prior finding");
    expect(prompt).toContain('"priorFindingAssessments"');
    expect(prompt).toContain("same semantic result call");
    expect(prompt).toContain('"upstreamFindingId"');
    expect(prompt).toContain('"present", "fixed", or "unknown"');
    expect(prompt).toContain('specific "reason"');
    expect(prompt).toContain('optional "evidence"');
    expect(prompt).toContain("same canonical code-evidence shape");
    expect(prompt).toContain(
      '"unknown" only after investigating and being unable to establish either status',
    );
    expect(prompt).toContain("Never skip a seeded prior finding");
    expect(prompt).not.toContain("not_checked");
    expect(prompt).toContain("submit a separate assessment call");
    expect(
      prompt.match(/record_codex_security_dependency_artifact_result/g),
    ).toHaveLength(1);
    await client.close();
  });

  test("rejects API-key authentication for cloud dependency scans", async () => {
    const root = await temporaryDirectory();
    const repository = await gitRepository(root);
    let runtimeInitialized = false;
    const client = new TestClientBase(
      {},
      {
        environment: { OPENAI_API_KEY: "synthetic-api-key" },
        prepareRuntime: async () => {
          runtimeInitialized = true;
          throw new Error("runtime should not initialize");
        },
      },
    );

    await expect(
      client.run(repository, {
        target: DiffTarget.refs({ base: "HEAD" }),
        scanDependencies: true,
      }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
    expect(runtimeInitialized).toBe(false);
    await client.close();
  });

  test("advances artifact scans to reporting before host-owned completion", async () => {
    const { client, repository, commands, prompts, threadsStarted } =
      await createArtifactScanHarness([[dependencyArtifactResultEvent()]]);

    await expect(
      client.run(repository, { target: DiffTarget.refs({ base: "HEAD" }) }),
    ).rejects.toThrow("host preparation observed");
    expect(commands.map(([command]) => command)).toEqual([
      "register-cli-scan",
      "get-scan-feedback",
      "set-scan-thread",
      "update-progress",
      "prepare-scan-completion",
      "get-scan",
      "fail-scan",
    ]);
    expect(commands[3]).toEqual([
      "update-progress",
      "--scan-id",
      "scan_dependency_fixture",
      "--phase",
      "reporting",
    ]);
    expect(prompts).toHaveLength(1);
    expect(threadsStarted()).toBe(1);
    await client.close();
  });

  test("enforces the cost limit before correcting an unrecorded artifact result", async () => {
    const { client, repository, prompts } = await createArtifactScanHarness([
      [],
      [dependencyArtifactResultEvent()],
    ]);
    await expect(
      client.run(repository, { maxCostUsd: 0.00000001 }),
    ).rejects.toThrow(/exceeded.*limit/i);
    expect(prompts).toHaveLength(1);
    await client.close();
  });

  test("accepts a genuine clean artifact result without resuming the scanner", async () => {
    const { client, repository, prompts, threadsStarted } =
      await createArtifactScanHarness([
        [dependencyArtifactResultEvent({ findingsRecorded: 0 })],
      ]);

    await expect(
      client.run(repository, { target: DiffTarget.refs({ base: "HEAD" }) }),
    ).rejects.toThrow("host preparation observed");
    expect(prompts).toHaveLength(1);
    expect(threadsStarted()).toBe(1);
    await client.close();
  });

  test.each<[string, Record<string, unknown>[]]>([
    ["no semantic result", []],
    [
      "a rejected semantic result",
      [
        dependencyArtifactResultEvent({
          toolStatus: "failed",
          error: "The source evidence does not match the published file.",
        }),
      ],
    ],
    [
      "a failed semantic result with structured content",
      [dependencyArtifactResultEvent({ toolStatus: "failed" })],
    ],
    [
      "a semantic result without its structured receipt",
      [dependencyArtifactResultEvent({ structuredResult: false })],
    ],
    [
      "a result belonging to a different scan",
      [dependencyArtifactResultEvent({ scanId: "different_scan" })],
    ],
    [
      "a result from another MCP server",
      [dependencyArtifactResultEvent({ server: "codex_security" })],
    ],
    [
      "a result without its existing recorded status",
      [dependencyArtifactResultEvent({ status: "pending" })],
    ],
    [
      "a result without its existing replace operation",
      [dependencyArtifactResultEvent({ operation: "append" })],
    ],
  ])(
    "continues the same artifact scanner until a trusted result is accepted (%s)",
    async (description, firstTurn) => {
      const { client, repository, commands, prompts, threadsStarted } =
        await createArtifactScanHarness([
          firstTurn,
          [dependencyArtifactResultEvent()],
        ]);
      await expect(
        client.run(repository, { target: DiffTarget.refs({ base: "HEAD" }) }),
      ).rejects.toThrow("host preparation observed");

      expect(prompts, description).toHaveLength(2);
      expect(threadsStarted(), description).toBe(1);
      expect(prompts[1], description).toContain(
        "record_codex_security_dependency_artifact_result",
      );
      expect(prompts[1], description).toContain("already-reviewed");
      expect(prompts[1], description).toContain("every genuine finding");
      expect(prompts[1], description).toContain("Do not restart analysis");
      expect(prompts[1], description).toContain("Do not create or complete");
      expect(
        commands.filter(([command]) => command === "prepare-scan-completion"),
        description,
      ).toHaveLength(1);
      if (description === "a rejected semantic result") {
        expect(prompts[1]).toContain(
          "The source evidence does not match the published file.",
        );
      }
      await client.close();
    },
  );

  test("keeps correcting the same artifact turn without an invented retry cap", async () => {
    const { client, repository, prompts, threadsStarted } =
      await createArtifactScanHarness([
        [],
        [dependencyArtifactResultEvent({ toolStatus: "failed" })],
        [dependencyArtifactResultEvent({ scanId: "different_scan" })],
        [dependencyArtifactResultEvent()],
      ]);

    await expect(
      client.run(repository, { target: DiffTarget.refs({ base: "HEAD" }) }),
    ).rejects.toThrow("host preparation observed");
    expect(prompts).toHaveLength(4);
    expect(threadsStarted()).toBe(1);
    await client.close();
  });

  test("does not require dependency result submission outside artifact mode", async () => {
    const { client, repository, prompts, commands } =
      await createArtifactScanHarness([[]], { artifactMode: false });

    await expect(
      client.run(repository, { target: DiffTarget.refs({ base: "HEAD" }) }),
    ).rejects.toThrow("host preparation observed");
    expect(prompts).toHaveLength(1);
    expect(commands.map(([command]) => command)).toEqual([
      "register-cli-scan",
      "get-scan-feedback",
      "set-scan-thread",
      "prepare-scan-completion",
      "get-scan",
      "fail-scan",
    ]);
    await client.close();
  });

  test("honors cancellation before resuming an unfinished artifact turn", async () => {
    const controller = new AbortController();
    const { client, repository, prompts } = await createArtifactScanHarness(
      [[]],
      { cancelAfterTurn: controller },
    );

    await expect(
      client.run(repository, {
        target: DiffTarget.refs({ base: "HEAD" }),
        signal: controller.signal,
      }),
    ).rejects.toThrow(/interrupted/i);
    expect(prompts).toHaveLength(1);
    await client.close();
  });

  describe("dependency calculation", () => {
    test.each(["repository", "paths", "refs", "working_tree"] as const)(
      "calculates %s dependencies locally and saves raw output with its exact snapshot",
      async (kind) => {
        const harness = await createCalculationHarness();
        const { client, repository, outputDir, dependencyGraphPath } = harness;
        await mkdir(join(repository, "src"));
        const target: ScanTarget =
          kind === "paths"
            ? ["src", "package.json"]
            : kind === "refs"
              ? DiffTarget.refs({ base: "HEAD" })
              : kind === "working_tree"
                ? DiffTarget.workingTree({ base: "HEAD" })
                : "repository";
        const ready: string[] = [];
        const authentications: unknown[] = [];
        const activities: unknown[] = [];
        const costs: unknown[] = [];
        const result = await client.calculateDependencies(repository, {
          target,
          onOutputDirReady: (path) => ready.push(path),
          onAuthentication: (authentication) =>
            authentications.push(authentication),
          onActivity: (activity) => activities.push(activity),
          onCost: (cost) => costs.push(cost),
          maxCostUsd: 1,
        });
        expect(result).toEqual({ depthCounts: [2, 1], dependencyGraphPath });
        expect(await readFile(dependencyGraphPath, "utf8")).toBe(
          nativeResolverOutput,
        );
        expect(harness.commands.map(([command]) => command)).toEqual([
          "inspect-cli-dependencies",
          "inspect-cli-dependencies",
        ]);
        expect(harness.commands[0]).toEqual(harness.commands[1]);
        const recipe = JSON.parse(
          harness.commands[0]?.[
            harness.commands[0].indexOf("--recipe-json") + 1
          ] ?? "null",
        );
        const normalizedTarget = {
          kind,
          paths: [...recipe.target.paths].sort(),
          ...(recipe.target.base === undefined
            ? {}
            : { base: recipe.target.base }),
          ...(recipe.target.head === undefined
            ? {}
            : { head: recipe.target.head }),
        };
        expect(
          JSON.parse(
            await readFile(`${dependencyGraphPath}.setup.json`, "utf8"),
          ),
        ).toEqual({
          repository,
          target: normalizedTarget,
          targetRevision: "deadbeef",
          snapshotDigest: null,
          depthCounts: [2, 1],
        });
        const configuration = harness.runtimeConfigs[0];
        expect(configuration).toMatchObject({
          model: "gpt-5.6-luna",
          model_reasoning_effort: "low",
          default_permissions: "codex_security_dependency_calculation",
          permissions: {
            codex_security_dependency_calculation: {
              filesystem: { ":root": "read", ":workspace_roots": "write" },
              network: { enabled: false },
            },
          },
          features: {
            apps: false,
            plugins: false,
            multi_agent: false,
            multi_agent_v2: { enabled: false },
          },
          agents: { fixture: { description: "A configured fixture role" } },
          mcp_servers: { "codex-security": { enabled: false } },
          web_search: "disabled",
        });
        expect(configuration?.["agents"]).not.toHaveProperty("enabled");
        expect(harness.threadOptions).toEqual([
          {
            threadSource: "security_scan",
            workingDirectory: outputDir,
            skipGitRepoCheck: true,
            approvalPolicy: "on-request",
          },
        ]);
        expect(harness.streamOptions[0]).not.toHaveProperty("outputSchema");
        expect(harness.prompts).toHaveLength(1);
        expect(harness.prompts[0]).toContain(JSON.stringify(repository));
        expect(harness.prompts[0]).toContain(
          JSON.stringify(dependencyGraphPath),
        );
        expect(harness.prompts[0]).toContain(
          JSON.stringify(kind === "paths" ? ["package.json", "src"] : ["."]),
        );
        if (kind === "refs" || kind === "working_tree") {
          expect(harness.prompts[0]).toContain('"mode":"dependency_update"');
          expect(harness.prompts[0]).toContain(recipe.target.base);
          expect(harness.prompts[0]).toContain(recipe.target.head);
        }
        expect(ready).toEqual([outputDir]);
        expect(authentications).toHaveLength(1);
        expect(activities.length).toBeGreaterThan(0);
        expect(costs.length).toBeGreaterThan(0);
        expect(await readFile(harness.configPath, "utf8")).toBe(
          harness.originalConfig,
        );
        await client.close();
      },
    );

    test("preserves explicit model settings even with a selected scan profile", async () => {
      const harness = await createCalculationHarness({
        selectedProfile: "selected",
      });
      await harness.client.calculateDependencies(harness.repository, {
        model: "gpt-5.6-terra",
        reasoningEffort: "high",
      });
      expect(harness.runtimeConfigs[0]).toMatchObject({
        model: "gpt-5.6-terra",
        model_reasoning_effort: "high",
        mcp_servers: {
          "codex-security": { enabled: false },
          "extra-tools": { enabled: false },
        },
      });
      expect(harness.runtimeConfigs[0]).not.toHaveProperty("sandbox_mode");
      expect(await readFile(harness.configPath, "utf8")).toBe(
        harness.originalConfig,
      );
      await harness.client.close();
    });

    test.each(["fixture.profile", "fixture profile", 'fixture"profile'])(
      "preserves literal MCP and profile names in calculator config (%s)",
      async (selectedProfile) => {
        const mcpServers = [
          "extra-tools",
          "fixture.tools",
          "fixture tools",
          'fixture"tools',
        ];
        const harness = await createCalculationHarness({
          selectedProfile,
          mcpServers,
        });
        await harness.client.calculateDependencies(harness.repository);
        const runtimeConfig = harness.runtimeConfigs[0]!;
        const servers = runtimeConfig["mcp_servers"] as Record<string, unknown>;
        expect(Object.keys(servers).sort()).toEqual(
          [...mcpServers, "codex-security"].sort(),
        );
        for (const name of mcpServers) {
          expect(servers[name]).toMatchObject({ enabled: false });
        }
        expect(runtimeConfig).toMatchObject({
          model: "gpt-5.6-luna",
          model_reasoning_effort: "low",
        });
        expect(runtimeConfig).not.toHaveProperty("profiles");
        expect(runtimeConfig).not.toHaveProperty("sandbox_mode");
        expect(harness.codexOptions[0]?.config ?? {}).not.toHaveProperty(
          "mcp_servers",
        );
        expect(harness.codexOptions[0]?.config ?? {}).not.toHaveProperty(
          "profiles",
        );
        expect(await readFile(harness.configPath, "utf8")).toBe(
          harness.originalConfig,
        );
        await harness.client.close();
      },
    );

    test("returns matching saved counts before authentication, model execution, or output allocation", async () => {
      const harness = await createCalculationHarness({
        credentialsAvailable: false,
      });
      const { client, repository, root } = harness;
      await mkdir(join(repository, "src"));
      const dependencyGraphPath = join(root, "saved graph.json");
      await writeFile(dependencyGraphPath, nativeResolverOutput);
      await writeFile(
        `${dependencyGraphPath}.setup.json`,
        JSON.stringify({
          repository,
          target: { kind: "paths", paths: ["src", "package.json", "src"] },
          targetRevision: "deadbeef",
          snapshotDigest: null,
          depthCounts: [2, 1],
        }),
      );
      let authenticated = false;
      await expect(
        client.calculateDependencies(repository, {
          target: ["package.json", "./src"],
          dependencyGraphPath,
          onAuthentication: () => {
            authenticated = true;
          },
        }),
      ).resolves.toEqual({ depthCounts: [2, 1], dependencyGraphPath });
      expect(authenticated).toBe(false);
      expect(harness.codexOptions).toEqual([]);
      expect(harness.outputCalls()).toBe(0);
      expect(harness.commands.map(([command]) => command)).toEqual([
        "inspect-cli-dependencies",
      ]);
      expect(await readFile(harness.configPath, "utf8")).toBe(
        harness.originalConfig,
      );
      await client.close();
    });

    test("warns and recalculates when a saved graph belongs to an older snapshot", async () => {
      const harness = await createCalculationHarness();
      const saved = join(harness.root, "saved.json");
      await writeFile(saved, nativeResolverOutput);
      await writeFile(
        `${saved}.setup.json`,
        JSON.stringify({
          repository: harness.repository,
          target: { kind: "repository", paths: [] },
          targetRevision: "previous-revision",
          snapshotDigest: null,
          depthCounts: [99],
        }),
      );
      const warnings: string[] = [];
      await expect(
        harness.client.calculateDependencies(harness.repository, {
          dependencyGraphPath: saved,
          onWarning: (warning) => warnings.push(warning),
        }),
      ).resolves.toEqual({
        depthCounts: [2, 1],
        dependencyGraphPath: harness.dependencyGraphPath,
      });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("calculating dependencies again");
      expect(harness.prompts).toHaveLength(1);
      expect(
        JSON.parse(await readFile(`${saved}.setup.json`, "utf8")).depthCounts,
      ).toEqual([99]);
      await harness.client.close();
    });

    test("does not mark a graph reusable if the target changes during calculation", async () => {
      const harness = await createCalculationHarness();
      harness.inspectionOverrides.push(
        {},
        { snapshotDigest: "changed-snapshot" },
      );
      const warnings: string[] = [];
      const warningDetails: unknown[] = [];
      await expect(
        harness.client.calculateDependencies(harness.repository, {
          onWarning: (warning, details) => {
            warnings.push(warning);
            warningDetails.push(details);
          },
        }),
      ).resolves.toEqual({
        depthCounts: [2, 1],
        dependencyGraphPath: harness.dependencyGraphPath,
      });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("target changed during calculation");
      expect(warningDetails).toEqual([{ kind: "target_changed" }]);
      await expect(
        readFile(`${harness.dependencyGraphPath}.setup.json`),
      ).rejects.toMatchObject({ code: "ENOENT" });
      await harness.client.close();
    });

    test.each([
      [
        "failed turn",
        [
          {
            type: "turn.failed",
            error: { message: "synthetic calculation failure" },
          },
        ],
      ],
      [
        "incomplete turn",
        calculationEvents().filter(
          (event) => event["type"] !== "turn.completed",
        ),
      ],
      [
        "invalid JSON",
        [
          {
            type: "item.completed",
            item: { type: "agent_message", text: "not-json" },
          },
          { type: "turn.completed" },
        ],
      ],
      ["negative counts", calculationEvents({ depthCounts: [-1] })],
      ["fractional counts", calculationEvents({ depthCounts: [1.5] })],
      ["nonnumeric counts", calculationEvents({ depthCounts: ["2"] })],
    ] as const)("does not cache %s", async (_description, events) => {
      const harness = await createCalculationHarness({ events });
      await expect(
        harness.client.calculateDependencies(harness.repository),
      ).rejects.toThrow();
      await expect(
        readFile(`${harness.dependencyGraphPath}.setup.json`),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(harness.commands.map(([command]) => command)).toEqual([
        "inspect-cli-dependencies",
      ]);
      expect(await readFile(harness.configPath, "utf8")).toBe(
        harness.originalConfig,
      );
      await harness.client.close();
    });

    test("preserves a descriptive native-resolution-unavailable result", async () => {
      const message =
        "Dependency estimation unavailable: the native resolver is unavailable offline.";
      const harness = await createCalculationHarness({
        events: [
          {
            type: "item.completed",
            item: { type: "agent_message", text: message },
          },
          { type: "turn.completed" },
        ],
      });
      await expect(
        harness.client.calculateDependencies(harness.repository),
      ).rejects.toThrow(message);
      await expect(
        readFile(`${harness.dependencyGraphPath}.setup.json`),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(harness.commands).toHaveLength(1);
      expect(await readFile(harness.configPath, "utf8")).toBe(
        harness.originalConfig,
      );
      await harness.client.close();
    });

    test.each([false, true])(
      "requires the native graph file, including a changed target (%p)",
      async (changed) => {
        const harness = await createCalculationHarness({ writeGraph: false });
        if (changed)
          harness.inspectionOverrides.push(
            {},
            { snapshotDigest: "changed-snapshot" },
          );
        await expect(
          harness.client.calculateDependencies(harness.repository),
        ).rejects.toThrow();
        await expect(
          readFile(`${harness.dependencyGraphPath}.setup.json`),
        ).rejects.toMatchObject({ code: "ENOENT" });
        expect(await readFile(harness.configPath, "utf8")).toBe(
          harness.originalConfig,
        );
        await harness.client.close();
      },
    );

    test("preserves cancellation without saving a reusable graph", async () => {
      const controller = new AbortController();
      const harness = await createCalculationHarness({
        beforeEvents: () => controller.abort(),
      });
      await expect(
        harness.client.calculateDependencies(harness.repository, {
          signal: controller.signal,
        }),
      ).rejects.toThrow(/interrupted/i);
      await expect(
        readFile(`${harness.dependencyGraphPath}.setup.json`),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(harness.commands).toHaveLength(1);
      expect(await readFile(harness.configPath, "utf8")).toBe(
        harness.originalConfig,
      );
      await harness.client.close();
    });

    test("reports observer errors without discarding a valid calculation", async () => {
      const harness = await createCalculationHarness();
      const errors: string[] = [];
      await expect(
        harness.client.calculateDependencies(harness.repository, {
          onActivity: () => {
            throw new Error("synthetic observer failure");
          },
          onObserverError: (observer) => errors.push(observer),
        }),
      ).resolves.toEqual({
        depthCounts: [2, 1],
        dependencyGraphPath: harness.dependencyGraphPath,
      });
      expect(errors).toContain("onActivity");
      await harness.client.close();
    });
  });

  describe("saved dependency graph reuse", () => {
    test("associates saved output with the authoritative registration snapshot", async () => {
      const baseRevision = "registered-base";
      const headRevision = "registered-head";
      const targetRevision = "registered-revision";
      const snapshotDigest = "registered-working-tree-content";
      const harness = await createArtifactScanHarness([[]], {
        artifactMode: false,
        registration: {
          targetRevision,
          contract: {
            target: { allowedKinds: ["git_diff"] },
            scope: { requiredIncludePaths: [] },
            diffTarget: {
              baseRevision,
              headRevision,
              contentDigest: snapshotDigest,
            },
          },
        },
      });
      const saved = join(await temporaryDirectory(), "registered graph.json");
      await writeFile(saved, nativeResolverOutput);
      await writeFile(
        `${saved}.setup.json`,
        JSON.stringify({
          repository: harness.repository,
          target: {
            kind: "working_tree",
            paths: [],
            base: baseRevision,
            head: headRevision,
          },
          targetRevision,
          snapshotDigest,
          depthCounts: [2, 1],
        }),
      );
      const warnings: string[] = [];
      await expect(
        harness.client.scanDependencies(harness.repository, {
          target: DiffTarget.workingTree({ base: "HEAD" }),
          dependencyGraphPath: saved,
          onWarning: (warning) => warnings.push(warning),
        }),
      ).rejects.toThrow("host preparation observed");
      expect(warnings).toEqual([]);
      expect(
        await readFile(
          join(
            harness.scanDir,
            "artifacts",
            "02_discovery",
            "dependency-update-scan",
            "dependency-resolver-output.json",
          ),
          "utf8",
        ),
      ).toBe(nativeResolverOutput);
      expect(harness.prompts[0]).toContain(
        "The SDK staged saved native resolver output",
      );
      expect(
        harness.commands.some(
          ([command]) => command === "inspect-cli-dependencies",
        ),
      ).toBe(false);
      await harness.client.close();
    });

    test.each([
      ["dedicated", "repository"],
      ["dedicated", "paths"],
      ["dedicated", "refs"],
      ["dedicated", "working_tree"],
      ["combined", "paths"],
    ] as const)(
      "stages matching native output for %s %s scans",
      async (mode, kind) => {
        const harness = await createArtifactScanHarness([[]], {
          artifactMode: false,
        });
        const { client, repository, scanDir } = harness;
        await mkdir(join(repository, "src"));
        const target: ScanTarget =
          kind === "paths"
            ? ["./src", "package.json", "src"]
            : kind === "refs"
              ? DiffTarget.refs({ base: "HEAD" })
              : kind === "working_tree"
                ? DiffTarget.workingTree({ base: "HEAD" })
                : "repository";
        const preflight = await client.preflight(repository, {
          target,
          scanDependencies: true,
        });
        const saved = join(await temporaryDirectory(), "saved graph.json");
        await writeFile(saved, nativeResolverOutput);
        await writeFile(
          `${saved}.setup.json`,
          JSON.stringify({
            repository,
            target: preflight.target,
            targetRevision: "deadbeef",
            snapshotDigest: null,
            depthCounts: [2, 1],
          }),
        );
        const warnings: string[] = [];
        const options = {
          target,
          dependencyGraphPath: saved,
          onWarning: (warning: string) => warnings.push(warning),
        };
        await expect(
          mode === "dedicated"
            ? client.scanDependencies(repository, options)
            : client.run(repository, { ...options, scanDependencies: true }),
        ).rejects.toThrow("host preparation observed");
        const staged = join(
          scanDir,
          "artifacts",
          "02_discovery",
          "dependency-update-scan",
          "dependency-resolver-output.json",
        );
        expect(await readFile(staged, "utf8")).toBe(nativeResolverOutput);
        expect(warnings).toEqual([]);
        expect(harness.prompts[0]).toContain(
          "The SDK staged saved native resolver output",
        );
        expect(harness.prompts[0]).toContain("do not rerun covered ecosystems");
        expect(
          harness.commands.some(
            ([command]) => command === "inspect-cli-dependencies",
          ),
        ).toBe(false);
        const registration =
          harness.commands.find(
            ([command]) => command === "register-cli-scan",
          ) ?? [];
        const recipe = JSON.parse(
          registration[registration.indexOf("--recipe-json") + 1] ?? "null",
        );
        expect(recipe).not.toHaveProperty("dependencyGraphPath");
        expect(recipe.scanDependencies).toBe(true);
        await client.close();
      },
    );

    test.each([
      "different repository",
      "different scope",
      "different target revision",
      "different snapshot",
      "different diff base",
      "different diff head",
      "missing graph",
      "missing sidecar",
    ])("warns and resolves normally for %s", async (mismatch) => {
      const harness = await createArtifactScanHarness([[]], {
        artifactMode: false,
      });
      const { client, repository, scanDir } = harness;
      await mkdir(join(repository, "src"));
      const target: ScanTarget = mismatch.includes("diff")
        ? DiffTarget.refs({ base: "HEAD" })
        : ["src"];
      const preflight = await client.preflight(repository, {
        target,
        scanDependencies: true,
      });
      const saved = join(await temporaryDirectory(), "saved.json");
      const setup = {
        repository,
        target: { ...preflight.target, paths: [...preflight.target.paths] },
        targetRevision: "deadbeef",
        snapshotDigest: null as string | null,
        depthCounts: [2, 1],
      };
      if (mismatch === "different repository")
        setup.repository = join(repository, "other");
      if (mismatch === "different scope") setup.target.paths = ["package.json"];
      if (mismatch === "different target revision")
        setup.targetRevision = "previous-revision";
      if (mismatch === "different snapshot")
        setup.snapshotDigest = "previous-snapshot";
      if (mismatch === "different diff base")
        setup.target.base = "previous-base";
      if (mismatch === "different diff head")
        setup.target.head = "previous-head";
      if (mismatch !== "missing graph")
        await writeFile(saved, nativeResolverOutput);
      if (mismatch !== "missing sidecar")
        await writeFile(`${saved}.setup.json`, JSON.stringify(setup));
      const warnings: string[] = [];
      await expect(
        client.scanDependencies(repository, {
          target,
          dependencyGraphPath: saved,
          onWarning: (warning) => warnings.push(warning),
        }),
      ).rejects.toThrow("host preparation observed");
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("resolving dependencies normally");
      expect(harness.prompts[0]).toContain(
        "$codex-security:dependency-update-scan",
      );
      expect(harness.prompts[0]).not.toContain(
        "The SDK staged saved native resolver output",
      );
      await expect(
        readFile(
          join(
            scanDir,
            "artifacts",
            "02_discovery",
            "dependency-update-scan",
            "dependency-resolver-output.json",
          ),
        ),
      ).rejects.toMatchObject({ code: "ENOENT" });
      await client.close();
    });
  });
});
