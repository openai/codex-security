import { createCliTest } from "./support/cli-run.js";
import { mkdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { stringify } from "yaml";
import {
  DiffTarget,
  loadProjectConfig,
  resolveProjectConfig,
  type ProjectConfigInput,
  type ScanOptions,
  type ScanSettings,
} from "../src/index.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting } from "./support/errors.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

test.each(["standard", "deep"] as const)(
  "%s settings agree across SDK options, typed configuration, YAML, JSON, and CLI flags",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const directory = join(root, "settings");
    const output = join(root, "output");
    await mkdir(join(repository, "src"), { recursive: true });
    await mkdir(directory);
    await writeFile(join(directory, "context.md"), "Synthetic context.");
    await writeFile(join(directory, "scan.md"), "Synthetic instructions.");
    const deep = {
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 3,
      stopAfterConsecutiveErrors: 2,
      maxDiscoveryRuns: 6,
    };
    const input = {
      auth: "api-key",
      scan: {
        mode,
        max_time_minutes: 90,
        scope: { paths: ["src"] },
        knowledge_base: ["context.md"],
        instructions_file: "scan.md",
        deep: {
          workers: 2,
          subagents_per_worker: 0,
          stop_after_no_new: 3,
          stop_after_consecutive_errors: 2,
          max_discovery_runs: 6,
        },
      },
      output: { directory: "../output" },
      limits: { max_cost_usd_per_scan: 5 },
      policy: { fail_on_severity: "high" },
      codex: {
        profile: "review",
        profiles: {
          review: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
        },
      },
    } satisfies ProjectConfigInput;
    const original = structuredClone(input);
    const options = {
      auth: "api-key",
      mode,
      maxTimeMinutes: 90,
      target: ["src"],
      knowledgeBasePaths: [join(directory, "context.md")],
      scanPromptFile: join(directory, "scan.md"),
      outputDir: output,
      maxCostUsd: 5,
      failureSeverity: "high",
      ...(mode === "deep" ? deep : {}),
    } satisfies ScanSettings;
    const environment = {
      CODEX_HOME: join(root, "ambient"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-test-key",
    };
    const clientDependencies = {
      environment,
      prepareRuntime: rejecting("Preflight must not initialize a runtime"),
    };
    await using direct = new TestClient(
      { codexOverrides: input.codex },
      clientDependencies,
    );
    const expected = await direct.preflight(repository, options);
    const configurations = [resolveProjectConfig(input, directory)];
    const commands: string[][] = [];
    for (const extension of ["yaml", "json"]) {
      const file = join(directory, `scan.${extension}`);
      await writeFile(
        file,
        extension === "yaml" ? stringify(input) : JSON.stringify(input),
      );
      const loaded = await loadProjectConfig(`scan.${extension}`, directory);
      expect(loaded.projectConfig?.path).toBe(file);
      configurations.push(loaded);
      commands.push(["scan", repository, "-c", file]);
    }
    for (const configuration of configurations) {
      expect(configuration.config).toEqual({ codexOverrides: input.codex });
      expect<ScanOptions>(configuration.options).toEqual({
        ...options,
        validationPromptFile: undefined,
      });
      await using client = new TestClient(
        configuration.config,
        clientDependencies,
      );
      expect(await client.preflight(repository, configuration.options)).toEqual(
        expected,
      );
    }
    commands.push([
      "scan",
      repository,
      "--auth",
      "api-key",
      "--mode",
      mode,
      "--path",
      "src",
      "--knowledge-base",
      join(directory, "context.md"),
      "--scan-prompt-file",
      join(directory, "scan.md"),
      "--output-dir",
      output,
      "--max-cost",
      "5",
      "--max-time",
      "90",
      "--fail-on-severity",
      "high",
      "--codex",
      'profile="review"',
      "--codex",
      'profiles.review.model="gpt-5.6-terra"',
      "--codex",
      'profiles.review.model_reasoning_effort="high"',
      ...(mode === "deep"
        ? [
            "--workers",
            "2",
            "--subagents",
            "0",
            "--stop-after-no-new",
            "3",
            "--max-discovery-runs",
            "6",
          ]
        : []),
    ]);
    for (const command of commands) {
      const { stdout, runCli } = createCliTest(main);

      const deps = dependencies({ currentDirectory: root, environment });
      let selected: ScanOptions | undefined;
      deps.createSecurity = (config) => {
        const client = new TestClient(config, clientDependencies);
        return {
          run: client.run.bind(client),
          validate: client.validate.bind(client),
          close: client.close.bind(client),
          preflight: async (repository, options) => {
            selected = options;
            return await client.preflight(repository, options);
          },
        };
      };
      expect(await runCli([...command, "--dry-run", "--json"], deps)).toBe(0);
      expect(selected).toMatchObject({
        failureSeverity: "high",
        scanPrompt: "Synthetic instructions.",
      });
      const resolved = JSON.parse(stdout.text());
      // The CLI has no flag for stopAfterConsecutiveErrors; files and SDK calls do.
      expect(resolved).toMatchObject({
        ...expected,
        ...(mode === "deep" && command[2] !== "-c"
          ? {
              stopAfterConsecutiveErrors: 3,
              deepScanSources: {
                ...expected.deepScanSources,
                stopAfterConsecutiveErrors: "default",
              },
            }
          : {}),
        ...(command[2] === "-c" ? { failOnSeverity: "high" } : {}),
      });
    }
    expect(input).toEqual(original);
    await expect(stat(output)).rejects.toThrow();
    await expect(stat(environment.CODEX_SECURITY_STATE_DIR)).rejects.toThrow();
  },
);

test("typed configuration keeps repository-relative scopes and does not discover files", async () => {
  const directory = await temporaryDirectory();
  await writeFile(join(directory, "codex-security.yaml"), "scan: [");
  expect(resolveProjectConfig({}, directory)).toMatchObject({
    config: { codexOverrides: {} },
    options: {
      auth: "auto",
      mode: "standard",
      target: "repository",
      knowledgeBasePaths: [],
    },
  });
  expect(resolveProjectConfig({}, directory).projectConfig).toBeUndefined();
  for (const [scope, target] of [
    [{ paths: ["src"] }, ["src"]],
    [{ diff: { base: "HEAD~1" } }, DiffTarget.refs({ base: "HEAD~1" })],
    [{ working_tree: {} }, DiffTarget.workingTree({})],
  ] as const) {
    expect(
      resolveProjectConfig(
        { scan: { scope: structuredClone(scope) } } as ProjectConfigInput,
        directory,
      ).options.target,
    ).toEqual(target);
  }
});

test("SDK preflight binds parsed project routing to the original checkout across link chains", async () => {
  const root = await temporaryDirectory();
  const checkout = join(root, "checkout");
  const operator = join(root, "operator");
  const other = join(root, "other-checkout");
  await Promise.all([checkout, operator, other].map((path) => mkdir(path)));
  const selected = join(operator, "selected");
  const controlled = join(checkout, "settings");
  await symlink(operator, controlled, "junction");
  await symlink(controlled, selected, "junction");
  await writeFile(
    join(operator, "scan.json"),
    JSON.stringify({
      codex: {
        profiles: {
          "named.profile": {
            openai_base_url: "https://source.example.invalid",
          },
        },
      },
    }),
  );
  const loaded = await loadProjectConfig(join(selected, "scan.json"));
  await rm(selected);
  await rm(controlled);
  await rm(join(operator, "scan.json"));
  await using security = new TestClient(loaded.config, {
    environment: {
      CODEX_HOME: join(root, "home"),
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
    prepareRuntime: rejecting("Preflight must not initialize a runtime"),
  });
  await expect(security.preflight(checkout, loaded.options)).rejects.toThrow(
    /codex\.profiles\.named\.profile\.openai_base_url.*--codex/,
  );
  expect((await security.preflight(other, loaded.options)).mode).toBe(
    "standard",
  );
});

test.each([
  ["model_providers.gateway.env_key", "codex.model_providers"],
  [
    "profiles.review.model_providers.gateway.base_url",
    "codex.profiles.review.model_providers",
  ],
  ["chatgpt_base_url", "codex.chatgpt_base_url"],
])(
  "file-backed SDK routing recognizes native override %s",
  async (key, field) => {
    const root = await temporaryDirectory();
    const checkout = join(root, "checkout");
    await mkdir(checkout);
    const path = join(checkout, "scan.json");
    await writeFile(
      path,
      JSON.stringify({ codex: { [key]: "synthetic-setting-value" } }),
    );
    const loaded = await loadProjectConfig(path);
    await using security = new TestClient(loaded.config, {
      environment: {
        CODEX_HOME: join(root, "home"),
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
      prepareRuntime: rejecting(
        "File routing must be rejected before runtime setup",
      ),
    });
    await expect(security.run(checkout, loaded.options)).rejects.toThrow(field);
  },
);

test("a checkout file can select a credential-home provider profile", async () => {
  const root = await temporaryDirectory();
  const checkout = join(root, "checkout");
  const home = join(root, "home");
  await Promise.all([mkdir(checkout), mkdir(home)]);
  await writeFile(
    join(home, "gateway.config.toml"),
    [
      'model_provider = "openrouter"',
      'model = "operator-model"',
      "[model_providers.openrouter]",
      'base_url = "https://operator.example.invalid"',
      'env_key = "OPERATOR_PROVIDER_MARKER"',
    ].join("\n"),
  );
  const path = join(checkout, "scan.json");
  await writeFile(
    path,
    JSON.stringify({
      codex: {
        profile: "gateway",
        "profiles.review.some_extension.model_providers": "extension-value",
        '"openai_base_url"': "literal-key",
      },
    }),
  );
  const loaded = await loadProjectConfig(path);
  await using security = new TestClient(loaded.config, {
    environment: {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPERATOR_PROVIDER_MARKER: "fixture-marker",
    },
    prepareRuntime: rejecting("Preflight must not initialize a runtime"),
  });
  expect(await security.preflight(checkout, loaded.options)).toMatchObject({
    model: "operator-model",
    modelProvider: "openrouter",
    authentication: { source: "OPERATOR_PROVIDER_MARKER" },
  });
});

test("public file and object entry points reject the same invalid settings", async () => {
  const directory = await temporaryDirectory();
  for (const input of [
    { scan: { workres: 2 } },
    { limits: { max_cost_usd_per_scan: 0 } },
    { scan: { deep: { subagents_per_worker: -1 } } },
    { limits: { maxCostUsdPerScan: 5 } },
    JSON.parse('{"codex":{"__proto__":{"synthetic":true}}}'),
  ]) {
    const file = join(directory, "scan.json");
    await writeFile(file, JSON.stringify(input));
    expect(() => resolveProjectConfig(input, directory)).toThrow();
    await expect(loadProjectConfig(file)).rejects.toThrow();
  }
});
