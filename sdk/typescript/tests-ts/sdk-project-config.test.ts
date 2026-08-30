import { mkdir, stat, writeFile } from "node:fs/promises";
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
import { capture, dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";

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
      maxTimeHours: 1.5,
    };
    const { subagents, ...fileDeep } = deep;
    const input = {
      auth: "api-key",
      scan: {
        mode,
        scope: { paths: ["src"] },
        knowledgeBase: ["context.md"],
        instructionsFile: "scan.md",
        deep: { ...fileDeep, subagentsPerWorker: subagents },
      },
      output: { directory: "../output" },
      limits: { maxCostUsdPerScan: 5 },
      policy: { failOnSeverity: "high" },
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
      prepareRuntime: async () => {
        throw new Error("Preflight must not initialize a runtime");
      },
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
      expect(configuration.options).toEqual({
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
            "--max-time-hours",
            "1.5",
          ]
        : []),
    ]);
    for (const command of commands) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({ currentDirectory: root, environment });
      let selected: ScanOptions | undefined;
      deps.createSecurity = (config) => {
        const client = new TestClient(config, clientDependencies);
        return {
          run: client.run.bind(client),
          close: client.close.bind(client),
          preflight: async (repository, options) => {
            selected = options;
            return await client.preflight(repository, options);
          },
        };
      };
      expect(
        await main(
          [...command, "--dry-run", "--json"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
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
    [{ workingTree: {} }, DiffTarget.workingTree({})],
  ] as const) {
    expect(
      resolveProjectConfig(
        { scan: { scope: structuredClone(scope) } } as ProjectConfigInput,
        directory,
      ).options.target,
    ).toEqual(target);
  }
});

test("public file and object entry points reject the same invalid settings", async () => {
  const directory = await temporaryDirectory();
  for (const input of [
    { scan: { workres: 2 } },
    { limits: { maxCostUsdPerScan: 0 } },
    { scan: { deep: { subagentsPerWorker: -1 } } },
    JSON.parse('{"codex":{"__proto__":{"synthetic":true}}}'),
  ]) {
    const file = join(directory, "scan.json");
    await writeFile(file, JSON.stringify(input));
    expect(() => resolveProjectConfig(input, directory)).toThrow();
    await expect(loadProjectConfig(file)).rejects.toThrow();
  }
});
