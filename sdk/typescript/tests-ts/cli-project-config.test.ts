import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import { main } from "../src/cli.js";
import type { CodexSecurityConfig, JsonObject } from "../src/config.js";
import type { ProjectConfigInput } from "../src/project-config-schema.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture(input: ProjectConfigInput | string) {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "cli-project-config-")),
  );
  directories.push(root);
  const repository = join(root, "repository");
  const configDirectory = join(root, "settings");
  await mkdir(repository);
  await mkdir(configDirectory);
  await mkdir(join(repository, "src"));
  await mkdir(join(repository, "lib"));
  const config = join(
    configDirectory,
    typeof input === "string" ? "scan.yaml" : "scan.json",
  );
  await writeFile(
    config,
    typeof input === "string" ? input : JSON.stringify(input),
  );
  return { root, repository, configDirectory, config };
}

test("actual CLI parsing preserves file values when flags are absent", async () => {
  const input = await fixture({
    auth: "api-key",
    scan: {
      mode: "deep",
      scope: { paths: ["src"] },
      deep: {
        workers: 8,
        subagentsPerWorker: 0,
        stopAfterConsecutiveErrors: 2,
      },
    },
    limits: { maxCostUsdPerScan: 7 },
    policy: { failOnSeverity: "high" },
    codex: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
  });
  let selected: ScanOptions | undefined;
  let native: CodexSecurityConfig | undefined;
  let repository: string | undefined;
  const stdout = capture();
  const stderr = capture();
  expect(
    await main(
      ["scan", "-c", input.config, "--json"],
      stdout.stream,
      stderr.stream,
      dependencies({
        currentDirectory: input.repository,
        environment: { OPENAI_API_KEY: "synthetic-test-key" },
        onConfig: (value) => {
          native = value;
        },
        onTurn: (target, value) => {
          repository = target;
          selected = value as ScanOptions;
        },
        result: fakeResult(["high"]),
      }),
    ),
  ).toBe(1);
  expect(repository).toBe(input.repository);
  expect(selected).toMatchObject({
    auth: "api-key",
    mode: "deep",
    target: ["src"],
    workers: 8,
    subagents: 0,
    stopAfterConsecutiveErrors: 2,
    maxCostUsd: 7,
    failureSeverity: "high",
  });
  expect(native?.codexOverrides).toMatchObject({
    model: "gpt-5.6-terra",
    model_reasoning_effort: "high",
  });
  expect(JSON.parse(stdout.text())).toMatchObject({
    manifest: { scan: { status: "completed" } },
  });
});

test("CLI values override matching file values, including native objects and lists", async () => {
  const input = await fixture({
    auth: "chatgpt",
    scan: {
      mode: "deep",
      scope: { paths: ["src"] },
      knowledgeBase: ["file-context.md"],
      deep: { workers: 8, subagentsPerWorker: 3 },
    },
    limits: { maxCostUsdPerScan: 7 },
    policy: { failOnSeverity: "high" },
    codex: {
      model: "gpt-5.6-sol",
      synthetic_setting: { enabled: true, names: ["first"] },
    },
  });
  let selected: ScanOptions | undefined;
  let native: CodexSecurityConfig | undefined;
  expect(
    await main(
      [
        "scan",
        "--config",
        input.config,
        "--auth",
        "auto",
        "--path",
        "lib",
        "--knowledge-base",
        "cli-context.md",
        "--subagents",
        "0",
        "--workers",
        "2",
        "--max-cost",
        "3",
        "--fail-on-severity",
        "low",
        "--model",
        "gpt-5.6-terra",
        "--codex",
        "synthetic_setting.enabled=false",
        "--codex",
        "synthetic_setting.names=[]",
        "--json",
      ],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        onConfig: (value) => {
          native = value;
        },
        onTurn: (_target, value) => {
          selected = value as ScanOptions;
        },
      }),
    ),
  ).toBe(0);
  expect(selected).toMatchObject({
    auth: "auto",
    mode: "deep",
    target: ["lib"],
    knowledgeBasePaths: [join(input.repository, "cli-context.md")],
    workers: 2,
    subagents: 0,
    maxCostUsd: 3,
    failureSeverity: "low",
  });
  expect(native?.codexOverrides).toMatchObject({
    model: "gpt-5.6-terra",
    synthetic_setting: { enabled: false, names: [] },
  });
});

test.each([
  [
    { paths: ["src"] },
    ["--diff", "HEAD"],
    { kind: "refs", base: "HEAD", head: "HEAD" },
  ],
  [{ diff: { base: "HEAD", head: "HEAD~1" } }, ["--path", "lib"], ["lib"]],
  [
    { diff: { base: "HEAD", head: "HEAD~1" } },
    ["--head", "HEAD"],
    { kind: "refs", base: "HEAD", head: "HEAD" },
  ],
  [
    { workingTree: {} },
    ["--base", "HEAD~1"],
    { kind: "working_tree", base: "HEAD~1" },
  ],
  [{ workingTree: {} }, ["--no-working-tree"], "repository"],
] as const)(
  "resolves scope %j with overrides %j",
  async (scope, flags, target) => {
    const input = await fixture({
      scan: { scope: structuredClone(scope) },
    } as ProjectConfigInput);
    let selected: ScanOptions | undefined;
    const stderr = capture();
    expect(
      await main(
        ["scan", "-c", input.config, ...flags, "--json"],
        capture().stream,
        stderr.stream,
        dependencies({
          currentDirectory: input.repository,
          onTurn: (_target, value) => {
            selected = value as ScanOptions;
          },
        }),
      ),
    ).toBe(0);
    if (typeof target === "string" || Array.isArray(target))
      expect(selected?.target).toEqual(target);
    else expect(selected?.target).toMatchObject(target);
  },
);

test.each([
  [["--path", "src", "--diff", "HEAD"], "mutually exclusive"],
  [["--head", "HEAD"], "--head requires --diff"],
  [["--base", "HEAD"], "--base requires --working-tree"],
  [["--workers", "2", "--mode", "standard"], "require --mode deep"],
  [
    ["--model", "gpt-5.6-terra", "--codex", 'model="gpt-5.6-sol"'],
    "--model conflicts",
  ],
] as const)(
  "rejects incompatible explicit overrides: %j",
  async (flags, message) => {
    const input = await fixture({});
    let initialized = false;
    const stderr = capture();
    expect(
      await main(
        ["scan", "-c", input.config, ...flags, "--json"],
        capture().stream,
        stderr.stream,
        dependencies({
          currentDirectory: input.repository,
          onConfig: () => {
            initialized = true;
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(message);
    expect(initialized).toBe(false);
  },
);

test("selecting standard mode leaves inactive file deep settings out of the active scan", async () => {
  const input = await fixture({
    scan: { mode: "deep", deep: { workers: 8, stopAfterConsecutiveErrors: 2 } },
  });
  let selected: ScanOptions | undefined;
  expect(
    await main(
      ["scan", "-c", input.config, "--mode", "standard", "--json"],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        onTurn: (_target, value) => {
          selected = value as ScanOptions;
        },
      }),
    ),
  ).toBe(0);
  expect(selected?.mode).toBe("standard");
  expect(selected?.workers).toBeUndefined();
  expect(selected?.stopAfterConsecutiveErrors).toBeUndefined();
});

test("file prompts use the config directory and CLI prompt overrides use the invocation directory", async () => {
  const input = await fixture({
    scan: { instructionsFile: "scan.md", validationFile: "validate.md" },
  });
  await writeFile(
    join(input.configDirectory, "scan.md"),
    "Synthetic file instructions.",
  );
  await writeFile(
    join(input.configDirectory, "validate.md"),
    "Synthetic file validation.",
  );
  await writeFile(
    join(input.repository, "validate.md"),
    "Synthetic CLI validation.",
  );
  let selected: ScanOptions | undefined;
  expect(
    await main(
      [
        "scan",
        "-c",
        input.config,
        "--validation-prompt-file",
        "validate.md",
        "--json",
      ],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        onTurn: (_target, value) => {
          selected = value as ScanOptions;
        },
      }),
    ),
  ).toBe(0);
  expect(selected).toMatchObject({
    scanPrompt: "Synthetic file instructions.",
    validationPrompt: "Synthetic CLI validation.",
  });
});

test("an explicit file can supply the model required by a provider override", async () => {
  const input = await fixture({
    codex: { model: "synthetic-model" },
  });
  let native: CodexSecurityConfig | undefined;
  expect(
    await main(
      ["scan", "-c", input.config, "--provider", "amazon-bedrock", "--json"],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        onConfig: (value) => {
          native = value;
        },
      }),
    ),
  ).toBe(0);
  expect(native?.codexOverrides).toMatchObject({
    model: "synthetic-model",
    model_provider: "amazon-bedrock",
  });
});

test.each([
  { argv: ["scan", "--help"] },
  { argv: ["scan", "--schema", "--json"] },
  { argv: ["info", "--json"] },
])("malformed unselected files do not affect %j", async ({ argv }) => {
  const input = await fixture("scan: [");
  await writeFile(join(input.repository, "codex-security.yaml"), "scan: [");
  let initialized = false;
  expect(
    await main(
      [...argv],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        onConfig: () => {
          initialized = true;
        },
      }),
    ),
  ).toBe(0);
  expect(initialized).toBe(false);
});

test.each(["--help", "--schema"])(
  "%s does not load even an explicitly selected invalid file",
  async (flag) => {
    const input = await fixture("scan: [");
    const stdout = capture();
    expect(
      await main(
        ["scan", "-c", input.config, flag, "--json"],
        stdout.stream,
        capture().stream,
        dependencies({ currentDirectory: input.repository }),
      ),
    ).toBe(0);
    if (flag === "--schema")
      expect(JSON.parse(stdout.text())).toMatchObject({
        options: { properties: { config: { type: "string" } } },
      });
  },
);

test("a malformed selected file fails before constructing a client", async () => {
  const input = await fixture("scan: [");
  let initialized = false;
  const stdout = capture();
  const stderr = capture();
  expect(
    await main(
      ["scan", "-c", input.config, "--dry-run", "--json"],
      stdout.stream,
      stderr.stream,
      dependencies({
        currentDirectory: input.repository,
        onConfig: () => {
          initialized = true;
        },
      }),
    ),
  ).toBe(2);
  expect(initialized).toBe(false);
  expect(stderr.text()).toContain("Cannot parse project configuration");
  expect(stdout.text()).toBe("");
});

test("dry-run uses the real SDK without initializing its runtime and reports provenance", async () => {
  const input = await fixture({
    scan: {
      mode: "deep",
      scope: { paths: ["src"] },
      deep: { workers: 8, stopAfterConsecutiveErrors: 2 },
    },
    codex: {
      profile: "review",
      model: "gpt-5.6-sol",
      profiles: {
        review: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
      },
    },
    policy: { failOnSeverity: "high" },
  });
  const ambient = join(input.root, "ambient");
  await mkdir(join(ambient, "codex-security"), { recursive: true });
  await writeFile(
    join(ambient, "codex-security", "config.toml"),
    "[deep_scan]\nworkers = 6\nsubagents = 1\nstop_after_no_new = 5\n",
  );
  const environment = {
    codex_home: ambient,
    CODEX_SECURITY_STATE_DIR: join(input.root, "state"),
  };
  const stdout = capture();
  const stderr = capture();
  let initialized = false;
  const deps = dependencies({
    currentDirectory: input.repository,
    environment,
  });
  deps.createSecurity = (config) =>
    new CodexSecurity(
      config,
      {
        environment,
        createCodex: () => {
          initialized = true;
          throw new Error("No inference in dry-run");
        },
        prepareRuntime: async () => {
          initialized = true;
          throw new Error("No runtime in dry-run");
        },
      },
      { surface: "cli" },
    );
  expect(
    await main(
      [
        "scan",
        "-c",
        input.config,
        "--subagents",
        "0",
        "--model",
        "gpt-5.6-sol",
        "--dry-run",
        "--json",
      ],
      stdout.stream,
      stderr.stream,
      deps,
    ),
  ).toBe(0);
  expect(initialized).toBe(false);
  expect(JSON.parse(stdout.text())).toMatchObject({
    dryRun: true,
    repository: input.repository,
    mode: "deep",
    model: "gpt-5.6-terra",
    reasoningEffort: "high",
    target: { kind: "paths", paths: ["src"] },
    workers: 8,
    subagents: 0,
    stopAfterNoNew: 5,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 40,
    maxTimeHours: 96,
    projectConfig: {
      path: input.config,
      sources: {
        "scan.deep.workers": "project",
        "scan.deep.subagentsPerWorker": "cli",
        "scan.deep.stopAfterNoNew": "legacy",
        "scan.deep.maxTimeHours": "default",
        "codex.model": "cli",
        "codex.profiles.review.model": "project",
      },
    },
    failOnSeverity: "high",
  });
});

test.each([
  [{ output: { directory: "../repository/artifacts" } }, "outside"],
  [{ codex: { plugins: {} } }, "plugin"],
  [{ scan: { mode: "deep", validationFile: "validate.md" } }, "Deep"],
] as const)(
  "project files retain active scan checks: %j",
  async (config, message) => {
    const input = await fixture(config as ProjectConfigInput);
    await writeFile(
      join(input.configDirectory, "validate.md"),
      "Synthetic validation instructions.",
    );
    const environment = {
      CODEX_HOME: join(input.root, "ambient"),
      CODEX_SECURITY_STATE_DIR: join(input.root, "state"),
    };
    const stderr = capture();
    let initialized = false;
    const deps = dependencies({
      currentDirectory: input.repository,
      environment,
    });
    deps.createSecurity = (configuration) =>
      new CodexSecurity(
        configuration,
        {
          environment,
          createCodex: () => {
            initialized = true;
            throw new Error("No inference");
          },
          prepareRuntime: async () => {
            initialized = true;
            throw new Error("No runtime");
          },
        },
        { surface: "cli" },
      );
    expect(
      await main(
        ["scan", "-c", input.config, "--dry-run", "--json"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text().toLowerCase()).toContain(message.toLowerCase());
    expect(initialized).toBe(false);
  },
);

test("rerun restores all saved deep settings and authentication without loading project files", async () => {
  const input = await fixture("scan: [");
  const deep = {
    workers: 7,
    subagents: 0,
    stopAfterNoNew: 5,
    stopAfterConsecutiveErrors: 2,
    maxDiscoveryRuns: 12,
    maxTimeHours: 3,
  };
  const recipe: JsonObject = {
    repository: input.repository,
    target: { kind: "repository", paths: [] },
    mode: "deep",
    config: {},
    auth: "api-key",
    deepScan: deep,
    deepScanResolved: true,
  };
  let selected: ScanOptions | undefined;
  expect(
    await main(
      ["scans", "rerun", "saved", "--json"],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        environment: { OPENAI_API_KEY: "synthetic-test-key" },
        onWorkbench: async () => ({ recipe }),
        onTurn: (_target, value) => {
          selected = value as ScanOptions;
        },
      }),
    ),
  ).toBe(0);
  expect(selected).toMatchObject({
    ...deep,
    auth: "api-key",
    parentScanId: "saved",
  });
});

test.each([
  [{ requiresScanPrompt: true }, "additional instructions"],
  [
    { mode: "deep", deepScan: { workers: 7 }, deepScanResolved: true },
    "missing resolved deep scan settings",
  ],
] as const)(
  "rerun rejects an incomplete saved input: %j",
  async (extra, message) => {
    const input = await fixture({});
    const recipe: JsonObject = {
      repository: input.repository,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      config: {},
      ...extra,
    };
    const stderr = capture();
    let ran = false;
    expect(
      await main(
        ["scans", "rerun", "saved", "--json"],
        capture().stream,
        stderr.stream,
        dependencies({
          currentDirectory: input.repository,
          onWorkbench: async () => ({ recipe }),
          onRun: () => {
            ran = true;
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(message);
    expect(ran).toBe(false);
  },
);
