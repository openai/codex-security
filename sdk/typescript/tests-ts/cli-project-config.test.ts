import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import { main } from "../src/cli.js";
import type { CodexSecurityConfig, JsonObject } from "../src/config.js";
import type { ProjectConfigInput } from "../src/project-config-schema.js";
import { readProjectConfig } from "../src/project-config.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

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

test.each([
  [undefined, "./node_modules"],
  ["starter.json", "./node_modules"],
  ["settings/starter.yaml", "../node_modules"],
  ["settings/starter.json", "../node_modules"],
])(
  "init writes a valid unpinned starter and refuses overwrites: %s",
  async (file, modules) => {
    const input = await fixture({});
    const args = ["init", ...(file === undefined ? [] : [file]), "--json"];
    const output = capture();
    const deps = dependencies({
      currentDirectory: input.root,
      onConfig: () => {
        throw new Error("No runtime for init");
      },
    });
    expect(await main(args, output.stream, capture().stream, deps)).toBe(0);
    const path = join(input.root, file ?? "codex-security.yaml");
    expect(JSON.parse(output.text())).toEqual({ path });
    const selected = await readProjectConfig(path);
    expect(selected.input).toEqual({
      $schema: `${modules}/@openai/codex-security/schemas/project-config.schema.json`,
    });
    const contents = await readFile(path, "utf8");
    const refused = capture();
    expect(await main(args, capture().stream, refused.stream, deps)).toBe(2);
    expect(await readFile(path, "utf8")).toBe(contents);
    expect(refused.text()).toContain(`${path} already exists.`);
    expect(refused.text()).not.toContain("EEXIST");
  },
);

test("init leaves starter permissions to the umask", async () => {
  const input = await fixture({});
  const output = capture();
  const deps = dependencies({
    currentDirectory: input.root,
    onConfig: () => {
      throw new Error("No runtime for init");
    },
  });
  expect(
    await main(["init", "--json"], output.stream, capture().stream, deps),
  ).toBe(0);
  // Tracked configuration should match an ordinary write, not a private file.
  const reference = join(input.root, "reference.yaml");
  await writeFile(reference, "");
  expect((await stat(join(input.root, "codex-security.yaml"))).mode).toBe(
    (await stat(reference)).mode,
  );
});

test("init explains the settings a JSON starter cannot carry inline", async () => {
  const input = await fixture({});
  const notes = capture();
  expect(
    await main(
      ["init", "starter.json", "--json"],
      capture().stream,
      notes.stream,
      dependencies({
        currentDirectory: input.root,
        onConfig: () => {
          throw new Error("No runtime for init");
        },
      }),
    ),
  ).toBe(0);
  expect(notes.text()).toContain("cannot carry comments");
  expect(notes.text()).toContain("init codex-security.yaml");
});

test("init points the editor hint at an installed schema above the file", async () => {
  const input = await fixture({});
  const installed = join(
    input.root,
    "node_modules",
    "@openai",
    "codex-security",
    "schemas",
  );
  await mkdir(installed, { recursive: true });
  await writeFile(join(installed, "project-config.schema.json"), "{}");
  const nested = join(input.root, "packages", "app");
  await mkdir(nested, { recursive: true });
  expect(
    await main(
      ["init", "packages/app/codex-security.yaml", "--json"],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.root,
        onConfig: () => {
          throw new Error("No runtime for init");
        },
      }),
    ),
  ).toBe(0);
  // Hoisted workspaces resolve upward instead of emitting a broken sibling path.
  expect(
    (await readProjectConfig(join(nested, "codex-security.yaml"))).input,
  ).toEqual({
    $schema:
      "../../node_modules/@openai/codex-security/schemas/project-config.schema.json",
  });
});

test("info resolves a config and its sources without a target, prompt reads, or runtime", async () => {
  const input = await fixture({
    scan: {
      mode: "deep",
      instructions_file: "not-read.md",
      deep: { workers: 2 },
    },
    codex: {
      model: "gpt-5.6-terra",
      synthetic_private_setting: "synthetic-private-value",
    },
  });
  const home = join(input.root, "home");
  await mkdir(join(home, "codex-security"), { recursive: true });
  await writeFile(
    join(home, "codex-security", "config.toml"),
    "[deep_scan]\nsubagents = 1\n",
  );
  const stdout = capture();
  expect(
    await main(
      ["info", "-c", input.config, "--json"],
      stdout.stream,
      capture().stream,
      dependencies({
        currentDirectory: input.configDirectory,
        environment: { CODEX_HOME: home },
        onConfig: () => {
          throw new Error("No runtime for info");
        },
      }),
    ),
  ).toBe(0);
  expect(stdout.text()).not.toContain("synthetic-private-value");
  expect(JSON.parse(stdout.text())).toMatchObject({
    model: "gpt-5.6-terra",
    configuration: {
      path: input.config,
      settings: {
        mode: "deep",
        workers: 2,
        subagents: 1,
        scanPromptFile: join(input.configDirectory, "not-read.md"),
      },
      sources: {
        "scan.deep.workers": "project",
        "scan.deep.subagents_per_worker": "legacy",
        "scan.deep.max_time_hours": "default",
        "policy.fail_on_severity": "default",
      },
    },
  });
});

test("info without a file reports default sources, including unset settings", async () => {
  const input = await fixture({});
  const stdout = capture();
  expect(
    await main(
      ["info", "--json", "--filter-output", "configuration"],
      stdout.stream,
      capture().stream,
      dependencies({ currentDirectory: input.root }),
    ),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toMatchObject({
    configuration: {
      sources: {
        auth: "default",
        "scan.mode": "default",
        "scan.scope": "default",
        "scan.knowledge_base": "default",
        "scan.instructions_file": "default",
        "scan.validation_file": "default",
        "output.directory": "default",
        "policy.fail_on_severity": "default",
        "limits.max_cost_usd_per_scan": "default",
      },
    },
  });
});

test("an explicit config flag overrides the operator-selected environment file", async () => {
  const input = await fixture({ codex: { model: "gpt-5.6-terra" } });
  const override = join(input.root, "override.json");
  await writeFile(
    override,
    JSON.stringify({ codex: { model: "gpt-5.6-sol" } }),
  );
  for (const [flags, expected] of [
    [[], "gpt-5.6-terra"],
    [["-c", override], "gpt-5.6-sol"],
  ] as const) {
    let selected: CodexSecurityConfig | undefined;
    expect(
      await main(
        ["scan", ...flags, "--json"],
        capture().stream,
        capture().stream,
        dependencies({
          currentDirectory: input.repository,
          environment: { CODEX_SECURITY_PROJECT_CONFIG: input.config },
          onConfig: (config) => {
            selected = config;
          },
        }),
      ),
    ).toBe(0);
    expect(selected?.codexOverrides?.["model"]).toBe(expected);
  }
});

test("a missing operator-selected environment file fails without falling back", async () => {
  const input = await fixture({});
  let initialized = false;
  expect(
    await main(
      ["scan", "--json"],
      capture().stream,
      capture().stream,
      dependencies({
        currentDirectory: input.repository,
        environment: {
          CODEX_SECURITY_PROJECT_CONFIG: join(input.root, "missing.yaml"),
        },
        onConfig: () => {
          initialized = true;
        },
      }),
    ),
  ).toBe(2);
  expect(initialized).toBe(false);
});

test.each([123, "", "   "])(
  "a selected profile's invalid model is reported at the provider flag: %j",
  async (model) => {
    const input = await fixture({
      codex: { profile: "selected", profiles: { selected: { model } } },
    });
    let initialized = false;
    const stderr = capture();
    expect(
      await main(
        ["scan", "-c", input.config, "--provider", "amazon-bedrock", "--json"],
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
    expect(stderr.text()).toContain(
      "--model must be a nonempty string when using --provider amazon-bedrock",
    );
    expect(initialized).toBe(false);
  },
);

test("rerun rejects a blank replacement when scan instructions are required", async () => {
  const input = await fixture({});
  const prompt = join(input.root, "empty.md");
  await writeFile(prompt, " \n");
  const stderr = capture();
  let initialized = false;
  expect(
    await main(
      ["scans", "rerun", "saved", "--scan-prompt-file", prompt, "--json"],
      capture().stream,
      stderr.stream,
      dependencies({
        currentDirectory: input.root,
        onWorkbench: async () => ({
          recipe: {
            repository: input.repository,
            target: { kind: "repository", paths: [] },
            mode: "standard",
            config: {},
            requiresScanPrompt: true,
          },
        }),
        onConfig: () => {
          initialized = true;
        },
      }),
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("--scan-prompt-file must not be empty");
  expect(initialized).toBe(false);
});

test.each(["instructions_file", "validation_file"] as const)(
  "bulk %s retains directory-link protection for local CSV repositories",
  async (file) => {
    const input = await fixture({
      scan: { [file]: "../repository/linked/prompt.md" },
      output: { directory: "../batch-results" },
    });
    const external = join(input.root, "external");
    await mkdir(external);
    await writeFile(join(external, "prompt.md"), "Synthetic external data.");
    await symlink(external, join(input.repository, "linked"), "junction");
    const csv = join(input.root, "repositories.csv");
    await writeFile(
      csv,
      `id,repository,revision\nsource,${input.repository},${"a".repeat(40)}\n`,
    );
    let initialized = false;
    const stderr = capture();
    const exit = await main(
      ["bulk-scan", csv, "-c", input.config, "--json"],
      capture().stream,
      stderr.stream,
      dependencies({
        currentDirectory: input.repository,
        onConfig: () => {
          initialized = true;
          throw new Error("Runtime must not start");
        },
      }),
    );
    expect(exit).toBe(2);
    expect(stderr.text()).toContain(
      "Input files must not follow repository directory links",
    );
    expect(initialized).toBe(false);
  },
);

test("bulk scans apply config and linked operator prompts, preserve CSV scope overrides, and retain the policy on resume", async () => {
  const config: ProjectConfigInput = {
    auth: "api-key",
    scan: {
      scope: { paths: ["src"] },
      knowledge_base: ["context.md"],
      instructions_file: "linked/instructions.md",
      deep: { workers: 2, subagents_per_worker: 0 },
    },
    codex: { model: "gpt-5.6-terra" },
    limits: { max_cost_usd_per_scan: 5 },
    policy: { fail_on_severity: "high" },
    output: { directory: "../batch-results" },
  };
  const input = await fixture(config);
  const promptDirectory = await realpath(
    await mkdtemp(join(tmpdir(), "bulk-operator-prompts-")),
  );
  directories.push(promptDirectory);
  await symlink(
    promptDirectory,
    join(input.configDirectory, "linked"),
    "junction",
  );
  await writeFile(
    join(input.configDirectory, "context.md"),
    "Synthetic context.",
  );
  await writeFile(
    join(promptDirectory, "instructions.md"),
    "Review synthetic boundaries.",
  );
  await writeFile(
    join(input.repository, "src", "index.ts"),
    "export const value = 1;\n",
  );
  await writeFile(
    join(input.repository, "lib", "index.ts"),
    "export const value = 2;\n",
  );
  for (const args of [
    ["init", "-q", input.repository],
    ["-C", input.repository, "add", "."],
    [
      "-C",
      input.repository,
      "-c",
      "user.name=Test",
      "-c",
      "user.email=test@example.test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "-qm",
      "fixture",
    ],
  ])
    execFileSync("git", args);
  const revision = execFileSync(
    "git",
    ["-C", input.repository, "rev-parse", "HEAD"],
    { encoding: "utf8" },
  ).trim();
  const csv = join(input.root, "repositories.csv");
  await writeFile(
    csv,
    `id,repository,revision,mode,scope\nstandard,${input.repository},${revision},standard,lib\ndeep,${input.repository},${revision},deep,\n`,
  );
  const selected: ScanOptions[] = [];
  const deps = dependencies({ currentDirectory: input.root });
  deps.createSecurity = (native) => {
    expect(native.codexOverrides?.["model"]).toBe("gpt-5.6-terra");
    return {
      preflight: async () => fakePreflight(),
      close: async () => {},
      run: async (_repository, options = {}) => {
        selected.push(options);
        const result = fakeResult(["high"]);
        await mkdir(options.outputDir!, { recursive: true });
        for (const [name, content] of Object.entries({
          "scan-manifest.json": result.manifest,
          "findings.json": result.findings,
          "coverage.json": result.coverage,
          "report.md": "Synthetic report.",
        }))
          await writeFile(
            join(options.outputDir!, name),
            typeof content === "string" ? content : JSON.stringify(content),
          );
        return result;
      },
    };
  };
  const args = [
    "bulk-scan",
    csv,
    "-c",
    input.config,
    "--max-cost",
    "3",
    "--json",
  ];
  const output = capture();
  expect(await main(args, output.stream, capture().stream, deps)).toBe(1);
  expect(JSON.parse(output.text())).toMatchObject({
    completed: 2,
    failed: 0,
    policyFailed: true,
  });
  expect(selected.find((options) => options.mode === "standard")).toMatchObject(
    {
      target: ["lib"],
      auth: "api-key",
      maxCostUsd: 3,
      failureSeverity: "high",
      knowledgeBasePaths: [join(input.configDirectory, "context.md")],
      scanPrompt: "Review synthetic boundaries.",
    },
  );
  expect(
    selected.find((options) => options.mode === "standard")?.workers,
  ).toBeUndefined();
  expect(selected.find((options) => options.mode === "deep")).toMatchObject({
    target: ["src"],
    workers: 2,
    subagents: 0,
  });
  const resumed = capture();
  expect(await main(args, resumed.stream, capture().stream, deps)).toBe(1);
  expect(JSON.parse(resumed.text())).toMatchObject({
    skipped: 2,
    policyFailed: true,
  });
  expect(selected).toHaveLength(2);
  await writeFile(
    input.config,
    JSON.stringify({ ...config, policy: { fail_on_severity: "low" } }),
  );
  const stderr = capture();
  expect(await main(args, capture().stream, stderr.stream, deps)).toBe(2);
  expect(stderr.text()).toContain("manifest does not match");
  expect(selected).toHaveLength(2);
});

test.each(["standard", "deep"] as const)(
  "component scans honor shared %s settings and severity policy",
  async (mode) => {
    const input = await fixture({
      scan: {
        mode,
        scope: { paths: ["src"] },
        instructions_file: "instructions.md",
        ...(mode === "standard" ? { validation_file: "validation.md" } : {}),
        deep: { workers: 2, subagents_per_worker: 0 },
      },
      codex: { model: "gpt-5.6-terra" },
      policy: { fail_on_severity: "high" },
      output: { directory: "../component-results" },
    });
    await writeFile(
      join(input.repository, "lib", "index.ts"),
      "export const value = 1;\n",
    );
    await writeFile(
      join(input.configDirectory, "instructions.md"),
      "Review synthetic boundaries.",
    );
    await writeFile(
      join(input.configDirectory, "validation.md"),
      "Validate synthetic boundaries.",
    );
    let selected: ScanOptions | undefined;
    const stdout = capture();
    expect(
      await main(
        [
          "scan-components",
          input.repository,
          "-c",
          input.config,
          "--component",
          "lib",
          "--headless",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          currentDirectory: input.root,
          result: fakeResult(["high"]),
          onTurn: (_repository, options) => {
            selected = options as ScanOptions;
          },
        }),
      ),
    ).toBe(1);
    expect(selected).toMatchObject({
      mode,
      target: ["lib"],
      scanPrompt: "Review synthetic boundaries.",
      failureSeverity: "high",
    });
    if (mode === "deep")
      expect(selected).toMatchObject({ workers: 2, subagents: 0 });
    else
      expect(selected?.validationPrompt).toBe("Validate synthetic boundaries.");
    expect(JSON.parse(stdout.text())).toMatchObject({
      completed: 1,
      failed: 0,
      policyFailed: true,
    });
  },
);

test("actual CLI parsing preserves file values when flags are absent", async () => {
  const input = await fixture({
    auth: "api-key",
    scan: {
      mode: "deep",
      scope: { paths: ["src"] },
      deep: {
        workers: 8,
        subagents_per_worker: 0,
        stop_after_consecutive_errors: 2,
      },
    },
    limits: { max_cost_usd_per_scan: 7 },
    policy: { fail_on_severity: "high" },
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
      knowledge_base: ["file-context.md"],
      deep: { workers: 8, subagents_per_worker: 3 },
    },
    limits: { max_cost_usd_per_scan: 7 },
    policy: { fail_on_severity: "high" },
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

test("rerun accepts replacement scan and validation files relative to the invocation directory", async () => {
  const input = await fixture({});
  await writeFile(
    join(input.configDirectory, "instructions.md"),
    "Review the synthetic boundary.",
  );
  await writeFile(
    join(input.configDirectory, "validation.md"),
    "Validate the synthetic boundary.",
  );
  const recipe: JsonObject = {
    repository: input.repository,
    target: { kind: "repository", paths: [] },
    mode: "standard",
    config: {},
    requiresScanPrompt: true,
    validationMode: "custom",
  };
  let selected: ScanOptions | undefined;
  const stderr = capture();
  expect(
    await main(
      [
        "scans",
        "rerun",
        "saved",
        "--scan-prompt-file",
        "instructions.md",
        "--validation-prompt-file",
        "validation.md",
        "--json",
      ],
      capture().stream,
      stderr.stream,
      dependencies({
        currentDirectory: input.configDirectory,
        onWorkbench: async () => ({ recipe }),
        onTurn: (_target, options) => {
          selected = options as ScanOptions;
        },
      }),
    ),
  ).toBe(0);
  expect(selected).toMatchObject({
    scanPrompt: "Review the synthetic boundary.",
    validationPrompt: "Validate the synthetic boundary.",
    parentScanId: "saved",
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
    { working_tree: {} },
    ["--base", "HEAD~1"],
    { kind: "working_tree", base: "HEAD~1" },
  ],
  [{ working_tree: {} }, ["--no-working-tree"], "repository"],
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
  [["--workers", "2", "--mode", "standard"], "require deep mode"],
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
    scan: {
      mode: "deep",
      deep: { workers: 8, stop_after_consecutive_errors: 2 },
    },
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
    scan: { instructions_file: "scan.md", validation_file: "validate.md" },
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

test.each(["file", "CLI"])(
  "a profile selected by the %s supplies the provider model",
  async (selection) => {
    const overrideProfile = selection === "CLI";
    const input = await fixture({
      codex: {
        profile: overrideProfile ? "other" : "review",
        profiles: {
          review: { model: "synthetic-profile-model" },
          other: { model: "synthetic-other-model" },
        },
      },
    });
    let native: CodexSecurityConfig | undefined;
    expect(
      await main(
        [
          "scan",
          "-c",
          input.config,
          "--provider",
          "amazon-bedrock",
          ...(overrideProfile ? ["--codex", 'profile="review"'] : []),
          "--json",
        ],
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
      profile: "review",
      profiles: { review: { model: "synthetic-profile-model" } },
      model_provider: "amazon-bedrock",
    });
  },
);

test("an unselected file profile does not satisfy the provider model requirement", async () => {
  const input = await fixture({
    codex: {
      profiles: { review: { model: "synthetic-profile-model" } },
    },
  });
  const stderr = capture();
  let initialized = false;
  expect(
    await main(
      ["scan", "-c", input.config, "--provider", "amazon-bedrock", "--json"],
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
  expect(initialized).toBe(false);
  expect(stderr.text()).toContain(
    "--model is required when using --provider amazon-bedrock",
  );
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
      deep: { workers: 8, stop_after_consecutive_errors: 2 },
    },
    codex: {
      profile: "review",
      model: "gpt-5.6-sol",
      profiles: {
        review: { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
      },
    },
    policy: { fail_on_severity: "high" },
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
        "scan.deep.subagents_per_worker": "cli",
        "scan.deep.stop_after_no_new": "legacy",
        "scan.deep.max_time_hours": "default",
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
  [{ scan: { mode: "deep", validation_file: "validate.md" } }, "Deep"],
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
        environment: {
          OPENAI_API_KEY: "synthetic-test-key",
          CODEX_SECURITY_PROJECT_CONFIG: input.config,
        },
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
