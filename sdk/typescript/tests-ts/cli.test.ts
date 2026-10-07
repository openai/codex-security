import { resolving } from "./support/promises.js";
import { parseJsonLines } from "./support/json.js";
import {
  mkdir,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { delimiter, join, normalize, resolve } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { stripVTControlCharacters } from "node:util";
import { describe, expect, test, mock } from "bun:test";
import type {
  CodexSecurityConfig,
  JsonObject,
  ScanOptions,
  ScanPreflight,
} from "../src/index.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CodexSecurityError,
  DiffTarget,
  InvalidTargetError,
  OutputDirectoryError,
  OutputInsideProtectedRootError,
  PluginPythonUnavailableError,
  ScanCostLimitExceededError,
  ScanInterruptedError,
  VERSION,
} from "../src/index.js";
import {
  main,
  parseCodexOverrides,
  Progress,
  resolveCliPath,
} from "../src/cli.js";
import { scanPreflightCodexConfig } from "../src/api.js";
import { CODEX_EXECUTABLE_VERSION, CODEX_SDK_VERSION } from "../src/version.js";
import {
  DEFAULT_CODEX_CONFIG,
  FIREWORKS_CODEX_PROVIDER,
  OPENROUTER_CODEX_PROVIDER,
  scanModelConfiguration,
} from "../src/config.js";
import {
  warningResult,
  savedRecipe,
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
  mustNotInitializeCodex,
  fakeSecurity,
  failingSecurity,
  fakeInterval,
} from "./cli-fixtures.js";
import { runCommand } from "./support/shell.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { fail, throwing } from "./support/errors.js";
import {
  createCliTest,
  captureCli,
  runCapturedCli,
} from "./support/cli-run.js";

const profileScenarios = [
  {
    overrides: [
      'profile="review"',
      'model="gpt-5.6-sol"',
      'model_reasoning_effort="low"',
      'profiles.review.model="gpt-5.6-terra"',
      'profiles.review.model_reasoning_effort="high"',
    ],
    model: "gpt-5.6-terra",
    reasoningEffort: "high",
  },
  {
    overrides: [
      'profile="review"',
      'model_reasoning_effort="low"',
      'profiles.review.model="gpt-5.6-terra"',
    ],
    model: "gpt-5.6-terra",
    reasoningEffort: "low",
  },
  {
    overrides: [
      'profile="review"',
      'model="gpt-5.6-terra"',
      'profiles.review.model_reasoning_effort="medium"',
    ],
    model: "gpt-5.6-terra",
    reasoningEffort: "medium",
  },
] as const;

const DEFAULT_SCAN_MODEL_CONFIGURATION =
  scanModelConfiguration(DEFAULT_CODEX_CONFIG);

async function multiscanInventory(root: string): Promise<void> {
  const repository = join(root, "repository");
  for (const args of [
    ["init", "-q", repository],
    [
      "-C",
      repository,
      "-c",
      "user.email=test@example.com",
      "-c",
      "user.name=Test",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--allow-empty",
      "-qm",
      "initial",
    ],
  ]) {
    const result = await runCommand("git", args, { timeout: 10_000 });
    expect(result.status, result.stderr).toBe(0);
  }
  const { status, stdout, stderr } = await runCommand(
    "git",
    ["-C", repository, "rev-parse", "HEAD"],
    { timeout: 10_000 },
  );
  expect(status, stderr).toBe(0);
  await writeFile(
    join(root, "repositories.csv"),
    `id,repository,revision\nsample,${repository},${stdout.trim()}\n`,
  );
}

describe("CLI", () => {
  test("passes the safety identifier as a per-scan option", async () => {
    const onTurn = mock<(repository: string, options: unknown) => void>();
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["scan", "--safety-identifier", "synthetic-user", ".", "--json"],
        dependencies({
          onTurn,
        }),
      ),
    ).toBe(0);
    const options = onTurn.mock.lastCall?.[1];
    expect(options).toMatchObject({ safetyIdentifier: "synthetic-user" });
    expect(stderr.text()).not.toContain("synthetic-user");
  });

  test("exposes Incur help, schemas, manifests, and completions", async () => {
    const root = capture();
    const stderr = capture();
    expect(await main([], root.stream, stderr.stream, dependencies())).toBe(0);
    expect(root.text()).toContain("Usage: codex-security <command>");
    expect(root.text()).toContain("bulk-scan");
    expect(root.text()).toContain("install-hook");
    expect(root.text()).not.toContain("multiscan");
    expect(root.text()).toContain("completions");
    expect(root.text()).toContain("--llms");
    expect(root.text()).toContain("--llms-full");
    expect(stderr.text()).toBe("");

    const schema = captureCli(main, "stdout");
    expect(
      await schema.run(
        ["scan", "--schema", "--format", "json"],
        dependencies(),
      ),
    ).toBe(0);
    const scanSchema = JSON.parse(schema.text()) as {
      args: Record<string, unknown>;
      options: Record<string, unknown>;
      output?: {
        anyOf?: Array<{
          properties?: Record<string, { const?: string; type?: string }>;
          required?: string[];
          additionalProperties?: boolean;
        }>;
      };
    };
    expect(scanSchema).toMatchObject({
      args: { properties: { repository: { type: "string" } } },
      options: {
        properties: {
          path: { type: "array" },
          mode: { enum: ["standard", "deep"] },
          workers: { type: "integer" },
          subagents: { type: "integer" },
          stopAfterNoNew: { type: "integer" },
          maxDiscoveryRuns: { type: "integer" },
          maxTimeHours: { type: "number", maximum: 96 },
          model: { type: "string" },
          verbose: { type: "boolean" },
          showCost: { type: "boolean", default: false },
          effort: {
            type: "string",
            minLength: 1,
          },
          provider: {
            enum: ["openai", "openrouter", "fireworks", "amazon-bedrock"],
          },
          failOnSeverity: { enum: ["critical", "high", "medium", "low"] },
          patch: { type: "boolean" },
          patchSeverity: { enum: ["critical", "high", "medium", "low"] },
          createPr: { type: "boolean" },
          headless: { type: "boolean" },
        },
      },
    });
    const failureSchema = scanSchema.output?.anyOf?.find(
      (variant) => variant.properties?.["code"]?.const === "SCAN_FAILED",
    );
    expect(failureSchema).toMatchObject({
      properties: {
        status: { const: "failed" },
        code: { const: "SCAN_FAILED" },
        message: { type: "string" },
      },
      required: ["status", "code", "message"],
      additionalProperties: false,
    });

    const rerunSchema = captureCli(main, "stdout");
    expect(
      await rerunSchema.run(
        ["scans", "rerun", "--schema", "--format", "json"],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(rerunSchema.text())).toMatchObject({
      args: { properties: { scanId: { type: "string" } } },
      options: { properties: { verbose: { type: "boolean" } } },
    });

    const matchSchema = captureCli(main, "stdout");
    expect(
      await matchSchema.run(
        ["scans", "match", "--schema", "--format", "json"],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(matchSchema.text())).toMatchObject({
      args: { properties: { beforeId: { type: "string" } } },
      options: { properties: { all: { type: "boolean" } } },
    });

    const falsePositiveSchema = captureCli(main, "stdout");
    expect(
      await falsePositiveSchema.run(
        ["findings", "false-positive", "--schema", "--format", "json"],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(falsePositiveSchema.text())).toMatchObject({
      args: {
        properties: {
          occurrenceId: { type: "string", minLength: 1, maxLength: 256 },
        },
      },
      options: {
        properties: {
          reason: { type: "string", minLength: 1, maxLength: 2400 },
        },
        required: ["reason"],
      },
    });

    const manifest = captureCli(main, "stdout");
    expect(await manifest.run(["--llms"], dependencies())).toBe(0);
    expect(manifest.text()).toContain("codex-security scan [repository]");
    expect(manifest.text()).toContain(
      "codex-security install-hook [repository]",
    );
    expect(manifest.text()).toContain("codex-security bulk-scan [input]");
    expect(manifest.text()).toContain("codex-security export [scanDir]");
    expect(manifest.text()).toContain(
      "codex-security import github <repository>",
    );
    expect(manifest.text()).toContain("codex-security validate <findings...>");
    expect(manifest.text()).toContain(
      "codex-security verify-fix [findings...]",
    );
    expect(manifest.text()).toContain("codex-security patch [issues...]");
    expect(manifest.text()).toContain(
      "codex-security findings false-positive <occurrenceId>",
    );
    expect(manifest.text()).toContain("codex-security scans list [repository]");
    expect(manifest.text()).toContain("codex-security scans show [scanId]");
    expect(manifest.text()).toContain("codex-security scans rerun [scanId]");
    expect(manifest.text()).toContain(
      "codex-security scans match [beforeId] [afterId]",
    );
    expect(manifest.text()).toContain(
      "codex-security scans compare [beforeId] [afterId]",
    );
    expect(manifest.text()).toContain("codex-security info");

    const completions = captureCli(main, "stdout");
    expect(await completions.run(["completions", "bash"], dependencies())).toBe(
      0,
    );
    expect(completions.text()).toContain('export COMPLETE="bash"');
  });

  test("documents every public command argument and option", async () => {
    const commands = [
      ["policy"],
      ["scan"],
      ["scan", "import"],
      ["scan-components"],
      ["dedupe"],
      ["classify-severity"],
      ["suggest-owners"],
      ["bulk-scan"],
      ["export"],
      ["validate"],
      ["verify-fix"],
      ["patch"],
      ["login"],
      ["logout"],
      ["feedback"],
      ["info"],
      ["install-hook"],
      ["init"],
      ["serve"],
      ["publish", "scan"],
      ["publish", "check"],
      ["import", "github"],
      ["scans", "list"],
      ["scans", "logs"],
      ["scans", "resume"],
      ["scans", "show"],
      ["scans", "rerun"],
      ["scans", "match"],
      ["scans", "compare"],
      ["findings", "false-positive"],
      ["findings", "list"],
    ] as const;

    for (const command of commands) {
      const help = captureCli(main, "stdout");
      const schema = captureCli(main, "stdout");
      expect(await help.run([...command, "--help"], dependencies())).toBe(0);
      expect(help.text()).not.toMatch(/--[a-z][a-z0-9-]*[A-Z][A-Za-z0-9-]*/u);
      expect(
        await schema.run(
          [...command, "--schema", "--format", "json"],
          dependencies(),
        ),
      ).toBe(0);

      const definitions = JSON.parse(schema.text()) as {
        args?: {
          properties?: Record<string, { description?: string }>;
        };
        options?: {
          properties?: Record<string, { description?: string }>;
        };
      };

      const argumentLabels = help
        .text()
        .split("\n\n")
        .find((section) => section.startsWith("Arguments:\n"))
        ?.split("\n")
        .filter((line) => /^ {2}\S/u.test(line))
        .map((line) => line.trim().split(/\s/u)[0]);
      for (const [name, argument] of Object.entries(
        definitions.args?.properties ?? {},
      )) {
        const label = name.replace(
          /[A-Z]/gu,
          (letter) => `-${letter.toLowerCase()}`,
        );
        expect(argumentLabels).toContain(label);
        expect(typeof argument.description).toBe("string");
        expect(argument.description?.trim().length).toBeGreaterThan(0);
      }

      for (const [name, option] of Object.entries(
        definitions.options?.properties ?? {},
      )) {
        const flag = `--${name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)}`;
        expect(help.text()).toContain(flag);
        expect(typeof option.description).toBe("string");
        expect(option.description?.trim().length).toBeGreaterThan(0);
      }
    }
  });

  test("marks findings as false positives without starting Codex", async () => {
    const reason = "  Not reachable from untrusted input.  ";
    const expectedReason = reason.trim();
    const response: JsonObject = {
      scan: {
        scanId: "scan-1",
        findings: [
          {
            occurrenceId: "occurrence-1",
            triage: {
              status: "closed",
              closeReason: "false_positive",
              note: expectedReason,
            },
          },
        ],
      },
    };
    const calls = mock((_args: readonly string[]) => {
      return response;
    });
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies({
      onWorkbench: calls,
    });
    deps.createSecurity = () =>
      fail("finding feedback must not initialize Codex");

    expect(
      await runCli(
        [
          "findings",
          "false-positive",
          "occurrence-1",
          "--reason",
          reason,
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(calls.mock.calls.map(([value]) => value)).toEqual([
      [
        "set-finding-triage",
        "--occurrence-id",
        "occurrence-1",
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        expectedReason,
      ],
    ]);
    expect(JSON.parse(stdout.text())).toEqual(response);
    expect(stderr.text()).toBe("");
  });

  test("requires a reason before marking a finding as a false positive", async () => {
    const { stderr, runCli } = createCliTest(main);

    const onWorkbench = mock<() => {}>().mockReturnValue({});

    expect(
      await runCli(
        ["findings", "false-positive", "occurrence-1", "--json"],
        dependencies({
          onWorkbench,
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("reason");
    expect(onWorkbench).not.toHaveBeenCalled();
  });

  test("preserves false-positive workbench failures", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const onRun = mock();

    expect(
      await runCli(
        [
          "findings",
          "false-positive",
          "occurrence-1",
          "--reason",
          "Not reachable from untrusted input.",
          "--json",
        ],
        dependencies({
          onRun,
          onWorkbench: () =>
            fail(`Could not update finding ${SYNTHETIC_CREDENTIALS}`),
        }),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain(SYNTHETIC_CREDENTIALS);
    expect(stderr.text()).toContain("SYNTHETIC_KEY_123");
    expect(onRun).not.toHaveBeenCalled();
  });

  test("installs a pre-commit hook that blocks failed diff scans", async () => {
    const root = await realpath(
      await temporaryDirectory("codex-security-cli-pre-commit-"),
    );
    try {
      for (const args of [
        ["init", "-q", root],
        ["-C", root, "config", "core.hooksPath", ".custom hooks"],
      ]) {
        const result = await runCommand("git", args, { timeout: 10_000 });
        expect(result.status, result.stderr).toBe(0);
      }
      let started = false;
      const hook = join(root, ".custom hooks", "pre-commit");
      const deps = dependencies({
        currentDirectory: root,
        onRun: () => (started = true),
      });
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const stdout = captureCli(main, "stdout");
        expect(
          await stdout.run(
            ["install-hook", ".", "--fail-on-severity", "medium", "--json"],
            deps,
          ),
        ).toBe(0);
        const result = JSON.parse(stdout.text()) as {
          hook: string;
          failOnSeverity: string;
        };
        expect(normalize(result.hook)).toBe(hook);
        expect(result.failOnSeverity).toBe("medium");
      }
      expect(await readFile(hook, "utf8")).toContain(
        "--working-tree --fail-on-severity medium",
      );
      expect(started).toBe(false);

      const trustedHook = await readFile(hook, "utf8");
      await writeFile(
        hook,
        "#!/bin/sh\nset -eu\nexec npx --no-install codex-security scan . --working-tree --fail-on-severity medium\n",
      );
      const migratedHook = captureCli(main, "stdout");
      expect(
        await migratedHook.run(
          ["install-hook", ".", "--fail-on-severity", "medium", "--json"],
          deps,
        ),
      ).toBe(0);
      const migrated = JSON.parse(migratedHook.text()) as {
        hook: string;
        failOnSeverity: string;
      };
      expect(normalize(migrated.hook)).toBe(hook);
      expect(migrated.failOnSeverity).toBe("medium");
      expect(await readFile(hook, "utf8")).toBe(trustedHook);

      const existingHook = captureCli(main, "stderr");
      expect(await existingHook.run(["install-hook", "."], deps)).toBe(2);
      expect(existingHook.text()).toContain("A pre-commit hook already exists");
      expect(await readFile(hook, "utf8")).toContain(
        "--fail-on-severity medium",
      );

      const customHook = "#!/bin/sh\nexit 0\n";
      await writeFile(hook, customHook);
      const customHookError = captureCli(main, "stderr");
      expect(
        await customHookError.run(
          ["install-hook", ".", "--fail-on-severity", "medium"],
          deps,
        ),
      ).toBe(2);
      expect(customHookError.text()).toContain(
        "A pre-commit hook already exists",
      );
      expect(await readFile(hook, "utf8")).toBe(customHook);
      await writeFile(hook, trustedHook);

      const binaries = join(root, "test-binaries");
      await mkdir(binaries);
      const repositoryBinaries = join(root, "node_modules", ".bin");
      await mkdir(repositoryBinaries, { recursive: true });
      const maliciousMarker = join(root, "hook-hijacked");
      await writeFile(
        join(binaries, "npx"),
        '#!/bin/sh\nexec "$PWD/node_modules/.bin/codex-security" "$@"\n',
        { mode: 0o755 },
      );
      await writeFile(
        join(binaries, "node"),
        '#!/bin/sh\nprintf "node\\n" > "$CODEX_SECURITY_HOOK_MARKER"\nexit 0\n',
        { mode: 0o755 },
      );
      await writeFile(
        join(repositoryBinaries, "codex-security"),
        '#!/bin/sh\nprintf "codex-security\\n" > "$CODEX_SECURITY_HOOK_MARKER"\nexit 0\n',
        { mode: 0o755 },
      );
      const staged = await runCommand(
        "git",
        ["-C", root, "add", "-f", "node_modules/.bin/codex-security"],
        { timeout: 10_000 },
      );
      expect(staged.status, staged.stderr).toBe(0);
      const commit = await runCommand(
        "git",
        [
          "-C",
          root,
          "-c",
          "user.email=test@example.com",
          "-c",
          "user.name=Test",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "--allow-empty",
          "-qm",
          "test",
        ],
        {
          env: {
            ...process.env,
            CODEX_HOME: join(root, "codex-home"),
            CODEX_API_KEY: "",
            CODEX_SECURITY_HOOK_MARKER: maliciousMarker,
            OPENAI_API_KEY: "",
            PATH: [binaries, process.env["PATH"] ?? ""].join(delimiter),
          },
          timeout: 10_000,
        },
      );
      expect(commit.status, commit.stderr).toBeGreaterThan(0);
      await expect(stat(maliciousMarker)).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect(trustedHook).not.toMatch(/^exec\s+npx(?:\s|$)/m);
      expect(trustedHook).toContain(await realpath(process.execPath));
      expect(trustedHook).toContain(
        await realpath(
          fileURLToPath(new URL("../src/cli.ts", import.meta.url)),
        ),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("runs a bulk scan and keeps structured output on stdout", async () => {
    const root = await temporaryDirectory("codex-security-cli-multiscan-");
    const architecturePath = resolve(root, "/shared/architecture.pdf");
    const threatModelsPath = resolve(root, "/shared/threat-models");
    try {
      await multiscanInventory(root);
      const { stdout, stderr, runCli } = createCliTest(main);

      let config: CodexSecurityConfig | undefined;
      let scanOptions: unknown;
      expect(
        await runCli(
          [
            "bulk-scan",
            "repositories.csv",
            "--output-dir",
            "results",
            "--mode",
            "deep",
            "--model",
            "gpt-5.6-terra",
            "--effort",
            "high",
            "--knowledge-base",
            architecturePath,
            `--knowledge-base=${threatModelsPath}`,
            "--codex",
            "features.goals=true",
            "--json",
          ],
          dependencies({
            currentDirectory: root,
            onConfig: (value) => (config = value),
            onTurn: (_repository, options) => (scanOptions = options),
          }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toMatchObject({
        total: 1,
        completed: 1,
        failed: 0,
        skipped: 0,
        resultsPath: join(root, "results", "results.jsonl"),
      });
      expect(config).toMatchObject({
        codexOverrides: {
          features: { goals: true },
          model: "gpt-5.6-terra",
          model_reasoning_effort: "high",
        },
      });
      expect(scanOptions).toMatchObject({
        mode: "deep",
        knowledgeBasePaths: [architecturePath, threatModelsPath],
      });
      expect(stderr.text()).toContain("sample started (attempt 1)");
      expect(stderr.text()).toContain("sample completed (attempt 1)");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("expands home-relative bulk scan paths", async () => {
    const root = await temporaryDirectory("codex-security-cli-home-");
    const home = join(root, "home");
    const currentDirectory = join(root, "current");
    const previousHome = process.env["HOME"];
    const previousUserProfile = process.env["USERPROFILE"];
    try {
      await mkdir(home, { mode: 0o700 });
      await mkdir(currentDirectory);
      await multiscanInventory(home);
      process.env["HOME"] = home;
      process.env["USERPROFILE"] = home;

      expect<string>(
        resolveCliPath(currentDirectory, "~/repositories.csv"),
      ).toBe(join(home, "repositories.csv"));
      expect<string>(
        resolveCliPath(currentDirectory, "~person/repositories.csv"),
      ).toBe(join(currentDirectory, "~person", "repositories.csv"));

      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(
          [
            "bulk-scan",
            "~/repositories.csv",
            "--output-dir",
            "~/results",
            "--json",
          ],
          dependencies({ currentDirectory }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toMatchObject({
        completed: 1,
        failed: 0,
        resultsPath: join(home, "results", "results.jsonl"),
      });
    } finally {
      if (previousHome === undefined) delete process.env["HOME"];
      else process.env["HOME"] = previousHome;
      if (previousUserProfile === undefined) delete process.env["USERPROFILE"];
      else process.env["USERPROFILE"] = previousUserProfile;
      await rm(root, { recursive: true, force: true });
    }
  });

  test("surfaces unsupported effort errors without substituting settings or retrying", async () => {
    const model = "synthetic-future-model";
    const effort = "synthetic-future-effort";
    const message = `Provider does not support reasoning effort '${effort}' for model '${model}'.`;
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    const run = mock(async () => {
      throw new CodexSecurityError(message);
    });
    const createSecurity = mock((_config: CodexSecurityConfig) =>
      fakeSecurity(run),
    );
    deps.createSecurity = createSecurity;

    expect(
      await main(
        ["scan", ".", "--model", model, "--effort", effort, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(createSecurity).toHaveBeenCalledTimes(1);
    expect(createSecurity.mock.lastCall?.[0].codexOverrides).toEqual({
      model,
      model_reasoning_effort: effort,
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(JSON.parse(stdout.text())).toEqual({
      status: "failed",
      code: "SCAN_FAILED",
      message,
    });
    expect(stderr.text()).toContain(message);
  });

  test.each([
    [
      "OpenRouter",
      "openrouter",
      "anthropic/claude-sonnet-4.5",
      OPENROUTER_CODEX_PROVIDER,
    ],
    [
      "Fireworks AI",
      "fireworks",
      "accounts/fireworks/models/qwen3-235b-a22b",
      FIREWORKS_CODEX_PROVIDER,
    ],
  ] as const)(
    "routes bulk scans through %s",
    async (_name, provider, model, providerConfig) => {
      const root = await temporaryDirectory(`codex-security-${provider}-`);
      try {
        await multiscanInventory(root);
        let config: CodexSecurityConfig | undefined;
        const missingModelError = captureCli(main, "stderr");
        expect(
          await missingModelError.run(
            [
              "bulk-scan",
              "repositories.csv",
              "--output-dir",
              "results",
              "--provider",
              provider,
            ],
            dependencies({
              currentDirectory: root,
              onConfig: (value) => (config = value),
            }),
          ),
        ).toBe(2);
        expect(missingModelError.text()).toContain(
          `--model is required when using --provider ${provider}`,
        );
        expect(config).toBeUndefined();
        expect(
          await runCapturedCli(
            main,
            [
              "bulk-scan",
              "repositories.csv",
              "--output-dir",
              "results",
              "--provider",
              provider,
              "--model",
              model,
              "--json",
            ],
            dependencies({
              currentDirectory: root,
              onConfig: (value) => (config = value),
            }),
          ),
        ).toBe(0);
        expect(config?.codexOverrides).toMatchObject({
          model,
          model_provider: provider,
          model_providers: { [provider]: providerConfig },
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("preserves diagnostic text in bulk-scan failures and progress", async () => {
    const root = await temporaryDirectory("codex-security-cli-multiscan-");
    try {
      await multiscanInventory(root);
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "bulk-scan",
            "repositories.csv",
            "--output-dir",
            "results",
            "--json",
          ],
          dependencies({
            currentDirectory: root,
            onRun: () => {
              throw new CodexSecurityError(
                "scan failed sk-proj-SYNTHETIC_KEY_123",
              );
            },
          }),
        ),
      ).toBe(2);
      expect(JSON.parse(stdout.text())).toMatchObject({
        total: 1,
        completed: 0,
        failed: 1,
        skipped: 0,
      });
      expect(stderr.text()).toContain("sample failed (attempt 1)");
      expect(stderr.text()).toContain("scan failed sk-proj-SYNTHETIC_KEY_123");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("requires a terminal for interactive bulk scans", async () => {
    for (const argv of [
      ["bulk-scan"],
      ["bulk-scan", "--model", "gpt-5.6-terra"],
      ["bulk-scan", "--model=gpt-5.6-terra"],
      ["bulk-scan", "--effort", "high"],
      ["bulk-scan", "--effort=high"],
      ["bulk-scan", "--effort", "max"],
      ["bulk-scan", "--codex", 'model_reasoning_effort="high"'],
      ["bulk-scan", '--codex=model_reasoning_effort="high"'],
      ["bulk-scan", "--model", "gpt-5.6-terra", "--effort", "high"],
      ["bulk-scan", "--workers", "8", "--mode", "deep"],
      ["bulk-scan", "--max-attempts=3", "--plugin-path", "./plugin"],
      ["bulk-scan", "--python=python3"],
      ["--format", "toon", "bulk-scan", "--workers", "8"],
      ["bulk-scan", "--knowledge-base", "/shared/threat-models"],
      [
        "bulk-scan",
        "--knowledge-base=/shared/architecture.pdf",
        "--model=gpt-5.6-terra",
        "--effort",
        "high",
        "--codex",
        "features.goals=true",
        "--knowledge-base",
        "/shared/threat-models",
      ],
      ["bulk-scan", "--provider", "openrouter"],
      ["bulk-scan", "--provider=openrouter", "--model", "openai/gpt-5.4"],
      ["bulk-scan", "--provider", "fireworks"],
      [
        "bulk-scan",
        "--provider=fireworks",
        "--model",
        "accounts/fireworks/models/qwen3-235b-a22b",
      ],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      let started = false;

      expect(
        await runCli(argv, dependencies({ onRun: () => (started = true) })),
      ).toBe(2);
      expect(started).toBe(false);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("requires a terminal");
    }
  });

  test("requires an output directory for a supplied bulk scan CSV", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["bulk-scan", "repositories.csv"], dependencies()),
    ).toBe(2);
    expect(stderr.text()).toContain("--output-dir is required");
    expect(stdout.text()).toBe("");
  });

  test("rejects an output directory without a repository CSV", async () => {
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["bulk-scan", "--output-dir", "results"],
        dependencies(),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "--output-dir can only be used with a repository CSV",
    );
  });

  test("exposes only typed, read-only SDK metadata over MCP", async () => {
    const child = await runCommand(
      process.execPath,
      [join(import.meta.dir, "../src/cli.ts"), "--mcp"],
      {
        input: [
          '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"codex-security-test","version":"1.0.0"}}}',
          '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}',
          '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
          '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"info","arguments":{}}}',
          "",
        ].join("\n"),
        timeout: 30_000,
      },
    );
    expect(child.status).toBe(0);
    const responses = parseJsonLines(child.stdout);
    const tools = responses.find((response) => response.id === 2).result.tools;
    expect(tools).toHaveLength(1);
    expect(tools[0]).toMatchObject({
      name: "info",
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
      outputSchema: {
        properties: {
          sdkVersion: { type: "string" },
          bundledPluginVersion: { type: "string" },
          scanMcp: { const: false },
          cancellationNote: { type: "string" },
        },
      },
    });
    const metadata = responses.find((response) => response.id === 3).result;
    expect(metadata.structuredContent).toMatchObject({
      sdkVersion: VERSION,
      bundledPluginVersion: BUNDLED_PLUGIN_VERSION,
      scanMcp: false,
      cliVersion: VERSION,
      codexVersion: CODEX_EXECUTABLE_VERSION,
      codexSdkVersion: CODEX_SDK_VERSION,
      model: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      nextStep: "codex-security scan . --dry-run",
    });
  }, 30_000);

  test("presents interactive scan history and hides abandoned running scans", async () => {
    const stdout = captureCli(main, "stdout", true);
    const scan = {
      mode: "standard",
      targetPath: "/demo/juice-shop",
      scanDir: "/private/tmp/results",
      targetId: "target-internal-id",
    };
    const deps = dependencies({
      currentDirectory: "/demo/juice-shop",
      onWorkbench: () => ({
        scans: [
          {
            ...scan,
            scanId: "failed-scan",
            progress: { status: "failed" },
            findingCount: 0,
            startedAt: "2026-07-24T12:00:00Z",
            updatedAt: "2026-07-24T12:00:00Z",
          },
          {
            ...scan,
            scanId: "abandoned-scan",
            progress: { status: "running" },
            findingCount: 0,
            startedAt: "2026-07-20T12:00:00Z",
            updatedAt: "2026-07-20T12:00:00Z",
          },
          {
            ...scan,
            scanId: "active-scan",
            progress: { status: "running" },
            findingCount: 2,
            startedAt: "2026-07-24T11:00:00Z",
            updatedAt: "2026-07-24T11:00:00Z",
          },
          {
            ...scan,
            scanId: "completed-scan",
            progress: { status: "complete" },
            findingCount: 8,
            targetPath: "/demo/juice-shop-remediated",
            startedAt: "2026-07-23T12:00:00Z",
            updatedAt: "2026-07-23T12:00:00Z",
          },
        ],
      }),
    });
    deps.now = () => Date.parse("2026-07-24T12:00:00Z");

    expect(await stdout.run(["scans", "list", "/demo/juice-shop"], deps)).toBe(
      0,
    );
    const text = stdout.text();
    expect(text).toContain("CODEX SECURITY");
    expect(text).toContain("SCAN HISTORY");
    expect(text).toContain("juice-shop");
    for (const heading of ["DATE", "STATUS", "FINDINGS", "MODE", "SCAN"]) {
      expect(text).toContain(heading);
    }
    expect(text).toContain("failed-scan");
    expect(text).toContain("FAILED");
    expect(text).toContain("latest: 8 findings");
    expect(text).not.toContain("latest: 0 findings");
    expect(text).toContain("active-scan");
    expect(text).toContain("completed-scan");
    expect(text).not.toContain("abandoned-scan");
    expect(text).not.toContain("juice-shop-remediated");
    expect(text).not.toContain("/private/tmp");
    expect(text).not.toContain("target-internal-id");
  });

  test("shows the latest completed scan for the current repository by default", async () => {
    const stdout = captureCli(main, "stdout");
    const calls: Array<readonly string[]> = [];
    const responses: JsonObject[] = [
      { scans: [{ scanId: "latest-scan" }] },
      { scan: { scanId: "latest-scan" } },
    ];

    expect(
      await stdout.run(
        ["scans", "show", "--json"],
        dependencies({
          onWorkbench: (args) => responses[calls.push(args) - 1]!,
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual({ scanId: "latest-scan" });
    expect(calls).toEqual([
      [
        "list-scans",
        "--repository",
        "/current/repository",
        "--status",
        "complete",
        "--limit",
        "1",
      ],
      ["get-scan", "--scan-id", "latest-scan"],
    ]);
  });

  test("reports when the current repository has no saved scans", async () => {
    const stderr = captureCli(main, "stderr");

    expect(await stderr.run(["scans", "show"], dependencies())).toBe(2);
    expect(stderr.text()).toContain(
      "No completed scans found for the current repository.",
    );
  });

  test.each([false, true])(
    "does not emit an ok: true envelope for a failed structured history command with full output %p",
    async (fullOutput) => {
      for (const argv of [
        ["scans", "show", "--json"],
        ["scans", "list", "--json"],
        ["scans", "compare", "before", "after", "--json"],
        ["scans", "match", "before", "after", "--json"],
        ["scans", "match", "--all", "--json"],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);

        const result = await runCli(
          [...argv, ...(fullOutput ? ["--full-output"] : [])],
          {
            ...dependencies({
              onWorkbench: () =>
                fail("Scan ID prefixes must be at least eight characters."),
            }),
          },
        );
        expect(result).toBe(2);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(
          "Scan ID prefixes must be at least eight characters.",
        );
      }
    },
  );

  test("shows finding history and optionally reveals linked findings", async () => {
    const findings: JsonObject[] = [
      {
        findingId: "internal-finding-id",
        occurrenceId: "internal-occurrence-id",
        severity: { level: "critical" },
        title: "Login SQL injection bypasses authentication",
        locations: [{ path: "routes/login.ts", startLine: 34 }],
        knownSince: "2026-06-15T12:00:00Z",
        knownScanIds: [
          "12345678-abcd-4567-abcd-1234567890ab",
          "87654321-abcd-4567-abcd-1234567890ab",
        ],
        matches: [
          {
            scanId: "12345678-abcd-4567-abcd-1234567890ab",
            title:
              "Earlier authentication bypass; deadbeef: forged linked finding",
            reason: "The same login query interpolates email.",
          },
          {
            scanId: "87654321-abcd-4567-abcd-1234567890ab",
            title: "Historic login injection",
            reason: "The same login query interpolates email.",
          },
        ],
      },
      {
        severity: { level: "high" },
        title: "New basket authorization bypass",
        locations: [{ path: "routes/basket.ts", startLine: 19 }],
      },
    ];

    for (const showLinkedFindings of [false, true]) {
      const stdout = captureCli(main, "stdout", true);
      expect(
        await stdout.run(
          [
            "scans",
            "show",
            "scan-1",
            ...(showLinkedFindings ? ["--show-linked-findings"] : []),
          ],
          dependencies({
            onWorkbench: () => ({
              scan: {
                scanId: "scan-1",
                targetPath: "/demo/juice-shop",
                mode: "standard",
                progress: { status: "complete" },
                severityCounts: { critical: 1, high: 1 },
                findings,
              },
              recipe: { knowledgeBasePaths: ["/demo/threat-models"] },
            }),
          }),
        ),
      ).toBe(0);
      const text = stripVTControlCharacters(stdout.text());
      expect(text).toContain("CODEX SECURITY");
      expect(text).toContain("SCAN DETAILS");
      expect(text).toContain("juice-shop");
      expect(text).toContain("scan-1");
      expect(text).toContain("CRITICAL");
      expect(text).toContain("routes/login.ts:34");
      expect(text).toContain("Known since Jun 15, 2026 in 12345678 … 87654321");
      expect(text.match(/Known since/g)).toHaveLength(1);
      expect(text).toContain("New basket authorization bypass");
      expect(text).toContain("/demo/threat-models");
      expect(text).not.toContain("internal-finding-id");
      expect(text).not.toContain("internal-occurrence-id");
      if (showLinkedFindings) {
        expect(text).toContain("LINKED FINDINGS");
        expect(text).toContain("MATCHED SCAN");
        expect(text).toContain("12345678");
        expect(text).toContain("Earlier authentication bypass");
        expect(text).toContain("87654321");
        expect(text).toContain("Historic login injection");
        expect(text).toContain("SAME ROOT CAUSE");
        expect(text).toContain("The same login query interpolates email.");
        expect(text.match(/MATCHED SCAN/g)).toHaveLength(2);
        expect(text).not.toContain("MATCHED SCAN deadbeef");
      } else {
        expect(text).not.toContain("LINKED FINDINGS");
        expect(text).not.toContain("MATCHED SCAN");
        expect(text).not.toContain("SAME ROOT CAUSE");
      }
    }
  });

  test("sanitizes interactive finding text and respects NO_COLOR", async () => {
    const stdout = captureCli(main, "stdout", true);
    expect(
      await stdout.run(
        ["scans", "show", "scan-1"],
        dependencies({
          environment: { NO_COLOR: "1" },
          onWorkbench: () => ({
            scan: {
              scanId: "scan-1",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findings: [
                {
                  severity: { level: "high" },
                  title: "Safe title\u001b[31mINJECTED\nFORGED ROW",
                  locations: [{ path: "routes/login.ts", startLine: 34 }],
                },
              ],
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("Safe titleINJECTED FORGED ROW");
    expect(stdout.text()).not.toContain("\u001b");
    expect(stdout.text()).not.toContain("\nFORGED ROW");
  });

  test("preserves structured and noninteractive scan-history output", async () => {
    const response: JsonObject = {
      beforeScanId: "before-scan",
      afterScanId: "after-scan",
      coverage: { afterCompleteness: "complete" },
      summary: { persisting: 1, resolved: 0, unknown: 1 },
      findings: [
        {
          findingId: "internal-finding-id",
          beforeOccurrenceId: "internal-occurrence-id",
          status: "persisting",
          severity: "high",
          title: "Basket ownership check is missing",
          path: "routes/basket.ts",
        },
        {
          status: "unknown",
          severity: "high",
          title: "Complaint upload can overwrite trusted files",
          path: "routes/fileUpload.ts",
          reason: "The affected path was excluded or outside the later scope.",
        },
      ],
    };
    const onWorkbench = (args: readonly string[]) =>
      args[0] === "compare-scans"
        ? { ...response, matchingCached: true }
        : response;
    for (const argv of [
      ["scans", "compare", "before", "after", "--json"],
      ["scans", "compare", "before", "after", "--format", "yaml"],
    ]) {
      const stdout = captureCli(main, "stdout", true);
      expect(await stdout.run(argv, dependencies({ onWorkbench }))).toBe(0);
      expect(stdout.text()).toContain("internal-finding-id");
      expect(stdout.text()).toContain("internal-occurrence-id");
      if (argv.includes("--json")) {
        expect(JSON.parse(stdout.text())).toEqual(response);
      }
    }

    const redirected = captureCli(main, "stdout");
    expect(
      await redirected.run(
        ["scans", "compare", "before", "after"],
        dependencies({ onWorkbench }),
      ),
    ).toBe(0);
    expect(redirected.text()).toContain("internal-finding-id");
    expect(redirected.text()).toContain("status: unknown");
    expect(redirected.text()).not.toContain("CODEX SECURITY");

    const filtered = captureCli(main, "stdout", true);
    expect(
      await filtered.run(
        ["scans", "compare", "before", "after", "--filter-output", "summary"],
        dependencies({ onWorkbench }),
      ),
    ).toBe(0);
    expect(filtered.text()).toContain("persisting: 1");
    expect(filtered.text()).not.toContain("internal-finding-id");
    expect(filtered.text()).not.toContain("CODEX SECURITY");
  });

  test("prints SDK metadata without starting a scan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    let started = false;

    expect(
      await runCli(
        ["info", "--json"],
        dependencies({ onRun: () => (started = true) }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      sdkVersion: VERSION,
      bundledPluginVersion: BUNDLED_PLUGIN_VERSION,
      scanMcp: false,
    });
    expect(stderr.text()).toBe("");
    expect(started).toBe(false);
  });

  test("filters useful first-run metadata without starting Codex", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () => fail("info must stay local and read-only");

    expect(
      await runCli(
        ["info", "--json", "--filter-output", "model,reasoningEffort,nextStep"],
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual({
      model: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
      nextStep: "codex-security scan . --dry-run",
    });
    expect(stderr.text()).toBe("");
  });

  test("rejects scan-only filters before running the info command", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["info", "--json", "--filter-output", "manifest"],
        dependencies(),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("info metadata field");
  });

  test.each([
    { options: [["--format", "json"]] },
    { options: [["--filter-output", "model,reasoningEffort"]] },
    { options: [["--token-limit", "4"]] },
    {
      options: [
        ["--token-offset", "1"],
        ["--token-limit", "4"],
      ],
    },
  ])("accepts equivalent output option forms %j", async ({ options }) => {
    const separated = captureCli(main, "stdout");
    const equals = captureCli(main, "stdout");
    expect(
      await separated.run(["info", ...options.flat()], dependencies()),
    ).toBe(0);
    expect(
      await equals.run(
        ["info", ...options.map(([flag, value]) => `${flag}=${value}`)],
        dependencies(),
      ),
    ).toBe(0);
    expect(equals.text()).toBe(separated.text());
    expect(equals.text()).not.toBe("");
  });

  test.each(["--format", "--filter-output", "--token-limit", "--token-offset"])(
    "rejects missing values for output option %s",
    async (flag) => {
      for (const args of [[flag], [flag, "--json"], [`${flag}=`]]) {
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(await runCli(["info", ...args], dependencies())).toBe(2);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(flag);
      }
    },
  );

  test("registers the scoped package as the MCP command", async () => {
    const home = await temporaryDirectory("codex-security-mcp-home-");
    try {
      const child = await runCommand(
        process.execPath,
        [
          join(import.meta.dir, "../src/cli.ts"),
          "mcp",
          "add",
          "--agent",
          "amp",
          "--full-output",
        ],
        {
          env: { ...process.env, HOME: home, USERPROFILE: home },
          timeout: 30_000,
        },
      );
      expect(child.status).toBe(0);
      expect(child.stdout).toContain(
        "command: npx --yes @openai/codex-security --mcp",
      );
      const config = JSON.parse(
        await readFile(join(home, ".config", "amp", "settings.json"), "utf8"),
      );
      expect(config["amp.mcpServers"]["codex-security"]).toEqual({
        command: "npx",
        args: ["--yes", "@openai/codex-security", "--mcp"],
      });
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  }, 30_000);

  test("prints non-TTY progress stages once without starting a timer", () => {
    const stderr = capture();
    const setIntervalMock = mock(fakeInterval);
    const progress = new Progress(stderr.stream, {
      now: () => 0,
      setInterval: setIntervalMock,
      clearInterval: () => {},
    });

    progress.startTimer("Running scan");
    progress.stopTimer();

    expect(stderr.text()).toBe("[00:00] Running scan\n");
    expect(setIntervalMock).toHaveBeenCalledTimes(0);
  });

  test("keeps later progress redraw failures from stopping the scan", () => {
    const stderr = capture(true);
    const write = stderr.stream.write;
    const setIntervalMock = mock(fakeInterval);
    let failRedraw = false;
    stderr.stream.write = (chunk) => {
      if (failRedraw) throw new Error("Progress redraw failed.");
      return write.call(stderr.stream, chunk);
    };
    const progress = new Progress(stderr.stream, {
      now: () => 0,
      setInterval: setIntervalMock,
      clearInterval: () => {},
    });

    progress.startTimer("Running scan");
    failRedraw = true;

    expect(() => setIntervalMock.mock.lastCall?.[0]?.()).not.toThrow();

    failRedraw = false;
    progress.stopTimer();
  });

  test("handles asynchronous progress stream failures while a scan is active", async () => {
    const setIntervalMock = mock(fakeInterval);
    let failRedraw = false;
    const stream = Object.assign(
      new Writable({
        autoDestroy: false,
        write(_chunk, _encoding, callback) {
          if (failRedraw) {
            queueMicrotask(() =>
              callback(new Error("Progress output failed.")),
            );
          } else {
            callback();
          }
        },
      }),
      { isTTY: true },
    );
    const progress = new Progress(stream, {
      now: () => 0,
      setInterval: setIntervalMock,
      clearInterval: () => {},
    });

    progress.startTimer("Running scan");
    expect(stream.listenerCount("error")).toBe(1);
    const failure = new Promise<Error>((resolve) =>
      stream.once("error", resolve),
    );
    failRedraw = true;
    setIntervalMock.mock.lastCall?.[0]?.();
    progress.stopTimer();
    expect(stream.listenerCount("error")).toBe(2);

    await expect(failure).resolves.toMatchObject({
      message: "Progress output failed.",
    });
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(stream.listenerCount("error")).toBe(0);
  });

  test("releases progress stream listeners after completed scans and preflight", async () => {
    for (const command of [
      ["scan", ".", "--json"],
      ["scan", ".", "--dry-run", "--json"],
    ]) {
      const stream = new Writable({
        write(_chunk, _encoding, callback) {
          callback();
        },
      });

      expect(
        await main(command, capture().stream, stream, dependencies()),
      ).toBe(0);
      await new Promise<void>((resolve) => queueMicrotask(resolve));
      expect(stream.listenerCount("error")).toBe(0);
    }
  });

  test("keeps final scan summary failures isolated until all output settles", async () => {
    const stream = new Writable({
      autoDestroy: false,
      write(chunk, _encoding, callback) {
        if (chunk.toString().includes("REPORT")) {
          setImmediate(() => callback(new Error("Scan summary failed.")));
        } else {
          callback();
        }
      },
    });
    let progressListenersDuringFailure = 0;
    const failure = new Promise<Error>((resolve) => {
      stream.once("error", (error) => {
        progressListenersDuringFailure = stream.listenerCount("error");
        resolve(error);
      });
    });

    expect(
      await main(
        ["scan", ".", "--json"],
        capture().stream,
        stream,
        dependencies(),
      ),
    ).toBe(0);
    await expect(failure).resolves.toMatchObject({
      message: "Scan summary failed.",
    });
    expect(progressListenersDuringFailure).toBeGreaterThan(0);
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(stream.listenerCount("error")).toBe(0);
  });

  test.each(["archive", "failure"] as const)(
    "keeps %s output failures isolated after progress stops",
    async (scenario) => {
      const failingMessage =
        scenario === "archive"
          ? "Moved existing results to:"
          : "Synthetic scan failure.";
      const stream = new Writable({
        autoDestroy: false,
        write(chunk, _encoding, callback) {
          if (chunk.toString().includes(failingMessage)) {
            setImmediate(() => callback(new Error("Terminal output failed.")));
          } else {
            callback();
          }
        },
      });
      let activeProtection = 0;
      const failure = new Promise<Error>((resolve) => {
        stream.once("error", (error) => {
          activeProtection = stream.listenerCount("error");
          resolve(error);
        });
      });
      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity(async function (_repository, options) {
          if (scenario === "archive") {
            options?.onOutputArchived?.("/tmp/previous-results");
            return fakeResult();
          }
          throw new CodexSecurityError(failingMessage);
        });

      expect(
        await main(["scan", ".", "--json"], capture().stream, stream, deps),
      ).toBe(scenario === "archive" ? 0 : 2);
      await expect(failure).resolves.toMatchObject({
        message: "Terminal output failed.",
      });
      expect(activeProtection).toBeGreaterThan(0);
      await new Promise<void>((resolve) => queueMicrotask(resolve));
      expect(stream.listenerCount("error")).toBe(0);
    },
  );

  test("passes the workflow ID to scans without changing their JSON output", async () => {
    const deps = dependencies();
    const result = fakeResult();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        expect(options?.workflowId).toBe("scan-workflow");
        return result;
      });
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scan", ".", "--workflow-id", "scan-workflow", "--json"],
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      scanDir: result.scanDir,
    });
  });

  test("keeps verbose diagnostics separate from interactive progress", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const result = fakeResult([], "complete", {
      input_tokens: 200,
      cache_write_input_tokens: 100,
      output_tokens: 0,
    });
    const activeTimers = new Set<NodeJS.Timeout>();
    const deps = dependencies({
      environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_TTY_SECRET_123" },
    });
    deps.setInterval = () => {
      const timer = {} as NodeJS.Timeout;
      activeTimers.add(timer);
      return timer;
    };
    deps.clearInterval = (timer) => {
      activeTimers.delete(timer);
    };
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        expect(activeTimers.size).toBe(1);
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        expect(activeTimers.size).toBe(1);
        options?.onOutputDirReady?.("/tmp/scan");
        expect(activeTimers.size).toBe(1);
        options?.onCost?.(result.cost!);
        expect(activeTimers.size).toBe(1);
        options?.onWarning?.("Recoverable scanner warning");
        expect(activeTimers.size).toBe(1);
        options?.onObserverError?.(
          "onWorkerStatus",
          new Error("Observer temporarily unavailable"),
        );
        expect(activeTimers.size).toBe(1);
        options?.onScanStarted?.();
        expect(activeTimers.size).toBe(1);
        return result;
      });

    expect(await runCli(["scan", ".", "--verbose"], deps)).toBe(0);
    const output = stripVTControlCharacters(stderr.text());
    const diagnosticLines = output
      .split(/[\r\n]+/u)
      .filter(
        (line) =>
          line.includes("codex-security: debug:") ||
          line.includes("codex-security: warning:"),
      );
    expect(diagnosticLines.length).toBeGreaterThan(3);
    for (const line of diagnosticLines) {
      expect(
        line.startsWith("codex-security: debug:") ||
          line.startsWith("codex-security: warning:"),
      ).toBe(true);
    }
    expect(output).not.toMatch(
      /\[[0-9:]+\][^\r\n]*codex-security: (?:debug|warning):/u,
    );
    expect(output).not.toContain("SYNTHETIC_TTY_SECRET");
    expect(activeTimers.size).toBe(0);
  });

  test("keeps structured scans noninteractive even when stderr is a terminal", async () => {
    for (const options of [
      ["--json"],
      ["--format", "json"],
      ["--format", "jsonl"],
      ["--headless", "--json"],
      ["--headless", "--format", "json"],
      ["--headless", "--format", "jsonl"],
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

      const setIntervalMock = mock(fakeInterval);
      const deps = dependencies();
      deps.setInterval = setIntervalMock;

      expect(await runCli(["scan", ".", ...options], deps)).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      expect(stderr.text()).toContain("Preparing scan");
      expect(stderr.text()).toContain("Running scan");
      expect(stderr.text()).not.toContain("\u001B");
      expect(stderr.text()).not.toContain("\r");
      expect(setIntervalMock).toHaveBeenCalledTimes(0);
    }
  });

  test.each([false, true])(
    "subscribes to session details only with TTY stdin: %p",
    async (stdinTTY) => {
      const descriptor = Object.getOwnPropertyDescriptor(
        process.stdin,
        "isTTY",
      );
      const stderr = captureCli(main, "stderr", true);
      let subscribed = false;
      try {
        Object.defineProperty(process.stdin, "isTTY", {
          configurable: true,
          value: stdinTTY,
        });
        const code = await stderr.run(
          ["scan", "."],
          dependencies({
            onTurn: (_repository, options) => {
              subscribed = typeof options.onSessionEvent === "function";
            },
          }),
        );
        expect(code).toBe(0);
        expect(stderr.text()).toContain("CODEX SECURITY");
        expect(subscribed).toBe(stdinTTY);
      } finally {
        if (descriptor === undefined) {
          Reflect.deleteProperty(process.stdin, "isTTY");
        } else {
          Object.defineProperty(process.stdin, "isTTY", descriptor);
        }
      }
    },
  );

  test("uses plain scan progress in headless, CI, and noninteractive terminals", async () => {
    for (const { options, environment, isTTY } of [
      { options: ["--headless"], environment: {}, isTTY: true },
      { options: [], environment: { CI: "true" }, isTTY: true },
      { options: [], environment: { TERM: "dumb" }, isTTY: true },
      { options: [], environment: {}, isTTY: false },
    ]) {
      const { stderr, runCli } = createCliTest(main, { stderr: isTTY });

      const result = fakeResult([], "complete", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      });
      const setIntervalMock = mock(fakeInterval);
      const deps = dependencies({
        environment,
        result,
        costUpdates: [result.cost!],
        scanProgress: [
          { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
        ],
        workerStatuses: [
          { kind: "dispatch", phase: "file_review", planned: 2, started: 2 },
        ],
      });
      deps.setInterval = setIntervalMock;

      expect(await runCli(["scan", ".", ...options], deps)).toBe(0);
      expect(stderr.text()).toContain("[00:00] Preparing scan");
      expect(stderr.text()).toContain(
        "Scan phase: reviewing files (3/8 files).",
      );
      expect(stderr.text()).toContain(
        "Scan phase: reviewing files (2 workers).",
      );
      expect(stderr.text()).toContain(
        "Running scan: reviewing files | Workers: 2/2 | Files: 3/8 | Tokens: unavailable uncached input, 200 cache reads, unavailable cache writes, 30 output, 1,280 total",
      );
      expect(stderr.text()).not.toContain("Cost:");
      expect(stderr.text()).not.toContain("COST");
      expect(stderr.text()).not.toContain("CODEX SECURITY");
      expect(stderr.text()).not.toContain("\u001B");
      expect(stderr.text()).not.toContain("\r");
      expect(setIntervalMock).toHaveBeenCalledTimes(0);
    }
  });

  test("uses plain progress when rerunning scans in CI", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    expect(
      await runCli(
        ["scans", "rerun", "scan-original"],
        dependencies({
          environment: { CI: "true" },
          onWorkbench: () => savedRecipe(),
          scanProgress: [
            { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
          ],
        }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("[00:00] Preparing scan");
    expect(stderr.text()).toContain("Scan phase: reviewing files (3/8 files).");
    expect(stderr.text()).not.toContain("\u001B");
    expect(stderr.text()).not.toContain("\r");
  });

  test("falls back to plain progress when the dashboard cannot initialize", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const onRun = mock();
    const onClose = mock();
    const setIntervalMock = mock(throwing("Dashboard timer unavailable."));
    const deps = dependencies({
      onRun,
      onClose,
    });
    deps.setInterval = setIntervalMock;

    expect(await runCli(["scan", "."], deps)).toBe(0);
    expect(onRun).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(setIntervalMock).toHaveBeenCalledTimes(1);
    expect(stderr.text()).toContain("Preparing scan");
    expect(stderr.text()).toContain("Running scan");
  });

  test("closes the client when dashboard cleanup cannot restore the terminal", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const write = stderr.stream.write;
    const signals = new FakeSignals();
    const onClose = mock();
    stderr.stream.write = (chunk) => {
      if (chunk.toString().includes("\u001B[?25h\u001B[?1049l")) {
        throw new Error("Terminal cleanup failed.");
      }
      return write.call(stderr.stream, chunk);
    };

    expect(
      await runCli(
        ["scan", "."],
        dependencies({
          signals,
          onClose,
        }),
      ),
    ).toBe(0);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test("keeps terminal scans in one live dashboard", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const result = fakeResult([], "complete", {
      input_tokens: 17_985,
      cached_input_tokens: 10_496,
      output_tokens: 236,
    });

    expect(
      await runCli(
        [
          "scan",
          "/code/juice-shop",
          "--model",
          "gpt-5.6-terra",
          "--codex",
          'model_reasoning_effort="low"',
          "--max-cost",
          "2",
        ],
        dependencies({
          environment: { NO_COLOR: "1" },
          result,
          activities: [
            {
              id: "read-1",
              kind: "command",
              status: "running",
              description:
                'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
              paths: ["routes/login.ts"],
            },
            {
              id: "worker-1:read-1",
              kind: "command",
              status: "running",
              description:
                'rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
              paths: ["routes/login.ts"],
              worker: 1,
            },
            {
              id: "worker-1:thinking-1",
              kind: "reasoning",
              status: "completed",
              description: "Following the login request into the SQL query.",
              paths: [],
              worker: 1,
            },
            {
              id: "worker-1:message-1",
              kind: "message",
              status: "completed",
              description: "The request reaches the query without validation.",
              paths: [],
              worker: 1,
            },
            {
              id: "request-1",
              kind: "command",
              status: "running",
              description:
                'curl -H "Authorization: Bearer sk-proj-SYNTHETIC_OPENAI_VALUE_123"',
              paths: [],
            },
          ],
          costUpdates: [result.cost!],
          scanProgress: [
            { phase: "preflight", filesCompleted: 0, filesTotal: 1_258 },
            { phase: "discovery", filesCompleted: 3, filesTotal: 1_258 },
          ],
          workerStatuses: [
            { kind: "dispatch", phase: "file_review", planned: 6, started: 3 },
          ],
        }),
      ),
    ).toBe(0);

    const text = stripVTControlCharacters(stderr.text());
    expect(text).toContain(
      "CODEX SECURITY  ·  juice-shop  ·  gpt-5.6-terra (low)",
    );
    expect(text).not.toContain("ACTIVITY");
    expect(text).not.toContain("events · live");
    expect(text).not.toContain("WORKERS");
    expect(text).toContain("routes/login.ts");
    expect(text).toMatch(/\[\d{2}:\d{2}:\d{2}\]/u);
    expect(text).toContain(
      'worker 1 · rg -n "password" "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
    );
    expect(text).toContain(
      "worker 1 · Following the login request into the SQL query.",
    );
    expect(text).toContain(
      "worker 1 · The request reaches the query without validation.",
    );
    expect(text).not.toContain("thinking ·");
    expect(text).not.toContain("said ·");
    expect(text).toContain("Bearer sk-proj-SYNTHETIC_OPENAI_VALUE_123");
    expect(text).not.toContain("Building the file inventory");
    expect(text).not.toContain("Running a scan command");
    expect(text).toContain("3 / 1,258 reviewed");
    expect(text).not.toContain("opened");
    expect(text).not.toContain("3 / 6 active");
    expect(text.replace(/\s+/gu, " ")).toContain(
      "unavailable uncached input, 10,496 cache reads, unavailable cache writes, 236 output, 18,221 total",
    );
    expect(text).toContain("/ $2.00");
    expect(stderr.text()).toContain("\u001B[?1049h");
    expect(stderr.text()).toContain("\u001B[?1049l");
    expect(text).not.toContain("Running scan: preflight");
    expect(text).not.toContain("Estimated cost: $0.0248865 of $2.00 limit");
  });

  test("omits stage and file counts from interactive Deep scan dashboards", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const result = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });

    expect(
      await runCli(
        ["scan", "/code/juice-shop", "--mode", "deep"],
        dependencies({
          environment: { NO_COLOR: "1" },
          result,
          activities: [
            {
              id: "worker-1:read-1",
              kind: "command",
              status: "completed",
              description: "read routes/login.ts",
              paths: ["routes/login.ts"],
              worker: 1,
            },
          ],
          costUpdates: [result.cost!],
          scanProgress: [
            { phase: "preflight", filesCompleted: 0, filesTotal: 1_258 },
          ],
        }),
      ),
    ).toBe(0);

    const text = stripVTControlCharacters(stderr.text());
    expect(text).not.toContain("STAGE");
    expect(text).not.toContain("FILES");
    expect(text).not.toContain("0 / 1,258 reviewed");
    expect(text).toContain("worker 1 · read routes/login.ts");
    expect(text).toContain("TOKENS");
    expect(text).not.toContain("COST");
    expect(text).toContain("TIME");
  });

  test("rejects structured modes before starting interactive Codex commands", async () => {
    for (const [command, arguments_] of [
      ["validate", ["finding"]],
      ["login", []],
      ["login", ["status"]],
      ["logout", []],
    ] as const) {
      for (const format of [
        ["--json"],
        ["--format", "json"],
        ["--format=json"],
        ["--format", "jsonl"],
        ["--format=jsonl"],
      ] as const) {
        const onCodex = mock<() => number>().mockReturnValue(0);
        const { stdout, stderr, runCli } = createCliTest(main, {
          stderr: true,
        });

        expect(
          await runCli(
            [command, ...arguments_, ...format],
            dependencies({
              onCodex,
            }),
          ),
        ).toBe(2);
        expect(onCodex).not.toHaveBeenCalled();
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(
          `${command} does not support noninteractive JSON output; run it without --json, --format json, or --format jsonl.`,
        );
      }
    }
  });

  test("rejects CSV stdout when JSON output is requested", async () => {
    const exportFindings = mock(resolving(new Uint8Array()));
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.exportFindings = exportFindings;

    expect(
      await runCli(
        ["export", "scan", "--export-format", "csv", "--output", "-", "--json"],
        deps,
      ),
    ).toBe(2);
    expect(exportFindings).not.toHaveBeenCalled();
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain(
      "CSV stdout cannot be combined with JSON output",
    );
  });

  test("prints export help without initializing Codex", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = mustNotInitializeCodex;
    expect(await runCli(["export", "--help"], deps)).toBe(0);
    expect(stdout.text()).toContain("Usage: codex-security export [scan-dir]");
    expect(stdout.text()).toContain("--artifact <artifact>");
    expect(stdout.text()).toContain("--scan <scan-id>");
    expect(stdout.text()).toContain("--export-format <format>");
    expect(stdout.text()).toContain("threatmodel.md");
    expect(stdout.text()).toContain("--source-root <path>");
    expect(stdout.text()).toContain("sarif");
    expect(stdout.text()).not.toContain("--format {sarif}");
    expect(stderr.text()).toBe("");
  });

  test("uses Incur version and command help", async () => {
    const version = capture();
    const stderr = capture();
    expect(
      await main(["--version"], version.stream, stderr.stream, dependencies()),
    ).toBe(0);
    expect(version.text()).toBe(`${VERSION}\n`);
    expect(stderr.text()).toBe("");

    const help = capture();
    expect(
      await main(
        ["scan", "--help"],
        help.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(0);
    const text = help.text().replace(/\s+/gu, " ");
    expect(text).toContain("Usage: codex-security scan [repository]");
    for (const option of [
      "--verbose",
      "--path <path>",
      "--max-cost <usd>",
      "--show-cost",
      "--workers <count>",
      "--subagents <count>",
      "--stop-after-no-new <count>",
      "--max-discovery-runs <count>",
      "--max-time-hours <hours>",
      "--headless",
      "--model <model>",
      "--provider <provider>",
      "--effort <effort>",
    ]) {
      expect(text).toContain(option);
    }
    expect(text).toContain(DEFAULT_SCAN_MODEL_CONFIGURATION.model);
    expect(text).toContain(DEFAULT_SCAN_MODEL_CONFIGURATION.reasoningEffort);
    expect(text).toContain('model_reasoning_effort="high"');
    expect(text).toContain("CODEX_SECURITY_STATE_DIR");
    expect(text).not.toContain("openai:gpt");
    expect(text).not.toContain("codex-security scan . --path src,tests");
    expect(stderr.text()).toBe("");
  });

  test("documents existing model and reasoning options in bulk-scan help", async () => {
    const help = capture();
    const stderr = capture();

    expect(
      await main(
        ["bulk-scan", "--help"],
        help.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(0);
    const text = help.text().replace(/\s+/gu, " ");
    expect(text).toContain("--model <model>");
    expect(text).toContain(DEFAULT_SCAN_MODEL_CONFIGURATION.model);
    expect(text).toContain("--effort <effort>");
    expect(text).toContain(DEFAULT_SCAN_MODEL_CONFIGURATION.reasoningEffort);
    expect(text).toContain("--codex <key=value>");
    expect(text).toContain('model_reasoning_effort="high"');
    expect(text).toContain("Concurrent repository scans.");
    expect(text).toContain("--mode <mode>");
    expect(text).toContain("bundled plugin");
    expect(text).toContain("PYTHON");
    expect(text).toContain("codex-security bulk-scan repositories.csv");
    expect(text).not.toContain("--outputDir");
    expect(text).not.toContain("--maxAttempts");
    expect(text).toContain("--provider <provider>");
    expect(stderr.text()).toBe("");
  });

  test("selects scan models and reasoning without TOML quoting", async () => {
    for (const [options, expected] of [
      [["--model", "gpt-5.6-terra"], { model: "gpt-5.6-terra" }],
      [
        ["--model", "gpt-6-astra", "--effort", "max"],
        { model: "gpt-6-astra", model_reasoning_effort: "max" },
      ],
      [
        ["--model=gpt-6.1-sol", "--effort=max"],
        { model: "gpt-6.1-sol", model_reasoning_effort: "max" },
      ],
      [["--model=gpt-5.6-sol"], { model: "gpt-5.6-sol" }],
      [["--effort", "minimal"], { model_reasoning_effort: "minimal" }],
      [["--effort", "none"], { model_reasoning_effort: "none" }],
      [["--effort", "ultra"], { model_reasoning_effort: "ultra" }],
      [["--effort=xhigh"], { model_reasoning_effort: "xhigh" }],
      [["--effort", "max"], { model_reasoning_effort: "max" }],
      [
        [
          "--model",
          "synthetic-future-model",
          "--effort",
          "synthetic-future-effort",
        ],
        {
          model: "synthetic-future-model",
          model_reasoning_effort: "synthetic-future-effort",
        },
      ],
      [
        ["--model", "gpt-5.6-terra", "--effort", "high"],
        { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
      ],
      [["--codex", 'model="gpt-5.6-terra"'], { model: "gpt-5.6-terra" }],
      [
        ["--codex", 'model_reasoning_effort="high"'],
        { model_reasoning_effort: "high" },
      ],
      [
        [
          "--model",
          "gpt-5.6-terra",
          "--codex",
          'model_reasoning_effort="high"',
        ],
        { model: "gpt-5.6-terra", model_reasoning_effort: "high" },
      ],
      [
        ["--model", "gpt-5.6-terra", "--codex", "features.goals=true"],
        { model: "gpt-5.6-terra", features: { goals: true } },
      ],
    ] as const) {
      let config: CodexSecurityConfig | undefined;
      expect(
        await runCapturedCli(
          main,
          ["scan", ".", ...options],
          dependencies({ onConfig: (value) => (config = value) }),
        ),
      ).toBe(0);
      expect(config?.codexOverrides).toEqual(expected);
    }
  });

  test.each([
    [
      "OpenRouter",
      "openrouter",
      "anthropic/claude-sonnet-4.5",
      "google/gemini-2.5-pro",
      OPENROUTER_CODEX_PROVIDER,
    ],
    [
      "Fireworks AI",
      "fireworks",
      "accounts/fireworks/models/gpt-oss-120b",
      "accounts/fireworks/models/llama-v3p3-70b-instruct",
      FIREWORKS_CODEX_PROVIDER,
    ],
  ] as const)(
    "routes scans through %s",
    async (_name, provider, selectedModel, codexModel, providerConfig) => {
      for (const [options, expectedModel] of [
        [[`--provider=${provider}`, "--model", selectedModel], selectedModel],
        [
          ["--provider", provider, "--codex", `model="${codexModel}"`],
          codexModel,
        ],
      ] as const) {
        let config: CodexSecurityConfig | undefined;
        expect(
          await runCapturedCli(
            main,
            ["scan", ".", ...options],
            dependencies({ onConfig: (value) => (config = value) }),
          ),
        ).toBe(0);
        expect(config?.codexOverrides).toEqual({
          model: expectedModel,
          model_provider: provider,
          model_providers: { [provider]: providerConfig },
        });
      }
    },
  );

  test("routes scans through the built-in Amazon Bedrock provider", async () => {
    for (const options of [
      ["--provider", "amazon-bedrock", "--model", "openai.gpt-5.6-luna"],
      ["--provider=amazon-bedrock", "--codex", 'model="openai.gpt-5.6-luna"'],
    ] as const) {
      let config: CodexSecurityConfig | undefined;
      expect(
        await runCapturedCli(
          main,
          ["scan", ".", ...options],
          dependencies({
            environment: { AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock" },
            onConfig: (value) => (config = value),
          }),
        ),
      ).toBe(0);
      expect(config?.codexOverrides).toEqual({
        model: "openai.gpt-5.6-luna",
        model_provider: "amazon-bedrock",
      });
      expect(config?.codexOverrides).not.toHaveProperty("model_providers");
    }
  });

  test("parses repeatable options and every scan target through Incur", async () => {
    const pathOutput = captureCli(main, "stdout");
    let pathOptions: unknown;
    let pathConfig: CodexSecurityConfig | undefined;
    expect(
      await pathOutput.run(
        [
          "scan",
          "repo",
          "--path",
          "src",
          "--path=--fixtures",
          "--knowledge-base",
          "/shared/architecture.pdf",
          "--knowledge-base=/shared/threat-models",
          "--mode",
          "deep",
          "--workers",
          "2",
          "--subagents",
          "0",
          "--stop-after-no-new",
          "3",
          "--max-discovery-runs",
          "10",
          "--max-time-hours",
          "1.5",
          "--plugin-path",
          "plugin.zip",
          "--python=/managed/python",
          "--codex",
          "features.goals=true",
          "--output-dir",
          "/tmp/results",
          "--archive-existing",
        ],
        dependencies({
          onConfig: (config) => (pathConfig = config),
          onTurn: (_repository, options) => (pathOptions = options),
        }),
      ),
    ).toBe(0);
    expect(pathOptions).toMatchObject({
      target: ["src", "--fixtures"],
      knowledgeBasePaths: [
        resolve("/shared/architecture.pdf"),
        resolve("/shared/threat-models"),
      ],
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 3,
      maxDiscoveryRuns: 10,
      maxTimeHours: 1.5,
    });
    expect(pathConfig).toMatchObject({
      pluginPath: "plugin.zip",
      pythonPath: "/managed/python",
      codexOverrides: { features: { goals: true } },
    });

    for (const [argv, expected] of [
      [
        ["scan", "repo", "--diff", "origin/main", "--head", "HEAD"],
        DiffTarget.refs({ base: "origin/main", head: "HEAD" }),
      ],
      [
        ["scan", "repo", "--working-tree", "--base", "origin/main"],
        DiffTarget.workingTree({ base: "origin/main" }),
      ],
    ] as const) {
      let target: unknown;
      expect(
        await runCapturedCli(
          main,
          argv,
          dependencies({
            onTurn: (_repository, options) => {
              target = (options as { target?: unknown }).target;
            },
          }),
        ),
      ).toBe(0);
      expect(target).toEqual(expected);
    }
  });

  test("parses TOML override literals and rejects conflicts", () => {
    expect(
      parseCodexOverrides([
        "agents.max_threads=4",
        'model_reasoning_effort="high"',
        "features.goals=true",
      ]),
    ).toEqual({
      agents: { max_threads: 4 },
      model_reasoning_effort: "high",
      features: { goals: true },
    });
    expect(() =>
      parseCodexOverrides(["agents.max_threads=4", "agents.max_threads=8"]),
    ).toThrow("Duplicate --codex key");
    expect(() =>
      parseCodexOverrides(["agents=4", "agents.max_threads=8"]),
    ).toThrow("Conflicting --codex key");
    expect(() =>
      parseCodexOverrides(['model="gpt-5.6-sol"'], "gpt-5.6-terra"),
    ).toThrow("--model conflicts with --codex model");
    expect(parseCodexOverrides([], "gpt-5.6-terra", "high")).toEqual({
      model: "gpt-5.6-terra",
      model_reasoning_effort: "high",
    });
    expect(() =>
      parseCodexOverrides(
        ['model_reasoning_effort="medium"'],
        undefined,
        "high",
      ),
    ).toThrow("--effort conflicts with --codex model_reasoning_effort");
    for (const provider of [
      "openrouter",
      "fireworks",
      "amazon-bedrock",
    ] as const) {
      expect(() =>
        parseCodexOverrides([], undefined, undefined, provider),
      ).toThrow(`--model is required when using --provider ${provider}`);
      expect(() =>
        parseCodexOverrides(
          ['model_provider="other"'],
          undefined,
          undefined,
          provider,
        ),
      ).toThrow("--provider conflicts with --codex model_provider");
    }
  });

  test("ignores override key whitespace and preserves literal string contents", () => {
    expect(
      parseCodexOverrides([
        ' model = "  example  " ',
        " agents . max_threads = 4",
      ]),
    ).toEqual({ model: "  example  ", agents: { max_threads: 4 } });
    expect(() =>
      parseCodexOverrides([
        "agents.max_threads=4",
        " agents . max_threads = 8",
      ]),
    ).toThrow("Duplicate --codex key");
    expect(() =>
      parseCodexOverrides(["agents=4", " agents . max_threads = 8"]),
    ).toThrow("Conflicting --codex key");
    expect(() => parseCodexOverrides([' model = "example"'], "other")).toThrow(
      "--model conflicts with --codex model",
    );
    for (const key of ["agents. .limit", "agents. __proto__ .limit"]) {
      expect(() => parseCodexOverrides([`${key}=1`])).toThrow(
        "Invalid --codex key",
      );
    }
  });

  test.each(
    [
      ["classify-severity", "--scan", "--rubric", "policy.md"],
      ["classify-severity", "--scan-dir", "--rubric", "policy.md"],
      ["classify-severity", "--scan", "latest", "--rubric", "--reprocess"],
      [
        "dedupe",
        "--scan",
        "--all-repositories",
        "--findings-url",
        "http://localhost:3000",
      ],
      [
        "dedupe",
        "--workflow-id",
        "--all-repositories",
        "--findings-url",
        "http://localhost:3000",
      ],
    ].map((args) => ({ args })),
  )("rejects missing option values before running %j", async ({ args }) => {
    const deps = dependencies();
    const unexpected = mock(throwing("Unexpected SDK or workbench call"));
    deps.classifyScanSeverity = unexpected;
    deps.classifyScanDirectorySeverity = unexpected;
    deps.deduplicateScan = unexpected;
    deps.runWorkbench = unexpected;
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run(args, deps)).toBe(2);
    expect(stderr.text()).toContain("Missing value for flag:");
    expect(unexpected).not.toHaveBeenCalled();
  });

  test("does not echo malformed --codex overrides and accepts large values", () => {
    const secret = "SYNTHETIC_TOML_SECRET_MUST_NOT_ECHO";
    let malformed: unknown;
    try {
      parseCodexOverrides([`model=\"${secret}`]);
    } catch (error) {
      malformed = error;
    }
    expect(malformed).toBeInstanceOf(Error);
    expect(String(malformed)).toContain("Invalid --codex TOML value");
    expect(String(malformed)).not.toContain(secret);
    expect((malformed as Error).cause).toBeUndefined();

    const deep = `${Array.from({ length: 3_072 }, () => "a").join(".")}=1`;
    let nested: unknown = parseCodexOverrides([deep]);
    for (let index = 0; index < 3_072; index++) {
      nested = (nested as Record<string, unknown>)["a"];
    }
    expect(nested).toBe(1);

    for (const key of ["a".repeat(1_025), "ࠀ".repeat(342)]) {
      expect(parseCodexOverrides([`${key}=1`])[key]).toBe(1);
    }
    for (const value of ["x".repeat(64 * 1_024), "ࠀ".repeat(65_534)]) {
      expect(parseCodexOverrides([`model=\"${value}\"`])["model"]).toBe(value);
    }
  });

  test("rejects prototype-bearing override paths", () => {
    for (const key of ["__proto__", "constructor", "prototype"]) {
      expect(() => parseCodexOverrides([`${key}.polluted=true`])).toThrow(
        "Invalid --codex key",
      );
    }
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  test("rejects invalid scan and export options before starting the SDK", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [["scan", ".", "--path", "src", "--diff", "HEAD"], "mutually exclusive"],
      [["scan", ".", "--head", "HEAD"], "--head requires --diff"],
      [["scan", ".", "--base", "HEAD"], "--base requires --working-tree"],
      [["scan", ".", "--archive-existing"], "requires --output-dir"],
      [["scan", ".", "--max-cost=0"], "expected number to be >0"],
      [["scan", ".", "--workers", "2"], "Deep scan settings require deep mode"],
      [
        ["scan", ".", "--max-time-hours", "1.5"],
        "Deep scan settings require deep mode",
      ],
      [
        ["scan", ".", "--mode", "deep", "--workers", "0"],
        "must be a positive integer",
      ],
      [
        ["scan", ".", "--mode", "deep", "--subagents", "-1"],
        "must be a non-negative integer",
      ],
      [
        ["scan", ".", "--mode", "deep", "--stop-after-no-new", "0"],
        "must be a positive integer",
      ],
      [
        ["scan", ".", "--mode", "deep", "--max-discovery-runs", "0"],
        "must be a positive integer",
      ],
      [
        ["scan", ".", "--mode", "deep", "--max-time-hours", "0"],
        "must be a positive number no greater than 96",
      ],
      [
        ["scan", ".", "--mode", "deep", "--max-time-hours", "96.5"],
        "must be a positive number no greater than 96",
      ],
      [["scan", ".", "--path="], "--path must not be empty"],
      [
        ["bulk-scan", "--knowledge-base="],
        "--knowledge-base must not be empty",
      ],
      [
        ["bulk-scan", "--output-dir", "results", "--", "repositories.csv"],
        "Unknown flag: --",
      ],
      [["scan", ".", "--model="], "--model must not be empty"],
      [
        ["scan", ".", "--provider", "openrouter"],
        "--model is required when using --provider openrouter",
      ],
      [
        ["scan", ".", "--provider", "fireworks"],
        "--model is required when using --provider fireworks",
      ],
      [["scan", ".", "--effort="], "--effort must not be empty"],
      [["scan", ".", "--mode", "bogus"], "Invalid option"],
      [["scan", ".", "--unknown"], "Unknown flag: --unknown"],
      [["scan", ".", "--path", "--dry-run"], "Missing value for flag"],
      [["scan", ".", "--model", "--dry-run"], "Missing value for flag"],
      [["scan", ".", "--effort", "--dry-run"], "Missing value for flag"],
      [["scan", ".", "--output-dir", "--dry-run"], "Missing value for flag"],
      [["scan", ".", "--max-cost", "--dry-run"], "Missing value for flag"],
      [
        ["scan", ".", "--max-time-hours", "--dry-run"],
        "Missing value for flag",
      ],
      [["scan", "repo-a", "repo-b", "--dry-run"], "Unexpected positional"],
      [["findings", "false-positive"], "occurrenceId"],
      [["findings", "false-positive", "occurrence-1"], "reason"],
      [
        ["findings", "false-positive", "occurrence-1", "occurrence-2"],
        "Unexpected positional",
      ],
      [
        ["findings", "false-positive", "occurrence-1", "--reason"],
        "Missing value for flag: --reason",
      ],
      [
        ["findings", "false-positive", "occurrence-1", "--reason", "   "],
        "--reason must not be empty",
      ],
      [
        [
          "findings",
          "false-positive",
          "occurrence-1",
          "--reason",
          "x".repeat(2_401),
        ],
        "--reason must not exceed 2400 characters",
      ],
      [["scan", ".", "--format", "md"], "Markdown output is not supported"],
      [["scan", ".", "--format=md"], "Markdown output is not supported"],
      [["--format", "md", "scan", "."], "Markdown output is not supported"],
      [
        ["scan", ".", "--filter-output", "findings.findings.title"],
        "--filter-output is not supported",
      ],
      [
        ["scan", ".", "--filter-output=findings.findings.title"],
        "--filter-output is not supported",
      ],
      [
        ["--filter-output", "policy", "scan", ".", "--dry-run"],
        "--filter-output is not supported",
      ],
      [
        ["--filter-output=policy", "scan", ".", "--dry-run"],
        "--filter-output is not supported",
      ],
      [
        ["--format", "md", "--filter-output", "policy", "scan", "."],
        "--filter-output is not supported",
      ],
      [
        ["scan", ".", "--codex", "not-an-override"],
        "--codex expects KEY=VALUE",
      ],
      [
        [
          "scan",
          ".",
          "--model",
          "gpt-5.6-terra",
          "--codex",
          'model="gpt-5.6-sol"',
        ],
        "--model conflicts with --codex model",
      ],
      [
        [
          "scan",
          ".",
          "--effort",
          "high",
          "--codex",
          'model_reasoning_effort="medium"',
        ],
        "--effort conflicts with --codex model_reasoning_effort",
      ],
      [["export", "scan", "--unknown"], "Unknown flag: --unknown"],
      [["export", "scan", "--format", "sarif"], "Invalid format"],
      [["export", "scan", "--export-format", "xml"], "Invalid option"],
      [["export", "scan-a", "scan-b"], "Unexpected positional"],
      [["validate"], "findings..."],
      [["validate", ""], "A finding must not be empty"],
      [
        ["patch"],
        "Patch requires an issue, --linear-issue, or --linear-project.",
      ],
      [["patch", ""], "An issue must not be empty"],
      [
        ["export", "scan", "--output", "--source-root", "repo"],
        "Missing value",
      ],
      [
        ["export", "scan", "--export-format", "json", "--source-root", "repo"],
        "--source-root is only supported with --export-format sarif",
      ],
    ];
    for (const [argv, message] of cases) {
      const { stdout, stderr, runCli } = createCliTest(main);

      let started = false;
      expect(
        await runCli(argv, {
          ...dependencies({ onRun: () => (started = true) }),
          exportFindings: async () => {
            started = true;
            throw new Error("must not export invalid arguments");
          },
        }),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(message);
      expect(started).toBe(false);
    }
  });

  test("keeps invalid credential-bearing values out of parser output", async () => {
    for (const argv of [
      ["scan", "--fail-on-severity", SYNTHETIC_CREDENTIALS],
      ["export", "scan", "--export-format", SYNTHETIC_CREDENTIALS],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(argv, dependencies())).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).not.toContain("SYNTHETIC");
    }
  });

  test("honors Incur help before command validation", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["scan", "--mode", "bogus", "--help"], dependencies()),
    ).toBe(0);
    expect(stdout.text()).toContain("Usage: codex-security scan [repository]");
    expect(stderr.text()).toBe("");
  });

  test("maps configuration and emits JSON only on stdout", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const captured: { config?: CodexSecurityConfig } = {};
    const onTurn = mock<(repository: string) => void>();
    const exit = await runCli(
      [
        "scan",
        "repo",
        "--plugin-path",
        "plugin.zip",
        "--python",
        "/managed/python",
        "--codex",
        "features.goals=true",
        "--json",
      ],
      dependencies({
        onConfig: (value) => {
          captured.config = value;
        },
        onTurn,
      }),
    );
    expect(exit).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain("Preparing scan");
    expect(stderr.text()).toContain("Running scan");
    expect(stderr.text()).toContain("Scan complete");
    expect(captured.config).toEqual({
      pluginPath: "plugin.zip",
      pythonPath: "/managed/python",
      codexOverrides: { features: { goals: true } },
    });
    expect(onTurn.mock.lastCall?.[0] ?? "").toBe("repo");
  });

  test("emits verbose scan lifecycle diagnostics without changing JSON output", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult(["high"], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const deps = dependencies({
      environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_VERBOSE_SECRET_123" },
    });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onOutputDirReady?.("/tmp/scan");
        options?.onScanStarted?.();
        options?.onWorkerStatus?.({
          kind: "preflight",
          delegation: "available",
          configuredSlots: 8,
        });
        options?.onWorkerStatus?.({
          kind: "dispatch",
          phase: "validation",
          planned: 6,
          started: 3,
        });
        options?.onReconnect?.(2, 5, {
          reason: "rate_limit",
          retryAfterSeconds: 1.2,
        });
        options?.onCost?.(result.cost!);
        return result;
      });

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain(
      `codex-security: debug: scan.configuration cli_version=${JSON.stringify(VERSION)}`,
    );
    expect(stderr.text()).toContain(
      `bundled_plugin_version=${JSON.stringify(BUNDLED_PLUGIN_VERSION)}`,
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: authentication.selected requested="auto" method="api_key" source="OPENAI_API_KEY" verified=false',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.output_ready scan_dir="/tmp/scan"',
    );
    expect(stderr.text()).toContain("codex-security: debug: scan.started");
    expect(stderr.text()).toContain(
      'codex-security: debug: worker.preflight delegation="available" configured_slots=8',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: worker.phase phase="validation" planned=6 started=3',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: connection.retry reason="rate_limit" attempt=2 max_attempts=5 retry_after_seconds=1.2',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: cost.updated model="gpt-5.6-sol"',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.completed coverage="complete" findings=1',
    );
    expect(stderr.text()).toContain(
      "codex-security: debug: runtime.cleanup.started",
    );
    expect(stderr.text()).toContain(
      "codex-security: debug: runtime.cleanup.completed",
    );
    expect(stderr.text()).not.toContain("SYNTHETIC_VERBOSE_SECRET");
  });

  test("reports the effective default model and reasoning effort in verbose scan diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["scan", ".", "--verbose", "--json"], dependencies()),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    const configuration = stderr
      .text()
      .split("\n")
      .find((line) =>
        line.startsWith("codex-security: debug: scan.configuration"),
      );
    expect(configuration).toBeDefined();
    expect(configuration).toContain(
      `model=${JSON.stringify(DEFAULT_SCAN_MODEL_CONFIGURATION.model)}`,
    );
    expect(configuration).toContain(
      `reasoning_effort=${JSON.stringify(DEFAULT_SCAN_MODEL_CONFIGURATION.reasoningEffort)}`,
    );
  });

  test("includes selected reasoning effort in verbose scan diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", ".", "--effort", "high", "--verbose", "--json"],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "codex-security: debug: scan.configuration",
    );
    expect(stderr.text()).toContain('reasoning_effort="high"');
  });

  test("reports reasoning effort supplied through legacy --codex overrides", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          ".",
          "--codex",
          'model_reasoning_effort="high"',
          "--verbose",
          "--json",
        ],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain('reasoning_effort="high"');
  });

  test("reports effective model and reasoning settings from the selected Codex profile", async () => {
    for (const scenario of profileScenarios) {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "scan",
            ".",
            ...scenario.overrides.flatMap((override) => ["--codex", override]),
            "--verbose",
            "--json",
          ],
          dependencies(),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      const configuration = stderr
        .text()
        .split("\n")
        .find((line) =>
          line.startsWith("codex-security: debug: scan.configuration"),
        );
      expect(configuration).toBeDefined();
      expect(configuration).toContain('profile="review"');
      expect(configuration).toContain(
        `model=${JSON.stringify(scenario.model)}`,
      );
      expect(configuration).toContain(
        `reasoning_effort=${JSON.stringify(scenario.reasoningEffort)}`,
      );
    }
  });

  test("reports saved model and reasoning effort for verbose scan reruns", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scans", "rerun", "scan-original", "--verbose", "--json"],
        dependencies({
          onWorkbench: () =>
            savedRecipe({
              model: "gpt-original",
              model_reasoning_effort: "high",
            }),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "codex-security: debug: scan.configuration",
    );
    expect(stderr.text()).toContain("codex-security: debug: scan.started");
    expect(stderr.text()).toContain("codex-security: debug: scan.completed");
    expect(stderr.text()).toContain('model="gpt-original"');
    expect(stderr.text()).toContain('reasoning_effort="high"');
  });

  test("reports selected profile settings for verbose scan reruns", async () => {
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scans", "rerun", "scan-original"],
        dependencies({
          environment: { CODEX_SECURITY_LOG_LEVEL: "debug" },
          onWorkbench: () =>
            savedRecipe({
              profile: "review",
              model: "gpt-5.6-sol",
              model_reasoning_effort: "low",
              profiles: {
                review: {
                  model: "gpt-5.6-terra",
                  model_reasoning_effort: "high",
                },
              },
            }),
        }),
      ),
    ).toBe(0);
    const configuration = stderr
      .text()
      .split("\n")
      .find((line) =>
        line.startsWith("codex-security: debug: scan.configuration"),
      );
    expect(configuration).toBeDefined();
    expect(configuration).toContain('profile="review"');
    expect(configuration).toContain('model="gpt-5.6-terra"');
    expect(configuration).toContain('reasoning_effort="high"');
  });

  test.each([
    [
      "Amazon Bedrock",
      "amazon-bedrock",
      "openai.gpt-5.6-luna",
      { aws: { region: "us-east-2", profile: "security-prod" } },
      { AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock-bearer" },
    ],
    [
      "OpenRouter",
      "openrouter",
      "anthropic/claude-sonnet-4.5",
      OPENROUTER_CODEX_PROVIDER,
      { OPENROUTER_API_KEY: "synthetic-openrouter-key" },
    ],
    [
      "Fireworks AI",
      "fireworks",
      "accounts/fireworks/models/qwen3-235b-a22b",
      FIREWORKS_CODEX_PROVIDER,
      { FIREWORKS_API_KEY: "synthetic-fireworks-key" },
    ],
  ] as const)(
    "reruns profile-selected %s scans with their saved provider configuration",
    async (_name, provider, model, providerConfig, environment) => {
      const savedConfig = scanPreflightCodexConfig({
        model_provider: "openai",
        profile: "selected",
        profiles: { selected: { model, model_provider: provider } },
        model_providers: { [provider]: providerConfig },
      });
      let rerunConfig: CodexSecurityConfig | undefined;

      expect(
        await runCapturedCli(
          main,
          ["scans", "rerun", "scan-original", "--json"],
          dependencies({
            environment,
            onConfig: (value) => (rerunConfig = value),
            onWorkbench: () => savedRecipe(savedConfig),
          }),
        ),
      ).toBe(0);
      expect(rerunConfig?.codexOverrides).toMatchObject({
        model_provider: "openai",
        profile: "selected",
        profiles: { selected: { model, model_provider: provider } },
        model_providers: { [provider]: providerConfig },
      });
    },
  );

  test.each([
    [
      "enables verbose diagnostics through CODEX_SECURITY_LOG_LEVEL",
      ["scan", ".", "--json"],
      { CODEX_SECURITY_LOG_LEVEL: "  DeBuG  " },
      [
        "codex-security: debug: scan.configuration",
        "codex-security: debug: scan.started",
        "codex-security: debug: scan.completed",
      ],
      [],
    ],
    [
      "accepts Promptfoo-compatible LOG_LEVEL as a verbose fallback",
      ["scan", ".", "--json"],
      {
        CODEX_SECURITY_LOG_LEVEL: "  ",
        LOG_LEVEL: "  DEBUG  ",
      },
      [
        "codex-security: debug: scan.configuration",
        "codex-security: debug: scan.completed",
      ],
      [],
    ],
    [
      "prefers CODEX_SECURITY_LOG_LEVEL over a shared LOG_LEVEL",
      ["scan", ".", "--json"],
      {
        CODEX_SECURITY_LOG_LEVEL: "info",
        LOG_LEVEL: "debug",
      },
      [],
      ["codex-security: debug:"],
    ],
    [
      "lets --verbose override non-debug environment log levels",
      ["scan", ".", "--verbose", "--json"],
      {
        CODEX_SECURITY_LOG_LEVEL: "error",
        LOG_LEVEL: "warn",
      },
      [
        "codex-security: debug: scan.configuration",
        "codex-security: debug: scan.completed",
      ],
      [],
    ],
    [
      "does not emit verbose diagnostics unless explicitly requested",
      ["scan", ".", "--json"],
      {},
      [],
      ["codex-security: debug:"],
    ],
  ] as const)("%s", async (_name, args, environment, present, absent) => {
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(await runCli(args, dependencies({ environment }))).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    for (const diagnostic of present)
      expect(stderr.text()).toContain(diagnostic);
    for (const diagnostic of absent)
      expect(stderr.text()).not.toContain(diagnostic);
  });

  test("keeps verbose dry-run authentication unverified without starting a scan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const onRun = mock();
    const preflight = {
      ...fakePreflight("."),
      authentication: {
        method: "api_key" as const,
        source: "OPENAI_API_KEY" as const,
        verified: false as const,
      },
    };

    expect(
      await runCli(
        ["scan", ".", "--dry-run", "--verbose", "--json"],
        dependencies({
          environment: {
            OPENAI_API_KEY: "sk-proj-SYNTHETIC_DRY_RUN_SECRET_123",
          },
          preflight,
          onRun,
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual({ dryRun: true, ...preflight });
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.preflight.completed model="gpt-5.6-sol" reasoning_effort="xhigh" method="api_key" source="OPENAI_API_KEY" verified=false',
    );
    expect(stderr.text()).not.toContain("codex-security: debug: scan.started");
    expect(stderr.text()).not.toContain("SYNTHETIC_DRY_RUN_SECRET");
    expect(onRun).not.toHaveBeenCalled();
  });

  test("reports selected profile configuration consistently in verbose dry runs", async () => {
    for (const scenario of profileScenarios) {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "scan",
            ".",
            "--dry-run",
            "--verbose",
            "--json",
            ...scenario.overrides.flatMap((override) => ["--codex", override]),
          ],
          dependencies(),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual({
        dryRun: true,
        ...fakePreflight("."),
        model: scenario.model,
        reasoningEffort: scenario.reasoningEffort,
      });

      for (const event of ["scan.configuration", "scan.preflight.completed"]) {
        const diagnostic = stderr
          .text()
          .split("\n")
          .find((line) => line.startsWith(`codex-security: debug: ${event}`));

        expect(diagnostic).toBeDefined();
        expect(diagnostic).toContain(`model=${JSON.stringify(scenario.model)}`);
        expect(diagnostic).toContain(
          `reasoning_effort=${JSON.stringify(scenario.reasoningEffort)}`,
        );
      }
    }
  });

  test("classifies provider failures without including upstream context", async () => {
    const { stderr, runCli } = createCliTest(main);

    const deps = dependencies({
      environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_VERBOSE_KEY_123" },
    });
    deps.createSecurity = () =>
      failingSecurity(
        "401 invalid API key for org-private sk-proj-SYNTHETIC_PROVIDER_SECRET_123",
      );

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(2);
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.failed classification="unauthorized"',
    );
    expect(stderr.text()).toContain("OPENAI_API_KEY");
    expect(stderr.text()).not.toContain("org-private");
    expect(stderr.text()).not.toContain("SYNTHETIC_VERBOSE_KEY");
    expect(stderr.text()).not.toContain("SYNTHETIC_PROVIDER_SECRET");
  });

  test("keeps unclassified provider context out of structured failure diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      failingSecurity(
        "Provider failed for tenant=tenant-private request_id=req-internal",
      );

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(2);

    const failureDiagnostic = stderr
      .text()
      .split("\n")
      .find((line) => line.startsWith("codex-security: debug: scan.failed"));

    expect(failureDiagnostic).toBeDefined();
    expect(failureDiagnostic).toContain('classification="unknown"');
    expect(failureDiagnostic).toContain("partial_output=false");
    expect(failureDiagnostic).not.toContain("tenant-private");
    expect(failureDiagnostic).not.toContain("req-internal");
    expect(stderr.text()).toContain("Provider failed for");
    expect(stderr.text()).toContain("tenant-private");
    expect(stderr.text()).toContain("req-internal");
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "SCAN_FAILED",
    });
  });

  test("preserves provider identifier variants in scan failures", async () => {
    const cases = [
      {
        message:
          "Provider failed for TENANT_ID=tenant-private ORGANIZATION_ID=organization-private ORG_ID=org-private PROJECT_ID=project-private project-id=project-hyphen-private",
        identifiers: [
          "tenant-private",
          "organization-private",
          "org-private",
          "project-private",
          "project-hyphen-private",
        ],
      },
      {
        message:
          "Provider failed for x-request-id:req-private Trace-ID=trace-private correlationId=correlation-private",
        identifiers: ["req-private", "trace-private", "correlation-private"],
      },
      {
        message:
          'Provider failed for {"tenant":"tenant private","organizationId":"organization private","projectId":"project private","requestId":"request private","traceId":"trace private"}',
        identifiers: [
          "tenant private",
          "organization private",
          "project private",
          "request private",
          "trace private",
        ],
      },
      {
        message: `Provider failed for ${JSON.stringify({
          payload: JSON.stringify({
            tenant: 'tenant-"private" suffix',
            organizationId: "org-private",
            projectId: "project-private",
            requestId: "req-private",
            traceId: "trace-private",
            correlationId: "correlation-private",
          }),
        })}`,
        identifiers: [
          "tenant-",
          "private",
          "suffix",
          "org-private",
          "project-private",
          "req-private",
          "trace-private",
          "correlation-private",
        ],
      },
      {
        message: `Provider failed for ${JSON.stringify({
          payload: JSON.stringify({
            nested: JSON.stringify({
              tenant: "tenant-private",
              requestId: "req-private",
            }),
          }),
        })}`,
        identifiers: ["tenant-private", "req-private"],
      },
      {
        message:
          "Provider failed for https://api.example.test?tenant=tenant-private&project=project-private&request_id=req-private",
        identifiers: ["tenant-private", "project-private", "req-private"],
      },
    ];

    for (const { message, identifiers } of cases) {
      for (const verbose of [false, true]) {
        const { stdout, stderr, runCli } = createCliTest(main);

        const deps = dependencies();
        deps.createSecurity = () => failingSecurity(message);

        expect(
          await runCli(
            ["scan", ".", "--json", ...(verbose ? ["--verbose"] : [])],
            deps,
          ),
        ).toBe(2);
        expect(JSON.parse(stdout.text())).toMatchObject({
          status: "failed",
          code: "SCAN_FAILED",
        });
        expect(stderr.text()).toContain("Provider failed for");
        for (const identifier of identifiers) {
          expect(stderr.text()).toContain(identifier);
        }
      }
    }
  });

  test("preserves provider identifiers in scanner warnings", async () => {
    for (const verbose of [false, true]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onWarning?.(
            'Provider warning {"organizationId":"organization private","requestId":"request private"} tenant=tenant-private',
          );
          options?.onWarning?.(
            `Provider warning ${JSON.stringify({
              payload: JSON.stringify({
                organizationId: "organization private",
                requestId: "request private",
              }),
            })}`,
          );
          return fakeResult();
        });

      expect(
        await runCli(
          ["scan", ".", "--json", ...(verbose ? ["--verbose"] : [])],
          deps,
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      expect(stderr.text()).toContain(
        "codex-security: warning: Provider warning",
      );
      expect(stderr.text()).toContain("organization private");
      expect(stderr.text()).toContain("request private");
      expect(stderr.text()).toContain("tenant-private");
    }
  });

  test("prevents Unicode line separators from forging verbose diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    const separators = "\u0085\u2028\u2029";
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onOutputDirReady?.(
          `/tmp/scan${separators}codex-security: debug: forged`,
        );
        options?.onWarning?.(
          `Scanner warning${separators}codex-security: debug: forged`,
        );
        return fakeResult();
      });

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).not.toMatch(/[\u0085\u2028\u2029]/u);

    const diagnostics = stderr
      .text()
      .split("\n")
      .filter((line) => line.startsWith("codex-security: debug:"));

    expect(diagnostics.some((line) => line.includes("scan.output_ready"))).toBe(
      true,
    );
    expect(diagnostics.some((line) => line.includes("scan.warning"))).toBe(
      true,
    );
    for (const diagnostic of diagnostics) {
      expect(diagnostic).not.toMatch(/[\u0085\u2028\u2029]/u);
      expect(diagnostic).not.toMatch(/^codex-security: debug: forged$/u);
    }
  });

  test("preserves verbose output paths and observer errors", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onOutputArchived?.(
          "/tmp/archive_sk-proj-SYNTHETIC_ARCHIVE_SECRET_123",
        );
        options?.onOutputDirReady?.(
          "/tmp/scan_sk-proj-SYNTHETIC_OUTPUT_SECRET_123",
        );
        options?.onObserverError?.(
          "onWorkerStatus",
          new Error(`observer failed ${SYNTHETIC_CREDENTIALS}`),
        );
        return fakeResult();
      });

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.output_archived archive_dir="/tmp/archive_sk-proj-SYNTHETIC_ARCHIVE_SECRET_123"',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.output_ready scan_dir="/tmp/scan_sk-proj-SYNTHETIC_OUTPUT_SECRET_123"',
    );
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.observer_failed observer="onWorkerStatus"',
    );
    expect(stderr.text()).toContain(
      `onWorkerStatus observer failed: observer failed ${SYNTHETIC_CREDENTIALS}`,
    );
  });

  test("excludes observer failure context from verbose diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onObserverError?.(
          "onWorkerStatus",
          new Error(
            "Observer failed for tenant=tenant-private request_id=req-internal",
          ),
        );
        return fakeResult();
      });

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());

    const observerDiagnostic = stderr
      .text()
      .split("\n")
      .find((line) =>
        line.startsWith("codex-security: debug: scan.observer_failed"),
      );

    expect(observerDiagnostic).toBeDefined();
    expect(observerDiagnostic).toContain('observer="onWorkerStatus"');
    expect(observerDiagnostic).toContain('classification="unknown"');
    expect(observerDiagnostic).not.toContain("tenant-private");
    expect(observerDiagnostic).not.toContain("req-internal");
    expect(stderr.text()).toContain("Observer failed for");
    expect(stderr.text()).toContain("tenant-private");
    expect(stderr.text()).toContain("req-internal");
  });

  test("excludes cleanup failure context from verbose diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", ".", "--verbose", "--json"],
        dependencies({
          onClose: () =>
            fail(
              "Cleanup failed for tenant=tenant-private request_id=req-internal",
            ),
        }),
      ),
    ).toBe(2);

    for (const event of ["runtime.cleanup.failed", "scan.failed"]) {
      const diagnostic = stderr
        .text()
        .split("\n")
        .find((line) => line.startsWith(`codex-security: debug: ${event}`));

      expect(diagnostic).toBeDefined();
      expect(diagnostic).toContain('classification="unknown"');
      expect(diagnostic).not.toContain("tenant-private");
      expect(diagnostic).not.toContain("req-internal");
    }

    expect(stderr.text()).toContain("Cleanup failed for");
    expect(stderr.text()).toContain("tenant-private");
    expect(stderr.text()).toContain("req-internal");
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "SCAN_FAILED",
    });
  });

  test("reports reconnect progress on stderr and keeps JSON output clean", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        const callbacks = options as {
          onScanStarted?: () => void;
          onReconnect?: (attempt: number, maxAttempts: number) => void;
        };
        callbacks.onScanStarted?.();
        callbacks.onReconnect?.(2, 5);
        return fakeResult();
      });

    expect(await runCli(["scan", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "Codex connection interrupted; retrying (2/5)",
    );
    expect(stderr.text()).toContain("Running scan");
  });

  test("renders bounded rate-limit retry details without leaking provider context", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onScanStarted?.();
        options?.onReconnect?.(2, 5, {
          reason: "rate_limit",
          retryAfterSeconds: 1.2,
        });
        options?.onReconnect?.(3, 5, { reason: "rate_limit" });
        return fakeResult();
      });

    expect(await runCli(["scan", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "Rate limit reached; retrying in 1.2s (2/5).",
    );
    expect(stderr.text()).toContain("Rate limit reached; retrying (3/5).");
  });

  test("renders safe reconnect causes without forwarding provider messages", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onReconnect?.(1, 5, { reason: "network" });
        options?.onReconnect?.(2, 5, { reason: "authentication" });
        options?.onReconnect?.(3, 5, { reason: "authorization" });
        return fakeResult();
      });

    expect(await runCli(["scan", "--json"], deps)).toBe(0);
    expect(stderr.text()).toContain("Network connection interrupted; retrying");
    expect(stderr.text()).toContain("Authentication interrupted; retrying");
    expect(stderr.text()).toContain("Model access interrupted; retrying");
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
  });

  test("turns authentication and rate-limit failures into actionable safe messages", async () => {
    for (const [message, expected] of [
      ["401 invalid API key for org-private", "provide a valid API key"],
      ["403 model access denied for org-private", "model access"],
      ["429 rate limit reached for org-private", "rate limit"],
    ] as const) {
      const { stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => failingSecurity(message);

      expect(await runCli(["scan"], deps)).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).not.toContain("org-private");
    }
  });

  test("emits structured failures for machine-readable scan output", async () => {
    const message = "This content was flagged for possible cybersecurity risk.";
    for (const formatArgs of [
      ["--json"],
      ["--format", "json"],
      ["--format", "jsonl"],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => failingSecurity(message);

      expect(await runCli(["scan", ".", ...formatArgs], deps)).toBe(2);
      expect(JSON.parse(stdout.text().trim())).toEqual({
        status: "failed",
        code: "SCAN_FAILED",
        message,
      });
      expect(stderr.text()).toContain(`${message}\n`);
    }
  });

  test("reports full-output scan failures in an error envelope", async () => {
    const message = "This content was flagged for possible cybersecurity risk.";
    for (const formatArgs of [
      ["--json"],
      ["--format", "json"],
      ["--format", "jsonl"],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => failingSecurity(message);

      expect(
        await runCli(["scan", ".", ...formatArgs, "--full-output"], deps),
      ).toBe(2);
      const envelope = JSON.parse(stdout.text().trim());
      expect(envelope.ok).toBe(false);
      expect(envelope.error).toEqual({ code: "SCAN_FAILED", message });
      expect(envelope).not.toHaveProperty("data");
      expect(stderr.text()).toContain(`${message}\n`);
    }
  });

  test("preserves diagnostic text in full-output scan failures", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      failingSecurity(`network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`);

    expect(await runCli(["scan", ".", "--json", "--full-output"], deps)).toBe(
      2,
    );
    expect(JSON.parse(stdout.text()).error).toEqual({
      code: "SCAN_FAILED",
      message: `network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`,
    });
    expect(stderr.text()).toContain(
      `network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`,
    );
  });

  test("surfaces underlying scanner errors instead of inventing a model outage", async () => {
    for (const message of [
      "Could not save the Codex Security scan: UNIQUE constraint failed: scans.scan_dir",
      "sandbox-exec: sandbox_apply: Operation not permitted during network setup.",
      "network failure ECONNRESET while connecting to the model.",
      "request timed out while reading the scanner response.",
      "Local scan failed: project_directory=/tmp/project tenant_count=2 request_index=3.",
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => failingSecurity(message);

      expect(await runCli(["scan", ".", "--json"], deps)).toBe(2);
      expect(JSON.parse(stdout.text())).toEqual({
        status: "failed",
        code: "SCAN_FAILED",
        message,
      });
      expect(stderr.text()).toContain(`${message}\n`);
      expect(stderr.text()).not.toContain("codex-security:");
      expect(stderr.text()).not.toContain("model service could not be reached");
    }
  });

  test("reports local input and filesystem failures without connectivity advice", async () => {
    // https://github.com/openai/codex-security/issues/36 -- classification
    // matches bare words such as "permission denied" anywhere in the message,
    // so local failures were reported as credential or connectivity problems
    // and their own text was discarded.
    const failures: Array<[string, unknown]> = [
      [
        "EACCES from a read-only TMPDIR",
        Object.assign(
          new Error(
            "EACCES: permission denied, mkdtemp '/tmp/openai-codex-security-home-XXXXXX'",
          ),
          { code: "EACCES" },
        ),
      ],
      [
        "EPERM writing the scan directory",
        Object.assign(
          new Error("EPERM: operation not permitted, mkdir '/out/scan'"),
          { code: "EPERM" },
        ),
      ],
      [
        "output directory rejected",
        new OutputDirectoryError(
          "Scan output directory must not be accessible to other users (chmod 700): /out",
        ),
      ],
      [
        "path target naming a 403 directory",
        new InvalidTargetError("Path target does not exist: src/403/client.ts"),
      ],
      [
        "git ref naming a forbidden branch",
        new InvalidTargetError("unknown Git ref: origin/forbidden-paths"),
      ],
      [
        "python interpreter unavailable",
        new PluginPythonUnavailableError(
          "The configured plugin Python interpreter is unavailable or unusable: /usr/bin/python3",
        ),
      ],
    ];

    for (const [, failure] of failures) {
      const { stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity((Promise.reject<never>).bind(Promise, failure));

      expect(await runCli(["scan", ".", "--verbose"], deps)).toBe(2);
      expect(stderr.text()).toContain((failure as Error).message);
      expect(stderr.text()).toContain('scan.failed classification="local"');
      expect(stderr.text()).not.toContain("cannot access the configured model");
      expect(stderr.text()).not.toContain("Authentication failed");
      expect(stderr.text()).not.toContain("reached its rate limit");
    }
  });

  test("keeps model authorization advice for genuine transport failures", async () => {
    // The bypass must not swallow real 401/403 handling, and the advice must
    // still replace upstream text that can name the organization or project.
    for (const [detail, expected] of [
      ["401 invalid API key for org-private", "Authentication failed"],
      [
        "403 model access denied for org-private",
        "cannot access the configured model",
      ],
    ] as const) {
      const stderr = captureCli(main, "stderr");
      const deps = dependencies();
      deps.createSecurity = () => failingSecurity(detail);

      expect(await stderr.run(["scan", "."], deps)).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).not.toContain("org-private");
    }
  });

  test("preserves diagnostic text in underlying network errors", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      failingSecurity(`network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`);

    expect(await runCli(["scan", ".", "--json"], deps)).toBe(2);
    expect(JSON.parse(stdout.text())).toEqual({
      status: "failed",
      code: "SCAN_FAILED",
      message: `network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`,
    });
    expect(stderr.text()).toContain(
      `network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`,
    );
    expect(stderr.text()).not.toContain("model service could not be reached");
  });

  test("reports database connection failures without claiming the model network failed", async () => {
    const { stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      failingSecurity(
        [
          "Could not save the Codex Security scan: Traceback (most recent call last):",
          "    with closing(connect()) as connection:",
          "sqlite3.OperationalError: unable to open database file",
          "token=sk-proj-SYNTHETIC_DATABASE_SECRET_123",
        ].join("\n"),
      );

    expect(await runCli(["scan"], deps)).toBe(2);
    expect(stderr.text()).toContain("unable to open database file");
    expect(stderr.text()).not.toContain("model service could not be reached");
    expect(stderr.text()).not.toContain("Check your network connection");
    expect(stderr.text()).toContain(
      "token=sk-proj-SYNTHETIC_DATABASE_SECRET_123",
    );
  });

  test("prints only the completion summary for default scans", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult(["high"], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    result.manifest.scan.id = "12345678-abcd-4567-abcd-1234567890ab";
    result.manifest.scan.completedAt = "2026-01-01T00:06:37Z";

    expect(await runCli(["scan"], dependencies({ result }))).toBe(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan complete · 12345678");
    expect(stderr.text()).not.toContain(result.manifest.scan.id);
    expect(stderr.text()).toContain(
      [
        `  REPORT    ${result.reportPath}`,
        "",
        "  FINDINGS  1 (1 high)",
        "  COVERAGE  complete",
        "  ELAPSED   6m 37s",
        "  TOKENS    unavailable uncached input, 200 cache reads, unavailable cache writes, 30 output, 1,280 total",
        "  RESULTS   /tmp/scan",
      ].join("\n"),
    );
    expect(stderr.text()).not.toContain("codex-security:");
    expect(stderr.text()).not.toContain("Next:");
  });

  test("styles terminal scan summaries and respects color settings", async () => {
    for (const [environment, color] of [
      [{}, true],
      [{ NO_COLOR: "1" }, false],
      [{ TERM: "dumb" }, false],
    ] as const) {
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      const result = fakeResult(["medium"]);

      expect(
        await runCli(["scan"], dependencies({ environment, result })),
      ).toBe(0);

      if (color) {
        expect(stderr.text()).toContain("\u001B[1;36mREPORT\u001B[0m");
        expect(stderr.text()).toContain(
          `\u001B[4m${result.reportPath}\u001B[0m`,
        );
        expect(stderr.text()).toContain("\u001B[33m1 (1 medium)\u001B[0m");
      } else {
        expect(stderr.text()).toContain(`  REPORT    ${result.reportPath}`);
        expect(stderr.text()).not.toContain("\u001B[1;36mREPORT");
      }
    }
  });

  test("prints complete scan results only when explicitly requested", async () => {
    for (const [arguments_, marker] of [
      [["--json"], '"manifest"'],
      [["--format", "json"], '"manifest"'],
      [["--format=json"], '"manifest"'],
      [["--format", "jsonl"], '"manifest"'],
      [["--format=jsonl"], '"manifest"'],
      [["--format", "toon"], "manifest:"],
      [["--format=toon"], "manifest:"],
      [["--format", "yaml"], "manifest:"],
      [["--format=yaml"], "manifest:"],
      [["--full-output"], "manifest:"],
    ] as const) {
      const stdout = captureCli(main, "stdout");
      expect(await stdout.run(["scan", ...arguments_], dependencies())).toBe(0);
      expect(stdout.text()).toContain(marker);
    }
  });

  test("honors explicit scan token output operations", async () => {
    for (const arguments_ of [
      ["--token-count"],
      ["--token-limit", "4"],
      ["--token-offset", "1"],
      ["--token-offset", "1", "--token-limit", "4"],
    ] as const) {
      const stdout = captureCli(main, "stdout");
      expect(await stdout.run(["scan", ...arguments_], dependencies())).toBe(0);
      if (arguments_[0] === "--token-count") {
        expect(stdout.text().trim()).toMatch(/^\d+$/u);
        expect(Number(stdout.text().trim())).toBeGreaterThan(0);
      } else {
        expect(stdout.text()).toContain("[truncated: showing tokens ");
      }
    }
  });

  test("fails stale scans and includes target warnings in machine-readable results", async () => {
    for (const warning of [
      "Repository HEAD changed while the scan was running; results were saved for the original revision.",
      "Directory contents changed while the scan was running; results were saved for the original snapshot.",
      "Working-tree contents changed while the scan was running; results were saved for the original snapshot.",
      "The scanned Git repository became unavailable while the scan was running; results were saved for the original revision.",
      "The scan target became unavailable while the scan was running; results were saved for the original revision or snapshot.",
      "Repository HEAD changed while the scan was running; findings belong to the previous checkout.",
      "Completed findings no longer describe the selected source tree.",
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => fakeSecurity(warningResult(warning, true));

      expect(await runCli(["scan", ".", "--json"], deps)).toBe(2);
      expect(JSON.parse(stdout.text())).toEqual({
        ...fakeResult().toJSON(),
        warnings: [warning],
      });
      expect(stderr.text()).toContain(`codex-security: warning: ${warning}`);
      expect(stderr.text()).toContain(
        "Scan target changed during execution; results do not represent the current checkout.",
      );
    }
  });

  test("preserves non-target warnings without failing the scan", async () => {
    for (const warning of [
      "Recovered finding: normalized its semantic anchor.",
      "Repository HEAD changed while the scan was running; informational retry recovered.",
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => fakeSecurity(warningResult(warning));

      expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      expect(stderr.text()).toContain(`codex-security: warning: ${warning}`);
    }
  });

  test("preserves scan warnings in verbose diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(
        warningResult(
          "Repository HEAD changed during the scan: sk-proj-SYNTHETIC_WARNING_SECRET_123",
        ),
      );

    expect(await runCli(["scan", ".", "--verbose", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      'codex-security: debug: scan.warning message="Repository HEAD changed during the scan: sk-proj-SYNTHETIC_WARNING_SECRET_123"',
    );
    expect(stderr.text()).toContain(
      "codex-security: warning: Repository HEAD changed during the scan: sk-proj-SYNTHETIC_WARNING_SECRET_123",
    );
  });

  test("prints granted trusted cyber access without warning or corrupting JSON scans", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onTrustedAccessStatus?.("granted");
        return fakeResult();
      });

    expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "codex-security: ✓ Your account has Trusted Access for Cyber.\n",
    );
    expect(stderr.text()).not.toContain("warning:");
  });

  test("prints trusted cyber access guidance without failing or corrupting JSON scans", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(
        warningResult(
          "Some cybersecurity requests or findings may be refused because your account does not have Trusted Access for Cyber. Apply at https://chatgpt.com/cyber.",
        ),
      );

    expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "codex-security: warning: Some cybersecurity requests or findings may be refused because your account does not have Trusted Access for Cyber.",
    );
    expect(stderr.text()).toContain("Apply at https://chatgpt.com/cyber.");
  });

  test("prints unverified trusted cyber access guidance without corrupting JSON scans", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(
        warningResult(
          "Some cybersecurity requests or findings may be refused because your Trusted Access for Cyber status could not be verified. Check your access or apply at https://chatgpt.com/cyber.",
        ),
      );

    expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "codex-security: warning: Some cybersecurity requests or findings may be refused because your Trusted Access for Cyber status could not be verified.",
    );
    expect(stderr.text()).toContain(
      "Check your access or apply at https://chatgpt.com/cyber.",
    );
  });

  test("prints organizational trusted cyber access guidance without corrupting JSON scans", async () => {
    for (const warning of [
      "Some cybersecurity requests or findings may be refused because your API organization does not have Trusted Access for Cyber. Apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      "Some cybersecurity requests or findings may be refused because Trusted Access for Cyber for your API organization could not be verified. Check your organization's access or apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () => fakeSecurity(warningResult(warning));

      expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      expect(stderr.text()).toContain(`codex-security: warning: ${warning}\n`);
      expect(stderr.text()).not.toContain("chatgpt.com/cyber");
    }
  });

  test("reports isolated observer failures without failing the scan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onObserverError?.(
          "onWorkerStatus",
          new Error(`status observer failed ${SYNTHETIC_CREDENTIALS}`),
        );
        return fakeResult();
      });

    expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      `codex-security: warning: onWorkerStatus observer failed: status observer failed ${SYNTHETIC_CREDENTIALS}`,
    );
  });

  test("maps failed scan stdout writes to the runtime-error exit code", async () => {
    const stdout = new Writable({
      write(_chunk, _encoding, callback) {
        callback(new Error("SYNTHETIC_SCAN_STDOUT_WRITE_FAILED"));
      },
    });
    const stderr = capture();

    expect(
      await main(["scan", "--json"], stdout, stderr.stream, dependencies()),
    ).toBe(2);
    expect(stderr.text()).toContain("SYNTHETIC_SCAN_STDOUT_WRITE_FAILED");
  });

  test("maps failed export stdout writes to the runtime-error exit code", async () => {
    const stdout = new Writable({
      write(_chunk, _encoding, callback) {
        callback(new Error("SYNTHETIC_EXPORT_STDOUT_WRITE_FAILED"));
      },
    });
    const stderr = capture();

    expect(
      await main(
        ["export", "scan", "--output", "-"],
        stdout,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("SYNTHETIC_EXPORT_STDOUT_WRITE_FAILED");
  });

  test("reports partial worker capacity on stderr without changing JSON stdout", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "--json"],
        dependencies({
          workerStatuses: [
            {
              kind: "preflight",
              delegation: "available",
              configuredSlots: 8,
            },
            { kind: "dispatch", phase: "ranking", planned: 6, started: 3 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "Preflight: worker delegation supported (up to 8 worker slots).",
    );
    expect(stderr.text()).toContain(
      "Worker capacity changed during ranking; started 3 of 6 planned workers. Continuing scan.",
    );
  });

  test("reports scoped scan phases and deduplicates repeated worker updates", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const status = {
      kind: "dispatch",
      phase: "file_review",
      planned: 4,
      started: 4,
    } as const;

    expect(
      await runCli(
        ["scan", ".", "--path", "src", "--path", "tests", "--json"],
        dependencies({ workerStatuses: [status, status] }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain("Running scan: src, tests");
    expect(stderr.text()).toContain("Scan phase: reviewing files (4 workers).");
    expect(stderr.text().match(/Scan phase: reviewing files/g)).toHaveLength(1);
    expect(stderr.text()).toContain(
      "Running scan: reviewing files (src, tests)",
    );
    expect(stderr.text()).not.toContain("% complete");
  });

  test("preserves directory names for absolute scan paths with trailing separators", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          ".",
          "--path",
          "/synthetic-parent/trailing-directory/",
          "--json",
        ],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain("Running scan: trailing-directory");
    expect(stderr.text()).not.toContain("synthetic-parent");
  });

  test("shows live stage, files, workers, tokens, and opt-in cost without a budget", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });

    expect(
      await runCli(
        ["scan", ".", "--show-cost", "--json"],
        dependencies({
          result,
          costUpdates: [result.cost!],
          scanProgress: [
            { phase: "discovery", filesCompleted: 0, filesTotal: 8 },
            { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
          ],
          workerStatuses: [
            { kind: "dispatch", phase: "file_review", planned: 6, started: 4 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain(
      "Tokens: unavailable uncached input, 200 cache reads, unavailable cache writes, 30 output, 1,280 total. Estimated cost: $0.00488–$0.01156 (standard, context unknown, cache writes unknown).",
    );
    expect(stderr.text()).toContain("Scan phase: reviewing files (0/8 files).");
    expect(stderr.text()).toContain("Scan phase: reviewing files (3/8 files).");
    expect(stderr.text()).toContain(
      "Running scan: reviewing files | Workers: 4/6 | Files: 3/8 | Tokens: unavailable uncached input, 200 cache reads, unavailable cache writes, 30 output, 1,280 total | Cost: $0.00488–$0.01156",
    );
  });

  test("deduplicates live file progress and reports later scan phases", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const discovery = {
      phase: "discovery",
      filesCompleted: 8,
      filesTotal: 8,
    } as const;

    expect(
      await runCli(
        ["scan", ".", "--json"],
        dependencies({
          scanProgress: [
            discovery,
            discovery,
            { phase: "validation", filesCompleted: 8, filesTotal: 8 },
            { phase: "reporting", filesCompleted: 8, filesTotal: 8 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(
      stderr.text().match(/Scan phase: reviewing files \(8\/8 files\)/g),
    ).toHaveLength(1);
    expect(stderr.text()).toContain(
      "Scan phase: validating findings (8/8 files).",
    );
    expect(stderr.text()).toContain("Scan phase: writing report (8/8 files).");
  });

  test("prints a truthful completion summary without changing JSON results", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult(
      ["critical", "high", "high", "informational"],
      "complete",
      {
        input_tokens: 1250,
        cached_input_tokens: 200,
        output_tokens: 30,
      },
    );

    expect(
      await runCli(
        ["scan", ".", "--show-cost", "--json"],
        dependencies({
          result,
          workerStatuses: [
            { kind: "dispatch", phase: "validation", planned: 6, started: 3 },
          ],
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain(
      "FINDINGS  4 (1 critical, 2 high, 1 informational)",
    );
    expect(stderr.text()).toContain("COVERAGE  complete");
    expect(stderr.text()).toContain("ELAPSED   1s");
    expect(stderr.text()).toContain(
      "TOKENS    unavailable uncached input, 200 cache reads, unavailable cache writes, 30 output, 1,280 total",
    );
    expect(stderr.text()).toContain(
      "COST      $0.00488–$0.01156 (standard, context unknown, cache writes unknown)",
    );
    expect(stderr.text()).toContain(`REPORT    ${result.reportPath}`);
    expect(stderr.text()).toContain("RESULTS   /tmp/scan");
    expect(stderr.text()).not.toContain("Next:");
  });

  test.each([
    [[], {}, true, true, true],
    [["--headless"], {}, true, true, false],
    [["--verbose"], {}, true, true, false],
    [["--json"], {}, true, true, false],
    [["--format", "jsonl"], {}, true, true, false],
    [[], { CI: "true" }, true, true, false],
    [[], { TERM: "dumb" }, true, true, false],
    [[], {}, false, true, false],
    [[], {}, true, false, false],
  ] as const)(
    "gates budget interaction for flags %j, environment %j, input TTY %p, output TTY %p",
    async (flags, environment, inputTty, outputTty, expected) => {
      const input = Object.assign(new PassThrough(), { isTTY: inputTty });
      let budgetCallback: ScanOptions["onBudgetApproaching"];
      expect(
        await main(
          ["scan", ".", "--max-cost", "20", ...flags],
          capture().stream,
          capture(outputTty).stream,
          {
            ...dependencies({
              environment,
              onTurn: (_repository, options) => {
                budgetCallback = options.onBudgetApproaching;
              },
            }),
            scanInput: input,
          },
        ),
      ).toBe(0);
      expect(budgetCallback !== undefined).toBe(expected);
      expect(input.listenerCount("data")).toBe(0);
      input.destroy();
    },
  );

  test("reports a cost range while preserving the short-context scan budget", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });

    expect(
      await runCli(
        ["scan", ".", "--verbose", "--json", "--max-cost", "0.01"],
        dependencies({ result, costUpdates: [result.cost!] }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain("Estimated cost: $0.00488–$0.01156");
    expect(stderr.text()).toContain(
      "short-context budget baseline: $0.00488 of $0.01 limit",
    );
    expect(stderr.text()).toContain(
      'estimated_usd=0.00488 cost_estimate="$0.00488–$0.01156 (standard, context unknown, cache writes unknown)"',
    );
  });

  test("includes cache-write tokens in verbose cost diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const result = fakeResult([], "complete", {
      input_tokens: 200,
      cache_write_input_tokens: 200,
      output_tokens: 0,
    });

    expect(result.cost?.cacheWriteInputTokens).toBe(200);
    expect(result.cost?.estimatedUsd).toBeGreaterThan(0);
    expect(
      await runCli(
        ["scan", ".", "--verbose", "--json"],
        dependencies({ result, costUpdates: [result.cost!] }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
    expect(stderr.text()).toContain("codex-security: debug: cost.updated");
    expect(stderr.text()).toContain("cache_write_input_tokens=200");
    expect(stderr.text()).not.toContain("estimated_usd=");
    expect(stderr.text()).not.toContain("cost_estimate=");
  });

  test("reports and classifies a scan stopped when its live cost exceeds the limit", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const cost = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    }).cost!;

    expect(
      await runCli(
        ["scan", ".", "--verbose", "--json", "--max-cost", "0.004"],
        dependencies({
          onTurn: (_repository, options) => {
            options.onOutputDirReady?.("/tmp/scan");
            throw new ScanCostLimitExceededError(0.004, cost, "/tmp/scan");
          },
        }),
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "SCAN_FAILED",
      message: expect.stringContaining("estimated cost"),
    });
    expect(stderr.text()).toContain(
      "Scan stopped: short-context budget baseline $0.00488 exceeded the $0.004 limit; estimated cost $0.00488–$0.01156 (standard, context unknown, cache writes unknown); partial output remains at /tmp/scan.",
    );
    expect(stderr.text()).toMatch(
      /scan\.configuration[^\n]*max_cost_usd=0\.004/u,
    );
    expect(stderr.text()).toContain(
      'scan.failed classification="cost_limit_exceeded" partial_output=true max_cost_usd=0.004 estimated_usd=0.00488',
    );
  });

  test("accepts a scan at its estimated cost limit", async () => {
    const stdout = captureCli(main, "stdout");
    const result = fakeResult([], "complete", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });

    expect(
      await stdout.run(
        ["scan", ".", "--json", "--max-cost", "0.00488"],
        dependencies({ result }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
  });

  test("preserves scan progress scope and completion paths", async () => {
    const { stderr, runCli } = createCliTest(main);

    const result = fakeResult();
    Object.defineProperty(result, "scanDir", {
      value: "/tmp/scan_sk-proj-SYNTHETIC_OUTPUT_KEY_123",
    });

    expect(
      await runCli(
        [
          "scan",
          ".",
          "--path",
          "src/sk-proj-SYNTHETIC_SCOPE_KEY_123",
          "--json",
        ],
        dependencies({ result }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("src/sk-proj-SYNTHETIC_SCOPE_KEY_123");
    expect(stderr.text()).toContain(
      "/tmp/scan_sk-proj-SYNTHETIC_OUTPUT_KEY_123",
    );
  });

  test("reports parent fallback when delegated workers cannot start", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan"],
        dependencies({
          workerStatuses: [
            {
              kind: "preflight",
              delegation: "unavailable",
              configuredSlots: 8,
            },
            {
              kind: "dispatch",
              phase: "file_review",
              planned: 6,
              started: 0,
            },
          ],
        }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain(
      "Preflight: worker delegation unavailable; continuing without delegated workers.",
    );
    expect(stderr.text()).toContain(
      "Worker delegation unavailable during file review; continuing without delegated workers.",
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("FINDINGS  0\n  COVERAGE  complete");
  });

  test("validates a dry run without starting a scan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const onRun = mock();
    expect(
      await runCli(
        ["scan", "repo", "--dry-run"],
        dependencies({
          onRun,
        }),
      ),
    ).toBe(0);
    expect(onRun).not.toHaveBeenCalled();
    expect(stdout.text()).toContain("dryRun: true");
    expect(stdout.text()).toContain("repository: repo");
    expect(stdout.text()).toContain("mode: standard");
    expect(stderr.text()).toContain("Validating scan inputs");
    expect(stderr.text()).toContain("Preflight complete");
    expect(stderr.text()).not.toContain("Running scan");
  });

  test("emits a machine-readable dry-run plan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["scan", "repo", "--dry-run", "--json"], dependencies()),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual({
      dryRun: true,
      ...fakePreflight("repo"),
    });
    expect(stderr.text()).not.toContain("Running scan");
  });

  test("renders dry-run output with Incur structured formats", async () => {
    for (const [format, marker] of [
      ["toon", "dryRun: true"],
      ["yaml", "dryRun: true"],
      ["jsonl", '"dryRun":true'],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "repo", "--dry-run", "--format", format],
          dependencies(),
        ),
      ).toBe(0);
      expect(stdout.text()).toContain(marker);
      expect(stderr.text()).not.toContain("Running scan");
    }

    const full = captureCli(main, "stdout");
    expect(
      await full.run(
        ["scan", "repo", "--dry-run", "--full-output"],
        dependencies(),
      ),
    ).toBe(0);
    expect(full.text()).toContain("ok: true");
    expect(full.text()).toContain("dryRun: true");
  });

  test("previews an existing output archive during a dry run", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const preflight: ScanPreflight = {
      ...fakePreflight("repo"),
      outputDir: "/tmp/results",
      archiveDir: "/tmp/results.previous-20260721T031422-1234abcd",
    };
    expect(
      await runCli(
        [
          "scan",
          "repo",
          "--output-dir",
          "/tmp/results",
          "--archive-existing",
          "--dry-run",
        ],
        dependencies({ preflight }),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain(
      "archiveDir: /tmp/results.previous-20260721T031422-1234abcd",
    );
    expect(stderr.text()).not.toContain("Running scan");
  });

  test("keeps original archive notices on stderr for JSON scans", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          "repo",
          "--output-dir",
          "/tmp/results",
          "--archive-existing",
          "--json",
        ],
        dependencies({
          onTurn: (_repository, options) => {
            expect(options).toMatchObject({
              outputDir: resolve("/tmp/results"),
              archiveExisting: true,
            });
            (
              options as { onOutputArchived?: (archiveDir: string) => void }
            ).onOutputArchived?.(
              "/tmp/sk-proj-SYNTHETIC_ARCHIVE_KEY_123/results.previous-20260721T031422-1234abcd",
            );
          },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "[00:00] Preparing scan\n" +
        "Moved existing results to: /tmp/sk-proj-SYNTHETIC_ARCHIVE_KEY_123/results.previous-20260721T031422-1234abcd\n",
    );
    expect(stderr.text()).toContain("SYNTHETIC_ARCHIVE_KEY_123");
  });

  test("reports findings by severity and applies the requested policy", async () => {
    const result = fakeResult([
      "critical",
      "medium",
      "medium",
      "low",
      "informational",
    ]);
    const { stdout, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "--json", "--fail-on-severity", "high"],
        dependencies({ result }),
      ),
    ).toBe(1);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
  });

  test("keeps report-only and below-threshold scans successful", async () => {
    for (const arguments_ of [
      ["scan", "--json"],
      ["scan", "--json", "--fail-on-severity", "high"],
    ]) {
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(
          arguments_,
          dependencies({ result: fakeResult(["medium", "low"]) }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(
        fakeResult(["medium", "low"]).toJSON(),
      );
    }
  });

  test("keeps JSON output complete when findings block", async () => {
    const result = fakeResult(["high"]);
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scan", "--json", "--fail-on-severity", "high"],
        dependencies({ result }),
      ),
    ).toBe(1);
    expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
  });

  test("does not pass a policy when coverage is incomplete", async () => {
    for (const completeness of ["partial", "unknown"] as const) {
      const result = fakeResult(["high"], completeness);
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", "--json", "--fail-on-severity", "critical"],
          dependencies({ result }),
        ),
      ).toBe(2);
      expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
      expect(stderr.text()).toContain(
        `Cannot evaluate the failure policy: coverage is ${completeness}`,
      );
    }
  });

  test("does not report an incomplete scan as successful without a policy", async () => {
    for (const completeness of ["partial", "unknown"] as const) {
      const result = fakeResult(["high"], completeness);
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(["scan", "--json"], dependencies({ result }))).toBe(
        2,
      );
      expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
      expect(stderr.text()).toContain(
        `Scan coverage is ${completeness}; results may be incomplete.`,
      );
    }
  });

  test("reports SDK errors without a stack trace", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const failing = dependencies();
    failing.createSecurity = () => failingSecurity("invalid scan request");
    expect(await runCli(["scan", "."], failing)).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("invalid scan request\n");
    expect(stderr.text()).not.toContain("Running scan");
    expect(stderr.text()).not.toContain("CodexSecurityError");
  });

  test("does not emit a successful full-output envelope for a failed scan", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const failing = dependencies();
    failing.createSecurity = () => failingSecurity("invalid scan request");
    expect(await runCli(["scan", ".", "--full-output"], failing)).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("invalid scan request\n");

    const unavailableCwd = dependencies();
    unavailableCwd.currentDirectory = () =>
      fail("working directory is unavailable");
    const cwdOutput = capture();
    const cwdError = capture();
    expect(
      await main(
        ["scan", "--full-output"],
        cwdOutput.stream,
        cwdError.stream,
        unavailableCwd,
      ),
    ).toBe(2);
    expect(cwdOutput.text()).toBe("");
    expect(cwdError.text()).toContain("working directory is unavailable");
  });

  test("explains protected-root output failures without contaminating JSON stdout", async () => {
    const root = await temporaryDirectory("codex security's output & ");
    const worktree = join(root, "worktree");
    const repository = join(worktree, "packages", "service");
    const output = join(worktree, "scan");
    const suggestion = join(root, "worktree-codex-security-scan");
    await mkdir(repository, { recursive: true });
    const { stdout, stderr, runCli } = createCliTest(main);

    const failing = dependencies();
    failing.createSecurity = () => ({
      run: async () => {
        throw new OutputInsideProtectedRootError(output, worktree);
      },
      close: async () => {},
      preflight: async () => fakePreflight(repository),
    });

    try {
      expect(
        await runCli(
          ["scan", repository, "--output-dir", output, "--json"],
          failing,
        ),
      ).toBe(2);
      expect(JSON.parse(stdout.text())).toMatchObject({
        status: "failed",
        code: "SCAN_FAILED",
        message: expect.stringContaining(
          "Scan output directory must be outside",
        ),
      });
      expect(stderr.text()).toContain(
        "Scan output directory must be outside the scanned directory and any enclosing Git worktree.",
      );
      expect(stderr.text()).toContain(`Resolved path:  ${output}`);
      expect(stderr.text()).toContain(`Protected root: ${worktree}`);
      expect(stderr.text()).toContain(
        "Scan artifacts cannot be written inside the protected scan root.",
      );
      expect(stderr.text()).toContain(
        process.platform === "win32"
          ? `Re-run with --output-dir "${suggestion}".`
          : `Re-run with --output-dir '${suggestion.replaceAll("'", `'"'"'`)}'.`,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("explains when the temporary root is inside the protected scan root", async () => {
    const root = await temporaryDirectory("codex-security-cli-tmp-");
    const worktree = join(root, "worktree");
    const temporary = join(worktree, "tmp");
    await mkdir(temporary, { recursive: true });
    const { stdout, stderr, runCli } = createCliTest(main);

    const failing = dependencies();
    failing.createSecurity = () => ({
      run: async () => {
        throw new OutputInsideProtectedRootError(
          temporary,
          worktree,
          "temporary",
        );
      },
      close: async () => {},
      preflight: async () => fakePreflight(worktree),
    });

    try {
      expect(await runCli(["scan", worktree], failing)).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        "Temporary directory must be outside the scanned directory and any enclosing Git worktree.",
      );
      expect(stderr.text()).toContain(`Resolved path:  ${temporary}`);
      expect(stderr.text()).toContain(`Protected root: ${worktree}`);
      expect(stderr.text()).toContain("Set TMPDIR (or TEMP on Windows)");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("preserves partial-output guidance for a late protected-root failure", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const partial = "/tmp/codex-security-partial";
    const failing = dependencies();
    failing.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onOutputDirReady?.(partial);
        throw new OutputInsideProtectedRootError(
          "/tmp/worktree/runtime",
          "/tmp/worktree",
          "runtime",
        );
      });

    expect(await runCli(["scan", "."], failing)).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain(
      "Isolated Codex runtime directory must be outside the scanned directory and any enclosing Git worktree.",
    );
    expect(stderr.text()).toContain(`Partial output was kept at ${partial}.`);
    expect(stderr.text()).not.toContain("codex-security:");
  });

  test("preserves complete protected-root diagnostics", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const protectedRoot =
      "/private/tmp/worktree_sk-proj-SYNTHETIC_ROOT_KEY_123";
    const output = `${protectedRoot}/results_sk-proj-SYNTHETIC_OUTPUT_KEY_123`;
    const failing = dependencies();
    failing.createSecurity = () =>
      fakeSecurity(async () => {
        throw new OutputInsideProtectedRootError(output, protectedRoot);
      });

    expect(await runCli(["scan", ".", "--json"], failing)).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "SCAN_FAILED",
    });
    expect(stderr.text()).toContain(`Resolved path:  ${output}`);
    expect(stderr.text()).toContain(`Protected root: ${protectedRoot}`);
  });

  test("preserves diagnostic text in caught scan and interruption failures", async () => {
    for (const failure of [
      new CodexSecurityError(`scan failed ${SYNTHETIC_CREDENTIALS}`),
      new ScanInterruptedError(
        `scan failed ${SYNTHETIC_CREDENTIALS}`,
        "/tmp/scan",
      ),
    ]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const failing = dependencies();
      failing.createSecurity = () =>
        fakeSecurity((Promise.reject<never>).bind(Promise, failure));

      expect(await runCli(["scan", "."], failing)).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe(
        `[00:00] Preparing scan\nscan failed ${SYNTHETIC_CREDENTIALS}\n`,
      );
    }
  });

  test("preserves retained partial-output paths", async () => {
    const path = "/private/tmp/scan_sk-proj-SYNTHETIC_PATH_KEY_123/results";
    for (const [signal, expectedExit] of [
      [null, 2],
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const signals = new FakeSignals();
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies({
        signals,
        onTurn: (_repository, options) => {
          (
            options as { onOutputDirReady?: (scanDir: string) => void }
          ).onOutputDirReady?.(path);
        },
        onRun: () => {
          if (signal !== null) signals.emit(signal);
          throw new Error("runtime failed");
        },
      });

      expect(await runCli(["scan", "."], deps)).toBe(expectedExit);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(`Partial output was kept at ${path}.`);
    }
  }, 30_000);

  test("does not report success when SDK cleanup fails", async () => {
    for (const json of [false, true]) {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          json ? ["scan", ".", "--json"] : ["scan", "."],
          dependencies({
            onClose: () => fail("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED"),
          }),
        ),
      ).toBe(2);
      if (json) {
        expect(JSON.parse(stdout.text())).toEqual({
          status: "failed",
          code: "SCAN_FAILED",
          message: "SYNTHETIC_AUTH_HOME_CLEANUP_FAILED",
        });
      } else {
        expect(stdout.text()).toBe("");
      }
      expect(stderr.text()).toContain("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
      expect(stderr.text()).toContain("Partial output was kept at /tmp/scan.");
    }
  });

  test("preserves the original scan failure when SDK cleanup also fails", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", "."],
        dependencies({
          onRun: () => fail("SYNTHETIC_ORIGINAL_SCAN_FAILED"),
          onClose: () => fail("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED"),
        }),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("SYNTHETIC_ORIGINAL_SCAN_FAILED");
    expect(stderr.text()).not.toContain("SYNTHETIC_AUTH_HOME_CLEANUP_FAILED");
  });
});
