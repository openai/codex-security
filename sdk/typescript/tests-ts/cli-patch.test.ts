import { emptyPage } from "./support/linear-pagination.js";
import { resolving } from "./support/promises.js";
import { parse as parseToml } from "smol-toml";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import type { Finding, JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import type { LinearClientFactory } from "../src/linear.js";
import { capture, dependencies } from "./cli-fixtures.js";
import {
  temporaryDirectory,
  createTemporaryDirectories,
} from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";
import {
  CURRENT_REPOSITORY,
  SAVED_REPOSITORY,
  STATE_DIRECTORY,
  readAppliedText,
  resultWithFindings,
  savedScan,
  completePatches,
  patchRiskSummary,
  patchRiskAssessment,
  patchRiskReport,
  runWorkflow,
  repositoryGit,
  runGitRepositoryCommand,
  publicationRepository as createPublicationRepository,
} from "./cli-patch-fixtures.js";

describe("scan and patch workflow", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  test.each([false, true])(
    "shows progress during baseline preparation and cleans up on failure: %p",
    async (failSnapshot) => {
      const result = resultWithFindings(["high"]);
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      let snapshotHadProgress = false;
      let resultSnapshotHadProgress = false;
      let modelStarted = false;
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (_command, args) => {
          if (args.includes("add") && !modelStarted) {
            snapshotHadProgress = stderr
              .text()
              .includes("Patching 1/1 · Finding 1");
            if (failSnapshot) throw new Error("Baseline snapshot failed.");
          }
          if (args.includes("add") && modelStarted)
            resultSnapshotHadProgress =
              setInterval.mock.calls.length > clearInterval.mock.calls.length;
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
        onCodex: (args, output) => {
          modelStarted = true;
          completePatches(args, output);
          return 0;
        },
      });
      current.setInterval = setInterval;
      current.clearInterval = clearInterval;

      const status = await runCli(
        ["scan", "--patch", "--patch-severity", "high"],
        current,
      );

      expect(snapshotHadProgress).toBe(true);
      expect(resultSnapshotHadProgress).toBe(!failSnapshot);
      expect(modelStarted).toBe(!failSnapshot);
      expect(status).toBe(failSnapshot ? 2 : 0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      if (failSnapshot)
        expect(stderr.text()).toContain("Baseline snapshot failed.");
    },
  );

  test("puts patch runner diagnostics on a new line after the timer", async () => {
    for (const status of [1, 2]) {
      const result = resultWithFindings(["high"]);
      const stdout = capture();
      let errors = "";
      const stderr = Object.assign(
        new Writable({
          write(chunk, _encoding, callback) {
            errors += chunk.toString();
            callback();
          },
        }),
        { isTTY: true },
      );
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: async (_args, output) => {
          await new Promise<void>((resolve, reject) => {
            output!.stderr.write(
              "codex-security: Patch response failed.\n",
              (error) => {
                if (error) reject(error);
                else resolve();
              },
            );
          });
          return status;
        },
      });

      await main(
        ["patch", "--scan", "scan-1", "--json"],
        stdout.stream,
        stderr,
        current,
      );

      expect(stripVTControlCharacters(errors)).toContain(
        "\ncodex-security: Patch response failed.\n",
      );
      expect(JSON.parse(stdout.text()).patches[0].status).toBe("failed");
    }
  });

  test.each(["A long finding title ".repeat(12), "界".repeat(100)])(
    "keeps a long patch timer on one terminal row: %s",
    async (title) => {
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.title = title;
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      Object.assign(stderr.stream, { columns: 36 });
      let now = 0;
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          now = 84_000;
          setIntervalMock.mock.lastCall?.[0]?.();
          expect(completePatches(args, output)[0]!.title).toBe(title);
          return 0;
        },
      });
      const setIntervalMock = mock(current.setInterval);
      current.now = () => now;
      current.setInterval = setIntervalMock;
      current.clearInterval = () => {};

      expect(
        await runCli(["patch", "--scan", "scan-1", "--json"], current),
      ).toBe(0);

      const frames = stripVTControlCharacters(stderr.text())
        .split(/[\r\n]/u)
        .filter((line) => /^\[\d+:\d+\] Patching/u.test(line));
      expect(frames).toHaveLength(2);
      for (const frame of frames) {
        expect(Bun.stringWidth(frame)).toBeLessThan(36);
        expect(frame).toEndWith("…");
      }
    },
  );

  test("shows each patch and live activity before it finishes, with clean JSON output", async () => {
    for (const args of [
      ["scan", "--patch", "--patch-severity", "high"],
      ["patch", "--scan", "scan-1", "--json"],
    ]) {
      const result = resultWithFindings(["high", "high"]);
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

      let now = 0;
      let index = 0;
      const timers = new Map<NodeJS.Timeout, () => void>();
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          index += 1;
          const label = `Patching ${index}/2 · Finding ${index}`;
          expect(stderr.text()).toContain(label);
          expect(stderr.text()).not.toContain(`VERIFIED  Finding ${index}`);
          for (const delta of ["Checking ", "the ", "fix."]) {
            output!.appServer!.onEvent!({
              method: "item/reasoning/summaryTextDelta",
              params: { itemId: "reasoning-1", delta },
            });
          }
          expect(stderr.text().match(/Codex: Checking/gu) ?? []).toHaveLength(
            index - 1,
          );
          output!.appServer!.onEvent!({
            method: "item/completed",
            params: {
              item: {
                id: "reasoning-1",
                type: "reasoning",
                summary: ["Checking the fix."],
              },
            },
          });
          expect(stderr.text()).toContain("Codex: Checking the fix.");
          now += 84_000;
          for (const tick of [...timers.values()]) tick();
          expect(stderr.text()).toContain(`[01:24] ${label}`);
          completePatches(args, output);
          return 0;
        },
      });
      current.now = () => now;
      current.setInterval = (callback) => {
        const timer = {} as NodeJS.Timeout;
        timers.set(timer, callback);
        return timer;
      };
      current.clearInterval = (timer) => {
        timers.delete(timer);
      };

      expect(await runCli(args, current), stderr.text()).toBe(0);
      expect(index).toBe(2);
      expect(timers.size).toBe(0);
      const progress = stderr.text();
      expect(progress.indexOf("VERIFIED  Finding 1")).toBeLessThan(
        progress.indexOf("Patching 2/2"),
      );
      expect(progress).toContain("VERIFIED  Finding 2");
      expect(progress.match(/Codex: Checking the fix\./gu)).toHaveLength(2);
      if (args.includes("--json")) {
        expect(JSON.parse(stdout.text()).patches).toMatchObject([
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ]);
      }
      expect(stdout.text()).not.toContain("\u001B");
    }
  });

  test("uses plain patch progress for noninteractive runs", async () => {
    const saved = ["patch", "--scan", "scan-1", "--json"];
    for (const [interactive, environment, args] of [
      [false, {}, saved],
      [true, { CI: "1" }, saved],
      [true, { TERM: "dumb" }, saved],
      [true, {}, ["scan", "--patch", "--headless"]],
      [true, {}, ["scan", "--patch", "--json"]],
    ] as const) {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        [...args],
        {
          result,
          environment,
          onWorkbench: () => savedScan(result),
        },
        { interactive },
      );
      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain("Patching 1/1 · Finding 1");
      expect(outcome.stderr).not.toContain("\u001B");
    }
  });

  test("stops patch progress on interruption or an agent error", async () => {
    for (const status of [130, "error"] as const) {
      const result = resultWithFindings(["high", "high"]);
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: () => {
            if (status === "error") throw new Error("Agent failed");
            return status;
          },
        },
        {
          interactive: true,
          configure: (current) => {
            current.setInterval = setInterval;
            current.clearInterval = clearInterval;
          },
        },
      );
      expect(outcome.exitCode).not.toBe(0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      expect(outcome.stderr).toContain("\u001B[?25h");
      expect(outcome.stderr).not.toContain("Patching 2/2");
      expect(outcome.stderr).toContain(
        status === "error" ? "Agent failed" : "Patch operation was interrupted",
      );
    }
  });
  test("exposes the validation prompt in patch help and schema", async () => {
    const help = await runWorkflow(["patch", "--help"]);
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("--validation-prompt-file");
    const schema = await runWorkflow(["patch", "--schema", "--json"]);
    expect(schema.exitCode).toBe(0);
    expect(
      JSON.parse(schema.stdout).options.properties.validationPromptFile,
    ).toMatchObject({ type: "string" });
  });

  test.each(["literal", "file", "linear"])(
    "passes custom validation instructions to the %s patch task",
    async (source) => {
      const repository = await temporaryDirectory("patch-validation-");
      const validation =
        "Start the local app. Exercise the fix and a legitimate request. Stop the app.\n";
      try {
        await writeFile(join(repository, "validation.md"), validation);
        await writeFile(
          join(repository, "issues.md"),
          "Synthetic security issue",
        );
        let calls = 0;
        const outcome = await runWorkflow(
          [
            "patch",
            ...(source === "linear"
              ? [
                  "--linear-issue",
                  "SEC-123",
                  "--linear-api-key",
                  "lin_api_SYNTHETIC",
                ]
              : [source === "file" ? "issues.md" : "Synthetic security issue"]),
            "--validation-prompt-file",
            "validation.md",
            "--json",
          ],
          {
            currentDirectory: repository,
            linearClient: () =>
              ({
                issue: async () => ({
                  identifier: "SEC-123",
                  title: "Synthetic security issue",
                  description: "Synthetic issue details",
                  url: "https://linear.app/example/issue/SEC-123",
                  comments: emptyPage,
                }),
              }) as unknown as ReturnType<LinearClientFactory>,
            onCodex: (_args, output) => {
              calls++;
              expect(output?.appServer?.directory).toBe(repository);
              expect(output?.appServer?.prompt).toContain(
                JSON.stringify(validation),
              );
              expect(output?.appServer?.prompt).toContain(
                "$codex-security:fix-finding",
              );
              const issues = JSON.parse(
                output!.appServer!.prompt.split("\n").at(-1)!,
              );
              expect(issues).toHaveLength(1);
              expect(issues[0]).toContain("Synthetic security issue");
              output?.stdout.write("Fixed; runtime validation passed.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode).toBe(0);
        expect(calls).toBe(1);
        expect(JSON.parse(outcome.stdout).report).toBe(
          "Fixed; runtime validation passed.",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("reads validation from the invocation directory once for all saved findings", async () => {
    const directory = await temporaryDirectory("saved-patch-validation-");
    const repository = join(directory, "repository");
    const validation = "Build the app and run the regression tests.\n";
    const result = resultWithFindings(["high", "medium"]);
    let calls = 0;
    try {
      await mkdir(repository);
      await writeFile(join(directory, "validation.md"), validation);
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--validation-prompt-file",
          "validation.md",
          "--json",
        ],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            calls++;
            expect(output?.appServer?.directory).toBe(repository);
            expect(output?.appServer?.prompt).toContain(
              JSON.stringify(validation),
            );
            await rm(join(directory, "validation.md"), { force: true });
            completePatches(args, output, calls === 1 ? "verified" : "blocked");
            return 0;
          },
        },
      );
      expect(calls).toBe(2);
      expect(outcome.exitCode).toBe(1);
      expect(
        JSON.parse(outcome.stdout).patches.map(
          (patch: { status: string }) => patch.status,
        ),
      ).toEqual(["verified", "blocked"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["linked", "root"],
    ["explicit", "root"],
    ["linked", "subdirectory"],
    ["explicit", "subdirectory"],
    ["linked", "nested-worktree"],
    ["explicit", "nested-worktree"],
  ])(
    "checks the invocation checkout boundary for %s prompts from a %s",
    async (kind, invocation) => {
      const root = await temporaryDirectory("patch-prompt-boundary-");
      const checkout = join(root, "invocation");
      const directory =
        invocation === "root" ? checkout : join(checkout, "nested", "cwd");
      const repository = join(root, "repository");
      const outside = join(root, "outside");
      const result = resultWithFindings(["high"]);
      let started = false;
      try {
        await Promise.all(
          [directory, repository, outside].map((path) =>
            mkdir(path, { recursive: true }),
          ),
        );
        execFileSync("git", ["init", "--quiet", checkout]);
        if (invocation === "nested-worktree")
          execFileSync("git", ["init", "--quiet", dirname(directory)]);
        await writeFile(
          join(outside, "validation.md"),
          "Run the synthetic regression test.",
        );
        await symlink(
          outside,
          join(checkout, "validation"),
          process.platform === "win32" ? "junction" : "dir",
        );
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            "scan-1",
            "--validation-prompt-file",
            kind === "linked"
              ? relative(
                  directory,
                  join(checkout, "validation", "validation.md"),
                )
              : join(outside, "validation.md"),
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () => savedScan(result, "scan-1", repository),
            onCodex: (args, output) => {
              started = true;
              completePatches(args, output);
              return 0;
            },
          },
        );
        expect(started).toBe(kind === "explicit");
        expect(outcome.exitCode).toBe(kind === "explicit" ? 0 : 2);
        if (kind === "linked")
          expect(outcome.stderr).toContain("directory links outside");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["missing", "empty", "directory"])(
    "rejects a %s validation prompt before starting a patch",
    async (kind) => {
      const directory = await temporaryDirectory("invalid-patch-validation-");
      try {
        const path = join(directory, "validation.md");
        if (kind === "empty") await writeFile(path, " \n");
        if (kind === "directory") await mkdir(path);
        const onCodex = mock<() => number>().mockReturnValue(0);
        const outcome = await runWorkflow(
          [
            "patch",
            "Synthetic security issue",
            "--validation-prompt-file",
            path,
            "--json",
          ],
          {
            currentDirectory: directory,
            onCodex,
          },
        );
        expect(outcome.exitCode).toBe(2);
        expect(onCodex).not.toHaveBeenCalled();
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          ok: false,
          applied: false,
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("assesses patch risk only when the patch flag is selected", async () => {
    for (const enabled of [false, true]) {
      const result = resultWithFindings(["high"]);
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          "--auth",
          "chatgpt",
          "--scan",
          "scan-1",
          "--json",
          ...(enabled ? ["--assess-patch-risk"] : []),
        ],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            expect(args).toContain('model="gpt-6.1-sol"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(output?.auth).toBe("chatgpt");
            completePatches(args, output);
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async (request) => {
              expect(request.auth).toBe("chatgpt");
              expect(request.configuration.model).toBe("gpt-6.1-sol");
              expect(request.configuration.effort).toBe("max");
              assessments += 1;
              return patchRiskAssessment();
            };
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(enabled ? 1 : 0);
      expect(outcome.stderr.includes("Patch risk assessment:")).toBe(enabled);
      const resultBody = JSON.parse(outcome.stdout) as JsonObject;
      expect("patchRisk" in resultBody).toBe(enabled);
      if (enabled) {
        expect(resultBody["patchRisk"]).toEqual({
          report: patchRiskReport(),
        });
      }
    }
  });

  test("preserves patch-risk details in display and publication summaries", async () => {
    const result = resultWithFindings(["high"]);
    const detail = "Diagnostic detail: token=SYNTHETIC_RISK_VALUE";
    const report = patchRiskAssessment().report.replace(
      patchRiskSummary(),
      `${patchRiskSummary()}\n\n${detail}`,
    );
    const repositoryCommands: Array<{
      command: string;
      args: readonly string[];
    }> = [];
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (command, args) => {
          repositoryCommands.push({ command, args });
          if (command === "git") {
            if (args.includes("--cached")) return "";
            if (args[0] === "remote") {
              return "https://github.example.test/example/repository.git";
            }
            return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
          }
          return args[1] === "create"
            ? "https://github.example.test/example/repository/pull/15"
            : "[]";
        },
      },
      {
        configure: (current) => {
          Object.assign(current, {
            assessPatchRisk: async () => ({ report }),
          });
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(outcome.stderr).toContain("Patch risk assessment:");
    expect(outcome.stderr).toContain(patchRiskSummary());
    expect(outcome.stderr).toContain(detail);
    expect(JSON.parse(outcome.stdout).patchRisk.report).toContain(detail);
    const published = repositoryCommands.find(
      ({ command, args }) => command === "gh" && args[1] === "create",
    )?.args;
    const persisted = repositoryCommands.find(
      ({ command, args }) =>
        command === "git" &&
        args[0] === "config" &&
        args[2]?.endsWith(".codexSecurityPatchPullRequestBody"),
    )?.args;
    expect(published).toBeDefined();
    expect(persisted).toBeDefined();
    for (const body of [published?.at(-1), persisted?.at(-1)]) {
      expect(body).toContain(patchRiskSummary());
      expect(body).toContain(detail);
    }
  });

  test.each(["literal", "saved rename"])(
    "assesses only changes made during a %s patch run",
    async (mode) => {
      const directory = await temporaryDirectory("codex-security-patch-risk-");
      const repository = join(directory, "repository");
      await mkdir(join(repository, "sub"), { recursive: true });
      const git = repositoryGit(repository);

      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(repository, "sub", "app.ts"), "original\n");
        git("add", "--", "sub/app.ts");
        git("commit", "-m", "Initial synthetic checkout");
        await writeFile(
          join(repository, "sub", "app.ts"),
          "original\nuser change\n",
        );

        const outcome = await runWorkflow(
          [
            "patch",
            "--model",
            "gpt-6.1-sol",
            "--effort",
            "max",
            ...(mode === "literal"
              ? ["Synthetic issue"]
              : ["--scan", "scan-1"]),
            "--assess-patch-risk",
            "--codex",
            "analytics.enabled=false",
            "--codex",
            'model_provider="synthetic.gateway"',
            "--codex",
            'model_providers={"synthetic.gateway"={name="Synthetic",base_url="https://gateway.example.test/v1",wire_api="responses",env_key="SYNTHETIC_KEY"}}',
          ],
          {
            currentDirectory: join(repository, "sub"),
            onWorkbench: () => {
              const result = resultWithFindings(["high"]);
              result.findings.findings[0]!.locations[0]!.path = "app.ts";
              return savedScan(result, "scan-1", join(repository, "sub"));
            },
            onCodex: async (args, output) => {
              expect(args).toContain('model="gpt-6.1-sol"');
              expect(args).toContain('model_reasoning_effort="max"');
              expect(args).toContain("analytics.enabled=false");
              expect(args).toContain('model_provider="synthetic.gateway"');
              expect(output?.modelProvider).toBe("synthetic.gateway");
              expect(output?.codexOverrides).toMatchObject({
                model_providers: {
                  "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
                },
              });
              expect(
                parseToml(
                  args.find((arg) => arg.startsWith("model_providers="))!,
                ),
              ).toMatchObject({
                model_providers: {
                  "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
                },
              });
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                ) as { path: string; sha256: string };
                const patch = await readFile(artifact.path, "utf8");
                expect(patch).toContain("+patch change");
                if (mode === "literal")
                  expect(patch).not.toContain("+user change");
                else expect(patch).toContain("deleted file mode");
                output.stdout.write(patchRiskAssessment().report);
                return 0;
              }
              if (mode !== "literal")
                await rm(join(repository, "sub", "app.ts"));
              await writeFile(
                join(
                  repository,
                  "sub",
                  mode === "literal" ? "app.ts" : "new.ts",
                ),
                "original\nuser change\npatch change\n",
              );
              output?.stdout.write(
                mode === "literal"
                  ? "Patch complete."
                  : JSON.stringify({
                      patches: [
                        {
                          occurrenceId: "occ_1",
                          status: "verified",
                          files: ["new.ts"],
                          verification: "Synthetic verification",
                        },
                      ],
                    }),
              );
              return 0;
            },
            onRepositoryCommand: runGitRepositoryCommand,
          },
        );

        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(outcome.stderr).toContain("Patch risk assessment:");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("creates a draft pull request with the Linear patch-risk summary", async () => {
    const directory = await temporaryDirectory(
      "codex-security-linear-patch-pr-",
    );
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/17";
    const expectedBody = [
      "Applies a security fix generated for SEC-123.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const git = repositoryGit(repository);

    try {
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "checkout-hook.sh"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");

      const outcome = await runWorkflow(
        [
          "patch",
          "--linear-issue",
          "SEC-123",
          "--linear-api-key",
          "lin_api_SYNTHETIC",
          "--assess-patch-risk",
          "--create-pr",
        ],
        {
          currentDirectory: join(repository, "src"),
          linearClient: () =>
            ({
              issue: async () => ({
                identifier: "SEC-123",
                title: "Synthetic checkout hook issue",
                description:
                  "The trusted checkout hook resolves an untrusted module.",
                url: "https://linear.app/example/issue/SEC-123",
                comments: async () => ({
                  nodes: [],
                  pageInfo: { hasNextPage: false },
                  fetchNext: async () => undefined,
                }),
              }),
            }) as unknown as ReturnType<LinearClientFactory>,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { changedFiles: string[]; path: string };
              expect(artifact.changedFiles).toEqual(["src/checkout-hook.sh"]);
              expect(await readFile(artifact.path, "utf8")).toContain("+safe");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            expect(output?.appServer?.prompt).toContain("SEC-123");
            await writeFile(
              join(repository, "src", "checkout-hook.sh"),
              "safe\n",
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            if (
              args.includes("--show-toplevel") ||
              args.includes("--absolute-git-dir")
            )
              expect([repository, join(repository, "src")]).toContain(
                workingDirectory,
              );
            else expect(workingDirectory).toBe(repository);
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            if (args[1] === "list") return "[]";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe(
        "codex-security/patch-SEC-123",
      );
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/checkout-hook.sh",
      );
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-SEC-123"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-SEC-123",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedBody,
      ]);
      expect(outcome.stderr).toContain("Patch risk assessment:");
      expect(outcome.stderr).toContain(`Pull request: ${url}`);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(pullRequestArguments.at(-1)).not.toContain(
        "trusted checkout hook",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("assesses a patch larger than the repository command buffer", async () => {
    const directory = await temporaryDirectory("codex-security-large-patch-");
    const repository = join(directory, "repository");
    await mkdir(repository, { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "large.txt"), "original\n");
      git("add", "--", "large.txt");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic large issue", "--assess-patch-risk"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; sha256: string };
              const patch = await readFile(artifact.path);
              expect(patch.byteLength).toBeGreaterThan(1024 * 1024);
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "large.txt"),
              "x".repeat(2 * 1024 * 1024),
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([false, true])(
    "patches selected scan findings with analytics.enabled=%p in the scanned repository and returns JSON",
    async (analyticsEnabled) => {
      const result = resultWithFindings(["critical", "high", "medium", "low"]);
      const invocations: Array<{
        args: readonly string[];
        directory: string | undefined;
        prompt: string | undefined;
      }> = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [
          "scan",
          "../other/repository",
          "--patch",
          "--codex",
          `analytics.enabled=${analyticsEnabled}`,
          "--codex",
          "features.goals=false",
          "--patch-severity",
          "high",
          "--fail-on-severity",
          "high",
          "--json",
        ],
        {
          result,
          onCodex: (args, output) => {
            invocations.push({
              args,
              directory: output?.appServer?.directory,
              prompt: output?.appServer?.prompt,
            });
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
      ]);
      expect(invocations).toHaveLength(2);
      for (const invocation of invocations) {
        expect(invocation.args[0]).toBe("app-server");
        expect(invocation.args).toContain(
          `analytics.enabled=${analyticsEnabled}`,
        );
        expect(invocation.args).not.toContain("features.goals=false");
        expect(invocation.directory).toBe(
          resolve(CURRENT_REPOSITORY, "../other/repository"),
        );
        expect(invocation.prompt).toContain("Return exactly one JSON object");
      }
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        manifest: result.manifest,
        findings: result.findings,
        patchSeverity: "high",
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ],
      });
      expect(outcome.stderr).toContain("Patching 2 confirmed findings...");
    },
  );

  test("continues with separate patch tasks when one finding fails", async () => {
    const result = resultWithFindings(["critical", "high", "medium"]);
    const tasks: string[] = [];
    const outcome = await runWorkflow(["scan", "--patch", "--json"], {
      result,
      onCodex: (args, output) => {
        expect(args[0]).toBe("app-server");
        const [finding] = JSON.parse(
          output!.appServer!.prompt.split("\n").at(-1)!,
        ) as Finding[];
        tasks.push(finding!.occurrenceId);
        if (finding!.occurrenceId === "occ_2") return 1;
        completePatches(args, output);
        return 0;
      },
    });

    expect(tasks).toEqual(["occ_1", "occ_2", "occ_3"]);
    expect(outcome.exitCode).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        { occurrenceId: "occ_1", status: "verified" },
        {
          occurrenceId: "occ_2",
          status: "failed",
          reason: "Patch command exited with status 1.",
        },
        { occurrenceId: "occ_3", status: "verified" },
      ],
    });
  });

  test.each(["synthetic.provider", "openai"])(
    "preserves %s command-provider authentication when patching after a scan",
    async (provider) => {
      const home = join(tmpdir(), "synthetic-auth-home");
      let providerOverride: string | undefined;
      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--auth",
          "api-key",
          "--json",
          "--codex",
          `model_provider=${JSON.stringify(provider)}`,
          "--codex",
          `model_providers={${JSON.stringify(provider)}={name="Synthetic",auth={command="./synthetic-auth",args=["--json"]}}}`,
        ],
        {
          result: resultWithFindings(["high"]),
          environment: {
            CODEX_HOME: home,
          },
          onCodex: (args, output) => {
            providerOverride = args.find((arg) =>
              arg.startsWith("model_providers="),
            );
            expect(output?.modelProvider).toBe(provider);
            expect(output?.codexOverrides).toMatchObject({
              model_providers: {
                [provider]: {
                  auth: {
                    command: "./synthetic-auth",
                    args: ["--json"],
                  },
                },
              },
            });
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(parseToml(providerOverride!)).toEqual({
        model_providers: {
          [provider]: {
            name: "Synthetic",
            auth: { command: "./synthetic-auth", args: ["--json"], cwd: home },
          },
        },
      });
    },
  );

  test("passes the scan model, provider, and selected authentication to patching", async () => {
    const result = resultWithFindings(["high"]);
    let invocation: readonly string[] = [];
    let authentication: string | undefined;
    const chatgpt = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "chatgpt",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "high",
        "--json",
      ],
      {
        result,
        environment: {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_KEY_123",
          CODEX_SECURITY_STATE_DIR: STATE_DIRECTORY,
        },
        onCodex: (args, output, selectedEnvironment) => {
          invocation = args;
          authentication = output?.auth;
          expect(selectedEnvironment?.["CODEX_SECURITY_STATE_DIR"]).toBe(
            STATE_DIRECTORY,
          );
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(chatgpt.exitCode).toBe(0);
    expect(invocation).toContain('model="gpt-5.6-terra"');
    expect(invocation).toContain('model_reasoning_effort="high"');
    expect(authentication).toBe("chatgpt");

    const attributed = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "api-key",
        "--safety-identifier",
        "synthetic-user",
        "--codex",
        'model_reasoning_effort="ultra"',
        "--json",
      ],
      {
        result,
        environment: { OPENAI_API_KEY: "synthetic-key" },
        onCodex: (args, output) => {
          invocation = args;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(attributed.exitCode).toBe(0);
    expect(invocation).toContain('safety_identifier="synthetic-user"');
    expect(invocation).toContain('model_reasoning_effort="ultra"');

    for (const selection of [
      ["--provider", "fireworks"],
      ["--codex", 'model_provider="fireworks"'],
      [
        "--codex",
        'profile="synthetic"',
        "--codex",
        'profiles.synthetic.model_provider="fireworks"',
      ],
    ]) {
      const provider = await runWorkflow(
        [
          "scan",
          "--patch",
          ...selection,
          "--model",
          "accounts/fireworks/models/example",
          "--json",
        ],
        {
          result,
          environment: { FIREWORKS_API_KEY: "SYNTHETIC_FIREWORKS_KEY_123" },
          onCodex: (args, output) => {
            invocation = args;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(provider.exitCode).toBe(0);
      expect(invocation).toContain('model_provider="fireworks"');
      expect(
        invocation.some(
          (argument) =>
            argument.startsWith("model_providers=") &&
            argument.includes('"env_key"="FIREWORKS_API_KEY"'),
        ),
      ).toBe(true);
    }
  });

  test("publishes only verified patch files and preserves unrelated staged changes", async () => {
    const directory = await temporaryDirectory("codex-security-patch-pr-");
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/15";
    const result = resultWithFindings(["high", "medium"]);
    result.findings.findings[0]!.title = "Synthetic private finding";
    const expectedPullRequestBody = [
      "Applies verified security fixes from a completed scan.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const githubCommands: string[][] = [];
    await mkdir(join(repository, "src"), { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
      await writeFile(join(repository, "unrelated.ts"), "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");
      await writeFile(join(repository, "unrelated.ts"), "staged separately\n");
      git("add", "--", "unrelated.ts");

      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan",
          "--severity",
          "high",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => savedScan(result, "scan", repository),
          onCodex: async (args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              expect(output.command).toBe("patch");
              expect(output.appServer?.sandbox).toBe("read-only");
              expect(args).toContain(
                'responses_api_metadata.codex_security_command="assess-patch-risk"',
              );
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:start -->",
              );
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:end -->",
              );
              expect(output.appServer?.prompt).toContain(
                "--helper validate-patch-risk-assessment <assessment.json>",
              );
              expect(output.appServer?.prompt).toContain(
                process.platform === "win32"
                  ? "launch_codex_security_mcp.cmd"
                  : "launch_codex_security_mcp",
              );
              const artifact = JSON.parse(
                output
                  .appServer!.prompt.split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as {
                path: string;
                sourceType: string;
                changedFiles: string[];
                sha256: string;
              };
              const patch = await readFile(artifact.path);
              expect(artifact.sourceType).toBe("patch_file");
              expect(artifact.changedFiles).toEqual(["src/finding-1.ts"]);
              expect(patch.toString()).toEndWith("+fixed  \n");
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "src", "finding-1.ts"),
              "fixed  \n",
            );
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            expect(workingDirectory).toBe(repository);
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            githubCommands.push([...args]);
            if (args[1] === "list") return "[]";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/finding-1.ts",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.ts");
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-scan"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-scan",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedPullRequestBody,
      ]);
      expect(
        git(
          "config",
          "--get",
          "branch.codex-security/patch-scan.codexSecurityPatchPullRequestBody",
        ),
      ).toBe(expectedPullRequestBody);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(JSON.stringify(pullRequestArguments)).not.toContain(
        "Synthetic private finding",
      );
      expect(githubCommands.some((args) => args[1] === "comment")).toBe(false);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        pullRequest: { branch: "codex-security/patch-scan", url },
        patchRisk: { report: patchRiskReport() },
      });
      expect(outcome.stdout).not.toContain("codex-security:patch-risk-summary");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["github", "push"],
    ["github", "create"],
    ["gitlab", "push"],
    ["gitlab", "create"],
  ])(
    "resumes %s publication after %s fails without patching again",
    async (provider, failure) => {
      const directory = await temporaryDirectory("codex-security-pr-retry-");
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const branch = "codex-security/patch-scan-1";
      const gitlab = provider === "gitlab";
      const origin = "https://gitlab.com/example/subgroup/repository.git";
      const url = gitlab
        ? "https://gitlab.com/example/subgroup/repository/-/merge_requests/16"
        : "https://github.example.test/example/repository/pull/16";
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushCalls = 0;
      let created = 0;
      let failOnce = true;
      let publishedUrl = "";
      await mkdir(join(repository, "src"), { recursive: true });
      const git = repositoryGit(repository);

      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
        await writeFile(join(repository, "unrelated.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");

        const fixtures: Parameters<typeof dependencies>[0] = {
          currentDirectory: repository,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            modelCalls += 1;
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (gitlab && args[0] === "remote") {
                expect([
                  ["remote", "get-url", "--push", "--all", "origin"],
                  ["remote", "get-url", "origin"],
                ]).toContainEqual([...args]);
                return origin;
              }
              if (gitlab && args.includes("ls-remote")) {
                const mapping = `--config-env=url.${origin}.insteadOf=CODEX_SECURITY_PREFLIGHT_ALIAS`;
                expect(args).toContain(mapping);
                return runGitRepositoryCommand(
                  command,
                  args.map((value) =>
                    value === mapping
                      ? `--config-env=url.${remote}.insteadOf=CODEX_SECURITY_PREFLIGHT_ALIAS`
                      : value,
                  ),
                  cwd,
                  options,
                );
              }
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe(gitlab ? "glab" : "gh");
            if (args[0] === "repo") return "synthetic-origin-id";
            if (args[1] === "list") {
              const candidate = {
                url: publishedUrl,
                head: publishedUrl
                  ? git("rev-parse", `refs/heads/${branch}`)
                  : "",
                repository: "synthetic-origin-id",
                crossRepository: false,
              };
              return gitlab
                ? publishedUrl
                  ? JSON.stringify(candidate)
                  : ""
                : JSON.stringify(publishedUrl ? [candidate] : []);
            }
            expect(args[1]).toBe("create");
            if (failure === "create" && failOnce) {
              failOnce = false;
              throw new Error("Synthetic PR service failure");
            }
            created += 1;
            publishedUrl = url;
            return url;
          },
        };

        const first = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          fixtures,
        );
        expect(first.exitCode).toBe(2);
        expect(first.stderr).toContain(`patch --resume-pr ${branch}`);
        const commit = git("rev-parse", "HEAD");
        expect(
          git("config", "--get", `branch.${branch}.codexSecurityPatchCommit`),
        ).toBe(commit);
        if (failure === "create") {
          expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        }
        await writeFile(join(repository, "unrelated.ts"), "later local work\n");

        const retry = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          fixtures,
        );
        expect(retry.exitCode).toBe(0);
        expect(JSON.parse(retry.stdout)).toEqual({
          pullRequest: { branch, url },
        });
        expect(modelCalls).toBe(1);
        expect(created).toBe(1);
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        expect(git("diff", "--name-only")).toBe("unrelated.ts");

        const pushes = pushCalls;
        const repeated = await runWorkflow(
          ["patch", "--resume-pr", branch],
          fixtures,
        );
        expect(repeated.exitCode).toBe(0);
        expect(created).toBe(1);
        expect(pushCalls).toBe(pushes);
        expect(modelCalls).toBe(1);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("refuses to resume a missing or changed patch commit", async () => {
    for (const saved of ["", "saved-commit"]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            expect(command).toBe("git");
            return args[0] === "config" ? saved : "changed-commit";
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        saved ? "changed since verification" : "No verified patch commit",
      );
      expect(onCodex).toHaveBeenCalledTimes(0);
    }
  });

  test("rejects new patch inputs when resuming publication", async () => {
    for (const input of [
      ["--scan", "scan-1"],
      ["--model", "gpt-6-astra"],
      ["--linear-issue", "SEC-123"],
      ["--create-pr"],
      ["--assess-patch-risk"],
      ["--validation-prompt-file", "validation.md"],
      ["--external-sandbox"],
      ["occ_1"],
    ]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const onRepositoryCommand = mock<() => string>().mockReturnValue("");
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", ...input],
        {
          onCodex,
          onRepositoryCommand,
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("--resume-pr cannot be combined");
      expect(onCodex).not.toHaveBeenCalled();
      expect(onRepositoryCommand).not.toHaveBeenCalled();
    }
  });

  test("does not publish blocked, unchanged, or repository-external patches", async () => {
    for (const status of ["blocked", "no_change", "outside"] as const) {
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: status === "outside" ? "verified" : status,
                    files: status === "outside" ? ["../outside.ts"] : [],
                    ...(status === "blocked"
                      ? { reason: "A required service is unavailable." }
                      : { verification: "Focused checks pass." }),
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            commandStarted ||=
              (command !== "git" &&
                args[1] !== "list" &&
                !(args[0] === "repo" && args[1] === "view")) ||
              ["checkout", "commit", "push"].includes(args[0]!);
            if (command === "gh" && args[1] === "list") return "[]";
            return status === "outside" && args.includes("--name-only")
              ? "src/finding-1.ts\0"
              : "";
          },
        },
      );

      expect(commandStarted).toBe(false);
      expect(outcome.exitCode).toBe(
        status === "blocked" ? 1 : status === "outside" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout)).not.toHaveProperty("pullRequest");
      if (status === "outside") {
        expect(outcome.stderr).toContain(
          "Patch files must remain inside the scanned repository.",
        );
      }
    }
  });

  test("keeps completed scan results when publication preflight fails", async () => {
    const outcome = await runWorkflow(
      ["scan", "--patch", "--create-pr", "--json"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          if (command === "gh")
            throw new Error("GitHub authentication failed.");
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("GitHub authentication failed.");
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [],
    });
  });

  test.each([
    ["blocked", undefined],
    ["failed", undefined],
    ["malformed", undefined],
    ["verified", undefined],
    ["verified", " \n\t "],
    ["no_change", undefined],
    ["no_change", " \n\t "],
  ] as const)(
    "keeps %s patch results with verification %j unresolved",
    async (status, verification) => {
      const reason = "The requested check did not complete.";
      const outcome = await runWorkflow(
        ["scan", "--patch", "--fail-on-severity", "high", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              status === "malformed"
                ? "The patch is probably fixed."
                : JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status,
                        files: [],
                        verification,
                        ...(status === "blocked" || status === "failed"
                          ? { reason }
                          : {}),
                      },
                    ],
                  }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status === "blocked" ? 1 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status: status === "blocked" ? "blocked" : "failed",
            reason:
              status === "verified" || status === "no_change"
                ? "Patch verification was not reported."
                : status === "malformed"
                  ? "Patch results were not valid JSON."
                  : reason,
          },
        ],
      });
    },
  );

  test("does not patch incomplete scans or allow patching during a dry run", async () => {
    const onCodex = mock<() => number>().mockReturnValue(0);
    const incomplete = resultWithFindings(["high"]);
    incomplete.coverage.completeness = "partial";
    const partial = await runWorkflow(["scan", "--patch", "--json"], {
      result: incomplete,
      onCodex,
    });
    expect(partial.exitCode).toBe(2);
    expect(onCodex).not.toHaveBeenCalled();

    const dryRun = await runWorkflow(["scan", "--patch", "--dry-run"]);
    expect(dryRun.exitCode).toBe(2);
    expect(dryRun.stderr).toContain(
      "--patch cannot be combined with --dry-run",
    );
  });

  test("reviews full findings and honors individual interactive patch selections", async () => {
    for (const [argv, selection, expected] of [
      [
        ["scan"],
        { severity: "medium", occurrenceIds: ["occ_1", "occ_2"] },
        ["occ_1", "occ_2"],
      ],
      [
        ["scan", "--patch"],
        { severity: "low", occurrenceIds: ["occ_1", "occ_3"] },
        ["occ_1", "occ_3"],
      ],
      [["scan"], null, []],
    ] as const) {
      let reviewed: readonly Finding[] = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [...argv],
        {
          result: resultWithFindings(["high", "medium", "low"]),
          onCodex: (args, output) => {
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
        {
          interactive: true,
          configure: (value) => {
            value.patchEditor = async (repository, candidates) => {
              expect(repository).toBe(CURRENT_REPOSITORY);
              reviewed = candidates;
              return selection === null
                ? null
                : {
                    severity: selection.severity,
                    occurrenceIds: [...selection.occurrenceIds],
                  };
            };
          },
        },
      );
      expect(outcome.exitCode).toBe(0);
      expect(reviewed.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
        "occ_3",
      ]);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        ...expected,
      ]);
      if (argv[1] === "--patch") {
        expect(outcome.stderr).not.toContain(
          "Review and patch these findings?",
        );
      } else {
        expect(outcome.stderr).toContain("Review and patch these findings?");
      }
    }
  });

  test("shows normal scan findings before optionally opening patch review", async () => {
    for (const review of [true, false]) {
      let opened = false;
      let patched = false;
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (args, output) => {
            patched = true;
            completePatches(args, output);
            return 0;
          },
        },
        {
          interactive: true,
          review,
          configure: (value) => {
            value.patchEditor = async () => {
              opened = true;
              return { severity: "high", occurrenceIds: ["occ_1"] };
            };
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr.indexOf("FINDINGS")).toBeLessThan(
        outcome.stderr.indexOf("Review and patch these findings? (y/N)"),
      );
      expect(opened).toBe(review);
      expect(patched).toBe(review);
    }
  });

  test("does not offer patch review when there are no actionable findings", async () => {
    for (const severities of [[], ["informational"]] as const) {
      const confirmPatchReview = mock(resolving(true));
      const patchEditor = mock(resolving(null));
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(severities),
          environment: { NO_COLOR: "1" },
        },
        {
          interactive: true,
          configure: (value) => {
            value.confirmPatchReview = confirmPatchReview;
            value.patchEditor = patchEditor;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain(`FINDINGS  ${severities.length}`);
      expect(outcome.stderr).not.toContain("Review and patch these findings?");
      expect(confirmPatchReview).not.toHaveBeenCalled();
      expect(patchEditor).not.toHaveBeenCalled();
    }
  });

  test("sanitizes interactive patch status", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    finding.title = "\u001B[31mUnsafe title\u001B[0m\nforged line";
    finding.locations[0]!.path = "src/\u001B[31mquery.ts\u001B[0m";
    const outcome = await runWorkflow(
      ["scan"],
      { result },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
          });
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stderr).toContain("VERIFIED  Unsafe title forged line");
    expect(outcome.stderr).not.toContain("Unsafe title\u001B[0m");
  });

  test("passes separate instructions only for interactively selected findings", async () => {
    const prompts: string[] = [];
    const patched: Finding[] = [];
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high", "medium", "low"]),
        onCodex: (args, output) => {
          prompts.push(output!.appServer!.prompt);
          patched.push(...completePatches(args, output));
          return 0;
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "low",
            occurrenceIds: ["occ_1", "occ_3"],
            instructions: {
              occ_1: "Reuse the shared validator.\nDo not add a dependency.",
              occ_2: "This unselected guidance must not reach the model.",
              occ_3: "Preserve the public API.",
            },
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_3",
    ]);

    expect(prompts).toHaveLength(2);
    for (const [index, prompt] of prompts.entries()) {
      const lines = prompt.split("\n");
      const instructionsLine = lines.findIndex((line) =>
        line.startsWith("Follow these user-provided patch instructions"),
      );
      expect(instructionsLine).toBeGreaterThan(-1);
      expect(JSON.parse(lines[instructionsLine + 1]!)).toEqual(
        index === 0
          ? { occ_1: "Reuse the shared validator.\nDo not add a dependency." }
          : { occ_3: "Preserve the public API." },
      );
      expect(prompt).not.toContain("This unselected guidance");
    }
    expect(patched[0]).not.toHaveProperty("instructions");
  });

  test("creates a draft pull request when selected in the interactive review", async () => {
    let published = false;
    const url = "https://github.example.test/example/repository/pull/13";
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          if (args.includes("--cached")) return "";
          published ||= command === "gh" && args[1] === "create";
          if (command === "gh" && args[1] === "list") return "[]";
          return command === "gh" && args[1] === "create"
            ? url
            : args.includes("--name-only")
              ? "src/finding-1.ts\0"
              : "";
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
            createPullRequest: true,
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(published).toBe(true);
    expect(outcome.stderr).toContain(`Pull request: ${url}`);
  });

  test("patches a saved scan by severity and supports structured output", async () => {
    const result = resultWithFindings(["high", "medium"]);
    let patched: Finding[] = [];
    let workingDirectory = "";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--severity", "high", "--json"],
      {
        onWorkbench: (args): JsonObject => {
          expect(args).toEqual(["get-scan", "--scan-id", "scan-1"]);
          return savedScan(result);
        },
        onCodex: (args, output) => {
          workingDirectory = output!.appServer!.directory;
          patched = completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(workingDirectory).toBe(SAVED_REPOSITORY);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual(["occ_1"]);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      scanId: "scan-1",
      repository: SAVED_REPOSITORY,
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
    });
  });

  test.each([
    [
      "https://github.example.test/example/repository.git",
      { GITLAB_HOST: "gitlab.com" },
      "gh",
    ],
    ["https://gitlab.com/example/subgroup/repository.git", {}, "glab"],
    ["git@gitlab.com:example/subgroup/repository.git", {}, "glab"],
    ["ssh://git@gitlab.com:2222/example/subgroup/repository.git", {}, "glab"],
    [
      "git@gitlab.example.test:example/subgroup/repository.git",
      { GITLAB_HOST: "gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_HOST: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_URI: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GL_HOST: "gitlab.example.test" },
      "glab",
    ],
    ["https://gitlab.example.test/example/repository.git", {}, "gh"],
  ] as const)(
    "publishes saved-finding patches for origin %s with environment %j using %s",
    async (origin, environment, client) => {
      const repository = await fixtures.create("patch-provider-repository-");
      const result = resultWithFindings(["high"]);
      const url =
        client === "glab"
          ? "https://gitlab.example.test/example/repository/-/merge_requests/14"
          : "https://github.example.test/example/repository/pull/14";
      const publicationCommands: Array<readonly string[]> = [];
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          environment,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onRepositoryCommand: (command, args, target) => {
            expect(target).toBe(repository);
            if (command === "git") {
              if (args.includes("--show-toplevel")) return repository;
              if (args.includes("--cached")) return "";
              if (args[0] === "remote") {
                expect([
                  ["remote", "get-url", "--push", "--all", "origin"],
                  ["remote", "get-url", "origin"],
                ]).toContainEqual([...args]);
                return origin;
              }
              return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
            }
            expect(command).toBe(client);
            publicationCommands.push(args);
            return args[1] === "create" ? url : command === "gh" ? "[]" : "";
          },
        },
        {
          configure: (current) => {
            Object.assign(current, {
              assessPatchRisk: async () => patchRiskAssessment(),
            });
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(publicationCommands.map((args) => args[1])).toEqual([
        "list",
        "list",
        "create",
      ]);
      if (client === "glab") {
        expect(publicationCommands.slice(1)).toEqual([
          [
            "mr",
            "list",
            "--all",
            "--source-branch",
            "codex-security/patch-scan-1",
            "--output",
            "json",
            "--jq",
            ".[0] | select(. != null) | {url: .web_url, head: .sha}",
            "--repo",
            origin,
          ],
          [
            "mr",
            "create",
            "--draft",
            "--head",
            origin,
            "--source-branch",
            "codex-security/patch-scan-1",
            "--title",
            "fix: patch verified security findings",
            "--description",
            expect.stringContaining(patchRiskSummary()),
            "--yes",
            "--repo",
            origin,
          ],
        ]);
      }
      expect(outcome.stderr).toContain(
        `${client === "glab" ? "Merge" : "Pull"} request: ${url}`,
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        scanId: "scan-1",
        pullRequest: { branch: "codex-security/patch-scan-1", url },
      });
    },
  );

  test.each(["patch", "scan"])(
    "escapes controls in %s pull request failures while preserving error details",
    async (command) => {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr"]
          : ["scan", ".", "--patch", "--create-pr"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onRepositoryCommand: throwing(
            "GitHub rejected github_pat_SYNTHETIC_SECRET_123\u001b[2J\ncontinued",
          ),
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "GitHub rejected github_pat_SYNTHETIC_SECRET_123 [2J continued\n",
      );
      expect(outcome.stderr).not.toContain("\u001b");
    },
  );

  test("resolves a finding identifier to its saved scan and checkout", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    const calls: Array<readonly string[]> = [];
    let patched: Finding[] = [];
    const outcome = await runWorkflow(["patch", "occ_1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-global-findings") {
          return {
            findings: [
              { ...finding, scanId: "scan-1" } as unknown as JsonObject,
            ],
          };
        }
        return savedScan(result);
      },
      onCodex: (args, output) => {
        patched = completePatches(args, output);
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-global-findings", "--status", "open"],
      ["get-scan", "--scan-id", "scan-1", "--occurrence-id", "occ_1"],
    ]);
    expect(patched).toEqual([finding]);
  });

  test("selects the latest completed scan for the current repository", async () => {
    const result = resultWithFindings(["high"]);
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "latest"], {
      currentDirectory: SAVED_REPOSITORY,
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-scans") {
          return { scans: [{ scanId: "scan-complete" }] };
        }
        return savedScan(result, "scan-complete");
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", SAVED_REPOSITORY, "--status", "complete"],
      ["get-scan", "--scan-id", "scan-complete"],
    ]);
  });

  test("reads every page when saved scan findings are truncated", async () => {
    const result = resultWithFindings(["high", "medium"]);
    const patched: Finding[] = [];
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "scan-1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "get-scan") {
          return {
            scan: {
              scanId: "scan-1",
              targetPath: SAVED_REPOSITORY,
              findings: [],
              findingsTruncated: true,
            },
          };
        }
        const secondPage = args.includes("--offset");
        return {
          findingsPage: {
            findings: [
              result.findings.findings[
                secondPage ? 1 : 0
              ] as unknown as JsonObject,
            ],
            nextOffset: secondPage ? null : 1,
          },
        };
      },
      onCodex: (args, output) => {
        patched.push(...completePatches(args, output));
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_2",
    ]);
    expect(calls).toEqual([
      ["get-scan", "--scan-id", "scan-1"],
      ["list-findings", "--scan-id", "scan-1", "--status", "open"],
      [
        "list-findings",
        "--scan-id",
        "scan-1",
        "--status",
        "open",
        "--offset",
        "1",
      ],
    ]);
  });

  test("rejects a severity threshold without an explicit patch request", async () => {
    const outcome = await runWorkflow(["scan", "--patch-severity", "high"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("--patch-severity requires --patch");
  });

  test("requires patching and a clean supplied-issue checkout before creating a pull request", async () => {
    const scan = await runWorkflow(["scan", "--create-pr"]);
    expect(scan.exitCode).toBe(2);
    expect(scan.stderr).toContain("--create-pr requires --patch");

    const directory = await temporaryDirectory("codex-security-dirty-pr-");
    const git = repositoryGit(directory);
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", "--", "app.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(directory, "app.ts"), "user change\n");
      const onCodex = mock<() => number>().mockReturnValue(0);
      const literal = await runWorkflow(
        ["patch", "Synthetic security issue", "--create-pr"],
        {
          currentDirectory: directory,
          onCodex,
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );
      expect(literal.exitCode).toBe(2);
      expect(literal.stderr).toContain(
        "Pull request creation for supplied issues requires a clean working tree.",
      );
      expect(onCodex).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

describe("patch publication integrity", () => {
  const fixtures = createTemporaryDirectories(true);
  test.each(
    ["environment", "config"].flatMap((selection) =>
      ["root", "package"].flatMap((scope) =>
        ["absolute", "relative"].flatMap((spelling) =>
          [false, true].map((assess) => ({
            selection,
            scope,
            spelling,
            assess,
          })),
        ),
      ),
    ),
  )(
    "preserves separately configured worktree metadata from $scope with $spelling $selection path and assessment=$assess",
    async ({ selection, scope, spelling, assess }) => {
      const root = await fixtures.create("patch-separate-worktree-");
      const metadata = join(root, "metadata");
      const tree = join(root, "selected-tree");
      const directory = scope === "root" ? metadata : join(metadata, "package");
      const nested = join(tree, "nested");
      await mkdir(directory, { recursive: true });
      await mkdir(nested, { recursive: true });
      for (const repository of [metadata, nested]) {
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "nested before\n");
      const nestedGit = repositoryGit(nested);
      nestedGit("add", ".");
      nestedGit("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(tree, "app.ts"), "before\n");
      await writeFile(join(tree, "unrelated.txt"), "original\n");
      if (selection === "config")
        repositoryGit(metadata)(
          "config",
          "core.worktree",
          spelling === "absolute"
            ? tree
            : relative(join(metadata, ".git"), tree),
        );
      const environment =
        selection === "environment"
          ? {
              GIT_WORK_TREE:
                spelling === "absolute" ? tree : relative(directory, tree),
            }
          : {};
      const beforeEnvironment = { ...environment };
      const git = (...args: string[]) =>
        runGitRepositoryCommand("git", args, directory, { environment });
      await git("add", ".");
      await git("commit", "-m", "Synthetic baseline");
      await writeFile(join(tree, "unrelated.txt"), "staged user change\n");
      await git("add", "--", join(tree, "unrelated.txt"));
      const head = await git("rev-parse", "HEAD");
      const staged = await git("diff", "--cached", "--binary");
      const indexes = [metadata, nested].map((path) =>
        join(path, ".git", "index"),
      );
      const beforeIndexes = await Promise.all(
        indexes.map((path) => readFile(path)),
      );
      let modelCalls = 0;
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--json",
          ...(assess ? ["--assess-patch-risk"] : []),
        ],
        {
          currentDirectory: directory,
          environment,
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            modelCalls++;
            await writeFile(join(tree, "app.ts"), "fixed\n");
            if (!assess)
              await writeFile(join(nested, "app.ts"), "nested fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async (request) => {
              assessments++;
              expect(request.repository).toBe(tree);
              expect(request.files).toEqual(["app.ts"]);
              expect(
                await runGitRepositoryCommand(
                  "git",
                  ["rev-parse", "HEAD"],
                  tree,
                  {
                    environment: request.environment,
                  },
                ),
              ).toBe(head);
              expect(
                await runGitRepositoryCommand(
                  "git",
                  ["diff", "--name-only"],
                  tree,
                  {
                    environment: request.environment,
                  },
                ),
              ).toBe("app.ts");
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(assessments).toBe(assess ? 1 : 0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: assess ? ["app.ts"] : ["app.ts", "nested/app.ts"],
      });
      expect(await git("rev-parse", "HEAD")).toBe(head);
      expect(await git("diff", "--cached", "--binary")).toBe(staged);
      expect(await Promise.all(indexes.map((path) => readFile(path)))).toEqual(
        beforeIndexes,
      );
      expect(await readFile(join(tree, "unrelated.txt"), "utf8")).toBe(
        "staged user change\n",
      );
      expect(environment).toEqual(beforeEnvironment);
    },
  );

  test.each(
    ["ordinary", "absolute", "relative", "empty"].flatMap((settings) =>
      [
        { command: "patch", flag: undefined },
        { command: "patch", flag: "--assess-patch-risk" },
        { command: "patch", flag: "--create-pr" },
        { command: "scan", flag: undefined },
        { command: "scan", flag: "--create-pr" },
      ].map((entry) => ({ settings, ...entry })),
    ),
  )(
    "preserves $command patch scope with $settings Git settings and $flag",
    async ({ settings, command, flag }) => {
      const root = await fixtures.create("patch-direct-scope-");
      const directory = join(root, "package");
      await mkdir(directory);
      const gitSettings =
        settings === "ordinary"
          ? {}
          : {
              GIT_DIR:
                settings === "relative"
                  ? "../.git"
                  : settings === "empty"
                    ? ""
                    : join(root, ".git"),
              GIT_WORK_TREE:
                settings === "relative"
                  ? ".."
                  : settings === "empty"
                    ? ""
                    : root,
            };
      const settingsBefore = JSON.stringify(gitSettings);
      let inputDependencies: ReturnType<typeof dependencies> | undefined;
      let inputRunner:
        ReturnType<typeof dependencies>["runRepositoryCommand"] | undefined;
      let modelCalls = 0;
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-direct-scope-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const scanResult = resultWithFindings(["high"]);
      scanResult.findings.findings[0]!.locations[0]!.path = "app.ts";
      const fixture: Parameters<typeof dependencies>[0] = {
        result: scanResult,
        currentDirectory: directory,
        environment: gitSettings,
        onRepositoryCommand: async (command, args, cwd, options) => {
          const gitOptions = {
            ...options,
            environment: { ...gitSettings, ...options?.environment },
          };
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, gitOptions);
          if (args[1] === "list") {
            expect(
              resolve(
                await runGitRepositoryCommand(
                  "git",
                  ["rev-parse", "--show-toplevel"],
                  cwd,
                  gitOptions,
                ),
              ),
            ).toBe(root);
            return "[]";
          }
          return "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (_args, output) => {
          modelCalls++;
          expect(output?.appServer?.directory).toBe(directory);
          await writeFile(join(directory, "app.ts"), "fixed\n");
          if (command === "scan") completePatches(_args, output);
          else output?.stdout.write("Fixed and checked.");
          return 0;
        },
      };
      const outcome = await runWorkflow(
        [
          ...(command === "scan"
            ? ["scan", ".", "--patch"]
            : ["patch", "Synthetic issue"]),
          "--json",
          ...(flag ? [flag] : []),
        ],
        fixture,
        {
          configure: (current) => {
            inputDependencies = current;
            inputRunner = current.runRepositoryCommand;
            current.assessPatchRisk = async (request) => {
              expect(request.repository).toBe(root);
              expect(request.files).toEqual(["package/app.ts"]);
              expect(
                resolve(
                  await runGitRepositoryCommand(
                    "git",
                    ["rev-parse", "--show-toplevel"],
                    request.repository,
                    {
                      environment: request.environment ?? current.environment,
                    },
                  ),
                ),
              ).toBe(root);
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(inputDependencies!.runRepositoryCommand).toBe(inputRunner!);
      expect(JSON.stringify(inputDependencies!.environment)).toBe(
        settingsBefore,
      );
      expect(JSON.stringify(gitSettings)).toBe(settingsBefore);
      if (settings === "empty") {
        expect(outcome.exitCode).toBe(flag === undefined ? 0 : 2);
        expect(modelCalls).toBe(flag === undefined ? 1 : 0);
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      if (flag === "--create-pr") {
        const resumed = await runWorkflow(
          ["patch", "--resume-pr", git("branch", "--show-current"), "--json"],
          fixture,
        );
        expect(resumed.exitCode, resumed.stderr).toBe(0);
        expect(modelCalls).toBe(1);
      }
      const result = JSON.parse(outcome.stdout);
      if (command === "patch")
        expect({
          repository: relative(directory, result.repository),
          files: result.files,
        }).toEqual({ repository: "", files: ["package/app.ts"] });
      else
        expect(result.patches).toMatchObject([
          { status: "verified", files: ["app.ts"] },
        ]);
    },
  );

  test.each(
    ["staged", "unstaged", "assume-unchanged", "clean", "deleted-before"]
      .flatMap((dirty) =>
        ["new.ts", "old.ts/new.ts"].map((file) => [dirty, file] as const),
      )
      .concat(
        [
          "clean-staged-rename",
          "clean-staged-rename-supplied",
          "clean-source-directory",
          "clean-selected-source-directory",
          "clean-selected-absent",
          "clean-ignored-directory",
        ].flatMap((state) =>
          [
            "new.ts",
            ...(state.startsWith("clean-staged-rename") ||
            state.startsWith("clean-selected")
              ? [
                  "src/new.ts",
                  ...(process.platform === "win32" ? ["src\\new.ts"] : []),
                ]
              : []),
          ].map((file) => [state, file] as const),
        ),
      ),
  )("handles a renamed %s file at %s", async (dirty, file) => {
    const directory = await fixtures.create("patch-renamed-local-edits-");
    const git = repositoryGit(directory);
    const source = /^src[/\\]/u.test(file) ? "src/old.ts" : "old.ts";
    await mkdir(dirname(join(directory, source)), { recursive: true });
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(directory, source), "unsafe\noriginal\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const supplied = dirty === "clean-staged-rename-supplied";
    const hasLocalEdits =
      !dirty.startsWith("clean") && dirty !== "deleted-before";
    const content = hasLocalEdits ? "synthetic local edit" : "original";
    if (hasLocalEdits)
      await writeFile(join(directory, source), `unsafe\n${content}\n`);
    if (dirty === "deleted-before") await rm(join(directory, source));
    if (dirty === "staged") git("add", ".");
    if (dirty === "assume-unchanged")
      git("update-index", "--assume-unchanged", source);
    await writeFile(join(directory, "unrelated.ts"), "original\n");
    await writeFile(join(directory, "hidden.ts"), "hidden\n");
    git("add", "unrelated.ts", "hidden.ts");
    git(
      "commit",
      "--only",
      "-m",
      "Unrelated baseline",
      "--",
      "unrelated.ts",
      "hidden.ts",
    );
    if (!supplied) {
      await writeFile(join(directory, "unrelated.ts"), "staged work\n");
      git("add", "unrelated.ts");
      await writeFile(join(directory, "unrelated.ts"), "working work\n");
      git("update-index", "--skip-worktree", "hidden.ts");
      await writeFile(join(directory, "intent.ts"), "intent\n");
      git("add", "--intent-to-add", "intent.ts");
    }
    const unrelated = git(
      "ls-files",
      "--stage",
      "--debug",
      "--",
      "unrelated.ts",
      "hidden.ts",
      "intent.ts",
    );
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const remote = await fixtures.create("patch-renamed-local-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = source;
    const outcome = await runWorkflow(
      [
        "patch",
        ...(supplied ? ["Synthetic issue"] : ["--scan", "scan-1"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          if (dirty.startsWith("clean-staged-rename")) git("mv", source, file);
          else await rm(join(directory, source), { force: true });
          if (
            dirty.endsWith("source-directory") ||
            dirty === "clean-ignored-directory"
          ) {
            await mkdir(join(directory, source));
            await writeFile(
              join(directory, source, "unverified.txt"),
              "unverified\n",
            );
            if (dirty === "clean-ignored-directory")
              await writeFile(
                join(directory, ".git/info/exclude"),
                "old.ts/\n",
              );
          }
          await mkdir(dirname(join(directory, file)), { recursive: true });
          await writeFile(join(directory, file), `fixed\n${content}\n`);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: [
                    file,
                    ...(dirty.startsWith("clean-selected") ? [source] : []),
                  ],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(hasLocalEdits ? 2 : 0);
    if (hasLocalEdits) {
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
      expect(git("ls-remote", "origin")).toBe("");
    } else {
      expect(git("show", `HEAD:${file.replaceAll("\\", "/")}`)).toBe(
        `fixed\n${content}`,
      );
      if (dirty.startsWith("clean"))
        expect(
          git("diff", "--name-status", "--no-renames", "HEAD^", "HEAD"),
        ).toContain(`D\t${source}`);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
    }
    expect(
      git(
        "ls-files",
        "--stage",
        "--debug",
        "--",
        "unrelated.ts",
        "hidden.ts",
        "intent.ts",
      ),
    ).toBe(unrelated);
    expect(await readFile(join(directory, "unrelated.ts"), "utf8")).toBe(
      supplied ? "original\n" : "working work\n",
    );
    if (
      dirty.endsWith("source-directory") ||
      dirty === "clean-ignored-directory"
    ) {
      expect(
        await readFile(join(directory, source, "unverified.txt"), "utf8"),
      ).toBe("unverified\n");
      expect(
        git("ls-tree", "-r", "--name-only", "HEAD").includes("unverified.txt"),
      ).toBe(dirty === "clean-selected-source-directory");
    }
    expect(await readFile(join(directory, file), "utf8")).toBe(
      `fixed\n${content}\n`,
    );
  });

  afterEach(fixtures.cleanup);
  test.each(["commit", "commit result", "checkpoint"])(
    "preserves local work when patch %s fails",
    async (failure) => {
      const directory = await fixtures.create("patch-creation-failure-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
      await writeFile(join(directory, "other.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-creation-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      await writeFile(join(directory, "other.ts"), "staged work\n");
      git("add", "other.ts");
      const base = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command !== "git") return "[]";
            if (failure === "commit result" && args.includes("commit")) {
              runGitRepositoryCommand(command, args, cwd, options);
              throw new Error("Synthetic commit result failure");
            }
            if (
              (failure === "commit" && args.includes("commit")) ||
              (failure === "checkpoint" &&
                args[0] === "config" &&
                args[1] === "--local")
            )
              throw new Error(`Synthetic ${failure} failure`);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(`Synthetic ${failure} failure`);
      expect(outcome.stderr).not.toContain("Retry from this repository");
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("other.ts");
      if (failure === "commit") {
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("rev-parse", "HEAD")).toBe(base);
        expect(git("write-tree")).toBe(index);
        expect(
          git(
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/codex-security/patch-scan-1",
          ),
        ).toBe("");
      } else {
        expect(git("branch", "--show-current")).toBe(
          "codex-security/patch-scan-1",
        );
        expect(git("rev-parse", "HEAD")).not.toBe(base);
        expect(outcome.stderr).toContain("checkpoint could not be saved");
      }
    },
  );

  test.each(["gh", "glab"])(
    "refuses a %s resume when the published head differs from the saved commit",
    async (client) => {
      const onCodex = mock(() => 0);
      let pushes = 0;
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", "--json"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (args[0] === "config")
                return args.at(-1)?.endsWith("PatchCommit")
                  ? "verified-commit"
                  : "Synthetic body";
              if (args[0] === "rev-parse") return "verified-commit";
              if (args[0] === "remote")
                return `https://${client === "glab" ? "gitlab.com" : "github.example.test"}/example/repository.git`;
              if (args[0] === "push") pushes += 1;
              return "";
            }
            expect(command).toBe(client);
            if (args[0] === "repo") return "synthetic-origin-id";
            const candidate = {
              url: `https://${client === "glab" ? "gitlab.com" : "github.example.test"}/example/repository/requests/1`,
              head: "earlier-commit",
              repository: "synthetic-origin-id",
              crossRepository: false,
            };
            return JSON.stringify(client === "glab" ? candidate : [candidate]);
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "does not contain the saved patch commit",
      );
      expect(pushes).toBe(0);
      expect(onCodex).not.toHaveBeenCalled();
    },
  );

  test.each([
    ["staged", "src/finding-1.ts"],
    ["staged", "src"],
    ["unstaged", "src/finding-1.ts"],
    ["unstaged", "src"],
    ["assume-unchanged", "src/finding-1.ts"],
    ["assume-unchanged", "src"],
    ["untracked-and-ignored", "src"],
  ])("keeps %s edits out of publication of %s", async (dirty, reportedPath) => {
    for (const command of ["patch", "scan"]) {
      const directory = await fixtures.create("patch-publication-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = reportedPath;
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(
        join(directory, "src/finding-1.ts"),
        "unsafe\noriginal\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const originalHead = git("rev-parse", "HEAD");
      await writeFile(
        join(directory, "src/finding-1.ts"),
        "unsafe\nlocal edit\n",
      );
      if (dirty === "staged") git("add", ".");
      if (dirty === "assume-unchanged")
        git("update-index", "--assume-unchanged", "src/finding-1.ts");
      let expectedIndex = git("write-tree");
      const remote = await fixtures.create("patch-publication-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
          : ["scan", directory, "--patch", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(
              join(directory, "src/finding-1.ts"),
              "fixed\nlocal edit\n",
            );
            if (dirty === "untracked-and-ignored") {
              await writeFile(
                join(directory, ".gitignore"),
                "src/finding-1.ts\n",
              );
              git("rm", "--cached", "--force", "src/finding-1.ts");
              expectedIndex = git("write-tree");
            }
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(originalHead);
      expect(git("write-tree")).toBe(expectedIndex);
      expect(git("ls-remote", "origin")).toBe("");
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\nlocal edit\n",
      );
    }
  });

  test.each(["local", "remote", "push remote", "OPEN", "CLOSED", "MERGED"])(
    "preserves an existing %s patch publication",
    async (existing) => {
      const directory = await fixtures.create("patch-repeat-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await mkdir(join(directory, "src"));
      await writeFile(join(directory, "src/finding-1.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-repeat-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      if (existing === "local") git("branch", "codex-security/patch-scan-1");
      if (existing === "push remote") {
        const pushRemote = await fixtures.create("patch-repeat-push-remote-");
        git("init", "--bare", pushRemote);
        git("remote", "set-url", "--push", "origin", pushRemote);
      }
      if (existing === "remote" || existing === "push remote")
        git("push", "origin", "HEAD:refs/heads/codex-security/patch-scan-1");
      const branch = "codex-security/patch-scan-1";
      const pushRemote = git("remote", "get-url", "--push", "origin");
      const before = git("ls-remote", pushRemote, `refs/heads/${branch}`);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : existing === "remote" || existing === "push remote"
                ? "[]"
                : JSON.stringify([
                    {
                      url: "https://github.example.test/example/repository/pull/1",
                      head: git("rev-parse", "HEAD"),
                      repository: "synthetic-origin-id",
                      crossRepository: false,
                      state: existing,
                    },
                  ]),
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(onCodex).toHaveBeenCalledTimes(0);
      expect(git("ls-remote", pushRemote, `refs/heads/${branch}`)).toBe(before);
      expect(outcome.stderr).toContain("already exists");
    },
  );

  test.each([130, 143])(
    "retains completed and partial patch changes after exit %s",
    async (status) => {
      const directory = await fixtures.create("patch-interrupted-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high", "high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      for (const index of [1, 2])
        await writeFile(join(directory, `src/finding-${index}.ts`), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (args, output) => {
            calls += 1;
            await writeFile(
              join(directory, `src/finding-${calls}.ts`),
              "changed\n",
            );
            if (calls === 2) return status;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        filesChanged: 2,
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          {
            occurrenceId: "occ_2",
            status: "failed",
            files: ["src/finding-2.ts"],
          },
        ],
      });
    },
  );

  test.each(["outer", "nested"])(
    "ignores %s build output when a repository contains a gitlink",
    async (location) => {
      const directory = await fixtures.create("patch-git-ignore-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, ".gitignore"), "build.log\n");
      const nested = join(directory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, ".gitignore"), "build.log\n");
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(
              join(location === "outer" ? directory : nested, "build.log"),
              "build finished\n",
            );
            output?.stdout.write("No source changes were needed.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: false,
        files: [],
      });
      expect(git("status", "--porcelain")).toBe("");
    },
  );

  test.each([false, true])(
    "resolves pre-existing dirty paths from the Git root for a subdirectory scan: overlap=%s",
    async (overlap) => {
      const directory = await fixtures.create(
        "patch-subdirectory-publication-",
      );
      const git = repositoryGit(directory);
      const scanned = join(directory, "package");
      await mkdir(scanned);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "package.json"), "root original\n");
      await writeFile(join(scanned, "package.json"), "unsafe\noriginal\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const dirty = overlap ? "package/package.json" : "package.json";
      await writeFile(join(directory, dirty), "unsafe\nlocal edit\n");
      git("add", dirty);
      const originalHead = git("rev-parse", "HEAD");
      const originalIndex = git("write-tree");
      const remote = await fixtures.create("patch-subdirectory-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "package.json";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: scanned,
          onWorkbench: () => savedScan(result, "scan-1", scanned),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(
              join(scanned, "package.json"),
              overlap ? "fixed\nlocal edit\n" : "fixed\noriginal\n",
            );
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(overlap ? 2 : 0);
      if (overlap) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(originalHead);
        expect(git("write-tree")).toBe(originalIndex);
        expect(git("ls-remote", "origin")).toBe("");
      } else {
        expect(git("diff", "--cached", "--name-only")).toBe("package.json");
        expect(git("diff", "--name-only", originalHead, "HEAD")).toBe(
          "package/package.json",
        );
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      }
    },
  );

  test("keeps the original branch when a verified file belongs to a nested repository", async () => {
    const directory = await fixtures.create("patch-nested-publication-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const nested = join(directory, "nested");
    await mkdir(nested);
    const inner = repositoryGit(nested);
    inner("init", "--initial-branch=main");
    inner("config", "user.name", "Synthetic User");
    inner("config", "user.email", "synthetic@example.test");
    await writeFile(join(nested, "app.ts"), "unsafe\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const remote = await fixtures.create("patch-nested-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "nested/app.ts";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : "[]",
        onCodex: async (args, output) => {
          await writeFile(join(nested, "app.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("submodule");
    expect(git("branch", "--show-current")).toBe("main");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("write-tree")).toBe(index);
    expect(
      git(
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/codex-security/patch-scan-1",
      ),
    ).toBe("");
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
  });

  test.skipIf(process.platform === "win32")(
    "preserves trailing spaces in worktree roots during risk assessment and publication",
    async () => {
      for (const flag of ["--assess-patch-risk", "--create-pr"]) {
        const parent = await fixtures.create("patch-space-root-");
        const directory = join(parent, "checkout ");
        await mkdir(directory);
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(directory, "app.ts"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const remote = await fixtures.create("patch-space-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", flag, "--json"],
          {
            currentDirectory: directory,
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (_args, output) => {
              await writeFile(join(directory, "app.ts"), "fixed\n");
              output?.stdout.write("Fixed and checked.");
              return 0;
            },
          },
          {
            configure: (current) => {
              current.assessPatchRisk = async (request) => {
                expect(request.repository).toBe(directory);
                return patchRiskAssessment();
              };
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout)).toMatchObject({ applied: true });
      }
    },
  );

  test("patches a repository with a Git tree listing larger than one MiB", async () => {
    const directory = await fixtures.create("patch-large-tree-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const name = "a".repeat(70);
    await Promise.all(
      Array.from({ length: 10000 }, (_, index) =>
        writeFile(
          join(directory, `${name}${index.toString().padStart(5, "0")}.ts`),
          "original\n",
        ),
      ),
    );
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: directory,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        await writeFile(join(directory, "fix.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["fix.ts"],
    });
  });

  test.each(["saved", "supplied"])(
    "patches an unrelated file with an unresolved index in %s mode",
    async (mode) => {
      const { directory, git } = await createPublicationRepository(fixtures);
      const conflictPath = join(directory, "conflict [literal].txt");
      await writeFile(conflictPath, "baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic conflict baseline");
      git("switch", "-c", "other");
      await writeFile(conflictPath, "theirs\n");
      git("commit", "-am", "Synthetic other change");
      git("switch", "main");
      await writeFile(conflictPath, "ours\n");
      git("commit", "-am", "Synthetic main change");
      expect(() => git("merge", "other")).toThrow();
      const unmerged = git("ls-files", "--unmerged", "-z");
      expect(unmerged).not.toBe("");
      const indexPath = join(directory, ".git/index");
      const index = await readFile(indexPath);
      const indexMode = (await stat(indexPath)).mode;
      const conflict = await readFile(conflictPath);
      const conflictMode = (await stat(conflictPath)).mode;
      let modelCalls = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--json",
        ],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            modelCalls++;
            expect(await readFile(indexPath)).toEqual(index);
            expect(await readFile(conflictPath)).toEqual(conflict);
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            if (mode === "saved") completePatches(args, output);
            else output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(git("ls-files", "--unmerged", "-z")).toBe(unmerged);
      expect(await readFile(indexPath)).toEqual(index);
      expect((await stat(indexPath)).mode).toBe(indexMode);
      expect(await readFile(conflictPath)).toEqual(conflict);
      expect((await stat(conflictPath)).mode).toBe(conflictMode);
    },
  );

  test.each(["unborn", "nested"])(
    "detects local patches in %s Git repositories",
    async (kind) => {
      const directory = await fixtures.create("patch-git-state-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      let path = "app.ts";
      if (kind === "nested") {
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const nested = join(directory, "nested");
        await mkdir(nested);
        const inner = repositoryGit(nested);
        inner("init", "--initial-branch=main");
        inner("config", "user.name", "Synthetic User");
        inner("config", "user.email", "synthetic@example.test");
        await writeFile(join(nested, "app.ts"), "unsafe\n");
        inner("add", ".");
        inner("commit", "-m", "Synthetic nested baseline");
        path = "nested/app.ts";
      }
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(join(directory, path), "fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: [path],
      });
    },
  );
});

describe("patch change tracking", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  const publicationRepository = () => createPublicationRepository(fixtures);

  test.each(
    ["pre-commit", "post-checkout"].flatMap((hook) =>
      ["src/finding-1.ts", "src/finding-1.ts/fixed.ts"].map(
        (file) => [hook, file] as const,
      ),
    ),
  )("restores the complete index after %s fails for %s", async (hook, file) => {
    const { directory, git } = await publicationRepository();
    await writeFile(join(directory, "other.ts"), "original\n");
    await writeFile(join(directory, "hidden.ts"), "hidden original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic unrelated files");
    await writeFile(join(directory, "other.ts"), "staged local edit\n");
    git("add", "other.ts");
    git("update-index", "--skip-worktree", "hidden.ts");
    await writeFile(join(directory, "intent.ts"), "local intent\n");
    git("add", "--intent-to-add", "intent.ts");
    const head = git("rev-parse", "HEAD");
    const entries = git("ls-files", "--stage", "-v");
    let indexBefore: Buffer<ArrayBuffer> | undefined;
    const indexPath = git(
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    );
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command !== "git") return "[]";
          if (args[0] === "switch" && args[1] === "-c")
            indexBefore = await readFile(indexPath);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          await rm(join(directory, "src/finding-1.ts"));
          await mkdir(dirname(join(directory, file)), { recursive: true });
          await writeFile(join(directory, file), "fixed\n");
          const hookPath = git("rev-parse", "--git-path", `hooks/${hook}`);
          const absoluteHook = resolve(directory, hookPath);
          await writeFile(
            absoluteHook,
            "#!/bin/sh\necho 'Synthetic hook failure' >&2\nexit 1\n",
          );
          await chmod(absoluteHook, 0o755);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: [file],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("Synthetic hook failure");
    expect(git("branch", "--show-current")).toBe("main");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(indexPath)).toEqual(indexBefore!);
    expect(git("ls-files", "--stage", "-v")).toBe(entries);
    expect(
      git(
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/codex-security/patch-scan-1",
      ),
    ).toBe("");
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(directory, file), "utf8")).toBe("fixed\n");
  });

  test.each([false, true])(
    "risk assessment and publication agree when a rename source becomes a directory (selected: %p)",
    async (selectDirectory) => {
      const { directory, git } = await publicationRepository();
      await writeFile(join(directory, "z.ts"), "Verified rename source\n");
      await writeFile(join(directory, "zz.ts"), "Unrelated rename source\n");
      git("add", "z.ts", "zz.ts");
      git("commit", "-m", "Synthetic rename sources");
      const before = git("rev-parse", "HEAD");
      const result = resultWithFindings(["high"]);
      let assessedFiles: string[] = [];
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[] };
              assessedFiles = artifact.changedFiles;
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("diff --git a/new.ts b/new.ts");
              expect(patch).toContain("diff --git a/z.ts b/z.ts");
              if (selectDirectory) {
                expect(patch).toContain("z.ts/inside.ts");
                expect(patch).toContain("diff --git a/zz.ts b/zz.ts");
              } else {
                expect(patch).not.toContain("z.ts/inside.ts");
                expect(patch).not.toContain("zz.ts");
              }
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await rename(join(directory, "z.ts"), join(directory, "new.ts"));
            await mkdir(join(directory, "z.ts"));
            await rename(
              join(directory, "zz.ts"),
              join(directory, "z.ts/inside.ts"),
            );
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: selectDirectory ? ["new.ts", "z.ts"] : ["new.ts"],
                    verification: "Synthetic verification.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessedFiles.sort()).toEqual(
        selectDirectory
          ? ["new.ts", "z.ts", "z.ts/inside.ts", "zz.ts"]
          : ["new.ts", "z.ts"],
      );
      expect(git("diff", "--name-status", "--no-renames", before, "HEAD")).toBe(
        selectDirectory
          ? "A\tnew.ts\nD\tz.ts\nA\tz.ts/inside.ts\nD\tzz.ts"
          : "A\tnew.ts\nD\tz.ts",
      );
      expect(
        git("show", selectDirectory ? "HEAD:z.ts/inside.ts" : "HEAD:zz.ts"),
      ).toBe("Unrelated rename source");
      expect(git("show", "HEAD:new.ts")).toBe("Verified rename source");
      expect(await readFile(join(directory, "z.ts/inside.ts"), "utf8")).toBe(
        "Unrelated rename source\n",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("");
      expect(git("diff", "--name-only")).toBe(selectDirectory ? "" : "zz.ts");
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
    },
  );

  test.each(
    ["staged", "unstaged", "assume-unchanged", "clean"].flatMap((state) =>
      ["copy", "rename", "symlink", "gitlink"].map(
        (transfer) => [state, transfer] as const,
      ),
    ),
  )("protects %s content transferred by %s", async (state, transfer) => {
    const { directory, git } = await publicationRepository();
    const original = "unsafe\n" + "synthetic baseline line\n".repeat(12);
    const local =
      state === "clean" ? original : original + "synthetic local work\n";
    await writeFile(join(directory, "old.ts"), original);
    git("add", "old.ts");
    git("commit", "-m", "Synthetic source");
    await writeFile(join(directory, "old.ts"), local);
    if (state === "staged") git("add", "old.ts");
    if (state === "assume-unchanged")
      git("update-index", "--assume-unchanged", "old.ts");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          await writeFile(
            join(directory, "new.ts"),
            local.replace("unsafe", "fixed"),
          );
          if (transfer !== "copy") await rm(join(directory, "old.ts"));
          if (transfer === "symlink")
            await symlink("new.ts", join(directory, "old.ts"));
          if (transfer === "gitlink") {
            await mkdir(join(directory, "old.ts"));
            git("-C", "old.ts", "init", "--initial-branch=main");
            git("-C", "old.ts", "config", "user.name", "Synthetic User");
            git(
              "-C",
              "old.ts",
              "config",
              "user.email",
              "synthetic@example.test",
            );
            git(
              "-C",
              "old.ts",
              "commit",
              "--allow-empty",
              "-m",
              "Synthetic nested baseline",
            );
          }
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(state === "clean" ? 0 : 2);
    if (state !== "clean") {
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
      expect(git("ls-remote", "origin")).toBe("");
    } else {
      expect(git("show", "HEAD:new.ts")).toBe(
        local.replace("unsafe", "fixed").trim(),
      );
      if (transfer === "rename")
        expect(git("ls-tree", "HEAD", "old.ts")).toBe("");
    }
  });

  test.each(
    ["saved", "supplied"].flatMap((mode) =>
      [
        "move",
        "copy",
        "different",
        "vanished",
        "empty",
        "generated-template",
        "generated-build",
        "symlink",
      ].map((change) => [mode, change] as const),
    ),
  )("checks ignored content before publishing %s/%s", async (mode, change) => {
    const { directory, git } = await publicationRepository();
    await writeFile(join(directory, ".gitignore"), ".env\n.cache/\ndist/\n");
    git("add", ".gitignore");
    git("commit", "-m", "Synthetic ignored paths");
    const content =
      change === "empty"
        ? ""
        : change === "generated-template"
          ? "export const enabled = true;\n"
          : change === "generated-build"
            ? "export const answer = 42;\n"
            : "SYNTHETIC_LOCAL_CONTENT\n";
    const publishedContent =
      change === "different" || change === "vanished"
        ? "New independent content\n"
        : content;
    const source =
      change === "generated-template"
        ? ".cache/template.ts"
        : change === "generated-build"
          ? "dist/generated.js"
          : ".env";
    await mkdir(dirname(join(directory, source)), { recursive: true });
    if (change === "symlink") {
      const outside = await fixtures.create("ignored-link-target-");
      await writeFile(join(outside, "file"), content);
      await symlink(join(outside, "file"), join(directory, source));
    } else await writeFile(join(directory, source), content);
    let removed = false;
    const before = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git/index"));
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      [
        "patch",
        ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command === "git") {
            const result = await runGitRepositoryCommand(
              command,
              args,
              cwd,
              options,
            );
            if (
              change === "vanished" &&
              !removed &&
              args[0] === "ls-files" &&
              args.includes("--ignored")
            ) {
              await rm(join(directory, source));
              removed = true;
            }
            return result;
          }
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (_args, output) => {
          if (change === "move")
            await rename(join(directory, source), join(directory, "new.ts"));
          else await writeFile(join(directory, "new.ts"), publishedContent);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic verification.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    if (change === "vanished") expect(removed).toBe(true);
    const blocked = [
      "move",
      "copy",
      "generated-template",
      "generated-build",
    ].includes(change);
    expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
    if (blocked) {
      expect(outcome.stderr).toContain("matches pre-existing ignored content");
      expect(git("rev-parse", "HEAD")).toBe(before);
      expect(await readFile(join(directory, ".git/index"))).toEqual(index);
      expect(git("ls-remote", "origin")).toBe("");
    }
    expect(await readFile(join(directory, "new.ts"), "utf8")).toBe(
      publishedContent,
    );
  });

  test
    .skipIf(process.platform === "win32" || process.getuid?.() === 0)
    .each(["saved", "supplied"])(
    "stops before patching when ignored content cannot be read (%s)",
    async (mode) => {
      const { directory, git } = await publicationRepository();
      await writeFile(join(directory, ".gitignore"), ".env\n");
      git("add", ".gitignore");
      git("commit", "-m", "Synthetic ignored paths");
      const ignored = join(directory, ".env");
      await writeFile(ignored, "SYNTHETIC_LOCAL_CONTENT\n");
      await chmod(ignored, 0);
      const before = git("rev-parse", "HEAD");
      const index = await readFile(join(directory, ".git/index"));
      let codexCalls = 0;
      try {
        await expect(readFile(ignored)).rejects.toMatchObject({
          code: "EACCES",
        });
        const result = resultWithFindings(["high"]);
        const outcome = await runWorkflow(
          [
            "patch",
            ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : Promise.resolve(
                    args[1] === "list"
                      ? "[]"
                      : "https://github.example.test/example/repository/pull/1",
                  ),
            onCodex: async (_args, output) => {
              codexCalls++;
              await chmod(ignored, 0o600);
              await writeFile(
                join(directory, "new.ts"),
                await readFile(ignored),
              );
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status: "verified",
                      files: ["new.ts"],
                      verification: "Synthetic verification.",
                    },
                  ],
                }),
              );
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain("EACCES");
        expect(codexCalls).toBe(0);
        expect(git("rev-parse", "HEAD")).toBe(before);
        expect(await readFile(join(directory, ".git/index"))).toEqual(index);
        expect(git("ls-remote", "origin")).toBe("");
        expect((await stat(ignored)).mode & 0o777).toBe(0);
      } finally {
        await chmod(ignored, 0o600);
      }
    },
  );

  test.each(
    ["root", "src"].flatMap((scope) =>
      ["file", "directory"].map((selection) => ({ scope, selection })),
    ),
  )(
    "preserves newly tracked ignored patch content from $scope with $selection selection",
    async ({ scope, selection }) => {
      const { directory, git, remote } = await publicationRepository();
      await mkdir(join(directory, "src/nested"));
      await writeFile(join(directory, "src/nested/app.ts"), "old\n");
      await writeFile(join(directory, ".gitignore"), "generated.txt\n");
      await writeFile(join(directory, "unrelated.txt"), "baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic ignored output baseline");
      await writeFile(
        join(directory, "unrelated.txt"),
        "unrelated staged work\n",
      );
      git("add", "unrelated.txt");
      const unrelated = git(
        "ls-files",
        "--stage",
        "--debug",
        "--",
        "unrelated.txt",
      );
      const cwd = scope === "root" ? directory : join(directory, "src");
      const prefix = scope === "root" ? "src/nested" : "nested";
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = `${prefix}/app.ts`;
      let calls = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--create-pr",
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory: cwd,
          onWorkbench: () => savedScan(result, "scan-1", cwd),
          onRepositoryCommand: (command, args, repository, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, repository, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[] };
              expect(artifact.changedFiles).toEqual([
                "src/nested/app.ts",
                "src/nested/generated.txt",
              ]);
              const verification = await fixtures.create(
                "ignored-staged-risk-apply-",
              );
              await mkdir(join(verification, "src/nested"), {
                recursive: true,
              });
              await writeFile(join(verification, "src/nested/app.ts"), "old\n");
              repositoryGit(verification)("apply", "--check", artifact.path);
              repositoryGit(verification)("apply", artifact.path);
              expect(
                await readAppliedText(join(verification, "src/nested/app.ts")),
              ).toBe("fixed\n");
              expect(
                await readAppliedText(
                  join(verification, "src/nested/generated.txt"),
                ),
              ).toBe("new generated fix\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(join(directory, "src/nested/app.ts"), "fixed\n");
            await writeFile(
              join(directory, "src/nested/generated.txt"),
              "new generated fix\n",
            );
            git("add", "-f", "src/nested/generated.txt");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files:
                      selection === "file"
                        ? [`${prefix}/app.ts`, `${prefix}/generated.txt`]
                        : [prefix],
                    verification: "Synthetic check.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(calls).toBe(2);
      const commit = git("rev-parse", "HEAD");
      expect(
        repositoryGit(remote)("show", `${commit}:src/nested/generated.txt`),
      ).toBe("new generated fix");
      expect(git("show", "HEAD:unrelated.txt")).toBe("baseline");
      expect(git("ls-files", "--stage", "--debug", "--", "unrelated.txt")).toBe(
        unrelated,
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.txt");
    },
  );

  for (const mode of ["saved", "supplied"]) {
    test.each([
      "file",
      "directory",
      "info",
      "global",
      "unchanged",
      "unchanged-directory",
      "removed",
      "removed-unignored",
      "force-added",
      "new",
    ])(
      `preserves pre-existing ignored paths during ${mode} publication (%s)`,
      async (kind) => {
        const { directory: root, git, remote } = await publicationRepository();
        const removed = kind === "removed" || kind === "removed-unignored";
        const forced = kind === "force-added";
        const directory = kind === "unchanged-directory" || removed || forced;
        const file =
          kind === "directory"
            ? "cache/nested/local.txt"
            : directory
              ? "src/local.pyc"
              : "local.env";
        const pattern = `${kind === "directory" ? "cache/" : file}\n`;
        const unchanged =
          kind === "unchanged" || kind === "unchanged-directory";
        const rule =
          kind === "info"
            ? join(root, ".git", "info", "exclude")
            : kind === "global"
              ? join(remote, "excludes")
              : join(root, ".gitignore");
        await writeFile(
          join(root, ".gitignore"),
          rule === join(root, ".gitignore") ? pattern : "",
        );
        git("add", ".gitignore");
        git("commit", "-m", "Synthetic ignore rule");
        await writeFile(rule, pattern);
        if (kind === "global") git("config", "core.excludesFile", rule);
        if (kind !== "new") {
          await mkdir(dirname(join(root, file)), { recursive: true });
          await writeFile(join(root, file), "synthetic local data\n");
        }
        const head = git("rev-parse", "HEAD");
        let expectedIndex = git("write-tree");
        const result = resultWithFindings(["high"]);
        result.findings.findings[0]!.locations[0]!.path = file;
        const blocked = !unchanged && !removed && kind !== "new";
        const outcome = await runWorkflow(
          [
            "patch",
            ...(mode === "saved"
              ? ["--scan", "scan-1"]
              : ["Synthetic ignore update"]),
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: root,
            onWorkbench: () => savedScan(result, "scan-1", root),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (_args, output) => {
              if (!unchanged && kind !== "removed" && !forced)
                await writeFile(rule, "");
              if (kind === "new")
                await writeFile(join(root, file), "synthetic generated data\n");
              if (unchanged || removed || forced)
                await writeFile(join(root, "src/finding-1.ts"), "fixed\n");
              if (removed) await rm(join(root, file));
              if (forced) {
                git("add", "--force", file);
                expectedIndex = git("write-tree");
              }
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status: "verified",
                      files: directory
                        ? [
                            "src",
                            ...(kind === "removed-unignored"
                              ? [".gitignore"]
                              : []),
                          ]
                        : unchanged
                          ? ["src/finding-1.ts"]
                          : [".gitignore", file],
                      verification: "Synthetic verification.",
                    },
                  ],
                }),
              );
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
        if (blocked) {
          expect(outcome.stderr).toContain(
            "uncommitted changes before patching",
          );
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(git("write-tree")).toBe(expectedIndex);
          expect(git("ls-remote", "origin")).toBe("");
          expect(await readFile(rule, "utf8")).toBe(forced ? pattern : "");
        } else {
          expect(git("ls-remote", "origin")).toContain(
            git("rev-parse", "HEAD"),
          );
          expect(
            git("show", `HEAD:${kind === "new" ? file : "src/finding-1.ts"}`),
          ).toBe(kind === "new" ? "synthetic generated data" : "fixed");
        }
        if (unchanged || removed)
          expect(
            git("ls-tree", "-r", "--name-only", "HEAD").split("\n"),
          ).not.toContain(file);
        if (removed)
          await expect(
            readFile(join(root, file), "utf8"),
          ).rejects.toMatchObject({ code: "ENOENT" });
        else
          expect(await readFile(join(root, file), "utf8")).toBe(
            kind === "new"
              ? "synthetic generated data\n"
              : "synthetic local data\n",
          );
      },
    );
  }
});

describe("directory replacement publication", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  for (const state of ["clean", "unrelated", "dirty-nested", "staged-nested"])
    test(`directory replacement ${state}`, async () => {
      const root = await fixtures.create("synthetic-directory-replacement-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await mkdir(join(root, "entry"));
      await writeFile(join(root, "entry/old.ts"), "original\n");
      await writeFile(join(root, "other.ts"), "unrelated\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const dirtyNested = state.endsWith("nested");
      if (state !== "clean")
        await writeFile(join(root, "other.ts"), "unrelated local edits\n");
      if (dirtyNested)
        await writeFile(
          join(root, "entry/old.ts"),
          "original plus local edits\n",
        );
      if (state === "staged-nested") git("add", "entry/old.ts");
      const remote = await fixtures.create("synthetic-local-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const before = git("rev-parse", "HEAD");
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "entry";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: root,
          onWorkbench: () => savedScan(result, "scan-1", root),
          onRepositoryCommand: (command, args, cwd, options) => {
            return command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[0] === "repo"
                ? "synthetic-repository-id"
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/synthetic/project/pull/1";
          },
          onCodex: async (args, output) => {
            const previous = await readFile(join(root, "entry/old.ts"), "utf8");
            await rm(join(root, "entry"), { recursive: true });
            await writeFile(join(root, "entry"), `fixed\n${previous}`);
            completePatches(args, output);
            return 0;
          },
        },
      );
      const after = git("rev-parse", "HEAD"),
        remoteRef = git("ls-remote", "origin");
      expect(outcome.exitCode, outcome.stderr).toBe(dirtyNested ? 2 : 0);
      if (dirtyNested) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(after).toBe(before);
        expect(remoteRef).toBe("");
        expect(await readFile(join(root, "entry"), "utf8")).toContain(
          "original plus local edits",
        );
      } else {
        expect(git("show", "HEAD:entry")).toBe("fixed\noriginal");
        expect(remoteRef).toContain(after);
      }
      expect(await readFile(join(root, "other.ts"), "utf8")).toBe(
        state === "clean" ? "unrelated\n" : "unrelated local edits\n",
      );
    });
});
