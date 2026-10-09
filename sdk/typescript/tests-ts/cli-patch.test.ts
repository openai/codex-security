import { gitText } from "./support/shell.js";
import { emptyPage } from "./support/linear-pagination.js";
import { resolving } from "./support/promises.js";
import { parse as parseToml } from "smol-toml";
import { describe, expect, test, mock } from "bun:test";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import {
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import type { LinearClientFactory } from "../src/linear.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";

const CURRENT_REPOSITORY = resolve("/current/repository");
const SAVED_REPOSITORY = resolve("/saved/repository");
const STATE_DIRECTORY = resolve("/tmp/codex-security-state");

function resultWithFindings(severities: readonly SeverityLevel[]) {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Summary ${index + 1}`,
      locations: [
        { path: `src/finding-${index + 1}.ts`, startLine: index + 1 },
      ],
    });
  });
  return result;
}

function savedScan(
  result: ReturnType<typeof resultWithFindings>,
  scanId = "scan-1",
  targetPath = SAVED_REPOSITORY,
): JsonObject {
  return {
    scan: {
      scanId,
      targetPath,
      findings: result.findings.findings as unknown as JsonObject[],
    },
  };
}

function completePatches(
  args: readonly string[],
  output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
  status: "verified" | "blocked" = "verified",
): Finding[] {
  const prompt = output?.appServer?.prompt ?? args.at(-1)!;
  const findings = JSON.parse(prompt.split("\n").at(-1)!) as Finding[];
  output?.stdout.write(
    JSON.stringify({
      patches: findings.map((finding) => ({
        occurrenceId: finding.occurrenceId,
        status,
        files: status === "verified" ? [finding.locations[0]!.path] : [],
        ...(status === "verified"
          ? { verification: "The exploit fails and focused tests pass." }
          : { reason: "The required service is unavailable." }),
      })),
    }),
  );
  return findings;
}

function patchRiskSummary() {
  return [
    "### Recommendation: human review required",
    "",
    "The patch has moderate impact and low regression likelihood.",
    "",
    "- Protection: focused tests passed",
    "- Recovery: revert the patch commit",
  ].join("\n");
}

function patchRiskAssessment() {
  const summary = patchRiskSummary();
  return {
    report: [
      "<!-- codex-security:patch-risk-summary:start -->",
      summary,
      "<!-- codex-security:patch-risk-summary:end -->",
      "",
      "```json",
      '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
      "```",
    ].join("\n"),
  };
}

function patchRiskReport() {
  return [
    patchRiskSummary(),
    "",
    "```json",
    '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
    "```",
  ].join("\n");
}

async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const { stdout, stderr, runCli } = createCliTest(main, {
    stderr: options.interactive,
  });

  const current = dependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
  });
  if (options.interactive) {
    current.confirmPatchReview = async (question) => {
      stderr.stream.write(`\n${question} (y/N)\n`);
      return options.review ?? true;
    };
  }
  options.configure?.(current);
  return {
    exitCode: await runCli(arguments_, current),
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

describe("scan and patch workflow", () => {
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
            if (args[0] === "remote") {
              return "https://github.example.test/example/repository.git";
            }
            return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
          }
          return args[1] === "create"
            ? "https://github.example.test/example/repository/pull/15"
            : "";
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

  test("assesses only changes made during a literal patch run", async () => {
    const directory = await temporaryDirectory("codex-security-patch-risk-");
    const repository = join(directory, "repository");
    await mkdir(repository, { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", "--", "app.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(repository, "app.ts"), "original\nuser change\n");

      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          "Synthetic issue",
          "--assess-patch-risk",
          "--codex",
          "analytics.enabled=false",
          "--codex",
          'model_provider="synthetic.gateway"',
          "--codex",
          'model_providers={"synthetic.gateway"={name="Synthetic",base_url="https://gateway.example.test/v1",wire_api="responses",env_key="SYNTHETIC_KEY"}}',
        ],
        {
          currentDirectory: repository,
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
              expect(patch).not.toContain("+user change");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "app.ts"),
              "original\nuser change\npatch change\n",
            );
            output?.stdout.write("Patch complete.");
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
  });

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
          currentDirectory: repository,
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
            expect(workingDirectory).toBe(repository);
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            if (args[1] === "list") return "";
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
            if (args[1] === "list") return "";
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
    ["gitlab", "missing client"],
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
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (gitlab && args[0] === "remote") {
                expect(args).toEqual(["remote", "get-url", "--push", "origin"]);
                return origin;
              }
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return git(...args);
            }
            expect(command).toBe(gitlab ? "glab" : "gh");
            if (failure === "missing client" && failOnce) {
              failOnce = false;
              throw new Error("spawn glab ENOENT");
            }
            if (args[1] === "list") return publishedUrl;
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
        if (failure === "missing client") {
          expect(first.stderr).toContain("spawn glab ENOENT");
          expect(pushCalls).toBe(0);
        }
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
      ["--review-minimality"],
      ["--review-style"],
      ["--max-review-revisions", "5"],
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
              command !== "git" ||
              ["checkout", "commit", "push"].includes(args[0]!);
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

  test("keeps verified scan results when pull request creation fails", async () => {
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
      patchSeverity: "low",
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
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
          published ||= command === "gh" && args[1] === "create";
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
          onWorkbench: () => savedScan(result),
          onRepositoryCommand: (command, args, target) => {
            expect(target).toBe(SAVED_REPOSITORY);
            if (command === "git") {
              if (args[0] === "remote") {
                expect(args).toEqual(["remote", "get-url", "--push", "origin"]);
                return origin;
              }
              return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
            }
            expect(command).toBe(client);
            publicationCommands.push(args);
            return args[1] === "create" ? url : "";
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
        "create",
      ]);
      if (client === "glab") {
        expect(publicationCommands).toEqual([
          [
            "mr",
            "list",
            "--all",
            "--source-branch",
            "codex-security/patch-scan-1",
            "--output",
            "json",
            "--jq",
            ".[0].web_url // empty",
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

  test("runs independent review stages for scan and saved-finding patching", async () => {
    for (const arguments_ of [
      ["scan", "--patch"],
      ["patch", "--scan", "scan-1"],
      ["patch", "--scan", "scan-1", "--external-sandbox"],
    ]) {
      const result = resultWithFindings(["high"]);
      const stages: string[] = [];
      const outcome = await runWorkflow(
        [...arguments_, "--review-style", "--review-minimality"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            const { prompt, sandbox } = output!.appServer!;
            if (sandbox === "read-only") {
              expect(output!.appServer!.externalSandbox).toBe(
                arguments_.includes("--external-sandbox") ? true : undefined,
              );
              expect(prompt).toContain(JSON.stringify(["src/finding-1.ts"]));
              const stage = ["minimality", "local-coding-style"].find((value) =>
                prompt.includes(`only the ${value} review`),
              )!;
              stages.push(stage);
              output!.stdout.write(
                JSON.stringify({
                  status: "approved",
                  findings: [],
                }),
              );
            } else {
              expect(output!.appServer!.externalSandbox).toBe(
                arguments_.includes("--external-sandbox") ? true : undefined,
              );
              stages.push("author");
              completePatches(args, output);
            }
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(stages).toEqual(["author", "minimality", "local-coding-style"]);
    }
  });

  test("passes the configured revision budget to scan and saved-finding patching", async () => {
    for (const arguments_ of [
      ["scan", "--patch"],
      ["patch", "--scan", "scan-1"],
    ]) {
      const result = resultWithFindings(["high"]);
      let reviews = 0;
      const outcome = await runWorkflow(
        [...arguments_, "--review-minimality", "--max-review-revisions", "2"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
              output!.stdout.write(
                JSON.stringify(
                  reviews < 3
                    ? {
                        status: "revise",
                        findings: [`Remove unrelated change ${reviews}.`],
                      }
                    : { status: "approved", findings: [] },
                ),
              );
            } else {
              completePatches(args, output);
            }
            return 0;
          },
        },
      );

      expect({
        arguments_,
        exitCode: outcome.exitCode,
        stderr: outcome.stderr,
      }).toMatchObject({ exitCode: 0 });
      expect(reviews).toBe(3);
    }
  });

  test("updates the independent review scope after an author revision", async () => {
    const result = resultWithFindings(["high"]);
    const scopes: string[][] = [];
    let reviews = 0;
    let revised = false;
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--review-minimality",
        "--review-style",
        "--json",
      ],
      {
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (_command, args) =>
          args.includes("--name-only")
            ? revised
              ? "src/finding-1.ts\0src/existing-helper.ts\0"
              : "src/finding-1.ts\0"
            : "",
        onCodex: (args, output) => {
          const { prompt, sandbox } = output!.appServer!;
          if (sandbox === "read-only") {
            const lines = prompt.split("\n");
            const scope = lines.findIndex((line) =>
              line.startsWith("Candidate changes since the pre-author"),
            );
            scopes.push(JSON.parse(lines[scope + 1]!));
            reviews += 1;
            output!.stdout.write(
              JSON.stringify(
                reviews === 1
                  ? { status: "revise", findings: ["Use the existing helper."] }
                  : { status: "approved", findings: [] },
              ),
            );
          } else if (reviews === 0) {
            completePatches(args, output);
          } else {
            revised = true;
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["src/existing-helper.ts"],
                    verification: "The exploit fails and focused tests pass.",
                  },
                ],
              }),
            );
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(scopes).toEqual([
      ["src/finding-1.ts"],
      ["src/finding-1.ts", "src/existing-helper.ts"],
      ["src/finding-1.ts", "src/existing-helper.ts"],
    ]);
    expect(JSON.parse(outcome.stdout).patches[0].files).toEqual([
      "src/finding-1.ts",
      "src/existing-helper.ts",
    ]);
  });

  test("does not create a pull request when an independent review rejects the patch", async () => {
    const result = resultWithFindings(["high"]);
    const commands: string[][] = [];
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--create-pr",
        "--review-minimality",
        "--json",
      ],
      {
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (command, args) => {
          commands.push([command, ...args]);
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
        onCodex: (args, output) => {
          if (output!.appServer!.sandbox === "read-only") {
            output!.stdout.write(
              JSON.stringify({
                status: "blocked",
                findings: ["The patch is outside the production threat model."],
              }),
            );
          } else {
            completePatches(args, output);
          }
          return 0;
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [{ occurrenceId: "occ_1", status: "failed" }],
    });
    expect(
      commands.some((args) =>
        args.some((value) => ["commit", "push", "gh", "glab"].includes(value)),
      ),
    ).toBe(false);
    expect(outcome.stderr).toContain('"status":"blocked"');
    expect(outcome.stderr).toContain(
      "The patch is outside the production threat model.",
    );
  });

  test.each([
    { emptyFirstReport: false, renameFix: false, nested: false },
    { emptyFirstReport: true, renameFix: false, nested: false },
    { emptyFirstReport: false, renameFix: true, nested: false },
    { emptyFirstReport: false, renameFix: false, nested: true },
  ])(
    "publishes cumulative reviewed files (empty report: $emptyFirstReport, rename: $renameFix, nested: $nested)",
    async ({ emptyFirstReport, renameFix, nested }) => {
      const root = await temporaryDirectory("codex-security-reviewed-patch-");
      const gitRoot = join(root, "repository");
      const repository = nested ? join(gitRoot, "package") : gitRoot;
      const remote = join(root, "remote.git");
      await mkdir(join(repository, "src"), { recursive: true });
      const git = repositoryGit(gitRoot);
      const result = resultWithFindings(["high"]);
      let authors = 0;
      let reviews = 0;
      const scopes: string[][] = [];
      const unchanged = "unchanged context\n".repeat(12);
      const expectedFiles = [
        "src/finding-1.ts",
        ...(renameFix ? ["src/renamed.ts"] : []),
        "test.ts",
      ];
      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(
          join(repository, "src/finding-1.ts"),
          `${unchanged}unsafe\n`,
        );
        git("add", "--", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            "scan",
            "--review-minimality",
            "--create-pr",
            ...(nested ? ["--assess-patch-risk"] : []),
            "--json",
          ],
          {
            currentDirectory: repository,
            result,
            onWorkbench: () => savedScan(result, "scan", repository),
            onRepositoryCommand: (command, args, directory, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, directory, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.com/example/repository/pull/1",
            onCodex: async (_args, output) => {
              const { prompt, sandbox } = output!.appServer!;
              if (prompt.includes("$codex-security:assess-patch-risk")) {
                const artifact = JSON.parse(
                  prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
                expect(await readFile(artifact.path, "utf8")).toContain(
                  "+safe",
                );
                output!.stdout.write(patchRiskAssessment().report);
                return 0;
              }
              if (sandbox === "read-only") {
                const lines = prompt.split("\n");
                const index = lines.findIndex((line) =>
                  line.startsWith("Candidate changes since the pre-author"),
                );
                scopes.push(JSON.parse(lines[index + 1]!));
                reviews += 1;
                output!.stdout.write(
                  JSON.stringify(
                    reviews === 1
                      ? {
                          status: "revise",
                          findings: ["Add the focused regression test."],
                        }
                      : { status: "approved", findings: [] },
                  ),
                );
              } else {
                authors += 1;
                const file = authors === 1 ? "src/finding-1.ts" : "test.ts";
                await writeFile(
                  join(repository, file),
                  authors === 1 ? `${unchanged}safe\n` : "regression\n",
                );
                if (authors === 2 && renameFix)
                  await rename(
                    join(repository, "src/finding-1.ts"),
                    join(repository, "src/renamed.ts"),
                  );
                output!.stdout.write(
                  JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status: "verified",
                        files: authors === 1 && emptyFirstReport ? [] : [file],
                        verification:
                          "The exploit fails and the regression passes.",
                      },
                    ],
                  }),
                );
              }
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(authors).toBe(2);
        expect(reviews).toBe(2);
        expect(scopes).toEqual([["src/finding-1.ts"], expectedFiles]);
        expect(JSON.parse(outcome.stdout).patches[0].files).toEqual(
          expectedFiles,
        );
        expect(
          git("show", "--format=", "--name-only", "--no-renames", "HEAD").split(
            "\n",
          ),
        ).toEqual(
          expectedFiles.map((file) => (nested ? `package/${file}` : file)),
        );
        expect(git("status", "--porcelain")).toBe("");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["git", "directory"])(
    "preserves the pre-author %s baseline for review and revision",
    async (kind) => {
      const root = await temporaryDirectory("codex-security-review-baseline-");
      const repository = join(root, "repository");
      const validation = join(root, "validation.md");
      await mkdir(repository);
      const git = repositoryGit(repository);
      const before = "unsafe\npre-existing user edit\n";
      const validationInstructions =
        "Create a validation output directory, run the regression, and remove the output directory.";
      let authors = 0;
      let reviews = 0;
      let copiedBaseline: string | undefined;
      let baselineTree: string | undefined;
      try {
        await writeFile(join(repository, "app.ts"), "unsafe\n");
        if (kind === "git") {
          git("init", "--initial-branch=main");
          git("config", "user.name", "Synthetic User");
          git("config", "user.email", "synthetic@example.test");
          git("config", "commit.gpgsign", "false");
          git("add", "--", ".");
          git("commit", "-m", "Initial synthetic checkout");
        }
        await writeFile(join(repository, "app.ts"), before);
        await writeFile(validation, validationInstructions);
        const outcome = await runWorkflow(
          [
            "patch",
            "Synthetic issue",
            "--review-minimality",
            "--validation-prompt-file",
            validation,
            "--external-sandbox",
          ],
          {
            currentDirectory: repository,
            onRepositoryCommand: (command, args, directory, options) => {
              if (kind === "directory")
                throw new Error("fatal: not a git repository");
              return runGitRepositoryCommand(command, args, directory, options);
            },
            onCodex: async (_args, output) => {
              const { prompt, sandbox, externalSandbox } = output!.appServer!;
              expect(externalSandbox).toBe(true);
              if (sandbox === "read-only" || authors > 0) {
                const lines = prompt.split("\n");
                const index = lines.indexOf(
                  "Pre-author baseline and current candidate snapshot (JSON):",
                );
                const baseline = JSON.parse(lines[index + 1]!);
                if (kind === "git") {
                  baselineTree ??= baseline.tree;
                  expect(baseline.tree).toBe(baselineTree);
                  expect(git("show", `${baseline.tree}:app.ts`)).toBe(
                    before.trim(),
                  );
                  const diff = git("diff", baseline.tree, baseline.head);
                  expect(diff).toContain("-unsafe");
                  expect(diff).toContain("+safe");
                  expect(diff).not.toContain("+pre-existing user edit");
                } else {
                  copiedBaseline ??= baseline.directory;
                  expect(baseline.directory).toBe(copiedBaseline);
                  expect(
                    await readFile(join(baseline.directory, "app.ts"), "utf8"),
                  ).toBe(before);
                }
              }
              if (sandbox === "read-only") {
                expect(prompt).not.toContain(validationInstructions);
                expect(prompt).not.toContain(
                  "Custom patch validation instructions",
                );
                reviews += 1;
                output!.stdout.write(
                  JSON.stringify(
                    reviews === 1
                      ? {
                          status: "revise",
                          findings: [
                            "Keep the focused explanation beside the fix.",
                          ],
                        }
                      : { status: "approved", findings: [] },
                  ),
                );
              } else {
                expect(prompt).toContain(validationInstructions);
                authors += 1;
                await writeFile(
                  join(repository, "app.ts"),
                  `safe\npre-existing user edit\n${authors === 2 ? "focused explanation\n" : ""}`,
                );
                output!.stdout.write("Verified patch.");
              }
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(authors).toBe(2);
        expect(reviews).toBe(2);
        expect(await readFile(join(repository, "app.ts"), "utf8")).toContain(
          "pre-existing user edit",
        );
        if (copiedBaseline !== undefined)
          await expect(
            readFile(join(copiedBaseline, "app.ts")),
          ).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["blocked", "failed"] as const)(
    "preserves the reason for a %s author revision",
    async (status) => {
      const result = resultWithFindings(["high"]);
      const reason =
        "Regression failed: synthetic-api-key-value\nThe original failure still reproduces.";
      let authors = 0;
      let reviews = 0;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan", "--review-minimality", "--json"],
        {
          result,
          onWorkbench: () => savedScan(result, "scan"),
          onCodex: (args, output) => {
            if (output!.appServer!.sandbox === "read-only") {
              reviews += 1;
              output!.stdout.write(
                JSON.stringify({
                  status: "revise",
                  findings: ["Add the regression test."],
                }),
              );
            } else if (++authors === 1) {
              completePatches(args, output);
            } else {
              output!.stdout.write(
                JSON.stringify({
                  patches: [
                    { occurrenceId: "occ_1", status, files: [], reason },
                  ],
                }),
              );
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(authors).toBe(2);
      expect(reviews).toBe(1);
      expect(JSON.parse(outcome.stdout).patches[0].status).toBe("failed");
      expect(outcome.stderr).toContain(reason);
    },
  );

  test("rejects optional patch reviews without an explicit patch request", async () => {
    for (const flag of ["--review-minimality", "--review-style"]) {
      let started = false;
      const outcome = await runWorkflow(["scan", flag], {
        onCodex: () => {
          started = true;
          return 0;
        },
      });
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("Patch review options require --patch");
      expect(started).toBe(false);
    }
  });
});

function repositoryGit(repository: string) {
  return (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repository,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
}

const runGitRepositoryCommand: NonNullable<
  NonNullable<Parameters<typeof dependencies>[0]>["onRepositoryCommand"]
> = (command, args, workingDirectory, options) => {
  expect(command).toBe("git");
  const result = gitText(args, {
    cwd: workingDirectory,
    env: { ...process.env, ...options?.environment },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return options?.trim === false ? result : result.trim();
};
