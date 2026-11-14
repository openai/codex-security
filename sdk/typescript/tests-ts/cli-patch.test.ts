import { requestMetadata } from "./support/request-metadata.js";
import { gitText } from "./support/shell.js";
import { emptyPage } from "./support/linear-pagination.js";
import { resolving } from "./support/promises.js";
import { parse as parseToml } from "smol-toml";
import { afterEach, describe, expect, test, mock, spyOn } from "bun:test";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import * as os from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import type { LinearClientFactory } from "../src/linear.js";
import {
  capture,
  dependencies,
  fakeResult,
  type OnCodex,
} from "./cli-fixtures.js";
import {
  createApiTestFixtures,
  temporaryDirectory,
} from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { copyCompletedScan } from "./plugin-root.js";

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

function patchRiskAssessment(summary = patchRiskSummary()) {
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

function patchRiskReport(summary = patchRiskSummary()) {
  return [
    summary,
    "",
    "```json",
    '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
    "```",
  ].join("\n");
}

const publicationDirectories = createApiTestFixtures("codex-security-publish-");
afterEach(publicationDirectories.cleanup);

const initialPatchFiles = {
  "src/finding-1.ts": "unsafe\n",
  "unrelated.ts": "original\n",
};

async function publicationFixtures(
  files: Record<string, string> = {},
  severities: SeverityLevel[] = ["high"],
  scanId = "scan-1",
) {
  const root = await publicationDirectories.temporaryDirectory();
  const repository = join(root, "repository");
  const remote = join(root, "remote.git");
  await mkdir(join(repository, "src"), { recursive: true });
  const git = repositoryGit(repository);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  git("config", "commit.gpgsign", "false");
  for (const [path, contents] of Object.entries(files)) {
    const file = join(repository, path);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, contents);
  }
  git("add", "--", ".");
  git("commit", "--allow-empty", "-m", "Initial synthetic checkout");
  git("init", "--bare", remote);
  git("remote", "add", "origin", remote);
  const result = resultWithFindings(severities);
  const onCodex: OnCodex = async (args, output) => {
    await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
    completePatches(args, output);
    return 0;
  };
  return {
    git,
    remote,
    currentDirectory: repository,
    result,
    onWorkbench: () => savedScan(result, scanId, repository),
    onCodex,
  };
}

function resumedPublicationGit(args: readonly string[]) {
  if (
    args[0] === "rev-parse" ||
    args.at(-1)?.endsWith(".codexSecurityPatchCommit")
  )
    return "verified-commit";
  const defaultIndex = args.indexOf("--default");
  return defaultIndex < 0 ? "" : args[defaultIndex + 1]!;
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
  test.each([true, false])(
    "uses completion validation after an early HEAD drift warning (restored: %s)",
    async (restored) => {
      const root = await temporaryDirectory("scan-head-warning-");
      const repository = join(root, "repository");
      const codexHome = join(root, "home");
      const scanDir = join(root, "scan");
      for (const directory of [repository, codexHome, scanDir])
        await mkdir(directory, { mode: 0o700 });
      let revision = "deadbeef";
      const completionWarning =
        "Repository HEAD changed while the scan was running; results were saved for the original revision.";
      const client = TestClient.withDependencies({
        ...scanRuntimeDependencies(codexHome, scanDir),
        repositoryRevision: async () => revision,
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "prepare-scan-completion")
            return {
              targetWarnings:
                revision === "deadbeef" ? [] : [completionWarning],
            };
          if (args[0] === "complete-scan")
            return {
              scan: {
                warnings: revision === "deadbeef" ? [] : [completionWarning],
              },
            };
          const result = mockWorkbench(args, input);
          if (args[0] === "register-cli-scan") revision = "changed";
          return result;
        },
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              expect(earlyDetails).toEqual([undefined]);
              if (restored) revision = "deadbeef";
              await copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        }),
      });
      const result = resultWithFindings(["high"]);
      let patchCalls = 0;
      const earlyDetails: unknown[] = [];
      try {
        const outcome = await runWorkflow(
          ["scan", repository, "--patch", "--json"],
          {
            currentDirectory: repository,
            result,
            onCodex: (args, output) => {
              patchCalls++;
              completePatches(args, output);
              return 0;
            },
          },
          {
            configure: (current) => {
              current.createSecurity = () => ({
                preflight: client.preflight.bind(client),
                validate: client.validate.bind(client),
                close: client.close.bind(client),
                run: async (path, options) => {
                  await client.run(path, {
                    ...options,
                    onWarning: (message, details) => {
                      options?.onWarning?.(message, details);
                      if (
                        message.startsWith("Repository HEAD changed") &&
                        message !== completionWarning
                      ) {
                        earlyDetails.push(details);
                      }
                    },
                  });
                  return result;
                },
              });
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(restored ? 0 : 2);
        expect(patchCalls).toBe(restored ? 1 : 0);
        expect(earlyDetails).toEqual([undefined]);
        const payload = JSON.parse(outcome.stdout);
        expect(payload.warnings).toEqual(
          restored ? undefined : [completionWarning],
        );
        expect(outcome.stderr).toContain(
          "This scan remains bound to deadbeef.",
        );
        expect(outcome.stderr).toContain("stop this scan and restart it");
        if (restored)
          expect(payload.patches).toMatchObject([{ status: "verified" }]);
      } finally {
        await client.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );

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

  test.each([false, true])(
    "passes static verification to patching (saved findings: %p)",
    async (saved) => {
      const result = resultWithFindings(["high"]);
      const report =
        "Source review confirms the guard; runtime checks were not performed.";
      const onCodex = mock<OnCodex>((_args, output) => {
        expect(output?.appServer?.prompt).toContain(
          "Verification mode: static",
        );
        output?.stdout.write(
          saved
            ? JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["guard.ts"],
                    verification: report,
                  },
                ],
              })
            : report,
        );
        return 0;
      });
      const outcome = await runWorkflow(
        [
          "patch",
          ...(saved ? ["--scan", "scan-1"] : ["Synthetic finding"]),
          "--verification-mode",
          "static",
          "--json",
        ],
        { result, onWorkbench: () => savedScan(result), onCodex },
      );
      expect(outcome.exitCode).toBe(0);
      expect(onCodex).toHaveBeenCalledTimes(1);
      expect(outcome.stdout).toContain(report);
    },
  );

  test.each([
    [0, false, 0],
    [0, true, 2],
    [130, true, 130],
    [143, true, 143],
  ] as const)(
    "completes required patch output (status %i, failure %p)",
    async (codexStatus, failOutput, expectedStatus) => {
      const report = "Synthetic patch report: café → fixed.\n";
      const started = Promise.withResolvers<(error?: Error) => void>();
      const stdout = new Writable({
        highWaterMark: 1,
        write(_chunk, _encoding, callback) {
          started.resolve(callback);
        },
      });
      const failure = new Error("Synthetic patch output failure");
      const emitted = failOutput
        ? new Promise<Error>((resolve) => stdout.once("error", resolve))
        : undefined;
      const stderr = capture();
      let patched = false;
      let laterCommands = 0;
      const operation = main(
        ["patch", "Synthetic finding"],
        stdout,
        stderr.stream,
        dependencies({
          currentDirectory: CURRENT_REPOSITORY,
          onCodex: (_args, output) => {
            output?.stdout.write(report);
            patched = true;
            return codexStatus;
          },
          onRepositoryCommand: (_command, args) => {
            if (patched) laterCommands++;
            return args.includes("--name-only") ? "synthetic.ts\0" : "tree";
          },
        }),
      );
      const complete = await started.promise;
      const commandsBeforeCompletion = laterCommands;
      complete(failOutput ? failure : undefined);
      expect(await operation).toBe(expectedStatus);
      expect(commandsBeforeCompletion).toBe(0);
      expect(patched).toBe(true);
      if (failOutput) {
        expect(await emitted).toBe(failure);
        expect(laterCommands).toBe(0);
        expect(stderr.text()).toContain(failure.message);
        expect(stderr.text()).not.toContain("Patch applied.");
      } else {
        expect(laterCommands).toBeGreaterThan(0);
        expect(stderr.text()).toContain("Patch applied. Files changed: 1.");
        expect(stdout.writableEnded).toBe(false);
      }
      expect(stdout.listenerCount("error")).toBe(0);
      stdout.destroy();
    },
  );

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
          result,
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
            result,
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

  test("assesses only changes made during a literal patch run", async () => {
    const directory = await temporaryDirectory("codex-security-patch-risk-");
    using _temporary = spyOn(os, "tmpdir").mockReturnValue(
      relative(process.cwd(), directory),
    );
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
          "daybreak=true",
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
            expect(args).toContain("daybreak=true");
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
              expect(isAbsolute(artifact.path)).toBe(true);
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
          onRepositoryCommand: (command, args, cwd, options) => {
            const index = options?.environment?.["GIT_INDEX_FILE"];
            if (index !== undefined) expect(isAbsolute(index)).toBe(true);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
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
      "Applies the repository changes generated for SEC-123.",
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
          "--json",
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
        "fix: apply security patch",
        "--body",
        expectedBody,
      ]);
      expect(outcome.stderr).toContain("Patch risk assessment:");
      expect(outcome.stderr).toContain(`Pull request: ${url}`);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        pullRequest: { branch: "codex-security/patch-SEC-123", url },
      });
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
      const directory = await temporaryDirectory("scan-patch-target-");
      try {
        const currentDirectory = join(directory, "current");
        const repository = join(directory, "other", "repository");
        await mkdir(currentDirectory);
        await mkdir(repository, { recursive: true });
        const result = resultWithFindings([
          "critical",
          "high",
          "medium",
          "low",
        ]);
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
            currentDirectory,
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
          expect(invocation.directory).toBe(repository);
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
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test.each([
    [undefined, false],
    [true, false],
    [false, true],
  ] as const)(
    "passes selected-profile telemetry to scan patches (root=%p, profile=%p)",
    async (rootAnalytics, profileAnalytics) => {
      const result = resultWithFindings(["high"]);
      let childArgs: readonly string[] = [];
      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--mode",
          "standard",
          "--json",
          ...(rootAnalytics === undefined
            ? []
            : ["--codex", `analytics.enabled=${rootAnalytics}`]),
          "--codex",
          'profile="quiet"',
          "--codex",
          `profiles.quiet.analytics.enabled=${profileAnalytics}`,
          "--codex",
          'profiles.quiet.model_provider="amazon-bedrock"',
          "--codex",
          'responses_api_metadata={ "team.tag"="root", caller="preserved" }',
          "--codex",
          'profiles.quiet.responses_api_metadata={ "team.tag"="selected", codex_security_integration="github_action" }',
          "--codex",
          "otel.log_user_prompt=false",
          "--codex",
          'profiles.quiet.otel.metrics_exporter="none"',
        ],
        {
          result,
          onCodex: (args, output) => {
            childArgs = args;
            completePatches(args, output);
            return 0;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(childArgs).toContain(`analytics.enabled=${profileAnalytics}`);
      expect(requestMetadata(childArgs)).toMatchObject({
        "team.tag": "selected",
        caller: "preserved",
        codex_security_surface: "cli",
        codex_security_command: "patch",
        codex_security_integration: "github_action",
        codex_security_provider: "amazon-bedrock",
        codex_security_scan_mode: "standard",
      });
      expect(
        parseToml(childArgs.find((value) => value.startsWith("otel="))!)[
          "otel"
        ],
      ).toEqual({ log_user_prompt: false, metrics_exporter: "none" });
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
      const home = join(os.tmpdir(), "synthetic-auth-home");
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
        'synthetic-"model"\\雪\u007f',
        "--effort",
        'future-"effort"\\雪\u007f',
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
    expect(
      parseToml(invocation.find((value) => value.startsWith("model="))!),
    ).toEqual({ model: 'synthetic-"model"\\雪\u007f' });
    expect(
      parseToml(
        invocation.find((value) =>
          value.startsWith("model_reasoning_effort="),
        )!,
      ),
    ).toEqual({ model_reasoning_effort: 'future-"effort"\\雪\u007f' });
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

  describe("saved-finding Git publication", () => {
    test("publishes only verified patch files and preserves unrelated staged changes", async () => {
      const fixtures = await publicationFixtures(
        initialPatchFiles,
        ["high", "medium"],
        "scan",
      );
      const { currentDirectory: repository, git, result } = fixtures;
      const url = "https://github.example.test/example/repository/pull/15";
      result.findings.findings[0]!.title = "Synthetic private finding";
      const detail = "Diagnostic detail: token=SYNTHETIC_RISK_VALUE";
      const summary = `${patchRiskSummary()}\n\n${detail}`;
      const expectedPullRequestBody = [
        "Applies verified code changes for findings from a completed scan.",
        "",
        "## Patch risk assessment",
        "",
        summary,
      ].join("\n");
      let pullRequestArguments: readonly string[] = [];
      const githubCommands: string[][] = [];
      const dependency = "src/dependency";
      git(
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "--",
        repository,
        dependency,
      );
      git("commit", "-m", "Add fixture dependency");
      git("config", "diff.ignoreSubmodules", "all");
      git("config", "submodule.src/dependency.ignore", "all");
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
          ...fixtures,
          onCodex: async (args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              expect(output.command).toBe("patch");
              expect(output.appServer?.sandbox).toBe("read-only");
              expect(requestMetadata(args)).toMatchObject({
                codex_security_command: "assess-patch-risk",
              });
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
                "references/windows-validation.md",
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
              expect(artifact.changedFiles).toEqual([
                dependency,
                "src/finding-1.ts",
              ]);
              expect(patch.toString()).toContain(
                "+Subproject commit " +
                  git("-C", dependency, "rev-parse", "HEAD"),
              );
              expect(patch.toString()).toEndWith("+fixed  \n");
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment(summary).report);
              return 0;
            }
            await writeFile(
              join(repository, "src/finding-1.ts"),
              "intermediate\n",
            );
            git("add", "--", "src/finding-1.ts");
            git("-C", dependency, "fetch", "origin", "main");
            git("-C", dependency, "checkout", "--detach", "FETCH_HEAD");
            await writeFile(
              join(repository, "src", "finding-1.ts"),
              "fixed  \n",
            );
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["src", "unrelated.ts"],
                    verification: "Focused checks pass.",
                  },
                ],
              }),
            );
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
              if (args[0] === "push") {
                const branch = git("symbolic-ref", "HEAD");
                const verified = git("rev-parse", branch);
                const later = git(
                  "commit-tree",
                  "HEAD^{tree}",
                  "-p",
                  verified,
                  "-m",
                  "Later commit",
                );
                git("update-ref", branch, later, verified);
                try {
                  return runGitRepositoryCommand(
                    command,
                    args,
                    workingDirectory,
                    commandOptions,
                  );
                } finally {
                  git("update-ref", branch, verified, later);
                }
              }
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
      expect(outcome.stderr).toContain("Patch risk assessment:");
      expect(outcome.stderr).toContain(summary);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("rev-parse", "--abbrev-ref", "@{upstream}")).toBe(
        "origin/codex-security/patch-scan",
      );
      expect(
        git(
          "show",
          "--ignore-submodules=none",
          "--format=",
          "--name-only",
          "HEAD",
        ),
      ).toBe(dependency + "\nsrc/finding-1.ts");
      expect(
        git("rev-parse", "origin/codex-security/patch-scan:" + dependency),
      ).toBe(git("-C", dependency, "rev-parse", "HEAD"));
      expect(git("show", ":src/finding-1.ts")).toBe("intermediate");
      expect(outcome.stderr).toContain("Could not update local staging");
      expect(git("show", ":unrelated.ts")).toBe("staged separately");
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
        "fix: apply security patch",
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
        patchRisk: { report: patchRiskReport(summary) },
      });
      expect(outcome.stdout).not.toContain("codex-security:patch-risk-summary");
    });

    test.each([
      ["entry/child", "entry"],
      ["entry", "entry/\uFFFD"],
    ])(
      "publishes two verified turns replacing %s with %s",
      async (from, to) => {
        const fixtures = await publicationFixtures({ [from]: "original\n" }, [
          "high",
          "high",
        ]);
        const { currentDirectory: repository, git, remote, result } = fixtures;
        let expectedTree = "";
        result.findings.findings[0]!.locations[0]!.path = from;
        result.findings.findings[1]!.locations[0]!.path = "entry";
        const outcome = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            ...fixtures,
            onCodex: async (args, output) => {
              const [finding] = completePatches(args, output);
              if (finding!.occurrenceId === "occ_1") {
                await writeFile(join(repository, from), "first fix\n");
              } else {
                git("rm", "-f", "--", from);
                await mkdir(dirname(join(repository, to)), { recursive: true });
                await writeFile(join(repository, to), "second fix\n");
                if (from === "entry" && process.platform === "linux") {
                  // These two sibling names are identical after UTF-8 decoding.
                  const rawName = Buffer.concat([
                    Buffer.from(join(repository, "entry") + "/"),
                    Buffer.from([0xff]),
                  ]);
                  await writeFile(rawName, "raw filename fix\n");
                }
                git("add", "--", "entry");
                expectedTree = git("write-tree");
              }
              return 0;
            },
            onRepositoryCommand: (cmd, args, cwd, options) => {
              if (cmd === "gh")
                return args[1] === "create"
                  ? "https://github.example.test/example/repository/pull/1"
                  : "";
              return runGitRepositoryCommand(cmd, args, cwd, options);
            },
          },
        );

        expect(outcome.exitCode, outcome.stderr).toBe(0);
        const branch = "codex-security/patch-scan-1";
        const published = repositoryGit(remote);
        expect(published("rev-parse", `${branch}^{tree}`)).toBe(expectedTree);
        expect(published("show", `${branch}:${to}`)).toBe("second fix");
        expect(git("status", "--porcelain")).toBe("");
      },
    );

    test.each([
      ["github", "push"],
      ["github", "create"],
      ["gitlab", "push"],
      ["gitlab", "create"],
      ["gitlab", "missing client"],
    ])(
      "resumes %s publication after %s fails without patching again",
      async (provider, failure) => {
        const checkout = await publicationFixtures(initialPatchFiles);
        const { currentDirectory: repository, git } = checkout;
        const branch = "codex-security/patch-scan-1";
        const gitlab = provider === "gitlab";
        const origin = "https://gitlab.com/example/subgroup/repository.git";
        const url = gitlab
          ? "https://gitlab.com/example/subgroup/repository/-/merge_requests/16"
          : "https://github.example.test/example/repository/pull/16";
        let modelCalls = 0;
        let pushCalls = 0;
        let created = 0;
        let failOnce = true;
        let publishedUrl = "";
        git("push", "--set-upstream", "origin", "main");

        const fixtures: Parameters<typeof dependencies>[0] = {
          ...checkout,
          onCodex: (...args) => {
            modelCalls += 1;
            return checkout.onCodex(...args);
          },
          onRepositoryCommand: (command, args, cwd, options) => {
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
              return runGitRepositoryCommand(command, args, cwd, options);
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
      },
    );
  });

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
      ["--verification-mode", "static"],
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

  test.each([
    ["worktree", "pre-existing changes"],
    ["index", "pre-existing changes"],
    ["after verification", "differs from the verified changes"],
    ["ignored input", "ignored and untracked before patching"],
    ["intent-to-add", "pre-existing changes"],
    ["earlier turn", "earlier unverified changes"],
    ["parent commit", "base changed during verification"],
  ] as const)(
    "keeps local edits out of saved finding publication: %s",
    async (when, diagnostic) => {
      const path = "app.ts";
      const ignored = when === "ignored input" || when === "intent-to-add";
      const fixtures = await publicationFixtures(
        { [path]: "original\n", ".gitignore": ignored ? path + "\n" : "" },
        when === "earlier turn" ? ["high", "high"] : ["high"],
      );
      const { currentDirectory: repository, git } = fixtures;
      let turn = 0;
      let pushed = false;
      if (when === "intent-to-add") git("add", "-N", "-f", "--", path);
      if (when === "worktree" || when === "index") {
        await writeFile(join(repository, path), "in progress\n");
        if (when === "index") {
          git("add", "--", path);
          await writeFile(join(repository, path), "original\n");
        }
      }

      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          ...fixtures,
          onCodex: async (_args, output) => {
            turn++;
            const reported =
              when === "earlier turn" && turn === 1 ? "other.ts" : path;
            if (ignored) await writeFile(join(repository, ".gitignore"), "");
            if (when === "parent commit")
              git("commit", "--allow-empty", "-m", "Separate commit");
            if (reported !== path)
              await writeFile(join(repository, path), "first turn\n");
            await writeFile(join(repository, reported), `updated ${turn}\n`, {
              flag: when === "intent-to-add" ? "a" : "w",
            });
            if (when === "intent-to-add") git("add", "--", reported);
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: `occ_${turn}`,
                    status: "verified",
                    files: [reported],
                    verification: "Focused checks pass.",
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: async (cmd, args, cwd, options) => {
            if (when === "after verification" && args[0] === "switch") {
              await writeFile(join(repository, path), "later edit\n");
            }
            if (args[0] === "push" || cmd !== "git") pushed = true;
            return runGitRepositoryCommand(cmd, args, cwd, options);
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(diagnostic);
      expect(pushed).toBe(false);
      if (when !== "after verification")
        expect(git("branch", "--show-current")).toBe("main");
      if (when === "index") expect(git("show", ":" + path)).toBe("in progress");
      if (when === "intent-to-add")
        expect(git("show", ":" + path)).toBe("original\nupdated 1");
    },
  );

  test("keeps a saved finding's source patch while credential retirement is blocked", async () => {
    const path = "deploy.env";
    const fixtures = await publicationFixtures({
      [path]: "TOKEN=synthetic-fixture\n",
    });
    const { currentDirectory: repository, git } = fixtures;
    const patch = {
      occurrenceId: "occ_1",
      status: "blocked",
      files: [path],
      verification: "The deployment reads the token from its environment.",
      reason: "The owner must revoke the old registry token.",
    };
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        ...fixtures,
        onRepositoryCommand: runGitRepositoryCommand,
        onCodex: async (_args, output) => {
          await writeFile(join(repository, path), "TOKEN=${REGISTRY_TOKEN}\n");
          output?.stdout.write(JSON.stringify({ patches: [patch] }));
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(1);
    expect(outcome.stderr).toContain(patch.reason);
    const response = JSON.parse(outcome.stdout);
    expect(response).toMatchObject({
      applied: true,
      files: [path],
      patches: [patch],
    });
    expect(response.pullRequest).toBeUndefined();
    expect(git("diff", "--name-only")).toBe(path);
    expect(git("branch", "--show-current")).toBe("main");
  });

  test("does not publish blocked, unchanged, or repository-external patches", async () => {
    const reason = "Revoke the exposed token with its issuer.";
    for (const [status, files, exitCode] of [
      ["blocked", ["src/finding-1.ts"], 1],
      ["no_change", [], 0],
      ["verified", ["../outside.ts"], 2],
    ] as const) {
      const patch = {
        occurrenceId: "occ_1",
        status,
        files,
        ...(status === "blocked"
          ? { reason }
          : { verification: "Focused checks pass." }),
      };
      const fixtures = await publicationFixtures();
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          ...fixtures,
          onCodex: async (_args, output) => {
            if (files.length > 0)
              await writeFile(
                join(fixtures.currentDirectory, "src", "finding-1.ts"),
                "fixed\n",
              );
            output?.stdout.write(JSON.stringify({ patches: [patch] }));
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            commandStarted ||=
              command !== "git" ||
              ["checkout", "switch", "commit", "push"].includes(args[0]!);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
        },
      );

      expect(commandStarted).toBe(false);
      expect(outcome.exitCode).toBe(exitCode);
      const response = JSON.parse(outcome.stdout);
      expect(response).not.toHaveProperty("pullRequest");
      expect(response.patches).toEqual(status === "verified" ? [] : [patch]);
      if (status === "verified") {
        expect(outcome.stderr).toContain(
          "Patch files must remain inside the scanned repository.",
        );
      }
    }
  });

  test.each([false, true])(
    "keeps verified scan results when pull request creation fails (full-output: %p)",
    async (fullOutput) => {
      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--create-pr",
          "--json",
          ...(fullOutput ? ["--full-output"] : []),
        ],
        {
          ...(await publicationFixtures()),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "gh")
              throw new Error("GitHub authentication failed.");
            return runGitRepositoryCommand(command, args, cwd, options);
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("GitHub authentication failed.");
      const value = JSON.parse(outcome.stdout);
      expect(fullOutput ? value.data : value).toMatchObject({
        patchSeverity: "low",
        patches: [{ occurrenceId: "occ_1", status: "verified" }],
      });
      if (fullOutput)
        expect(value).toMatchObject({
          ok: false,
          error: {
            code: "SCAN_FAILED",
            message: "GitHub authentication failed.",
          },
        });
    },
  );

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

  test("does not patch failed scans or allow patching during a dry run", async () => {
    const onCodex = mock<() => number>().mockReturnValue(0);
    const failedScan = resultWithFindings(["high"]);
    failedScan.manifest.scan.status = "failed";
    const outcome = await runWorkflow(["scan", "--patch", "--json"], {
      result: failedScan,
      onCodex,
    });
    expect(outcome.exitCode).toBe(2);
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
        expect(outcome.stderr).not.toContain("Open findings for review?");
      } else {
        expect(outcome.stderr).toContain("Open findings for review?");
      }
    }
  });

  test("shows findings without offering interactive patches on a budgeted scan", async () => {
    const confirmPatchReview = mock(resolving(true));
    const patchEditor = mock(resolving(null));
    const outcome = await runWorkflow(
      ["scan", "--max-cost", "1"],
      { result: resultWithFindings(["high"]) },
      {
        interactive: true,
        configure: (value) =>
          Object.assign(value, { confirmPatchReview, patchEditor }),
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stderr).toContain("FINDINGS");
    expect(confirmPatchReview).not.toHaveBeenCalled();
    expect(patchEditor).not.toHaveBeenCalled();
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
        outcome.stderr.indexOf("Open findings for review? (y/N)"),
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
      expect(outcome.stderr).not.toContain("Open findings for review?");
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
        ...(await publicationFixtures()),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, options);
          expect(command).toBe("gh");
          published ||= args[1] === "create";
          return published ? url : "";
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
        result,
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
      undefined,
    ],
    [
      "https://gitlab.com/example/subgroup/repository.git",
      {},
      "glab",
      undefined,
    ],
    [
      "git@gitlab.com:example/subgroup/repository.git",
      {},
      "glab",
      "ssh://git@gitlab.com/example/subgroup/repository.git",
    ],
    [
      "gitlab.com:example/subgroup/repository.git",
      {},
      "glab",
      "ssh://gitlab.com/example/subgroup/repository.git",
    ],
    [
      "gitlab@gitlab.example.test:example/subgroup/repository.git",
      { GITLAB_HOST: "gitlab.example.test" },
      "glab",
      "ssh://gitlab@gitlab.example.test/example/subgroup/repository.git",
    ],
    [
      "ssh://git@gitlab.com:2222/example/subgroup/repository.git",
      {},
      "glab",
      undefined,
    ],
    [
      "git@gitlab.example.test:example/subgroup/repository.git",
      { GITLAB_HOST: "gitlab.example.test" },
      "glab",
      "ssh://git@gitlab.example.test/example/subgroup/repository.git",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_HOST: "https://gitlab.example.test" },
      "glab",
      undefined,
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_URI: "https://gitlab.example.test" },
      "glab",
      undefined,
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GL_HOST: "gitlab.example.test" },
      "glab",
      undefined,
    ],
    ["https://gitlab.example.test/example/repository.git", {}, "gh", undefined],
  ] as const)(
    "publishes saved patch branches for origin %s with environment %j using %s",
    async (origin, environment, client, expectedSelector) => {
      const selector = expectedSelector ?? origin;
      const branch = "codex-security/patch-scan-1";
      const url =
        client === "glab"
          ? "https://gitlab.example.test/example/repository/-/merge_requests/14"
          : "https://github.example.test/example/repository/pull/14";
      const publicationCommands: Array<readonly string[]> = [];
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", branch, "--json"],
        {
          environment,
          currentDirectory: SAVED_REPOSITORY,
          onRepositoryCommand: (command, args, target) => {
            expect(target).toBe(SAVED_REPOSITORY);
            if (command === "git") {
              if (args[0] === "remote") {
                expect(args).toEqual(["remote", "get-url", "--push", "origin"]);
                return origin;
              }
              return resumedPublicationGit(args);
            }
            expect(command).toBe(client);
            publicationCommands.push(args);
            return args[1] === "create" ? url : "";
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
            "map(select(.source_project_id == .target_project_id))[0].web_url // empty",
            "--repo",
            selector,
          ],
          [
            "mr",
            "create",
            "--draft",
            "--head",
            selector,
            "--source-branch",
            "codex-security/patch-scan-1",
            "--title",
            "fix: apply security patch",
            "--description",
            ">>>\nApplies verified code changes for findings from a completed scan.",
            "--yes",
            "--repo",
            selector,
          ],
        ]);
      }
      expect(outcome.stderr).toContain(
        `${client === "glab" ? "Merge" : "Pull"} request: ${url}`,
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        pullRequest: { branch, url },
      });
    },
  );

  test.each(
    (["github", "gitlab"] as const).flatMap((provider) =>
      (["fresh", "resume", "resume CRLF", "resume embedded CR"] as const).map(
        (mode) => [provider, mode] as const,
      ),
    ),
  )(
    "preserves Markdown and keeps %s quick actions advisory during %s publication",
    async (provider, mode) => {
      const gitlab = provider === "gitlab";
      const resumed = mode !== "fresh";
      const fixtures = await publicationFixtures();
      const { git } = fixtures;
      const branch = "codex-security/patch-scan-1";
      const bodyKey = `branch.${branch}.codexSecurityPatchPullRequestBody`;
      const summary = [
        "### Regression examples",
        "",
        "/label ~example ``",
        "Example `",
        "/close",
        "`",
        "",
        "/label ~reviewed",
        "",
        "```js",
        "// Regression check",
        "/^safe$/.test(value);",
        "/close",
        "```",
        "",
        "~~~~text",
        "/srv/example",
        "~~~",
        "/close",
        "~~~~~",
        "",
        "    /close",
        "    /srv/example",
        "",
        "Inline `example",
        "/close",
        "` content.",
        "",
        "Example ``const path = `",
        "/srv/example",
        "`;``",
        "/label ~after-inline",
        "",
        "Example ```literal `` and `",
        "/close",
        "` and `` end```.",
        "",
        "*Nested ``literal `",
        "/close",
        "` end`` emphasis.*",
        "",
        "Unmatched ` delimiter",
        "/label ~after-unmatched",
        "",
        "> Quoted example",
        "/close",
        "",
        "- List example",
        "/close",
        "",
        "<div>",
        "/close",
        "</div>",
        "",
        "<img",
        'src="/uploads/proof.png"',
        "/>",
        "",
        'See <a href="',
        '/docs">documentation</a>.',
        "",
        "$$",
        "1",
        "/2",
        "$$",
        "/label ~after-math",
        "",
        "Ratio $1+\\$",
        "/2$ and $$1",
        "/2$$.",
        "",
        "$$`",
        "/2$$",
        "/label ~after-math-backtick",
        "`",
        "",
        "$ incomplete math",
        "/label ~math-whitespace",
        "$",
        "",
        "$1",
        "/label ~math-digit$2",
        "",
        "$1",
        "/label ~math-closing-space",
        "$",
        "",
        "$``$",
        "/label ~math-empty-code",
        "`$",
        "",
        "$$$",
        "/label ~math-triple",
        "$$$",
        "",
        "$$",
        "/label ~math-unclosed",
        "",
        "Text",
        "<b>",
        "/close",
        "</b>",
        "",
        "<!--",
        "/close",
        "-->",
        "",
        ">>>",
        "Multiline quote",
        "/close",
        ">>>>",
        "",
        ">>>>",
        "Longer quote fence",
        ">>>",
        "/close",
        ">>>>>",
        "",
        ">>>",
        "```text",
        ">>>>",
        "/label ~after-quote",
        "",
        " /close",
        "  /close",
        "   /close",
        "",
        "Use /tmp/example.",
        "",
        "/assign @reviewer",
        "",
        "```text",
        "/close",
      ].join("\n");
      let savedBody = `Synthetic saved report\n\n\t/close\n\n${summary}`;
      if (mode === "resume CRLF")
        savedBody = savedBody.replaceAll("\n", "\r\n");
      if (mode === "resume embedded CR") {
        // A Markdown heading makes older Git quote the config value and preserve its CR.
        savedBody = "## Synthetic saved report\n\n>\r>>\n/label ~example";
      }
      if (resumed) {
        git("branch", branch);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
          git("rev-parse", "HEAD"),
        );
        git("config", bodyKey, savedBody);
      }
      let publishedBody = "";
      const outcome = await runWorkflow(
        resumed
          ? ["patch", "--resume-pr", branch, "--json"]
          : [
              "patch",
              "--scan",
              "scan-1",
              "--assess-patch-risk",
              "--create-pr",
              "--json",
            ],
        {
          ...fixtures,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args[0] === "remote")
                return `https://${provider}.com/example/repository.git`;
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe(gitlab ? "glab" : "gh");
            if (args[1] === "list") return "";
            publishedBody =
              args[args.indexOf(gitlab ? "--description" : "--body") + 1]!;
            return "https://example.test/review/1";
          },
        },
        {
          configure: (current) => {
            Object.assign(current, {
              assessPatchRisk: async () => ({
                report: `<!-- codex-security:patch-risk-summary:start -->\n${summary}\n<!-- codex-security:patch-risk-summary:end -->`,
              }),
            });
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      if (!resumed) savedBody = git("config", "--get", bodyKey);
      const fence = mode === "resume embedded CR" ? ">>>>" : ">>>>>>";
      expect(publishedBody).toBe(gitlab ? `${fence}\n${savedBody}` : savedBody);
      if (!resumed)
        expect(JSON.parse(outcome.stdout).patchRisk.report).toBe(summary);
    },
  );

  test.each([false, true])(
    "uses the GitLab project filter result before publishing (existing MR: %j)",
    async (hasExisting) => {
      const origin = "ssh://git@gitlab.com/example/subgroup/repository.git";
      const branch = "codex-security/patch-scan-1";
      const url =
        "https://gitlab.com/example/subgroup/repository/-/merge_requests/14";
      const commands: string[] = [];
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", branch, "--json"],
        {
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (args[0] === "remote") return origin;
              if (args[0] === "push") {
                expect(args).toEqual([
                  "push",
                  "origin",
                  `verified-commit:refs/heads/${branch}`,
                ]);
                commands.push("push");
              }
              return resumedPublicationGit(args);
            }
            expect(command).toBe("glab");
            commands.push(args[1]!);
            expect(args[args.indexOf("--repo") + 1]).toBe(origin);
            expect(args[args.indexOf("--source-branch") + 1]).toBe(branch);
            if (args[1] === "list") {
              // glab applies this filter to the branch-matched API response:
              // fork merge requests must not count as this project's patch.
              expect(args[args.indexOf("--jq") + 1]).toBe(
                "map(select(.source_project_id == .target_project_id))[0].web_url // empty",
              );
              return hasExisting ? url : "";
            }
            expect(args[args.indexOf("--head") + 1]).toBe(origin);
            return url;
          },
        },
      );
      expect(outcome.exitCode).toBe(0);
      expect(commands).toEqual(
        hasExisting ? ["list"] : ["list", "push", "create"],
      );
      expect(JSON.parse(outcome.stdout).pullRequest).toEqual({ branch, url });
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
      result,
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
      result,
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
      result,
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
    input: options?.input,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return options?.trim === false ? result : result.trim();
};
