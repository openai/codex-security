import { codexWithRun, jsonCodex } from "./support/codex.js";
import { mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { join, resolve } from "node:path";
import { describe, expect, test, mock, spyOn } from "bun:test";
import type { CodexSecurityConfig, JsonObject } from "../src/index.js";
import { DiffTarget, type ScanOptions } from "../src/index.js";
import { main } from "../src/cli.js";
import {
  matchScanFindings,
  type ScanComparisonInput,
} from "../src/scan-comparison.js";
import {
  savedRecipe,
  dependencies,
  FakeSignals,
  fakeResult,
  SYNTHETIC_CREDENTIALS,
} from "./cli-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";
import {
  createCliTest,
  captureCli,
  runCapturedCli,
} from "./support/cli-run.js";

describe("CLI workbench", () => {
  test("findings list matches directory identity when realpath preserves alias spelling", async () => {
    const root = await temporaryDirectory("finding-repository-identity-");
    const originalRealpath = fs.realpath;
    let spelling: ReturnType<typeof spyOn> | undefined;
    try {
      const repository = join(root, "repository");
      const upper = join(root, "first-alias");
      const lower = join(root, "second-alias");
      const other = join(root, "other");
      await Promise.all([mkdir(repository), mkdir(other)]);
      for (const alias of [upper, lower]) {
        await symlink(
          repository,
          alias,
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      const [upperMetadata, lowerMetadata, otherMetadata] = await Promise.all(
        [upper, lower, other].map((path) => fs.stat(path, { bigint: true })),
      );
      expect(upperMetadata!.ino).toBe(lowerMetadata!.ino);
      expect(upperMetadata!.dev).toBe(lowerMetadata!.dev);
      expect(upperMetadata!.ino).not.toBe(otherMetadata!.ino);
      // Case-insensitive POSIX realpath may retain each alias's spelling.
      // Keep actual directory stat calls while controlling only that spelling.
      const preserveSpelling = (async (
        ...args: Parameters<typeof realpath>
      ) => {
        const result = await originalRealpath(...args);
        const path = args[0];
        return path === upper || path === lower
          ? typeof result === "string"
            ? path
            : Buffer.from(path)
          : result;
      }) as typeof realpath;
      spelling = spyOn(fs, "realpath").mockImplementation(preserveSpelling);
      for (const [requested, stored] of [
        [upper, lower],
        [lower, upper],
      ]) {
        const calls: Array<readonly string[]> = [];
        const stdout = captureCli(main, "stdout");
        expect(
          await stdout.run(
            ["findings", "list", requested!, "--json"],
            dependencies({
              onWorkbench: (args): JsonObject => {
                calls.push(args);
                return args[0] === "list-repositories"
                  ? {
                      repositories: [
                        { targetId: "other", targetPath: other },
                        {
                          targetId: "missing",
                          targetPath: join(root, "missing"),
                        },
                        { targetId: "selected", targetPath: stored! },
                      ],
                    }
                  : {
                      findings: [{ title: "Saved finding" }],
                      nextOffset: null,
                    };
              },
            }),
          ),
        ).toBe(0);
        expect(calls[1]).toEqual([
          "list-global-findings",
          "--target-id",
          "selected",
          "--status",
          "open",
        ]);
        expect(JSON.parse(stdout.text()).findings).toEqual([
          { title: "Saved finding" },
        ]);
      }
    } finally {
      spelling?.mockRestore();
      await rm(root, { recursive: true, force: true });
    }
  });

  test("findings list prefers an exact saved repository before directory aliases", async () => {
    const root = await temporaryDirectory("finding-exact-repository-");
    try {
      const repository = join(root, "repository");
      const alias = join(root, "previous-checkout");
      await mkdir(repository);
      await symlink(
        repository,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      const unsavedAlias = join(root, "selected-checkout");
      await symlink(
        repository,
        unsavedAlias,
        process.platform === "win32" ? "junction" : "dir",
      );
      for (const [requested, first, exact] of [
        [repository, alias, repository],
        [alias, repository, alias],
        [unsavedAlias, alias, repository],
      ]) {
        const calls: Array<readonly string[]> = [];
        const stdout = captureCli(main, "stdout");
        expect(
          await stdout.run(
            ["findings", "list", requested!, "--json"],
            dependencies({
              onWorkbench: (args): JsonObject => {
                calls.push(args);
                return args[0] === "list-repositories"
                  ? {
                      repositories: [
                        { targetId: "alias-target", targetPath: first! },
                        { targetId: "exact-target", targetPath: exact! },
                      ],
                    }
                  : {
                      findings: [
                        {
                          title:
                            args[2] === "exact-target"
                              ? "Exact saved finding"
                              : "Other target finding",
                        },
                      ],
                      nextOffset: null,
                    };
              },
            }),
          ),
        ).toBe(0);
        expect(calls[1]).toEqual([
          "list-global-findings",
          "--target-id",
          "exact-target",
          "--status",
          "open",
        ]);
        expect(JSON.parse(stdout.text()).findings).toEqual([
          { title: "Exact saved finding" },
        ]);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("findings list resolves a repository directory alias", async () => {
    const root = await temporaryDirectory("finding-repository-alias-");
    try {
      const repository = join(root, "repository");
      const alias = join(root, "alias");
      await mkdir(repository);
      await symlink(
        repository,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      const canonical = await realpath(repository);
      for (const [requested, stored] of [
        [alias, canonical],
        [canonical, alias],
        [alias, alias],
      ]) {
        const stdout = captureCli(main, "stdout");
        expect(
          await stdout.run(
            ["findings", "list", requested!, "--json"],
            dependencies({
              onWorkbench: (args): JsonObject =>
                args[0] === "list-repositories"
                  ? {
                      repositories: [
                        {
                          targetId: "other",
                          targetPath: join(root, "missing"),
                        },
                        { targetId: "selected", targetPath: stored! },
                      ],
                    }
                  : {
                      findings: [{ title: "Saved finding" }],
                      nextOffset: null,
                    },
            }),
          ),
        ).toBe(0);
        expect(JSON.parse(stdout.text()).findings).toEqual([
          { title: "Saved finding" },
        ]);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  test("lists and summarizes open findings for the current repository", async () => {
    const repository = resolve("/current/repository");
    const stdout = captureCli(main, "stdout");
    const calls: Array<readonly string[]> = [];
    const responses: JsonObject[] = [
      {
        repositories: [
          { targetId: "other", targetPath: `${repository}-clone` },
          { targetId: "selected", targetPath: repository },
        ],
      },
      { findings: [{ title: "Finding 1" }], nextOffset: 1 },
      { findings: [{ title: "Finding 2" }], nextOffset: null },
    ];
    expect(
      await stdout.run(
        ["findings", "list", "--json"],
        dependencies({
          onWorkbench: (args) => responses[calls.push(args) - 1]!,
        }),
      ),
    ).toBe(0);
    expect(calls[0]).toEqual(["list-repositories"]);
    expect(calls[1]).toEqual([
      "list-global-findings",
      "--target-id",
      "selected",
      "--status",
      "open",
    ]);
    expect(calls[2]).toEqual([...calls[1]!, "--offset", "1"]);
    expect(JSON.parse(stdout.text())).toEqual({
      repository,
      findings: [{ title: "Finding 1" }, { title: "Finding 2" }],
    });
    expect(
      await runCapturedCli(
        main,
        ["findings", "--json"],
        dependencies({ onWorkbench: () => ({ repositories: [] }) }),
      ),
    ).toBe(0);
    for (const confirmed of [[true, false], []]) {
      const result = fakeResult(["high"]);
      Object.assign(result, {
        repositoryFindings: confirmed.map((confirmedInLatestScan) => ({
          severity: { level: "high" },
          confirmedInLatestScan,
        })),
      });
      const stderr = captureCli(main, "stderr");
      expect(await stderr.run(["scan"], dependencies({ result }))).toBe(0);
      expect(stderr.text()).toContain(
        confirmed.length
          ? "FINDINGS  2 (1 confirmed this scan; 1 previously found; 2 high)"
          : "FINDINGS  0\n",
      );
    }
  });

  test("lists repository and scan-root history without starting Codex", async () => {
    const repository = resolve("/current/repository");
    const cases: Array<[string[], string[]]> = [
      [["scans"], ["list-scans", "--repository", repository]],
      [
        ["scans", "list"],
        ["list-scans", "--repository", repository],
      ],
      [
        ["scans", "list", "other"],
        ["list-scans", "--repository", resolve(repository, "other")],
      ],
      [
        ["scans", "list", "--scan-root", "/tmp/history"],
        ["list-scans", "--scan-root", resolve("/tmp/history")],
      ],
    ];
    for (const [argv, expected] of cases) {
      const onWorkbench = mock((_args: readonly string[]) => {
        return { scans: [{ scanId: "scan-1" }] };
      });
      const deps = dependencies({
        onWorkbench,
      });
      deps.createSecurity = throwing("history must not initialize Codex");
      expect(await runCapturedCli(main, argv, deps)).toBe(0);
      expect(onWorkbench.mock.lastCall?.[0]).toEqual(expected);
    }

    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scan", "scans", "--dry-run", "--json"],
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({ repository: "scans" });
  });

  test("shows scans and returns cached comparisons with one workbench call", async () => {
    const cases: Array<[string[], string[], JsonObject, JsonObject]> = [
      [
        ["scans", "show", "scan-1", "--json"],
        ["get-scan", "--scan-id", "scan-1"],
        {
          scan: { scanId: "scan-1", findingCount: 2 },
          recipe: { repository: "/repo" },
          parentScanId: "scan-0",
          workspace: { results: { duplicated: true } },
        },
        {
          scanId: "scan-1",
          findingCount: 2,
          recipe: { repository: "/repo" },
          parentScanId: "scan-0",
        },
      ],
      [
        ["scans", "show", "14b85b21", "--json"],
        ["get-scan", "--scan-id", "14b85b21"],
        { scan: { scanId: "14b85b21-a276-48d7-9f0d-1ebd048fe2a3" } },
        { scanId: "14b85b21-a276-48d7-9f0d-1ebd048fe2a3" },
      ],
      [
        ["scans", "show", "scan-1", "--show-linked-findings", "--json"],
        ["get-scan", "--scan-id", "scan-1"],
        {
          scan: {
            scanId: "scan-1",
            findings: [
              {
                knownSince: "2026-06-15T12:00:00Z",
                knownScanIds: ["12345678-abcd-4567-abcd-1234567890ab"],
                matches: [{ scanId: "scan-0" }],
              },
            ],
          },
        },
        {
          scanId: "scan-1",
          findings: [
            {
              knownSince: "2026-06-15T12:00:00Z",
              knownScanIds: ["12345678-abcd-4567-abcd-1234567890ab"],
              matches: [{ scanId: "scan-0" }],
            },
          ],
        },
      ],
      [
        ["scans", "show", "legacy", "--json"],
        ["get-scan", "--scan-id", "legacy"],
        { scan: { scanId: "legacy" } },
        { scanId: "legacy" },
      ],
      [
        [
          "scans",
          "compare",
          "before",
          "after",
          "--model",
          "synthetic-model",
          "--effort",
          "high",
          "--json",
        ],
        [
          "compare-scans",
          "--before-scan-id",
          "before",
          "--after-scan-id",
          "after",
          "--include-matching-inputs",
        ],
        {
          comparable: true,
          matchingCached: true,
          matchingInputs: { before: [], after: [] },
          summary: { persisting: 1, resolved: 1 },
        },
        { comparable: true, summary: { persisting: 1, resolved: 1 } },
      ],
      [
        [
          "scans",
          "match",
          "before",
          "after",
          "--model",
          "synthetic-model",
          "--effort",
          "high",
          "--json",
        ],
        [
          "compare-scans",
          "--before-scan-id",
          "before",
          "--after-scan-id",
          "after",
          "--include-matching-inputs",
        ],
        {
          comparable: true,
          matchingCached: true,
          matchingInputs: { before: [], after: [] },
          summary: { persisting: 1, resolved: 1 },
        },
        { comparable: true, summary: { persisting: 1, resolved: 1 } },
      ],
    ];
    for (const [argv, expected, response, output] of cases) {
      const calls = mock((_args: readonly string[]) => {
        return response;
      });
      const stdout = captureCli(main, "stdout");
      const deps = dependencies({
        onWorkbench: calls,
      });
      deps.createSecurity = throwing("history must not initialize Codex");
      deps.matchFindings = rejecting("saved matches must not initialize Codex");
      expect(await stdout.run(argv, deps)).toBe(0);
      expect(calls.mock.calls.map(([value]) => value)).toEqual([expected]);
      expect(JSON.parse(stdout.text())).toEqual(output);
    }
  });

  test("shows saved scan activity without starting Codex", async () => {
    const state = await temporaryDirectory("codex-security-cli-logs-", true);
    try {
      const sessions = join(state, "codex-home", "sessions", "2026", "08");
      const scanDirectory = join(state, "scans", "scan-1");
      await mkdir(sessions, { recursive: true });
      await writeFile(
        join(sessions, "rollout-thread-1.jsonl"),
        [
          {
            type: "session_meta",
            payload: {
              id: "thread-1",
              timestamp: "2026-08-11T12:00:00.000Z",
            },
          },
          {
            type: "response_item",
            payload: {
              type: "function_call",
              call_id: "call-1",
              name: "exec_command",
              arguments: JSON.stringify({
                cmd: "OPENAI_API_KEY=sk-proj-SYNTHETIC_KEY_123 pytest",
              }),
            },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n"),
      );
      await writeFile(
        join(sessions, "rollout-worker.jsonl"),
        [
          {
            type: "session_meta",
            payload: {
              id: "worker",
              timestamp: "2026-08-11T12:01:00.000Z",
              cwd: join(scanDirectory, "artifacts"),
            },
          },
          {
            type: "event_msg",
            payload: { type: "agent_message", message: "independent worker" },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n"),
      );
      await writeFile(
        join(sessions, "rollout-after-completion.jsonl"),
        [
          {
            type: "session_meta",
            payload: {
              id: "after-completion",
              timestamp: "2026-08-11T12:03:00.000Z",
              cwd: join(scanDirectory, "artifacts"),
            },
          },
          {
            type: "event_msg",
            payload: {
              type: "agent_message",
              message: "PRIVATE LATER SESSION",
            },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n"),
      );

      const calls: Array<readonly string[]> = [];
      const stdout = captureCli(main, "stdout");
      const deps = dependencies({
        environment: {
          CODEX_SECURITY_STATE_DIR: state,
          CODEX_HOME: join(state, "codex-home"),
        },
        onWorkbench: (args): JsonObject => {
          calls.push(args);
          if (args[0] === "list-scans") {
            return { scans: [{ scanId: "scan-1" }] };
          }
          return {
            scan: {
              scanId: "scan-1",
              continuationThreadId: "thread-1",
              threadIds: ["thread-1"],
              executionThreadIds: ["thread-1"],
              mode: "deep",
              progress: {
                status: "complete",
                updatedAt: "2026-08-11T12:02:00.000Z",
              },
              scanDir: scanDirectory,
            },
          };
        },
      });
      deps.createSecurity = throwing("logs must not initialize Codex");
      expect(
        await stdout.run(["scans", "logs", "scan-1", "--json"], deps),
      ).toBe(0);
      expect(calls).toEqual([["get-scan", "--scan-id", "scan-1"]]);
      expect(stdout.text()).toContain("SYNTHETIC_KEY");
      expect(stdout.text()).toContain("independent worker");
      expect(stdout.text()).not.toContain("PRIVATE LATER SESSION");

      calls.length = 0;
      const latest = captureCli(main, "stdout");
      expect(await latest.run(["scans", "logs", "--json"], deps)).toBe(0);
      expect(calls).toEqual([
        ["list-scans", "--repository", "/current/repository", "--limit", "1"],
        ["get-scan", "--scan-id", "scan-1"],
      ]);
      expect(latest.text()).toContain("SYNTHETIC_KEY");
    } finally {
      await rm(state, { recursive: true, force: true });
    }
  });

  test("explains when a saved scan has no associated session", async () => {
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["scans", "logs", "scan-1"],
        dependencies({
          onWorkbench: () => ({
            scan: { scanId: "scan-1", targetPath: "/repo" },
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "No session is associated with scan scan-1.",
    );
  });

  test("matches findings before matching or comparing scans", async () => {
    const before = [{ occurrenceId: "before" }];
    const after = [{ occurrenceId: "after" }];
    const matching = {
      matches: [
        {
          beforeOccurrenceIds: ["before"],
          afterOccurrenceIds: ["after"],
          confidence: "high" as const,
          reason: "Same root cause.",
        },
      ],
      uncertain: [],
    };

    for (const [command, scanIds, expectedBefore, expectedAfter] of [
      ["match", ["before", "after"], "before", "after"],
      ["compare", ["before", "after"], "before", "after"],
      ["compare", [], "older-scan", "latest-scan"],
      ["compare", ["baseline-scan"], "baseline-scan", "latest-scan"],
    ] as const) {
      const calls: Array<readonly string[]> = [];
      let comparisonInput: string | undefined;
      const stdout = captureCli(main, "stdout");

      expect(
        await stdout.run(
          ["scans", command, ...scanIds, "--json"],
          dependencies({
            onWorkbench: (args, input): JsonObject => {
              calls.push(args);
              if (args[0] === "list-scans") {
                return {
                  scans: [{ scanId: "latest-scan" }, { scanId: "older-scan" }],
                };
              }
              if (args[0] === "save-scan-comparison") comparisonInput = input;
              return args[0] === "compare-scans"
                ? {
                    matchingCached: false,
                    matchingInputs: {
                      before,
                      after,
                      knownFindingGroups: [["known-a", "known-b"]],
                    },
                  }
                : { summary: { persisting: 1 } };
            },
            onMatch: async (input) => {
              expect(input).toEqual({
                before,
                after,
                knownFindingGroups: [["known-a", "known-b"]],
              });
              return matching;
            },
          }),
        ),
      ).toBe(0);
      expect(calls.map((args) => args[0])).toEqual([
        ...(scanIds.length < 2 ? ["list-scans"] : []),
        "compare-scans",
        "save-scan-comparison",
      ]);
      const comparison = calls.find((args) => args[0] === "compare-scans")!;
      expect(comparison[2]).toBe(expectedBefore);
      expect(comparison[4]).toBe(expectedAfter);
      const save = calls.find((args) => args[0] === "save-scan-comparison")!;
      expect(save.at(-1)).toBe("--matches-json-stdin");
      expect(JSON.parse(comparisonInput!)).toEqual(matching);
      expect(JSON.parse(stdout.text())).toEqual({ summary: { persisting: 1 } });
    }
  });

  test.each([
    ["match", ["before", "after"]],
    ["match", ["--all"]],
    ["compare", ["before", "after"]],
  ] as const)(
    "forwards optional model settings for scans %s %j",
    async (command, scanArgs) => {
      for (const selection of [
        [],
        ["--model", "synthetic-model", "--effort", "high"],
      ]) {
        const selections: Array<{
          model?: string;
          reasoningEffort?: string;
        }> = [];
        const before = [{ occurrenceId: "before" }];
        const after = [{ occurrenceId: "after" }];
        expect(
          await runCapturedCli(
            main,
            ["scans", command, ...scanArgs, ...selection, "--json"],
            dependencies({
              onWorkbench: (args): JsonObject => {
                if (args[0] === "compare-scans") {
                  return {
                    matchingCached: false,
                    matchingInputs: { before, after },
                  };
                }
                if (args[0] === "list-unmatched-scan-pairs") {
                  return {
                    repository: "/current/repository",
                    scanCount: 2,
                    unavailableScans: 0,
                    skippedPairs: 0,
                    batches: [
                      {
                        afterScanId: "after",
                        afterFindings: after,
                        beforeScans: [{ scanId: "before", findings: before }],
                      },
                    ],
                  };
                }
                return {};
              },
              onMatch: async (_input, options) => {
                selections.push({
                  model: options?.model,
                  reasoningEffort: options?.reasoningEffort,
                });
                return { matches: [], uncertain: [] };
              },
            }),
          ),
        ).toBe(0);
        expect(selections).toEqual([
          selection.length === 0
            ? { model: undefined, reasoningEffort: undefined }
            : { model: "synthetic-model", reasoningEffort: "high" },
        ]);
      }
    },
  );

  test("requires two completed scans for a default comparison", async () => {
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["scans", "compare"],
        dependencies({
          onWorkbench: () => ({
            scans: [{ scanId: "scan-1" }],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "At least 2 completed scans are required for the current repository.",
    );
  });

  test("reports automatic matching failures without saving a comparison", async () => {
    const calls: string[] = [];
    const stderr = captureCli(main, "stderr");

    expect(
      await stderr.run(
        ["scans", "compare", "before", "after"],
        dependencies({
          onWorkbench: (args) => {
            calls.push(args[0]!);
            return {
              matchingCached: false,
              matchingInputs: { before: [], after: [] },
            };
          },
          onMatch: rejecting("Root-cause matching failed."),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Root-cause matching failed.");
    expect(calls).toEqual(["compare-scans"]);
  });

  test.each([false, true])(
    "keeps matching progress on stderr with TTY=%p",
    async (isTTY) => {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: isTTY });

      expect(
        await runCli(
          ["scans", "match", "before", "after", "--json"],
          dependencies({
            onWorkbench: (args): JsonObject =>
              args[0] === "compare-scans"
                ? { matchingInputs: { before: [], after: [] } }
                : { summary: { persisting: 1 } },
            onMatch: async (_input, options) => {
              const progress = {
                phase: "catalogue" as const,
                beforeFindings: 10,
                beforeIssues: 3,
                afterFindings: 2,
                page: 1,
                pages: 2,
              };
              options?.onProgress?.(progress);
              options?.onProgress?.(progress);
              options?.onProgress?.({ ...progress, phase: "evidence" });
              return { matches: [], uncertain: [] };
            },
          }),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual({ summary: { persisting: 1 } });
      if (isTTY) {
        expect(stderr.text().match(/Matching 2 findings/g)).toHaveLength(1);
        expect(stderr.text()).toContain("3 known issues");
        expect(stderr.text()).toContain("catalogue page 1/2");
        expect(stderr.text()).toContain("selected finding evidence");
      } else {
        expect(stderr.text()).toBe("");
      }
    },
  );

  test.each([
    [["before", "after"], "SIGINT", 130],
    [["--all"], "SIGTERM", 143],
  ] as const)(
    "cancels matching %j on %s before saving",
    async (args, signal, expectedExit) => {
      const signals = new FakeSignals();
      const commands: string[] = [];
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          ["scans", "match", ...args, "--json"],
          dependencies({
            signals,
            environment: { CODEX_SECURITY_STATE_DIR: "/synthetic/state" },
            onWorkbench: (command): JsonObject => {
              commands.push(command[0]!);
              const before = [{ occurrenceId: "before" }];
              const after = [{ occurrenceId: "after" }];
              return command[0] === "compare-scans"
                ? { matchingInputs: { before, after } }
                : {
                    batches: [
                      {
                        afterScanId: "after",
                        afterFindings: after,
                        beforeScans: [{ scanId: "before", findings: before }],
                      },
                    ],
                  };
            },
            onMatch: async (_input, options) => {
              expect(options).toMatchObject({
                environment: { CODEX_SECURITY_STATE_DIR: "/synthetic/state" },
                workingDirectory: "/current/repository",
              });
              signals.emit(signal);
              expect(options?.signal?.aborted).toBe(true);
              return { matches: [], uncertain: [] };
            },
          }),
        ),
      ).toBe(expectedExit);
      expect(commands).not.toContain("save-scan-comparison");
      expect(stderr.text()).toContain("Saved comparisons are preserved");
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
    },
  );

  test.each(["cached comparison", "matching plan", "final save"] as const)(
    "reports cancellation during a %s instead of success",
    async (stage) => {
      const signals = new FakeSignals();
      const { stdout, stderr, runCli } = createCliTest(main);

      let observedSignal: AbortSignal | undefined;
      const target =
        stage === "cached comparison"
          ? "compare-scans"
          : stage === "matching plan"
            ? "list-unmatched-scan-pairs"
            : "save-scan-comparison";
      const args = stage === "matching plan" ? ["--all"] : ["before", "after"];
      expect(
        await runCli(
          ["scans", "match", ...args, "--json"],
          dependencies({
            signals,
            onWorkbench: (command, _input, signal): JsonObject => {
              if (command[0] === target) {
                observedSignal = signal;
                signals.emit("SIGTERM");
              }
              if (command[0] === "compare-scans")
                return {
                  matchingCached: stage === "cached comparison",
                  matchingInputs: { before: [], after: [] },
                  summary: { persisting: 1 },
                };
              if (command[0] === "list-unmatched-scan-pairs")
                return { batches: [] };
              return { summary: { persisting: 1 } };
            },
          }),
        ),
      ).toBe(143);
      expect(observedSignal?.aborted).toBe(true);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("terminated by SIGTERM");
    },
  );

  test.each([
    ["SIGINT", "SIGINT", 1_000, 130],
    ["SIGTERM", "SIGTERM", 1_000, 143],
    ["SIGINT", "SIGTERM", 100, 130],
  ] as const)(
    "debounces matching %s and allows a later %s to terminate a blocked workbench",
    async (first, second, delay, expectedExit) => {
      const signals = new FakeSignals();
      const started = Promise.withResolvers<void>();
      const pending = Promise.withResolvers<JsonObject>();
      let observedSignal: AbortSignal | undefined;
      const forced = mock((_signal: string) => {});
      let now = 0;
      const deps = dependencies({
        signals,
        onWorkbench: async (_args, _input, signal) => {
          observedSignal = signal;
          started.resolve();
          return await pending.promise;
        },
      });
      deps.now = () => now;
      deps.forceExit = forced;
      const running = runCapturedCli(
        main,
        ["scans", "match", "before", "after", "--json"],
        deps,
      );
      await started.promise;
      signals.emit(first);
      expect(observedSignal?.aborted).toBe(true);
      signals.emit(first);
      expect(forced).not.toHaveBeenCalled();
      now = delay;
      signals.emit(second);
      expect(forced.mock.calls.map(([value]) => value)).toEqual([second]);
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
      pending.resolve({ matchingCached: true, summary: {} });
      expect(await running).toBe(expectedExit);
    },
  );

  test("matches all scans once per later scan", async () => {
    const finding = (occurrenceId: string) => ({ occurrenceId });
    const batches = [
      {
        afterScanId: "scan-b",
        afterFindings: [finding("b"), finding("b-shared")],
        beforeScans: [
          {
            scanId: "scan-a",
            findings: [finding("a"), finding("a-shared")],
          },
        ],
      },
      {
        afterScanId: "scan-c",
        afterFindings: [finding("c"), finding("c-shared")],
        beforeScans: [
          {
            scanId: "scan-a",
            findings: [finding("a"), finding("a-shared")],
          },
          {
            scanId: "scan-b",
            findings: [finding("b"), finding("b-shared")],
          },
        ],
      },
    ];
    const calls: Array<readonly string[]> = [];
    const inputs: Array<string | undefined> = [];
    const matcherCalls = mock<typeof matchScanFindings>(async (input) => {
      return input.after[0]?.occurrenceId === "b"
        ? {
            matches: [
              {
                beforeOccurrenceIds: ["a"],
                afterOccurrenceIds: ["b"],
                confidence: "high",
                reason: "Same root cause.",
              },
            ],
            uncertain: [],
          }
        : {
            matches: [
              {
                beforeOccurrenceIds: ["a", "b"],
                afterOccurrenceIds: ["c"],
                confidence: "high",
                reason: "Same root cause.",
              },
              {
                beforeOccurrenceIds: ["a-shared"],
                afterOccurrenceIds: ["c-shared"],
                confidence: "high",
                reason: "Same root cause.",
              },
            ],
            uncertain: [
              {
                beforeOccurrenceId: "b-shared",
                afterOccurrenceId: "c-shared",
                reason: "Possibly the same root cause.",
              },
            ],
          };
    });
    const stdout = captureCli(main, "stdout");

    expect(
      await stdout.run(
        ["scans", "match", "--all", "--force", "--json"],
        dependencies({
          onWorkbench: (args, input): JsonObject => {
            calls.push(args);
            inputs.push(input);
            return args[0] === "list-unmatched-scan-pairs"
              ? {
                  repository: "/current/repository",
                  scanCount: 5,
                  unavailableScans: 2,
                  skippedPairs: 1,
                  batches,
                }
              : {};
          },
          onMatch: matcherCalls,
        }),
      ),
    ).toBe(0);
    expect(matcherCalls).toHaveBeenCalledTimes(2);
    expect(calls[0]).toEqual([
      "list-unmatched-scan-pairs",
      "--repository",
      "/current/repository",
      "--force",
    ]);
    expect(
      calls.slice(1).map((args, index) => ({
        before: args[2],
        after: args[4],
        result: JSON.parse(inputs[index + 1]!),
      })),
    ).toMatchObject([
      { before: "scan-a", after: "scan-b" },
      {
        before: "scan-a",
        after: "scan-c",
        result: {
          matches: [
            { beforeOccurrenceIds: ["a"], afterOccurrenceIds: ["c"] },
            {
              beforeOccurrenceIds: ["a-shared"],
              afterOccurrenceIds: ["c-shared"],
            },
          ],
          uncertain: [],
        },
      },
      {
        before: "scan-b",
        after: "scan-c",
        result: {
          matches: [{ beforeOccurrenceIds: ["b"] }],
          uncertain: [{ beforeOccurrenceId: "b-shared" }],
        },
      },
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      repository: "/current/repository",
      scanCount: 5,
      unavailableScans: 2,
      matchedPairs: 3,
      skippedPairs: 1,
      findingMatches: 4,
      relatedPairs: 0,
      uncertainPairs: 1,
    });
  });

  test("preserves confirmed groups and related pairs while matching all scans", async () => {
    const before = [{ occurrenceId: "before", findingId: "known-a" }];
    const after = [{ occurrenceId: "after", findingId: "other" }];
    const knownFindingGroups = [["known-a", "known-b"]];
    const related = {
      beforeOccurrenceId: "before",
      afterOccurrenceId: "after",
      reason: "Separate controls share a nearby trust boundary.",
    };
    let saved: string | undefined;

    expect(
      await runCapturedCli(
        main,
        ["scans", "match", "--all", "--json"],
        dependencies({
          onWorkbench: (args, input): JsonObject => {
            if (args[0] === "save-scan-comparison") saved = input;
            return args[0] === "list-unmatched-scan-pairs"
              ? {
                  repository: "/current/repository",
                  scanCount: 2,
                  unavailableScans: 0,
                  skippedPairs: 0,
                  batches: [
                    {
                      afterScanId: "later-scan",
                      afterFindings: after,
                      beforeScans: [
                        { scanId: "earlier-scan", findings: before },
                      ],
                      knownFindingGroups,
                    },
                  ],
                }
              : {};
          },
          onMatch: async (input) => {
            expect(input).toEqual({ before, after, knownFindingGroups });
            return { matches: [], uncertain: [], related: [related] };
          },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(saved!)).toEqual({
      matches: [],
      uncertain: [],
      related: [related],
    });
  });

  test("unions overlapping confirmed identities before later matching batches", async () => {
    const first = { occurrenceId: "first", findingId: "identity-a" };
    const second = { occurrenceId: "second", findingId: "identity-b" };
    const third = { occurrenceId: "third", findingId: "identity-c" };
    const fourth = { occurrenceId: "fourth", findingId: "identity-d" };
    const existingGroups = [
      [first.findingId, second.findingId],
      [third.findingId, fourth.findingId],
    ];
    const matchedInputs: ScanComparisonInput[] = [];

    expect(
      await runCapturedCli(
        main,
        ["scans", "match", "--all", "--json"],
        dependencies({
          onWorkbench: (args): JsonObject =>
            args[0] === "list-unmatched-scan-pairs"
              ? {
                  repository: "/current/repository",
                  scanCount: 4,
                  unavailableScans: 0,
                  skippedPairs: 0,
                  batches: [
                    {
                      afterScanId: "third-scan",
                      afterFindings: [third],
                      beforeScans: [
                        { scanId: "first-scan", findings: [first] },
                      ],
                      knownFindingGroups: existingGroups,
                    },
                    {
                      afterScanId: "fourth-scan",
                      afterFindings: [fourth],
                      beforeScans: [
                        { scanId: "second-scan", findings: [second] },
                      ],
                      knownFindingGroups: existingGroups,
                    },
                  ],
                }
              : {},
          onMatch: async (input) => {
            matchedInputs.push(input);
            return matchedInputs.length === 1
              ? {
                  matches: [
                    {
                      beforeOccurrenceIds: [first.occurrenceId],
                      afterOccurrenceIds: [third.occurrenceId],
                      confidence: "high",
                      reason: "These confirmed identities describe one issue.",
                    },
                  ],
                  uncertain: [],
                }
              : { matches: [], uncertain: [] };
          },
        }),
      ),
    ).toBe(0);
    expect(matchedInputs).toHaveLength(2);
    expect(matchedInputs[1]!.knownFindingGroups).toEqual([
      [first.findingId, second.findingId, third.findingId, fourth.findingId],
    ]);
  });

  test("saves empty comparisons without starting Codex", async () => {
    const calls: Array<readonly string[]> = [];
    let comparisonInput: string | undefined;
    const deps = dependencies({
      onWorkbench: (args, input): JsonObject => {
        calls.push(args);
        if (args[0] === "save-scan-comparison") comparisonInput = input;
        return args[0] === "list-unmatched-scan-pairs"
          ? {
              repository: "/repo",
              scanCount: 2,
              unavailableScans: 0,
              skippedPairs: 0,
              batches: [
                {
                  afterScanId: "after",
                  afterFindings: [],
                  beforeScans: [
                    {
                      scanId: "before",
                      findings: [{ occurrenceId: "before" }],
                    },
                  ],
                },
              ],
            }
          : {};
      },
    });
    deps.matchFindings = rejecting("empty comparisons must not start Codex");

    expect(await runCapturedCli(main, ["scans", "match", "--all"], deps)).toBe(
      0,
    );
    expect(calls[1]!.at(-1)).toBe("--matches-json-stdin");
    expect(JSON.parse(comparisonInput!)).toEqual({
      matches: [],
      uncertain: [],
    });
  });

  test("projects historical uncertainty per scan without losing a known match", async () => {
    const calls: Array<readonly string[]> = [];
    const inputs: Array<string | undefined> = [];
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scans", "match", "--all", "--json"],
        dependencies({
          onWorkbench: (args, input): JsonObject => {
            calls.push(args);
            inputs.push(input);
            if (args[0] !== "list-unmatched-scan-pairs") return {};
            return {
              repository: "/repo",
              scanCount: 3,
              unavailableScans: 0,
              skippedPairs: 1,
              batches: [
                {
                  afterScanId: "after",
                  afterFindings: [
                    { occurrenceId: "after", findingId: "shared" },
                  ],
                  beforeScans: [
                    {
                      scanId: "before",
                      findings: [
                        { occurrenceId: "confirmed", findingId: "shared" },
                      ],
                    },
                    {
                      scanId: "earlier",
                      findings: [
                        {
                          occurrenceId: "earlier-uncertain",
                          findingId: "earlier-other",
                        },
                        { occurrenceId: "uncertain", findingId: "other" },
                      ],
                    },
                  ],
                },
              ],
            };
          },
          onMatch: (input, options) =>
            matchScanFindings(input, {
              ...options,
              codex: jsonCodex(() => ({
                matches: [],
                uncertain: ["uncertain", "earlier-uncertain"].map(
                  (beforeOccurrenceId) => ({
                    beforeOccurrenceId,
                    afterOccurrenceId: "after",
                    reason: "Possibly the same root cause.",
                  }),
                ),
              })),
            }),
        }),
      ),
      stderr.text(),
    ).toBe(0);
    expect(inputs.slice(1).map((input) => JSON.parse(input!))).toMatchObject([
      {
        matches: [
          {
            beforeOccurrenceIds: ["confirmed"],
            afterOccurrenceIds: ["after"],
          },
        ],
        uncertain: [],
      },
      {
        matches: [],
        uncertain: [
          { beforeOccurrenceId: "uncertain" },
          { beforeOccurrenceId: "earlier-uncertain" },
        ],
      },
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      matchedPairs: 2,
      findingMatches: 1,
      uncertainPairs: 2,
    });
  });

  test.each([false, true])(
    "preserves surviving indirect matches during forced recomputation (%p)",
    async (force) => {
      const before = [{ occurrenceId: "old", findingId: "identity-old" }];
      const after = [{ occurrenceId: "new", findingId: "identity-new" }];
      const calls: Array<readonly string[]> = [];
      const run = mock<
        () => Promise<{ finalResponse: string }>
      >().mockResolvedValue({
        finalResponse: JSON.stringify({ matches: [], uncertain: [] }),
      });
      let saved: unknown;
      expect(
        await runCapturedCli(
          main,
          ["scans", "match", "before", "after", ...(force ? ["--force"] : [])],
          dependencies({
            onWorkbench: (args, input): JsonObject => {
              calls.push(args);
              if (args[0] === "compare-scans") {
                return {
                  matchingCached: force,
                  matchingInputs: {
                    before,
                    after,
                    knownFindingGroups: [
                      ["identity-old", "identity-bridge", "identity-new"],
                    ],
                  },
                };
              }
              saved = JSON.parse(input!);
              return {};
            },
            onMatch: (input, options) =>
              matchScanFindings(input, {
                ...options,
                codex: codexWithRun(run),
              }),
          }),
        ),
      ).toBe(0);
      expect(run).toHaveBeenCalledTimes(0);
      expect(saved).toMatchObject({
        matches: [
          { beforeOccurrenceIds: ["old"], afterOccurrenceIds: ["new"] },
        ],
        uncertain: [],
      });
      expect(calls.map((args) => args[0])).toEqual([
        "compare-scans",
        "save-scan-comparison",
      ]);
    },
  );

  test("rejects invalid matching arguments before loading history", async () => {
    for (const args of [
      ["scans", "match"],
      ["scans", "match", "before"],
      ["scans", "match", "--all", "before"],
      ["scans", "match", "before", "after", "--all"],
      ["scans", "compare", "before", "after", "--force"],
    ]) {
      const onWorkbench = mock<() => {}>().mockReturnValue({});
      expect(
        await runCapturedCli(
          main,
          args,
          dependencies({
            onWorkbench,
          }),
        ),
      ).toBe(2);
      expect(onWorkbench).toHaveBeenCalledTimes(0);
    }
  });

  test.each(["scan-original", undefined])(
    "rejects Markdown rerun output before loading scan %p",
    async (scanId) => {
      const { stdout, stderr, runCli } = createCliTest(main);

      const onWorkbench = mock<() => {}>().mockReturnValue({});

      expect(
        await runCli(
          [
            "scans",
            "rerun",
            ...(scanId === undefined ? [] : [scanId]),
            "--format",
            "md",
          ],
          dependencies({
            onWorkbench,
          }),
        ),
      ).toBe(2);
      expect(onWorkbench).toHaveBeenCalledTimes(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        "Markdown output is not supported for scan results.",
      );
    },
  );

  test("reruns the latest completed scan by default", async () => {
    let parentScanId: unknown;

    expect(
      await runCapturedCli(
        main,
        ["scans", "rerun"],
        dependencies({
          onTurn: (_repository, options) => {
            parentScanId = options.parentScanId;
          },
          onWorkbench: (args): JsonObject =>
            args[0] === "list-scans"
              ? { scans: [{ scanId: "latest-scan" }] }
              : {
                  scanId: "latest-scan",
                  recipe: {
                    repository: "/current/repository",
                    target: { kind: "repository", paths: [] },
                    mode: "standard",
                    config: {},
                  },
                },
        }),
      ),
    ).toBe(0);
    expect(parentScanId).toBe("latest-scan");
  });

  test("reruns a scan prefix with its resolved parent UUID", async () => {
    const scanId = "12345678-1234-4234-8234-123456789abc";
    const prefix = scanId.slice(0, 8);
    const onTurn = mock<(repository: string, options: ScanOptions) => void>();
    const onWorkbench = mock((args: readonly string[]): JsonObject => {
      expect(args).toEqual(["get-scan-recipe", "--scan-id", prefix]);
      return { ...savedRecipe(), scanId };
    });

    expect(
      await runCapturedCli(
        main,
        ["scans", "rerun", prefix],
        dependencies({ onWorkbench, onTurn }),
      ),
    ).toBe(0);
    expect(onTurn.mock.lastCall?.[1]?.parentScanId).toBe(scanId);
  });

  test.each([null, "", "unknown", 1])(
    "rejects an invalid saved severity policy: %j",
    async (failOnSeverity) => {
      const stderr = captureCli(main, "stderr");
      const onRun = mock();
      const saved = savedRecipe();
      expect(
        await stderr.run(
          ["scans", "rerun", saved.scanId],
          dependencies({
            onRun,
            onWorkbench: () => ({
              ...saved,
              recipe: { ...saved.recipe, failOnSeverity },
            }),
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("invalid severity policy");
      expect(onRun).not.toHaveBeenCalled();
    },
  );

  test("reruns canonical recipes with exact config, policy, plugin, and lineage", async () => {
    const onConfig = mock<(config: CodexSecurityConfig) => void>();
    const onTurn = mock<(repository: string, options: ScanOptions) => void>();
    const knowledgeBasePath = resolve("/original/security.md");
    const savedConfig = {
      approval_policy: "on-request",
      model: "gpt-original",
      model_reasoning_effort: "high",
      features: { goals: true },
      agents: { max_threads: 6 },
    };
    expect(
      await runCapturedCli(
        main,
        ["scans", "rerun", "scan-original"],
        dependencies({
          onConfig,
          onTurn,
          onWorkbench: () => ({
            scanId: "scan-original",
            recipe: {
              repository: "/original/repository",
              target: { kind: "paths", paths: ["src", "packages/core"] },
              mode: "deep",
              pluginVersion: "1.2.3",
              failOnSeverity: "high",
              knowledgeBasePaths: [knowledgeBasePath],
              deepScan: {
                workers: 2,
                subagents: 0,
                stopAfterNoNew: 3,
                maxDiscoveryRuns: 10,
                maxTimeHours: 1.5,
              },
              config: savedConfig,
            },
          }),
        }),
      ),
    ).toBe(0);
    expect(onConfig.mock.lastCall?.[0]?.codexOverrides).toEqual(savedConfig);
    expect(onTurn.mock.lastCall?.[0]).toBe("/original/repository");
    expect(onTurn.mock.lastCall?.[1]).toMatchObject({
      target: ["src", "packages/core"],
      mode: "deep",
      parentScanId: "scan-original",
      expectedPluginVersion: "1.2.3",
      failureSeverity: "high",
      knowledgeBasePaths: [knowledgeBasePath],
      workers: 2,
      subagents: 0,
      stopAfterNoNew: 3,
      maxDiscoveryRuns: 10,
      maxTimeHours: 1.5,
    });

    const references: Array<[JsonObject, ReturnType<typeof DiffTarget.refs>]> =
      [
        [
          {
            kind: "refs",
            paths: [],
            base: "old-base-sha",
            baseRef: "origin/main",
            head: "old-head-sha",
            headRef: "feature",
          },
          DiffTarget.refs({ base: "origin/main", head: "feature" }),
        ],
        [
          { kind: "refs", paths: [], base: "old-base-sha" },
          DiffTarget.refs({ base: "old-base-sha", head: "HEAD" }),
        ],
      ];
    for (const [target, expected] of references) {
      const onTurn = mock<(repository: string, options: ScanOptions) => void>();
      expect(
        await runCapturedCli(
          main,
          ["scans", "rerun", "scan-original"],
          dependencies({
            onTurn,
            onWorkbench: () => savedRecipe({}, target),
          }),
        ),
      ).toBe(0);
      expect(onTurn.mock.lastCall?.[1]?.target).toEqual(expected);
    }
  });

  test.each([
    ["legacy", undefined, "never"],
    ["strict", "never", "never"],
    ["reviewed", "on-request", "on-request"],
  ] as const)(
    "preserves %s scan approval policy when rerunning saved scans",
    async (_scenario, savedApprovalPolicy, expectedApprovalPolicy) => {
      const onConfig = mock<(config: CodexSecurityConfig) => void>();
      const savedConfig = {
        model: "gpt-original",
        ...(savedApprovalPolicy === undefined
          ? {}
          : { approval_policy: savedApprovalPolicy }),
      };

      expect(
        await runCapturedCli(
          main,
          ["scans", "rerun", "scan-original"],
          dependencies({
            onConfig,
            onWorkbench: () => savedRecipe(savedConfig),
          }),
        ),
      ).toBe(0);
      expect(onConfig.mock.lastCall?.[0]?.codexOverrides).toEqual({
        ...savedConfig,
        approval_policy: expectedApprovalPolicy,
      });
    },
  );

  test("preserves workbench failures and does not initialize Codex", async () => {
    const stderr = captureCli(main, "stderr");
    const onRun = mock();
    expect(
      await stderr.run(
        ["scans", "show", "missing"],
        dependencies({
          onRun,
          onWorkbench: throwing(`Scan lookup failed ${SYNTHETIC_CREDENTIALS}`),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(SYNTHETIC_CREDENTIALS);
    expect(stderr.text()).toContain("SYNTHETIC_KEY_123");
    expect(onRun).not.toHaveBeenCalled();
  });
});
