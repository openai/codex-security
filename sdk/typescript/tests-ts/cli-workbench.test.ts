import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import type { CodexSecurityConfig, JsonObject } from "../src/index.js";
import { DiffTarget } from "../src/index.js";
import { main } from "../src/cli.js";
import type { ScanComparisonInput } from "../src/scan-comparison.js";
import {
  capture,
  dependencies,
  fakeResult,
  SYNTHETIC_CREDENTIALS,
} from "./cli-fixtures.js";

describe("CLI workbench", () => {
  test("lists and summarizes open findings for the current repository", async () => {
    const repository = resolve("/current/repository");
    const stdout = capture();
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
      await main(
        ["findings", "list", "--json"],
        stdout.stream,
        capture().stream,
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
      await main(
        ["findings", "--json"],
        capture().stream,
        capture().stream,
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
      const stderr = capture();
      expect(
        await main(
          ["scan"],
          capture().stream,
          stderr.stream,
          dependencies({ result }),
        ),
      ).toBe(0);
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
      let invocation: readonly string[] | undefined;
      const deps = dependencies({
        onWorkbench: (args) => {
          invocation = args;
          return { scans: [{ scanId: "scan-1" }] };
        },
      });
      deps.createSecurity = () => {
        throw new Error("history must not initialize Codex");
      };
      expect(await main(argv, capture().stream, capture().stream, deps)).toBe(
        0,
      );
      expect(invocation).toEqual(expected);
    }

    const stdout = capture();
    expect(
      await main(
        ["scan", "scans", "--dry-run", "--json"],
        stdout.stream,
        capture().stream,
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
        ["scans", "compare", "before", "after", "--json"],
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
        ["scans", "match", "before", "after", "--json"],
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
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      const deps = dependencies({
        onWorkbench: (args) => {
          calls.push(args);
          return response;
        },
      });
      deps.createSecurity = () => {
        throw new Error("history must not initialize Codex");
      };
      deps.matchFindings = async () => {
        throw new Error("saved matches must not initialize Codex");
      };
      expect(await main(argv, stdout.stream, capture().stream, deps)).toBe(0);
      expect(calls).toEqual([expected]);
      expect(JSON.parse(stdout.text())).toEqual(output);
    }
  });

  test("shows saved scan activity without starting Codex", async () => {
    const state = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-cli-logs-")),
    );
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
      const stdout = capture();
      const deps = dependencies({
        environment: { CODEX_SECURITY_STATE_DIR: state },
        onWorkbench: (args): JsonObject => {
          calls.push(args);
          if (args[0] === "list-scans") {
            return { scans: [{ scanId: "scan-1" }] };
          }
          return {
            scan: {
              scanId: "scan-1",
              continuationThreadId: "thread-1",
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
      deps.createSecurity = () => {
        throw new Error("logs must not initialize Codex");
      };
      expect(
        await main(
          ["scans", "logs", "scan-1", "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual([["get-scan", "--scan-id", "scan-1"]]);
      expect(stdout.text()).toContain("SYNTHETIC_KEY");
      expect(stdout.text()).toContain("independent worker");
      expect(stdout.text()).not.toContain("PRIVATE LATER SESSION");

      calls.length = 0;
      const latest = capture();
      expect(
        await main(
          ["scans", "logs", "--json"],
          latest.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
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
    const stderr = capture();
    expect(
      await main(
        ["scans", "logs", "scan-1"],
        capture().stream,
        stderr.stream,
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
      const stdout = capture();

      expect(
        await main(
          ["scans", command, ...scanIds, "--json"],
          stdout.stream,
          capture().stream,
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

  test("requires two completed scans for a default comparison", async () => {
    const stderr = capture();
    expect(
      await main(
        ["scans", "compare"],
        capture().stream,
        stderr.stream,
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
    const stderr = capture();

    expect(
      await main(
        ["scans", "compare", "before", "after"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args[0]!);
            return {
              matchingCached: false,
              matchingInputs: { before: [], after: [] },
            };
          },
          onMatch: async () => {
            throw new Error("Root-cause matching failed.");
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Root-cause matching failed.");
    expect(calls).toEqual(["compare-scans"]);
  });

  test("matches all scans once per later scan", async () => {
    const finding = (occurrenceId: string) => ({ occurrenceId });
    const batches = [
      {
        afterScanId: "scan-b",
        afterFindings: [finding("b")],
        beforeScans: [{ scanId: "scan-a", findings: [finding("a")] }],
      },
      {
        afterScanId: "scan-c",
        afterFindings: [finding("c"), finding("c-shared")],
        beforeScans: [
          { scanId: "scan-a", findings: [finding("a")] },
          { scanId: "scan-b", findings: [finding("b")] },
        ],
      },
    ];
    const calls: Array<readonly string[]> = [];
    const inputs: Array<string | undefined> = [];
    let matcherCalls = 0;
    const stdout = capture();

    expect(
      await main(
        ["scans", "match", "--all", "--force", "--json"],
        stdout.stream,
        capture().stream,
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
          onMatch: async (input) => {
            matcherCalls += 1;
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
                      beforeOccurrenceIds: ["a"],
                      afterOccurrenceIds: ["c-shared"],
                      confidence: "high",
                      reason: "Same root cause.",
                    },
                  ],
                  uncertain: [
                    {
                      beforeOccurrenceId: "b",
                      afterOccurrenceId: "c-shared",
                      reason: "Possibly the same root cause.",
                    },
                  ],
                };
          },
        }),
      ),
    ).toBe(0);
    expect(matcherCalls).toBe(2);
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
            { beforeOccurrenceIds: ["a"], afterOccurrenceIds: ["c-shared"] },
          ],
          uncertain: [],
        },
      },
      {
        before: "scan-b",
        after: "scan-c",
        result: {
          matches: [{ beforeOccurrenceIds: ["b"] }],
          uncertain: [{ beforeOccurrenceId: "b" }],
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
      await main(
        ["scans", "match", "--all", "--json"],
        capture().stream,
        capture().stream,
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
      await main(
        ["scans", "match", "--all", "--json"],
        capture().stream,
        capture().stream,
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
    deps.matchFindings = async () => {
      throw new Error("empty comparisons must not start Codex");
    };

    expect(
      await main(
        ["scans", "match", "--all"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls[1]!.at(-1)).toBe("--matches-json-stdin");
    expect(JSON.parse(comparisonInput!)).toEqual({
      matches: [],
      uncertain: [],
    });
  });

  test("does not save conflicting confirmed and uncertain matches", async () => {
    const calls: Array<readonly string[]> = [];
    const stderr = capture();
    expect(
      await main(
        ["scans", "match", "--all"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return {
              batches: [
                {
                  afterScanId: "after",
                  afterFindings: [{ occurrenceId: "after" }],
                  beforeScans: [
                    {
                      scanId: "before",
                      findings: [
                        { occurrenceId: "confirmed" },
                        { occurrenceId: "uncertain" },
                      ],
                    },
                  ],
                },
              ],
            };
          },
          onMatch: async () => ({
            matches: [
              {
                beforeOccurrenceIds: ["confirmed"],
                afterOccurrenceIds: ["after"],
                confidence: "high",
                reason: "Same root cause.",
              },
            ],
            uncertain: [
              {
                beforeOccurrenceId: "uncertain",
                afterOccurrenceId: "after",
                reason: "Possibly the same root cause.",
              },
            ],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("conflicting confirmed and uncertain");
    expect(calls).toHaveLength(1);
  });

  test("force recomputes saved matches", async () => {
    const calls: Array<readonly string[]> = [];
    const matchingInputs = {
      before: [{ occurrenceId: "before", findingId: "identity-a" }],
      after: [{ occurrenceId: "after", findingId: "identity-b" }],
      knownFindingGroups: [["identity-a", "identity-c", "identity-b"]],
    };
    expect(
      await main(
        ["scans", "match", "before", "after", "--force"],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "compare-scans"
              ? {
                  matchingCached: true,
                  matchingInputs,
                }
              : {};
          },
          onMatch: async (input) => {
            expect(input).toEqual(matchingInputs);
            return { matches: [], uncertain: [] };
          },
        }),
      ),
    ).toBe(0);
    expect(calls.map((args) => args[0])).toEqual([
      "compare-scans",
      "save-scan-comparison",
    ]);
  });

  test("rejects invalid matching arguments before loading history", async () => {
    for (const args of [
      ["scans", "match"],
      ["scans", "match", "before"],
      ["scans", "match", "--all", "before"],
      ["scans", "match", "before", "after", "--all"],
      ["scans", "compare", "before", "after", "--force"],
    ]) {
      let calls = 0;
      expect(
        await main(
          args,
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: () => {
              calls += 1;
              return {};
            },
          }),
        ),
      ).toBe(2);
      expect(calls).toBe(0);
    }
  });

  test("reruns the latest completed scan by default", async () => {
    let parentScanId: unknown;

    expect(
      await main(
        ["scans", "rerun"],
        capture().stream,
        capture().stream,
        dependencies({
          onTurn: (_repository, options) => {
            parentScanId = (options as { parentScanId?: string }).parentScanId;
          },
          onWorkbench: (args): JsonObject =>
            args[0] === "list-scans"
              ? { scans: [{ scanId: "latest-scan" }] }
              : {
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

  test("reruns canonical recipes with exact config, policy, plugin, and lineage", async () => {
    let config: CodexSecurityConfig | undefined;
    let repository: string | undefined;
    let options: Record<string, unknown> | undefined;
    const savedConfig = {
      approval_policy: "on-request",
      model: "gpt-original",
      model_reasoning_effort: "high",
      features: { goals: true },
      agents: { max_threads: 6 },
    };
    expect(
      await main(
        ["scans", "rerun", "scan-original"],
        capture().stream,
        capture().stream,
        dependencies({
          onConfig: (value) => {
            config = value;
          },
          onTurn: (value, runOptions) => {
            repository = value;
            options = runOptions as Record<string, unknown>;
          },
          onWorkbench: () => ({
            recipe: {
              repository: "/original/repository",
              target: { kind: "paths", paths: ["src", "packages/core"] },
              mode: "deep",
              pluginVersion: "1.2.3",
              failOnSeverity: "high",
              knowledgeBasePaths: ["/original/security.md"],
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
    expect(config?.codexOverrides).toEqual(savedConfig);
    expect(repository).toBe("/original/repository");
    expect(options).toMatchObject({
      target: ["src", "packages/core"],
      mode: "deep",
      parentScanId: "scan-original",
      expectedPluginVersion: "1.2.3",
      failureSeverity: "high",
      knowledgeBasePaths: ["/original/security.md"],
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
      let runOptions: Record<string, unknown> | undefined;
      expect(
        await main(
          ["scans", "rerun", "scan-original"],
          capture().stream,
          capture().stream,
          dependencies({
            onTurn: (_repository, value) => {
              runOptions = value as Record<string, unknown>;
            },
            onWorkbench: () => ({
              recipe: {
                repository: "/original/repository",
                target,
                mode: "standard",
                config: {},
              },
            }),
          }),
        ),
      ).toBe(0);
      expect(runOptions?.["target"]).toEqual(expected);
    }
  });

  test.each([
    ["legacy", undefined, "never"],
    ["strict", "never", "never"],
    ["reviewed", "on-request", "on-request"],
  ] as const)(
    "preserves %s scan approval policy when rerunning saved scans",
    async (_scenario, savedApprovalPolicy, expectedApprovalPolicy) => {
      let config: CodexSecurityConfig | undefined;
      const savedConfig = {
        model: "gpt-original",
        ...(savedApprovalPolicy === undefined
          ? {}
          : { approval_policy: savedApprovalPolicy }),
      };

      expect(
        await main(
          ["scans", "rerun", "scan-original"],
          capture().stream,
          capture().stream,
          dependencies({
            onConfig: (value) => {
              config = value;
            },
            onWorkbench: () => ({
              recipe: {
                repository: "/original/repository",
                target: { kind: "repository", paths: [] },
                mode: "standard",
                config: savedConfig,
              },
            }),
          }),
        ),
      ).toBe(0);
      expect(config?.codexOverrides).toEqual({
        ...savedConfig,
        approval_policy: expectedApprovalPolicy,
      });
    },
  );

  test("preserves workbench failures and does not initialize Codex", async () => {
    const stderr = capture();
    let started = false;
    expect(
      await main(
        ["scans", "show", "missing"],
        capture().stream,
        stderr.stream,
        dependencies({
          onRun: () => {
            started = true;
          },
          onWorkbench: () => {
            throw new Error(`Scan lookup failed ${SYNTHETIC_CREDENTIALS}`);
          },
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(SYNTHETIC_CREDENTIALS);
    expect(stderr.text()).toContain("SYNTHETIC_KEY_123");
    expect(started).toBe(false);
  });
});
