import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import type { CodexSecurityConfig, JsonObject } from "../src/index.js";
import { DiffTarget } from "../src/index.js";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  REDACTED_CREDENTIALS,
  SYNTHETIC_CREDENTIALS,
} from "./support/cli.js";

describe("CLI workbench", () => {
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

    for (const command of ["match", "compare"]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();

      expect(
        await main(
          ["scans", command, "before", "after", "--json"],
          stdout.stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              return args[0] === "compare-scans"
                ? { matchingCached: false, matchingInputs: { before, after } }
                : { summary: { persisting: 1 } };
            },
            onMatch: async (input) => {
              expect(input).toEqual({ before, after });
              return matching;
            },
          }),
        ),
      ).toBe(0);
      expect(calls.map((args) => args[0])).toEqual([
        "compare-scans",
        "save-scan-comparison",
      ]);
      expect(JSON.parse(calls[1]![6]!)).toEqual(matching);
      expect(JSON.parse(stdout.text())).toEqual({ summary: { persisting: 1 } });
    }
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
    const findings = new Map([
      ["scan-a", [finding("a")]],
      ["scan-b", [finding("b")]],
      ["scan-c", [finding("c"), finding("c-shared")]],
    ]);
    const calls: Array<readonly string[]> = [];
    let matcherCalls = 0;
    const stdout = capture();

    expect(
      await main(
        ["scans", "match", "--all", "--force", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            if (args[0] === "list-unmatched-scan-pairs") {
              return {
                repository: "/current/repository",
                scanCount: 5,
                unavailableScans: 2,
                skippedPairs: 1,
                nextOffset: null,
                pairs: [
                  { beforeScanId: "scan-a", afterScanId: "scan-b" },
                  { beforeScanId: "scan-a", afterScanId: "scan-c" },
                  { beforeScanId: "scan-b", afterScanId: "scan-c" },
                ],
              };
            }
            if (args[0] === "get-scan-matching-inputs") {
              const scanId = args[2]!;
              return {
                scanId,
                findings: findings.get(scanId)!,
                nextOffset: null,
                totalFindings: findings.get(scanId)!.length,
              };
            }
            return {};
          },
          onMatch: async (input) => {
            matcherCalls += 1;
            const before = input.before[0]?.occurrenceId;
            const after = input.after[0]?.occurrenceId;
            if (before === "a" && after === "b") {
              return {
                matches: [
                  {
                    beforeOccurrenceIds: ["a"],
                    afterOccurrenceIds: ["b"],
                    confidence: "high",
                    reason: "Same root cause.",
                  },
                ],
                uncertain: [],
              };
            }
            if (before === "a" && after === "c") {
              return {
                matches: [
                  {
                    beforeOccurrenceIds: ["a"],
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
                uncertain: [],
              };
            }
            return {
              matches: [
                {
                  beforeOccurrenceIds: ["b"],
                  afterOccurrenceIds: ["c"],
                  confidence: "high",
                  reason: "Same root cause.",
                },
              ],
              uncertain: [],
            };
          },
        }),
      ),
    ).toBe(0);
    expect(matcherCalls).toBe(3);
    expect(calls[0]).toEqual([
      "list-unmatched-scan-pairs",
      "--repository",
      "/current/repository",
      "--offset",
      "0",
      "--force",
    ]);
    const saves = calls.filter(
      ([command]) => command === "save-scan-comparison",
    );
    expect(
      saves.map((args) => ({
        before: args[2],
        after: args[4],
        result: JSON.parse(args[6]!),
      })),
    ).toMatchObject([
      { before: "scan-a", after: "scan-b" },
      {
        before: "scan-a",
        after: "scan-c",
        result: {
          matches: [
            {
              beforeOccurrenceIds: ["a"],
              afterOccurrenceIds: ["c", "c-shared"],
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
          uncertain: [],
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

  test("pages match-all history and reconciles bounded finding batches", async () => {
    const calls: Array<readonly string[]> = [];
    const matcherInputs: Array<{
      before: string[];
      after: string[];
    }> = [];
    const pages = new Map([
      ["before:0", { findings: [{ occurrenceId: "b-1" }], nextOffset: 1 }],
      ["before:1", { findings: [{ occurrenceId: "b-2" }], nextOffset: null }],
      ["after:0", { findings: [{ occurrenceId: "a-1" }], nextOffset: 1 }],
      ["after:1", { findings: [{ occurrenceId: "a-2" }], nextOffset: null }],
    ]);
    const stdout = capture();

    expect(
      await main(
        ["scans", "match", "--all", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            if (args[0] === "list-unmatched-scan-pairs") {
              const offset = Number(args[4]);
              return {
                repository: "/repo",
                scanCount: 2,
                unavailableScans: 0,
                skippedPairs: 0,
                nextOffset: offset === 0 ? 64 : null,
                pairs:
                  offset === 0
                    ? []
                    : [{ beforeScanId: "before", afterScanId: "after" }],
              };
            }
            if (args[0] === "get-scan-matching-inputs") {
              const scanId = args[2]!;
              const offset = Number(args[4]);
              return {
                scanId,
                totalFindings: 2,
                ...pages.get(`${scanId}:${offset}`)!,
              };
            }
            return {};
          },
          onMatch: async (input) => {
            const before = input.before.map(({ occurrenceId }) => occurrenceId);
            const after = input.after.map(({ occurrenceId }) => occurrenceId);
            matcherInputs.push({ before, after });
            if (
              (before[0] === "b-1" && after[0] === "a-1") ||
              (before[0] === "b-1" && after[0] === "a-2") ||
              (before[0] === "b-2" && after[0] === "a-2")
            ) {
              return {
                matches: [
                  {
                    beforeOccurrenceIds: before,
                    afterOccurrenceIds: after,
                    confidence: "high",
                    reason: `${before[0]} matches ${after[0]}`,
                  },
                ],
                uncertain: [],
              };
            }
            return { matches: [], uncertain: [] };
          },
        }),
      ),
    ).toBe(0);

    expect(
      calls
        .filter(([command]) => command === "list-unmatched-scan-pairs")
        .map((args) => args[4]),
    ).toEqual(["0", "64"]);
    expect(matcherInputs).toEqual([
      { before: ["b-1"], after: ["a-1"] },
      { before: ["b-1"], after: ["a-2"] },
      { before: ["b-2"], after: ["a-1"] },
      { before: ["b-2"], after: ["a-2"] },
    ]);
    const save = calls.find(([command]) => command === "save-scan-comparison")!;
    expect(JSON.parse(save[6]!)).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["b-1", "b-2"],
          afterOccurrenceIds: ["a-1", "a-2"],
          confidence: "high",
          reason: "b-1 matches a-1",
        },
      ],
      uncertain: [],
    });
    expect(JSON.parse(stdout.text())).toMatchObject({
      matchedPairs: 1,
      findingMatches: 4,
    });
  });

  test("rejects oversized accumulated match-all results before persistence", async () => {
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
            if (args[0] === "list-unmatched-scan-pairs") {
              return {
                repository: "/repo",
                scanCount: 2,
                unavailableScans: 0,
                skippedPairs: 0,
                nextOffset: null,
                pairs: [{ beforeScanId: "before", afterScanId: "after" }],
              };
            }
            const scanId = args[2]!;
            return {
              scanId,
              findings: [{ occurrenceId: scanId }],
              nextOffset: null,
              totalFindings: 1,
            };
          },
          onMatch: async () => ({
            matches: [
              {
                beforeOccurrenceIds: ["before"],
                afterOccurrenceIds: ["after"],
                confidence: "high",
                reason: "x".repeat(1024 * 1024),
              },
            ],
            uncertain: [],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("more than 1 MiB");
    expect(calls.some(([command]) => command === "save-scan-comparison")).toBe(
      false,
    );
  });

  test("saves empty comparisons without starting Codex", async () => {
    const calls: Array<readonly string[]> = [];
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-unmatched-scan-pairs") {
          return {
            repository: "/repo",
            scanCount: 2,
            unavailableScans: 0,
            skippedPairs: 0,
            nextOffset: null,
            pairs: [{ beforeScanId: "before", afterScanId: "after" }],
          };
        }
        if (args[0] === "get-scan-matching-inputs") {
          const scanId = args[2]!;
          return {
            scanId,
            findings: scanId === "before" ? [{ occurrenceId: "before" }] : [],
            nextOffset: null,
            totalFindings: scanId === "before" ? 1 : 0,
          };
        }
        return {};
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
    const save = calls.find(([command]) => command === "save-scan-comparison")!;
    expect(JSON.parse(save[6]!)).toEqual({ matches: [], uncertain: [] });
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
            if (args[0] === "list-unmatched-scan-pairs") {
              return {
                repository: "/repo",
                scanCount: 2,
                unavailableScans: 0,
                skippedPairs: 0,
                nextOffset: null,
                pairs: [{ beforeScanId: "before", afterScanId: "after" }],
              };
            }
            const scanId = args[2]!;
            return {
              scanId,
              findings:
                scanId === "before"
                  ? [
                      { occurrenceId: "confirmed" },
                      { occurrenceId: "uncertain" },
                    ]
                  : [{ occurrenceId: "after" }],
              nextOffset: null,
              totalFindings: scanId === "before" ? 2 : 1,
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
    expect(calls.some(([command]) => command === "save-scan-comparison")).toBe(
      false,
    );
  });

  test("force recomputes saved matches", async () => {
    const calls: Array<readonly string[]> = [];
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
                  matchingInputs: { before: [], after: [] },
                }
              : {};
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

  test("reruns canonical recipes with exact config, policy, plugin, and lineage", async () => {
    let config: CodexSecurityConfig | undefined;
    let repository: string | undefined;
    let options: Record<string, unknown> | undefined;
    const savedConfig = {
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

  test("redacts workbench failures and does not initialize Codex", async () => {
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
    expect(stderr.text()).toContain(REDACTED_CREDENTIALS);
    expect(stderr.text()).not.toContain("SYNTHETIC_KEY_123");
    expect(started).toBe(false);
  });
});
