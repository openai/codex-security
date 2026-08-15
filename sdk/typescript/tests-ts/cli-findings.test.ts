import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

describe("CLI findings history", () => {
  test("lists active findings for the current repository by default", async () => {
    const repository = resolve("/current/repository");
    for (const command of [
      ["findings"],
      ["findings", "list"],
      ["findings", "list", repository],
    ]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      const deps = dependencies({
        onWorkbench: (args): JsonObject => {
          calls.push(args);
          return {
            findings: [
              { occurrenceId: "occ-1", title: "Missing authorization" },
            ],
            limit: 20,
            nextOffset: null,
            offset: 0,
          };
        },
      });
      deps.createSecurity = () => {
        throw new Error("saved findings must not initialize Codex");
      };

      expect(
        await main(
          [...command, "--json"],
          stdout.stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toEqual([
        [
          "list-global-findings",
          "--repository",
          repository,
          "--status",
          "open",
          "--offset",
          "0",
          "--limit",
          "20",
        ],
      ]);
      expect(JSON.parse(stdout.text())).toMatchObject({
        findings: [{ occurrenceId: "occ-1" }],
      });
    }
  });

  test("lets the workbench scope findings from a checkout subdirectory", async () => {
    const repository = resolve("/current/repository/src");
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        return { findings: [{ occurrenceId: "nested-finding" }] };
      },
    });
    deps.currentDirectory = () => repository;

    expect(
      await main(
        ["findings", "list", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-global-findings",
        "--repository",
        repository,
        "--status",
        "open",
        "--offset",
        "0",
        "--limit",
        "20",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      findings: [{ occurrenceId: "nested-finding" }],
    });
  });

  test("preserves pagination for machine-readable current-repository findings", async () => {
    const repository = resolve("/current/repository");
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    const page = {
      findings: [{ occurrenceId: "first-finding" }],
      limit: 20,
      nextOffset: 20,
      offset: 0,
    };

    expect(
      await main(
        ["findings", "list", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return calls.length === 1
              ? page
              : { ...page, findings: [], nextOffset: null, offset: 20 };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-global-findings",
        "--repository",
        repository,
        "--status",
        "open",
        "--offset",
        "0",
        "--limit",
        "20",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toEqual(page);
  });

  test("defaults all-repository finding lists to open without overriding explicit status", async () => {
    for (const [arguments_, expectedStatus] of [
      [[], "open"],
      [["--status", "closed"], "closed"],
    ] as const) {
      const calls: Array<readonly string[]> = [];
      expect(
        await main(
          ["findings", "list", "--all-repositories", ...arguments_],
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: (args) => {
              calls.push(args);
              return { findings: [], limit: 20, nextOffset: null, offset: 0 };
            },
          }),
        ),
      ).toBe(0);
      expect(calls[0]).toContain("--status");
      expect(calls[0]).toContain(expectedStatus);
    }
  });

  test("preserves the current checkout when opening a relocated finding", async () => {
    const stdout = capture();
    const deps = dependencies({
      onWorkbench: (): JsonObject => ({
        scan: {
          scanId: "historical-scan",
          targetPath: "/previous/checkout",
          currentTargetPath: "/current/repository",
          findings: [{ occurrenceId: "historical-occurrence" }],
        },
      }),
    });

    expect(
      await main(
        ["findings", "show", "historical-occurrence", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      targetPath: "/previous/checkout",
      currentTargetPath: "/current/repository",
    });
  });

  test("lists findings across repositories without a target filter", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        [
          "findings",
          "list",
          "--all-repositories",
          "--severity",
          "critical",
          "--status",
          "open",
          "--limit",
          "5",
        ],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return { findings: [], limit: 5, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-global-findings",
        "--severity",
        "critical",
        "--status",
        "open",
        "--offset",
        "0",
        "--limit",
        "5",
      ],
    ]);
  });

  test("paginates and filters findings from a selected historical scan", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        [
          "findings",
          "list",
          "--scan",
          "31107fbe",
          "--query",
          "login injection",
          "--severity",
          "high",
          "--status",
          "open",
          "--offset",
          "20",
          "--limit",
          "5",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return {
              findingsPage: {
                findings: [{ occurrenceId: "occ-25", title: "Historic SQLi" }],
                limit: 5,
                nextOffset: null,
                offset: 20,
                scanId: "31107fbe-full",
                total: 21,
              },
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-findings",
        "--scan-id",
        "31107fbe",
        "--query",
        "login injection",
        "--severity",
        "high",
        "--status",
        "open",
        "--offset",
        "20",
        "--limit",
        "5",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      findings: [{ occurrenceId: "occ-25", title: "Historic SQLi" }],
      limit: 5,
      nextOffset: null,
      offset: 20,
      scanId: "31107fbe-full",
      total: 21,
    });
  });

  test("rejects repository arguments with conflicting findings scopes", async () => {
    for (const [arguments_, conflictingOption] of [
      [
        [resolve("/requested/repository"), "--scan", "other-repository-scan"],
        "--scan",
      ],
      [
        ["--scan", "other-repository-scan", resolve("/requested/repository")],
        "--scan",
      ],
      [[".", "--scan=other-repository-scan"], "--scan"],
      [
        [resolve("/requested/repository"), "--all-repositories"],
        "--all-repositories",
      ],
      [
        ["--all-repositories", resolve("/requested/repository")],
        "--all-repositories",
      ],
      [[".", "--all-repositories"], "--all-repositories"],
    ] as const) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      const stderr = capture();

      expect(
        await main(
          ["findings", "list", ...arguments_, "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({
            onWorkbench: (args) => {
              calls.push(args);
              return {
                findingsPage: {
                  findings: [{ occurrenceId: "other-repository-occurrence" }],
                },
              };
            },
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(
        `${conflictingOption} cannot be combined with a repository argument.`,
      );
      expect(stdout.text()).toBe("");
      expect(calls).toEqual([]);
    }
  });

  test("shows a historical occurrence without exposing unrelated findings", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    const selected: JsonObject = {
      occurrenceId: "occ-25",
      severity: { level: "high" },
      title: "Historic SQL injection",
      matches: [{ scanId: "previous-scan", title: "Previous injection" }],
      remediationTests: ["Reject interpolated account identifiers."],
      preventiveControls: ["Require parameterized query helpers."],
    };
    expect(
      await main(
        ["findings", "show", "occ-25", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return {
              scan: {
                scanId: "31107fbe-full",
                scanDir: "/private/results/31107fbe-full",
                targetPath: "/current/repository",
                findings: [
                  { occurrenceId: "occ-other", title: "Unrelated finding" },
                  selected,
                ],
              },
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([["get-finding", "--occurrence-id", "occ-25"]]);
    expect(JSON.parse(stdout.text())).toEqual({
      ...selected,
      scanDir: "/private/results/31107fbe-full",
      scanId: "31107fbe-full",
      targetPath: "/current/repository",
    });
    expect(stdout.text()).not.toContain("Unrelated finding");
  });

  test("shows the latest completed scan without requiring its identifier", async () => {
    for (const command of [
      ["scans", "show"],
      ["scans", "show", "latest"],
    ]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      expect(
        await main(
          [...command, "--json"],
          stdout.stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              return args[0] === "list-scans"
                ? {
                    scans: [
                      {
                        scanId: "running",
                        targetPath: "/current/repository",
                        progress: { status: "running" },
                      },
                      {
                        scanId: "latest",
                        targetPath: "/current/repository",
                        progress: { status: "complete" },
                        completedAt: "2025-12-01T00:00:00Z",
                      },
                      {
                        scanId: "older",
                        targetPath: "/current/repository",
                        progress: { status: "complete" },
                        completedAt: "2026-01-01T00:00:00Z",
                      },
                    ],
                  }
                : { scan: { scanId: "latest", findings: [] } };
            },
          }),
        ),
      ).toBe(0);
      expect(calls).toEqual([
        ["list-scans", "--repository", "/current/repository"],
        ["get-scan", "--scan-id", "latest"],
      ]);
      expect(JSON.parse(stdout.text())).toEqual({
        scanId: "latest",
        findings: [],
      });
    }
  });

  test("explains when no completed scan is available", async () => {
    const stderr = capture();
    expect(
      await main(
        ["scans", "show"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: () => ({
            scans: [{ scanId: "running", progress: { status: "running" } }],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("No completed scans found");
    expect(stderr.text()).toContain("codex-security scan .");
  });

  test("rejects invalid filters before querying saved findings", async () => {
    const invalid = [
      ["findings", "list", "--scan", "scan-1", "--all-repositories"],
      ["findings", "list", "--limit", "0"],
      ["findings", "list", "--limit", "21"],
      ["findings", "list", "--offset", "-1"],
      ["findings", "list", "--severity", "urgent"],
      ["findings", "list", "--scan"],
      ["findings", "list", "first", "second"],
    ];
    for (const command of invalid) {
      let called = false;
      expect(
        await main(
          command,
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: () => {
              called = true;
              return {};
            },
          }),
        ),
      ).toBe(2);
      expect(called).toBe(false);
    }
  });
});
