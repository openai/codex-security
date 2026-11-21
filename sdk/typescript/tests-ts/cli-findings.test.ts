import { homedir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  mustNotInitializeCodex,
} from "./cli-fixtures.js";

async function runHistory(
  args: string[],
  response: JsonObject | ((args: readonly string[]) => JsonObject),
  options: { interactive?: boolean; directory?: string } = {},
) {
  const calls: (readonly string[])[] = [];
  const deps = dependencies({
    onWorkbench: (command) => {
      calls.push(command);
      return typeof response === "function" ? response(command) : response;
    },
  });
  const { directory, interactive } = options;
  if (directory !== undefined) deps.currentDirectory = () => directory;
  deps.createSecurity = mustNotInitializeCodex;
  const stdout = capture(interactive);
  const stderr = capture();
  const code = await main(args, stdout.stream, stderr.stream, deps);
  expect(code, stderr.text()).toBe(0);
  return { calls, stdout };
}

const repositoryQuery = (repository: string) => [
  "list-global-findings",
  "--repository",
  repository,
  "--status",
  "open",
  "--offset",
  "0",
  "--limit",
  "20",
];

describe("CLI findings history", () => {
  test("expands a home-relative repository before querying saved findings", async () => {
    const { calls } = await runHistory(
      ["findings", "list", "~/repository", "--json"],
      { findings: [] },
    );
    expect(calls[0]).toContain(resolve(homedir(), "repository"));
  });

  test.each([
    { scope: [] },
    { scope: ["--all-repositories"] },
    { scope: ["--scan", "saved-scan"] },
  ])("accepts larger finding pages for scope %j", async ({ scope }) => {
    const { calls } = await runHistory(
      ["findings", "list", ...scope, "--limit", "100", "--json"],
      { findings: [], findingsPage: { findings: [] } },
    );
    expect(calls[0]?.slice(-2)).toEqual(["--limit", "100"]);
  });

  test("lists active findings for the current repository by default", async () => {
    const repository = resolve("/current/repository");
    for (const command of [
      ["findings"],
      ["findings", "list"],
      ["findings", "list", repository],
    ]) {
      const { calls, stdout } = await runHistory([...command, "--json"], {
        findings: [{ occurrenceId: "occ-1", title: "Missing authorization" }],
        limit: 20,
        nextOffset: null,
        offset: 0,
      });
      expect(calls).toEqual([repositoryQuery(repository)]);
      expect(JSON.parse(stdout.text())).toMatchObject({
        findings: [{ occurrenceId: "occ-1" }],
      });
    }
  });

  test("lets the workbench scope findings from a checkout subdirectory", async () => {
    const repository = resolve("/current/repository/src");
    const { calls, stdout } = await runHistory(
      ["findings", "list", "--json"],
      { findings: [{ occurrenceId: "nested-finding" }] },
      { directory: repository },
    );
    expect(calls).toEqual([repositoryQuery(repository)]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      findings: [{ occurrenceId: "nested-finding" }],
    });
  });

  test("preserves pagination for machine-readable current-repository findings", async () => {
    const repository = resolve("/current/repository");
    const page = {
      findings: [{ occurrenceId: "first-finding" }],
      limit: 20,
      nextOffset: 20,
      offset: 0,
    };
    const { calls, stdout } = await runHistory(
      ["findings", "list", "--json"],
      (args) =>
        args[args.indexOf("--offset") + 1] === "20"
          ? { ...page, findings: [], nextOffset: null, offset: 20 }
          : page,
    );
    expect(calls).toEqual([repositoryQuery(repository)]);
    expect(JSON.parse(stdout.text())).toEqual({ ...page, repository });
  });

  test.each([
    { scope: [], status: "open" },
    { scope: ["--scan", "saved-scan"], status: "all" },
  ])("shows the effective filters for scope %j", async ({ scope, status }) => {
    const page = { findings: [], limit: 20, nextOffset: null, offset: 0 };
    const { calls, stdout } = await runHistory(
      [
        "findings",
        "list",
        ...scope,
        "--query",
        "authorization",
        "--severity",
        "high",
      ],
      scope.length === 0 ? page : { findingsPage: page },
      { interactive: true },
    );
    expect(calls).toHaveLength(1);
    expect(stdout.text()).toContain(`Status: ${status}`);
    expect(stdout.text()).toContain("Severity: high");
    expect(stdout.text()).toContain('Search: "authorization"');
  });

  test("defaults all-repository finding lists to open without overriding explicit status", async () => {
    for (const [arguments_, expectedStatus] of [
      [[], "open"],
      [["--status", "closed"], "closed"],
    ] as const) {
      const { calls } = await runHistory(
        ["findings", "list", "--all-repositories", ...arguments_],
        { findings: [], limit: 20, nextOffset: null, offset: 0 },
      );
      expect(calls[0]).toContain("--status");
      expect(calls[0]).toContain(expectedStatus);
    }
  });

  test.each([
    { scope: [], includeResolved: true },
    { scope: ["--all-repositories"], includeResolved: true },
    { scope: ["--scan", "saved-scan"], includeResolved: false },
  ])(
    "includes resolved findings in closed history for scope %j",
    async ({ scope, includeResolved }) => {
      const finding = { occurrenceId: "resolved-finding", status: "closed" };
      const { calls, stdout } = await runHistory(
        ["findings", "list", ...scope, "--status", "closed", "--json"],
        (args) => ({
          findings:
            args[0] === "list-findings" || args.includes("--include-resolved")
              ? [finding]
              : [],
        }),
      );
      expect(JSON.parse(stdout.text())).toEqual({
        ...(scope.length === 0
          ? { repository: resolve("/current/repository") }
          : {}),
        findings: [finding],
      });
      expect(calls).toHaveLength(1);
      expect(calls[0]?.includes("--include-resolved")).toBe(includeResolved);
    },
  );

  test("preserves the current checkout when opening a relocated finding", async () => {
    const { stdout } = await runHistory(
      ["findings", "show", "historical-occurrence", "--json"],
      {
        scan: {
          scanId: "historical-scan",
          targetPath: "/previous/checkout",
          currentTargetPath: "/current/repository",
          findings: [{ occurrenceId: "historical-occurrence" }],
        },
      },
    );
    expect(JSON.parse(stdout.text())).toMatchObject({
      targetPath: "/previous/checkout",
      currentTargetPath: "/current/repository",
    });
  });

  test("lists findings across repositories without a target filter", async () => {
    const { calls } = await runHistory(
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
      { findings: [], limit: 5, nextOffset: null, offset: 0 },
    );
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
    const page = {
      findings: [{ occurrenceId: "occ-25", title: "Historic SQLi" }],
      limit: 5,
      nextOffset: null,
      offset: 20,
      scanId: "31107fbe-full",
      total: 21,
    };
    const { calls, stdout } = await runHistory(
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
      { findingsPage: page },
    );
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
    expect(JSON.parse(stdout.text())).toEqual(page);
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
    const selected: JsonObject = {
      occurrenceId: "occ-25",
      severity: { level: "high" },
      title: "Historic SQL injection",
      matches: [{ scanId: "previous-scan", title: "Previous injection" }],
      remediationTests: ["Reject interpolated account identifiers."],
      preventiveControls: ["Require parameterized query helpers."],
    };
    const { calls, stdout } = await runHistory(
      ["findings", "show", "occ-25", "--json"],
      {
        scan: {
          scanId: "31107fbe-full",
          scanDir: "/private/results/31107fbe-full",
          targetPath: "/current/repository",
          findings: [
            { occurrenceId: "occ-other", title: "Unrelated finding" },
            selected,
          ],
        },
      },
    );
    expect(calls).toEqual([["get-finding", "--occurrence-id", "occ-25"]]);
    expect(JSON.parse(stdout.text())).toEqual({
      ...selected,
      scanDir: "/private/results/31107fbe-full",
      scanId: "31107fbe-full",
      targetPath: "/current/repository",
    });
    expect(stdout.text()).not.toContain("Unrelated finding");
  });

  test.each(["path", "locationPath"])(
    "shows canonical finding locations instead of an extra %s field",
    async (field) => {
      const selected: JsonObject = {
        occurrenceId: "saved-occurrence",
        severity: { level: "high" },
        title: "Missing authorization",
        locations: [
          { path: "src/handler.ts", startLine: 34, role: "root_control" },
        ],
        [field]: "unrelated/extra-field.ts",
      };
      const scan = {
        scanId: "saved-scan",
        scanDir: "/results/saved-scan",
        targetPath: "/current/repository",
      };
      const calls: Array<readonly string[]> = [];
      const deps = dependencies({
        onWorkbench: (args) => {
          calls.push(args);
          return { scan: { ...scan, findings: [selected] } };
        },
      });
      for (const json of [false, true]) {
        const stdout = capture(!json);
        const stderr = capture();
        expect(
          await main(
            [
              "findings",
              "show",
              "saved-occurrence",
              ...(json ? ["--json"] : []),
            ],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(0);
        expect(stderr.text()).toBe("");
        if (json) {
          expect(JSON.parse(stdout.text())).toEqual({ ...selected, ...scan });
        } else {
          expect(stdout.text()).toContain("src/handler.ts:34");
          expect(stdout.text()).not.toContain("unrelated/extra-field.ts");
        }
      }
      expect(calls).toEqual([
        ["get-finding", "--occurrence-id", "saved-occurrence"],
        ["get-finding", "--occurrence-id", "saved-occurrence"],
      ]);
    },
  );

  test("resolves the literal latest scan identifier", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["scans", "show", "latest", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "latest",
                      targetPath: "/current/repository",
                      progress: { status: "complete" },
                      completedAt: "2025-12-01T00:00:00Z",
                    },
                  ],
                }
              : { scan: { scanId: "latest", findings: [] } };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      [
        "list-scans",
        "--repository",
        "/current/repository",
        "--prefer-worktree",
        "--status",
        "complete",
        "--limit",
        "1",
      ],
      ["get-scan", "--scan-id", "latest"],
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      scanId: "latest",
      findings: [],
    });
  });

  test("explains when no completed scan is available", async () => {
    const stderr = capture();
    expect(
      await main(
        ["scans", "show"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: () => ({ scans: [] }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("No completed scans found");
  });

  test("rejects invalid filters before querying saved findings", async () => {
    const invalid = [
      ["findings", "list", "--scan", "scan-1", "--all-repositories"],
      ["findings", "list", "--limit", "0"],
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
