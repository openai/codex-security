import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

const DESTINATION_OPTIONS = [
  "--to",
  "linear",
  "--linear-team",
  "team-from-flags",
  "--project",
  "project-from-flags",
] as const;

function publicationResult(
  failed: { findingId: string; error: string }[] = [],
) {
  const created = [
    {
      findingId: "finding-1",
      occurrenceId: "occurrence-1",
      issueIdentifier: "SEC-123",
      url: "https://linear.app/example/issue/SEC-123",
    },
  ];
  return {
    scanId: "scan-123",
    uploadId: "scan-123",
    destination: {
      type: "linear" as const,
      teamId: "team-from-flags",
      projectId: "project-from-flags",
    },
    created,
    failed,
    counts: {
      findings: created.length + failed.length,
      created: created.length,
      failed: failed.length,
    },
  };
}

describe("publish scan", () => {
  test("publishes an explicit scan directory without inspecting scan history", async () => {
    const currentDirectory = join(tmpdir(), "codex-security-publish-current");
    const stdout = capture();
    const stderr = capture();
    let invocation:
      | { scanDirectory: string; options: Record<string, unknown> }
      | undefined;
    const deps = dependencies({
      currentDirectory,
      onWorkbench: () => {
        throw new Error("scan history must not be inspected");
      },
    });
    deps.createSecurity = () => {
      throw new Error("a new security scan must not be started");
    };
    deps.publishScan = async (scanDirectory, options) => {
      invocation = { scanDirectory, options: { ...options } };
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(invocation).toEqual({
      scanDirectory: resolve(currentDirectory, "completed-scan"),
      options: {
        destination: "linear",
        teamId: "team-from-flags",
        projectId: "project-from-flags",
        dryRun: false,
      },
    });
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
  });

  test("interactively selects a completed scan across all repositories", async () => {
    const firstDirectory = join(tmpdir(), "first-completed-scan");
    const selectedDirectory = join(tmpdir(), "selected-completed-scan");
    const stdout = capture();
    const stderr = capture(true);
    let question = "";
    let choices: readonly { label: string; value: string }[] = [];
    let workbenchArguments: readonly string[] | undefined;
    let publishedDirectory: string | undefined;
    const deps = dependencies({
      onWorkbench: (args) => {
        workbenchArguments = args;
        return {
          scans: [
            {
              scanId: "11111111-2222-3333-4444-555555abc123",
              scanDir: firstDirectory,
              targetPath: join(tmpdir(), "first-repository"),
              startedAt: "2026-08-15T01:00:00Z",
              completedAt: "2026-08-15T01:05:00Z",
              updatedAt: "2026-08-15T01:05:00Z",
              findingCount: 1,
              progress: { status: "complete" },
            },
            {
              scanId: "66666666-7777-8888-9999-000000def456",
              scanDir: selectedDirectory,
              targetPath: join(tmpdir(), "second-repository"),
              startedAt: null,
              completedAt: null,
              updatedAt: "2026-08-15T02:15:00Z",
              findingCount: 3,
              progress: { status: "complete" },
            },
            {
              scanId: "running-scan",
              scanDir: join(tmpdir(), "running-scan"),
              targetPath: join(tmpdir(), "running-repository"),
              startedAt: "2026-08-15T03:00:00Z",
              completedAt: null,
              updatedAt: "2026-08-15T03:01:00Z",
              findingCount: 0,
              progress: { status: "running" },
            },
          ],
        };
      },
    });
    deps.now = () => Date.parse("2026-08-15T02:17:00Z");
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async <Value extends string>(
        message: string,
        options: readonly { label: string; value: Value }[],
      ): Promise<Value> => {
        question = message;
        choices = options;
        return options[1]!.value;
      },
    };
    deps.publishScan = async (scanDirectory) => {
      publishedDirectory = scanDirectory;
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(workbenchArguments).toEqual(["list-scans", "--status", "complete"]);
    expect(question).toBe("Which completed scan would you like to publish?");
    expect(choices).toHaveLength(2);
    expect(choices[0]!.label).toStartWith(
      "\u001B[1mfirst-repository\u001B[22m",
    );
    expect(choices[0]!.label).toContain("...abc123");
    expect(choices[0]!.label).toContain("ran 1 hour ago");
    expect(choices[0]!.label).toContain("1 finding");
    expect(choices[1]!.label).toStartWith(
      "\u001B[1msecond-repository\u001B[22m",
    );
    expect(choices[1]!.label).toContain("...def456");
    expect(choices[1]!.label).toContain("ran 2 minutes ago");
    expect(choices[1]!.label).toContain("3 findings");
    expect(choices[0]!.label).not.toContain("11111111-2222-3333");
    expect(choices[1]!.label).not.toContain("2026-08-15T02:15:00Z");
    expect(choices[1]!.label).not.toContain("COMPLETE");
    expect(choices.every((choice) => !choice.label.includes("\n"))).toBe(true);
    expect(publishedDirectory).toBe(selectedDirectory);
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
  });

  test("formats scan choices as compact single lines with relative ages", async () => {
    const currentTime = Date.parse("2026-08-15T12:00:00Z");
    const scenarios = [
      { age: 0, expected: "ran just now" },
      { age: 30_000, expected: "ran 30 seconds ago" },
      { age: 60_000, expected: "ran 1 minute ago" },
      { age: 2 * 60_000, expected: "ran 2 minutes ago" },
      { age: 60 * 60_000, expected: "ran 1 hour ago" },
      { age: 4 * 24 * 60 * 60_000, expected: "ran 4 days ago" },
      { age: 8 * 24 * 60 * 60_000, expected: "ran 1 week ago" },
      { age: 32 * 24 * 60 * 60_000, expected: "ran 1 month ago" },
      { age: 366 * 24 * 60 * 60_000, expected: "ran 1 year ago" },
      { age: -30_000, expected: "ran just now" },
    ] as const;
    let choices: readonly { label: string; value: string }[] = [];
    const deps = dependencies({
      environment: { NO_COLOR: "1" },
      onWorkbench: () => ({
        scans: [
          ...scenarios.map(({ age }, index) => ({
            scanId: `scan-${String(index).padStart(6, "0")}`,
            scanDir: join(tmpdir(), `scan-${index}`),
            targetSummary: "payments\n\t api",
            completedAt: new Date(currentTime - age).toISOString(),
            findingCount: 2,
            progress: { status: "complete" },
          })),
          {
            scanId: "scan-999999",
            scanDir: join(tmpdir(), "scan-unknown"),
            targetSummary: "payments api",
            completedAt: "not-a-timestamp",
            findingCount: 0,
            progress: { status: "complete" },
          },
        ],
      }),
    });
    deps.now = () => currentTime;
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async <Value extends string>(
        _message: string,
        options: readonly { label: string; value: Value }[],
      ): Promise<Value> => {
        choices = options;
        return options[0]!.value;
      },
    };
    deps.publishScan = async () => publicationResult();

    expect(
      await main(
        ["publish", "scan", ...DESTINATION_OPTIONS],
        capture().stream,
        capture(true).stream,
        deps,
      ),
    ).toBe(0);

    for (const [index, scenario] of scenarios.entries()) {
      expect(choices[index]!.label).toBe(
        `payments api  ·  2 findings  ·  ${scenario.expected}  ·  ...${String(index).padStart(6, "0")}`,
      );
    }
    expect(choices.at(-1)!.label).toBe(
      "payments api  ·  0 findings  ·  run time unknown  ·  ...999999",
    );
    expect(choices.every((choice) => !choice.label.includes("\n"))).toBe(true);
  });

  test("requires an interactive terminal when no scan directory is supplied", async () => {
    const stdout = capture();
    const stderr = capture();
    let listed = false;
    let published = false;
    const deps = dependencies({
      onWorkbench: () => {
        listed = true;
        return { scans: [] };
      },
    });
    deps.publishPrompt = {
      isInteractive: () => false,
      select: async <Value extends string>(
        _message: string,
        options: readonly { label: string; value: Value }[],
      ): Promise<Value> => options[0]!.value,
    };
    deps.publishScan = async () => {
      published = true;
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "Interactive scan selection requires a terminal.",
    );
    expect(stderr.text()).toContain("codex-security publish scan");
    expect(stdout.text()).toBe("");
    expect(listed).toBe(false);
    expect(published).toBe(false);
  });

  test("fails clearly when no completed scans are available", async () => {
    const stdout = capture();
    const stderr = capture(true);
    let prompted = false;
    let published = false;
    const deps = dependencies({ onWorkbench: () => ({ scans: [] }) });
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async <Value extends string>(
        _message: string,
        options: readonly { label: string; value: Value }[],
      ): Promise<Value> => {
        prompted = true;
        return options[0]!.value;
      },
    };
    deps.publishScan = async () => {
      published = true;
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "No completed Codex Security scans are available to publish.",
    );
    expect(stdout.text()).toBe("");
    expect(prompted).toBe(false);
    expect(published).toBe(false);
  });

  test("requires an explicit supported destination, team, and project", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [["publish", "scan", "completed-scan"], "to"],
      [["publish", "scan", "completed-scan", "--to", "azure"], "linear"],
      [
        ["publish", "scan", "completed-scan", "--to", "linear"],
        "--linear-team or CODEX_SECURITY_LINEAR_TEAM is required.",
      ],
      [
        [
          "publish",
          "scan",
          "completed-scan",
          "--to",
          "linear",
          "--linear-team",
          "team-id",
        ],
        "--project or CODEX_SECURITY_LINEAR_PROJECT is required.",
      ],
      [
        ["publish", "scan", "completed-scan", "--to"],
        "Missing value for flag: --to",
      ],
      [
        [
          "publish",
          "scan",
          "completed-scan",
          "--to",
          "linear",
          "--linear-team",
        ],
        "Missing value for flag: --linear-team",
      ],
      [
        [
          "publish",
          "scan",
          "completed-scan",
          "--to",
          "linear",
          "--linear-team",
          "team-id",
          "--project",
        ],
        "Missing value for flag: --project",
      ],
    ];

    for (const [argv, expected] of cases) {
      const stdout = capture();
      const stderr = capture();
      let published = false;
      const deps = dependencies();
      deps.publishScan = async () => {
        published = true;
        return publicationResult();
      };

      expect(await main(argv, stdout.stream, stderr.stream, deps)).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(stdout.text()).toBe("");
      expect(published).toBe(false);
    }
  });

  test("uses environment destination settings and gives flags precedence", async () => {
    for (const scenario of [
      {
        argv: ["publish", "scan", "completed-scan", "--to", "linear"],
        expectedTeam: "team-from-environment",
        expectedProject: "project-from-environment",
      },
      {
        argv: ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        expectedTeam: "team-from-flags",
        expectedProject: "project-from-flags",
      },
    ]) {
      const deps = dependencies({
        environment: {
          CODEX_SECURITY_LINEAR_TEAM: "  team-from-environment  ",
          CODEX_SECURITY_LINEAR_PROJECT: "  project-from-environment  ",
        },
      });
      let destination: { teamId: string; projectId: string } | undefined;
      deps.publishScan = async (_scanDirectory, options) => {
        destination = {
          teamId: options.teamId,
          projectId: options.projectId,
        };
        return publicationResult();
      };

      expect(
        await main(scenario.argv, capture().stream, capture().stream, deps),
      ).toBe(0);
      expect(destination).toEqual({
        teamId: scenario.expectedTeam,
        projectId: scenario.expectedProject,
      });
    }
  });

  test("passes dry-run mode through and preserves machine-readable output", async () => {
    const stdout = capture();
    const stderr = capture();
    let dryRun: boolean | undefined;
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      dryRun = options.dryRun;
      return { ...publicationResult(), dryRun: true, issues: [] };
    };

    expect(
      await main(
        [
          "publish",
          "scan",
          "completed-scan",
          ...DESTINATION_OPTIONS,
          "--dry-run",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(dryRun).toBe(true);
    expect(JSON.parse(stdout.text())).toMatchObject({
      scanId: "scan-123",
      uploadId: "scan-123",
      dryRun: true,
      issues: [],
    });
    expect(stderr.text()).toBe("");
  });

  test("returns a nonzero exit code while preserving partial publication results", async () => {
    const stdout = capture();
    const stderr = capture();
    const failed = [
      { findingId: "finding-2", error: "Linear issue creation failed." },
    ];
    const deps = dependencies();
    deps.publishScan = async () => publicationResult(failed);

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toEqual(publicationResult(failed));
    expect(stderr.text()).toBe("");
  });

  test("reports publisher failures without claiming a successful upload", async () => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async () => {
      throw new Error("Linear is not connected to your Codex account.");
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "Linear is not connected to your Codex account.",
    );
    expect(stdout.text()).toBe("");
  });
});
