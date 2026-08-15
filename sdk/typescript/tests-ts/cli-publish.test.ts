import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

const DESTINATION_OPTIONS = [
  "--to",
  "linear",
  "--linear-team",
  "team-from-flags",
  "--project",
  "project-from-flags",
] as const;
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function publicationDirectory(): Promise<string> {
  const directory = await mkdtemp(
    join(tmpdir(), "codex-security-cli-publication-"),
  );
  temporaryDirectories.push(directory);
  return directory;
}

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
        signal: expect.any(AbortSignal),
      },
    });
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
  });

  test("publishes directly to a Linear team when no project is selected", async () => {
    const stdout = capture();
    const stderr = capture();
    const result = {
      ...publicationResult(),
      destination: { type: "linear" as const, teamId: "team-from-flags" },
    };
    let options: Record<string, unknown> | undefined;
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, selected) => {
      options = { ...selected };
      return result;
    };

    expect(
      await main(
        [
          "publish",
          "scan",
          "completed-scan",
          "--to",
          "linear",
          "--linear-team",
          "team-from-flags",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(options).toMatchObject({
      destination: "linear",
      teamId: "team-from-flags",
      dryRun: false,
      signal: expect.any(AbortSignal),
    });
    expect(options).not.toHaveProperty("projectId");
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(JSON.parse(stdout.text()).destination).not.toHaveProperty(
      "projectId",
    );
    expect(stderr.text()).toBe("");
  });

  test("waits for interrupted publication recovery before honoring either terminal signal", async () => {
    for (const [signal, expectedCode, expectedMessage] of [
      ["SIGINT", 130, "Publication canceled by Ctrl-C."],
      ["SIGTERM", 143, "Publication terminated by SIGTERM."],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const signals = new FakeSignals();
      const events: string[] = [];
      let enteredPublication!: () => void;
      const publicationStarted = new Promise<void>((resolve) => {
        enteredPublication = resolve;
      });
      let finishRecovery!: () => void;
      const recoveryFinished = new Promise<void>((resolve) => {
        finishRecovery = resolve;
      });
      const deps = dependencies({ signals });
      deps.forceExit = (forced) => events.push(`forced ${forced}`);
      deps.publishScan = async (_scanDirectory, options) => {
        expect(options.signal).toBeInstanceOf(AbortSignal);
        options.signal?.addEventListener("abort", () => {
          events.push(`aborted ${String(options.signal?.reason)}`);
        });
        signals.emit(signal);
        expect(events).toEqual([`aborted ${signal}`]);
        enteredPublication();
        await recoveryFinished;
        events.push("recovered created issues");
        throw new Error(
          "The publication handoff remains at /tmp/synthetic-handoff; recover it before retrying to avoid creating duplicate issues.",
        );
      };

      let finished = false;
      const publishing = main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ).then((status) => {
        finished = true;
        return status;
      });
      await publicationStarted;
      expect(finished).toBe(false);
      expect(signals.listeners.get("SIGINT")?.size).toBe(1);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(1);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe("");
      finishRecovery();

      expect(await publishing).toBe(expectedCode);

      expect(events).toEqual([`aborted ${signal}`, "recovered created issues"]);
      expect(stderr.text()).toContain(expectedMessage);
      expect(stderr.text()).toContain("recover it before retrying");
      expect(stdout.text()).toBe("");
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });

  test("interactively selects a completed scan across all repositories", async () => {
    const directory = await publicationDirectory();
    const firstDirectory = join(directory, "first-completed-scan");
    const selectedDirectory = join(directory, "selected-completed-scan");
    await Promise.all([mkdir(firstDirectory), mkdir(selectedDirectory)]);
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
              scanId: "first-scan",
              scanDir: firstDirectory,
              targetPath: join(tmpdir(), "first-repository"),
              startedAt: "2026-08-15T01:00:00Z",
              completedAt: "2026-08-15T01:05:00Z",
              updatedAt: "2026-08-15T01:05:00Z",
              findingCount: 1,
              progress: { status: "complete" },
            },
            {
              scanId: "second-scan",
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
    expect(choices[0]!.label).toContain("first-repository");
    expect(choices[0]!.label).toContain("first-scan");
    expect(choices[0]!.label).toContain("2026-08-15T01:05:00Z");
    expect(choices[0]!.label).toContain("1 finding");
    expect(choices[1]!.label).toContain("second-repository");
    expect(choices[1]!.label).toContain("second-scan");
    expect(choices[1]!.label).toContain("2026-08-15T02:15:00Z");
    expect(choices[1]!.label).toContain("3 findings");
    expect(choices[1]!.label).toContain("COMPLETE");
    expect(publishedDirectory).toBe(selectedDirectory);
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
  });

  test("omits deleted, replaced, and linked scan directories without changing valid scan order", async () => {
    const directory = await publicationDirectory();
    const firstDirectory = join(directory, "first-completed-scan");
    const selectedDirectory = join(directory, "selected-completed-scan");
    const deletedDirectory = join(directory, "deleted-scan");
    const replacedDirectory = join(directory, "replaced-scan");
    const linkedDirectory = join(directory, "linked-scan");
    await Promise.all([
      mkdir(firstDirectory),
      mkdir(selectedDirectory),
      mkdir(deletedDirectory),
      mkdir(replacedDirectory),
    ]);
    await Promise.all([
      rm(deletedDirectory, { recursive: true }),
      rm(replacedDirectory, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(replacedDirectory, "This completed scan was replaced."),
      symlink(firstDirectory, linkedDirectory, "junction"),
    ]);

    const saved = [
      { id: "first-scan", directory: firstDirectory },
      { id: "deleted-scan", directory: deletedDirectory },
      { id: "replaced-scan", directory: replacedDirectory },
      { id: "linked-scan", directory: linkedDirectory },
      { id: "selected-scan", directory: "selected-completed-scan" },
    ];
    const stdout = capture();
    const stderr = capture(true);
    let offered: readonly { label: string; value: string }[] = [];
    let publishedDirectory: string | undefined;
    const deps = dependencies({
      currentDirectory: directory,
      onWorkbench: () => ({
        scans: saved.map(({ id, directory: scanDirectory }) => ({
          scanId: id,
          scanDir: scanDirectory,
          targetSummary: id,
          completedAt: "2030-01-01T00:00:00Z",
          findingCount: 1,
          progress: { status: "complete" },
        })),
      }),
    });
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async <Value extends string>(
        _message: string,
        choices: readonly { label: string; value: Value }[],
      ): Promise<Value> => {
        offered = choices;
        return choices[1]!.value;
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
    expect(offered.map(({ value }) => value)).toEqual([
      firstDirectory,
      "selected-completed-scan",
    ]);
    expect(offered.map(({ label }) => label)).toEqual([
      expect.stringContaining("first-scan"),
      expect.stringContaining("selected-scan"),
    ]);
    expect(publishedDirectory).toBe(selectedDirectory);
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
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

  test("does not offer completed history when every scan directory is unavailable", async () => {
    const directory = await publicationDirectory();
    const replacedDirectory = join(directory, "replaced-scan");
    const validDirectory = join(directory, "unlisted-valid-scan");
    const linkedDirectory = join(directory, "linked-scan");
    await Promise.all([
      mkdir(validDirectory),
      writeFile(replacedDirectory, "This completed scan was replaced."),
    ]);
    await symlink(validDirectory, linkedDirectory, "junction");

    const stdout = capture();
    const stderr = capture(true);
    let prompted = false;
    let published = false;
    const deps = dependencies({
      onWorkbench: () => ({
        scans: [
          join(directory, "deleted-scan"),
          replacedDirectory,
          linkedDirectory,
        ].map((scanDirectory, index) => ({
          scanId: `unavailable-scan-${index}`,
          scanDir: scanDirectory,
          progress: { status: "complete" },
        })),
      }),
    });
    deps.publishPrompt = {
      isInteractive: () => true,
      select: async <Value extends string>(
        _message: string,
        choices: readonly { value: Value }[],
      ): Promise<Value> => {
        prompted = true;
        return choices[0]!.value;
      },
    };
    deps.publishScan = async () => {
      published = true;
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", ...DESTINATION_OPTIONS, "--json"],
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

  test("requires an explicit supported destination and team with valid optional flags", async () => {
    const cases: ReadonlyArray<[readonly string[], string]> = [
      [["publish", "scan", "completed-scan"], "to"],
      [["publish", "scan", "completed-scan", "--to", "azure"], "linear"],
      [
        ["publish", "scan", "completed-scan", "--to", "linear"],
        "--linear-team or CODEX_SECURITY_LINEAR_TEAM is required.",
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
          "   ",
        ],
        "--project must not be empty.",
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
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
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
    expect(signals.listeners.size).toBe(0);
  });

  test("surfaces receipt warnings without changing published issues or JSON output", async () => {
    const warning =
      "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.";
    const result = { ...publicationResult(), warnings: [warning] };
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async () => result;

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toBe(`codex-security: ${warning}\n`);
  });

  test("surfaces receipt warnings for default human-readable publication output", async () => {
    const warning =
      "Could not save the publication receipt: Disk is unavailable. Linear issues were already created; do not retry publication.";
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async () => ({
      ...publicationResult(),
      warnings: [warning],
    });

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("SEC-123");
    expect(stderr.text()).toBe(`codex-security: ${warning}\n`);
  });

  test("sanitizes receipt warnings while preserving partial publication results", async () => {
    const warnings = [
      "Receipt storage failed.\n\u001B[31mDo not retry publication.",
      "Receipt storage failed: sk-proj-SYNTHETIC_RECEIPT_SECRET",
    ];
    const result = {
      ...publicationResult([
        { findingId: "finding-2", error: "Linear issue creation failed." },
      ]),
      warnings,
    };
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async () => result;

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toBe(
      "codex-security: Receipt storage failed.  [31mDo not retry publication.\n" +
        "codex-security: [redacted]\n",
    );
    expect(stderr.text()).not.toContain("\u001B");
    expect(stderr.text()).not.toContain("SYNTHETIC_RECEIPT_SECRET");
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
