import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { afterEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { CheckScanPublicationResult } from "../src/publish.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

const DESTINATION_OPTIONS = [
  "--to",
  "linear",
  "--linear-team",
  "team-from-flags",
  "--linear-project",
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

async function publicationScanDirectories(count: number): Promise<string[]> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-publish-picker-"));
  temporaryDirectories.push(root);
  return Promise.all(
    Array.from({ length: count }, async (_, index) => {
      const directory = join(root, `scan-${index}`);
      await mkdir(directory, { mode: 0o700 });
      return directory;
    }),
  );
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

describe("publish scan to custom", () => {
  test("uses a workflow's exact scan without changing the publication receipt", async () => {
    const [scanDir] = await publicationScanDirectories(1);
    const deps = dependencies({
      onWorkbench: (args) => {
        expect(args).toEqual(["finding-workflow"]);
        return {
          workflow: {
            id: "publication-workflow",
            scanId: "exact-scan",
            scanDir: scanDir!,
          },
        };
      },
    });
    const receipt = {
      scanId: "exact-scan",
      repositoryId: "repository",
      findingIds: ["finding"],
      findingCount: 1,
    };
    deps.publishScanToCustom = async (directory, options) => {
      expect(directory).toBe(scanDir!);
      expect(options.workflowId).toBe("publication-workflow");
      expect(options.expectedScanId).toBe("exact-scan");
      return receipt;
    };
    const stdout = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          "--workflow-id",
          "publication-workflow",
          "--to",
          "custom",
          "--findings-url",
          "http://localhost:3000",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(receipt);
  });
  test.each([false, true])(
    "publishes a selected saved scan with dry-run=%j",
    async (dryRun) => {
      const [scanDir] = await publicationScanDirectories(1);
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        onWorkbench: () => ({
          scan: {
            scanId: "scan-example",
            scanDir: scanDir!,
            progress: { status: "complete" },
          },
        }),
      });
      const receipt = {
        scanId: "scan-example",
        repositoryId: "repository-example",
        findingIds: ["finding-1"],
        findingCount: 1,
      };
      let calls = 0;
      deps.publishScanToCustom = async (directory, options) => {
        calls++;
        expect(directory).toBe(scanDir!);
        expect(options).toEqual({
          findingsUrl: "http://localhost:3000",
          dryRun,
          expectedScanId: "scan-example",
          signal: expect.any(AbortSignal),
        });
        return receipt;
      };
      expect(
        await main(
          [
            "publish",
            "scan",
            "--scan",
            "scan-example",
            "--to",
            "custom",
            "--findings-url",
            "http://localhost:3000",
            "--json",
            ...(dryRun ? ["--dry-run"] : []),
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toBe(1);
      expect(JSON.parse(stdout.text())).toEqual(receipt);
      expect(stderr.text()).toBe("");
    },
  );

  test.each([
    [["--to", "custom"], "requires --findings-url"],
    [["--to", "custom", "--findings-url", "--dry-run"], "--findings-url"],
    [["--to", "custom", "--findings-url", "not-a-url"], "URL"],
    [
      [
        "--to",
        "custom",
        "--findings-url",
        "http://localhost:3000",
        "--skip-existing",
      ],
      "cannot be combined with Linear options",
    ],
    [
      [...DESTINATION_OPTIONS, "--findings-url", "http://localhost:3000"],
      "only supported with --to custom",
    ],
  ])(
    "rejects incompatible custom publication inputs %j",
    async (flags, message) => {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.publishScanToCustom = async () => {
        throw new Error("must not publish");
      };
      expect(
        await main(
          ["publish", "scan", "completed-scan", ...flags, "--json"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(message);
      expect(stdout.text().trim()).toBe("");
    },
  );

  test("forwards cancellation for an external scan and does not report success", async () => {
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.publishScanToCustom = async (directory, options) => {
      expect(directory).toBe(resolve(deps.currentDirectory(), "external-scan"));
      expect(options.expectedScanId).toBeUndefined();
      signals.emit("SIGINT");
      options.signal!.throwIfAborted();
      throw new Error("unreachable");
    };
    expect(
      await main(
        [
          "publish",
          "scan",
          "--scan-dir",
          "external-scan",
          "--to",
          "custom",
          "--findings-url",
          "http://localhost:3000",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(130);
    expect(stderr.text()).toContain("Publication canceled");
    expect(stdout.text().trim()).toBe("");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });
});

describe("publish check", () => {
  test("resolves the shared destination options without invoking publication", async () => {
    const stdout = capture();
    const stderr = capture();
    const currentDirectory = join(tmpdir(), "codex-security-check-current");
    const result: CheckScanPublicationResult = {
      scanId: "scan-example",
      destination: {
        type: "linear",
        teamId: "team-from-flags",
        projectId: "project-from-flags",
      },
      recorded: [],
      counts: { findings: 2, recorded: 0, pending: 2 },
      access: {
        transport: "linear-api",
        authentication: "verified",
        team: "verified",
        project: "verified",
        assignee: "verified",
        issueCreation: "not-tested",
      },
    };
    const deps = dependencies({
      currentDirectory,
      environment: {
        CODEX_SECURITY_LINEAR_API_KEY: "environment-key",
        CODEX_SECURITY_LINEAR_TEAM: "environment-team",
      },
    });
    deps.publishScan = async () => {
      throw new Error("Check must not publish.");
    };
    deps.checkScanPublication = async (directory, options) => {
      expect(directory).toBe(resolve(currentDirectory, "completed-scan"));
      expect(options).toEqual({
        destination: "linear",
        teamId: "team-from-flags",
        projectId: "project-from-flags",
        linearApiKey: "explicit-key",
        assigneeId: "teammate@example.com",
        signal: expect.any(AbortSignal),
      });
      return result;
    };
    expect(
      await main(
        [
          "publish",
          "check",
          "completed-scan",
          ...DESTINATION_OPTIONS,
          "--linear-api-key",
          "explicit-key",
          "--linear-assignee",
          "teammate@example.com",
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toBe("");
    expect(stdout.text()).not.toContain("explicit-key");
    expect(stdout.text()).not.toContain("teammate@example.com");
  });

  test("reports a failed check without publishing or returning a successful result", async () => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.checkScanPublication = async () => {
      throw new Error("The selected project is unavailable.");
    };
    deps.publishScan = async () => {
      throw new Error("Check must not publish.");
    };
    expect(
      await main(
        [
          "publish",
          "check",
          "completed-scan",
          ...DESTINATION_OPTIONS,
          "--json",
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("The selected project is unavailable.");
    expect(stdout.text().trim()).toBe("");
  });

  test("waits for read-only publication cleanup on terminal signals", async () => {
    for (const command of [
      ["check"],
      ["scan", "--dry-run", "--skip-existing"],
    ]) {
      for (const [signal, expectedCode] of [
        ["SIGINT", 130],
        ["SIGTERM", 143],
      ] as const) {
        const stdout = capture();
        const stderr = capture();
        const signals = new FakeSignals();
        const deps = dependencies({
          signals,
          environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
        });
        let now = 0;
        let forced = false;
        deps.now = () => now;
        deps.forceExit = () => {
          forced = true;
        };
        let started!: () => void;
        const operationStarted = new Promise<void>((resolve) => {
          started = resolve;
        });
        let finishCleanup!: () => void;
        const cleanup = new Promise<void>((resolve) => {
          finishCleanup = resolve;
        });
        const operation = async (
          _directory: string,
          options: { signal?: AbortSignal },
        ): Promise<never> => {
          expect(options.signal).toBeInstanceOf(AbortSignal);
          started();
          await cleanup;
          expect(options.signal?.reason).toBe(signal);
          options.signal!.throwIfAborted();
          throw new Error("Expected cancellation.");
        };
        deps.publishScan = operation;
        deps.checkScanPublication = operation;
        let finished = false;
        const running = main(
          [
            "publish",
            command[0]!,
            "completed-scan",
            ...command.slice(1),
            ...DESTINATION_OPTIONS,
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ).then((status) => {
          finished = true;
          return status;
        });
        await operationStarted;
        signals.emit(signal);
        expect(finished).toBe(false);
        now = 500;
        signals.emit(signal);
        expect(forced).toBe(false);
        finishCleanup();
        expect(await running).toBe(expectedCode);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(
          signal === "SIGINT" ? "canceled by Ctrl-C" : "terminated by SIGTERM",
        );
        expect(signals.listeners.get("SIGINT")?.size).toBe(0);
        expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
      }
    }
  });
});

describe("publish scan", () => {
  test("forwards opt-in retry and reports skipped issues separately", async () => {
    for (const dryRun of [false, true]) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.publishScan = async (_directory, options) => {
        expect(options.skipExisting).toBe(true);
        expect(options.dryRun).toBe(dryRun);
        const previous = publicationResult();
        return {
          ...previous,
          created: [],
          skipped: previous.created,
          counts: { findings: 1, created: 0, failed: 0, skipped: 1 },
          ...(dryRun ? { dryRun: true, issues: [] } : {}),
        };
      };
      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            "--skip-existing",
            ...(dryRun ? ["--dry-run", "--json"] : []),
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      if (dryRun) {
        expect(JSON.parse(stdout.text()).counts).toEqual({
          findings: 1,
          created: 0,
          failed: 0,
          skipped: 1,
        });
      } else {
        expect(stdout.text()).toContain("0 total issues created");
        expect(stdout.text()).toContain("1 previously recorded issue skipped");
      }
    }
  });

  test.each([false, true])(
    "resolves a saved scan ID for Linear publication with skipExisting=%j",
    async (skipExisting) => {
      const scanDir = await publicationDirectory();
      const deps = dependencies({
        onWorkbench: (args) => {
          expect(args).toEqual(["get-scan", "--scan-id", "scan-123"]);
          return {
            scan: {
              scanId: "scan-123",
              scanDir,
              progress: { status: "complete" },
            },
          };
        },
      });
      let calls = 0;
      deps.publishScan = async (directory, options) => {
        calls++;
        expect(directory).toBe(scanDir);
        expect(options.expectedScanId).toBe("scan-123");
        expect(options.skipExisting).toBe(skipExisting ? true : undefined);
        return publicationResult();
      };
      expect(
        await main(
          [
            "publish",
            "scan",
            "--scan",
            "scan-123",
            ...DESTINATION_OPTIONS,
            ...(skipExisting ? ["--skip-existing"] : []),
            "--json",
          ],
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(calls).toBe(1);
    },
  );

  test("accepts the Linear project flag and its published alias", async () => {
    for (const flag of ["--linear-project", "--project"]) {
      let projectId: string | undefined;
      const deps = dependencies();
      deps.publishScan = async (_directory, options) => {
        projectId = options.projectId;
        return publicationResult();
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
            "team-id",
            flag,
            "selected-project",
            "--json",
          ],
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(projectId).toBe("selected-project");
    }

    const stderr = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          "completed-scan",
          ...DESTINATION_OPTIONS,
          "--project",
          "different-project",
        ],
        capture().stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "--linear-project and --project must select the same project.",
    );
  });

  test.each(["positional", "flag"])(
    "publishes an explicit %s scan directory without inspecting scan history",
    async (syntax) => {
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
          [
            "publish",
            "scan",
            ...(syntax === "flag"
              ? ["--scan-dir", "completed-scan"]
              : ["completed-scan"]),
            ...DESTINATION_OPTIONS,
            "--json",
          ],
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
          onProgress: expect.any(Function),
        },
      });
      expect(JSON.parse(stdout.text())).toEqual(publicationResult());
      expect(stderr.text()).toBe("");
    },
  );

  test("selects direct Linear publication and forwards the requested assignee", async () => {
    for (const scenario of [
      { flags: [], key: "environment-key", assignee: undefined },
      {
        flags: [
          "--linear-api-key",
          "explicit-key",
          "--linear-assignee",
          "teammate@example.test",
        ],
        key: "explicit-key",
        assignee: "teammate@example.test",
      },
      {
        flags: ["--linear-assignee", "user-123"],
        key: "environment-key",
        assignee: "user-123",
      },
    ]) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        environment: { CODEX_SECURITY_LINEAR_API_KEY: "environment-key" },
      });
      let options: Record<string, unknown> | undefined;
      deps.publishScan = async (_directory, selected) => {
        options = { ...selected };
        return publicationResult();
      };

      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            ...scenario.flags,
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(options).toMatchObject({
        linearApiKey: scenario.key,
        ...(scenario.assignee === undefined
          ? {}
          : { assigneeId: scenario.assignee }),
      });
      if (scenario.assignee === undefined) {
        expect(options).not.toHaveProperty("assigneeId");
      }
      expect(stdout.text()).not.toContain(scenario.key);
    }
  });

  test("rejects a Linear assignee without direct API authentication", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        [
          "publish",
          "scan",
          "completed-scan",
          ...DESTINATION_OPTIONS,
          "--linear-assignee",
          "teammate@example.test",
        ],
        stdout.stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "--linear-assignee requires --linear-api-key or CODEX_SECURITY_LINEAR_API_KEY.",
    );
  });

  test("preserves Linear API error details", async () => {
    const key = "lin_api_SYNTHETIC_ERROR_DETAILS";
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies({
      environment: { CODEX_SECURITY_LINEAR_API_KEY: key },
    });
    deps.publishScan = async () => {
      throw new Error(`Linear rejected ${key}.`);
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(key);
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

  test("waits for direct publication recovery until a later terminal signal", async () => {
    for (const [signal, expectedCode, expectedMessage] of [
      ["SIGINT", 130, "Publication canceled by Ctrl-C."],
      ["SIGTERM", 143, "Publication terminated by SIGTERM."],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const signals = new FakeSignals();
      const events: string[] = [];
      let now = 0;
      let enteredPublication!: () => void;
      const publicationStarted = new Promise<void>((resolve) => {
        enteredPublication = resolve;
      });
      let finishRecovery!: () => void;
      const recoveryFinished = new Promise<void>((resolve) => {
        finishRecovery = resolve;
      });
      const deps = dependencies({ signals });
      deps.environment["CODEX_SECURITY_LINEAR_API_KEY"] = "synthetic-key";
      deps.now = () => now;
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

      const publishing = main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      );
      await publicationStarted;
      expect(signals.listeners.get("SIGINT")?.size).toBe(1);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(1);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe("");
      signals.emit(signal);
      expect(events).toEqual([`aborted ${signal}`]);
      now = 500;
      signals.emit(signal);
      expect(events).toEqual([`aborted ${signal}`, `forced ${signal}`]);
      expect(stderr.text()).toContain("reconcile retained Linear");
      finishRecovery();

      expect(await publishing).toBe(expectedCode);

      expect(events.at(-1)).toBe("recovered created issues");
      expect(stderr.text()).toContain(expectedMessage);
      expect(stderr.text()).toContain("recover it before retrying");
      expect(stdout.text()).toBe("");
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });

  test("prints the first five persisted Linear issues and database-backed totals", async () => {
    const stdout = capture();
    const stderr = capture();
    const result = publicationResult();
    result.created = Array.from({ length: 7 }, (_, index) => ({
      findingId: `private-finding-${index + 1}`,
      occurrenceId: `private-occurrence-${index + 1}`,
      issueIdentifier: `SEC-${200 + index}`,
      url: `https://linear.app/example/issue/SEC-${200 + index}`,
    }));
    result.counts.findings = 999;
    result.counts.created = 999;
    result.counts.failed = 999;
    const deps = dependencies();
    deps.publishScan = async () => result;

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);

    expect(stdout.text()).toBe(
      [
        "✓ Linear publication complete",
        "",
        "  SEC-200  https://linear.app/example/issue/SEC-200",
        "  SEC-201  https://linear.app/example/issue/SEC-201",
        "  SEC-202  https://linear.app/example/issue/SEC-202",
        "  SEC-203  https://linear.app/example/issue/SEC-203",
        "  SEC-204  https://linear.app/example/issue/SEC-204",
        "  ...",
        "",
        "7 total issues created",
        "0 total issues failed",
        "",
      ].join("\n"),
    );
    for (const privateValue of [
      "scan-123",
      "uploadId",
      "team-from-flags",
      "project-from-flags",
      "private-finding-",
      "private-occurrence-",
      "SEC-205",
      "SEC-206",
      "999",
    ]) {
      expect(stdout.text()).not.toContain(privateValue);
    }
    expect(stderr.text()).toBe("");
  });

  test("reports sanitized receipt warnings after terminal restoration without contaminating publication output", async () => {
    const warning =
      "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.";
    const unsafeWarning = "Injected\u001B[31m\nsecond line\u0007";
    for (const { json, tty, failed } of [
      { json: false, tty: false, failed: false },
      { json: true, tty: false, failed: false },
      { json: true, tty: true, failed: false },
      { json: false, tty: true, failed: true },
    ]) {
      const stdout = capture();
      const stderr = capture(tty);
      const result = {
        ...publicationResult(
          failed ? [{ findingId: "finding-2", error: "Private details" }] : [],
        ),
        warnings: [warning, unsafeWarning],
      };
      const deps = dependencies();
      deps.publishScan = async () => result;

      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            ...(json ? ["--json"] : []),
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(failed ? 2 : 0);

      expect(stderr.text()).toContain(`codex-security: ${warning}\n`);
      expect(stderr.text()).toContain(
        "codex-security: Injected [31m second line \n",
      );
      expect(stderr.text()).not.toContain("\nsecond line");
      expect(stderr.text()).not.toContain("\u0007");
      if (tty) {
        expect(stderr.text().indexOf("\u001B[?25h\u001B[?1049l")).toBeLessThan(
          stderr.text().indexOf(`codex-security: ${warning}`),
        );
      }
      if (json) {
        expect(JSON.parse(stdout.text())).toEqual(result);
        expect(stdout.text()).not.toContain("\u001B");
      } else {
        expect(stdout.text()).toContain("Linear publication");
        expect(stdout.text()).not.toContain("publication receipt");
        expect(stdout.text()).not.toContain("Injected");
      }
    }
  });

  test("omits the issue-list ellipsis when zero to five issues were created", async () => {
    for (const total of [0, 1, 5]) {
      const stdout = capture();
      const stderr = capture();
      const result = publicationResult();
      result.created = Array.from({ length: total }, (_, index) => ({
        findingId: `finding-${index + 1}`,
        occurrenceId: `occurrence-${index + 1}`,
        issueIdentifier: `SEC-${300 + index}`,
        url: `https://linear.app/example/issue/SEC-${300 + index}`,
      }));
      result.counts.findings = total;
      result.counts.created = total;
      const deps = dependencies();
      deps.publishScan = async () => result;

      expect(
        await main(
          ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(stdout.text()).not.toContain("\n  ...\n");
      expect(stdout.text()).toContain(
        `${total} total issue${total === 1 ? "" : "s"} created\n`,
      );
      expect(stdout.text()).toContain("0 total issues failed\n");
      expect(
        stdout.text().match(/https:\/\/linear\.app\//gu) ?? [],
      ).toHaveLength(total);
      if (total === 0) {
        expect(stdout.text()).toBe(
          "✓ Linear publication complete\n\n0 total issues created\n0 total issues failed\n",
        );
      }
    }
  });

  test("renders partial failures without exposing finding errors or changing exit codes", async () => {
    const stdout = capture();
    const stderr = capture();
    const failures = [
      {
        findingId: "private-finding-2",
        error: "PRIVATE_CONNECTOR_FAILURE_DETAILS",
      },
    ];
    const result = publicationResult(failures);
    result.counts.created = 100;
    result.counts.failed = 200;
    const deps = dependencies();
    deps.publishScan = async () => result;

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stdout.text()).toBe(
      [
        "! Linear publication completed with failures",
        "",
        "  SEC-123  https://linear.app/example/issue/SEC-123",
        "",
        "1 total issue created",
        "1 total issue failed",
        "",
      ].join("\n"),
    );
    expect(stdout.text()).not.toContain("private-finding-2");
    expect(stdout.text()).not.toContain("PRIVATE_CONNECTOR_FAILURE_DETAILS");
    expect(stdout.text()).not.toContain("100");
    expect(stdout.text()).not.toContain("200");
    expect(stderr.text()).toBe("");
  });

  test("omits missing or unsafe issue links and sanitizes issue identifiers", async () => {
    const stdout = capture();
    const stderr = capture();
    const initial = publicationResult();
    const base = initial.created[0]!;
    const { url: _unusedUrl, ...withoutUrl } = base;
    const created = [
      {
        ...base,
        issueIdentifier: "\u001B[31mSEC-400\u001B[0m\n\u009Fsafe",
        url: "javascript:alert(1)",
      },
      {
        ...base,
        issueIdentifier: "SEC-401",
        url: "https://user:PRIVATE_PASSWORD@linear.app/example/issue/SEC-401",
      },
      {
        ...base,
        issueIdentifier: "SEC-402",
        url: "https://linear.app/example/issue/SEC-402?token=PRIVATE_TOKEN",
      },
      {
        ...base,
        issueIdentifier: "SEC-403",
        url: "https://unsafe.example/issue/SEC-403",
      },
      { ...withoutUrl, issueIdentifier: "SEC-404" },
    ];
    const result = {
      ...initial,
      created,
      counts: { findings: created.length, created: created.length, failed: 0 },
    };
    const deps = dependencies();
    deps.publishScan = async () => result;

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("  SEC-400\n");
    for (const identifier of ["SEC-401", "SEC-402", "SEC-403", "SEC-404"]) {
      expect(stdout.text()).toContain(`  ${identifier}\n`);
    }
    expect(stdout.text()).not.toContain("javascript:");
    expect(stdout.text()).not.toContain("PRIVATE_PASSWORD");
    expect(stdout.text()).not.toContain("PRIVATE_TOKEN");
    expect(stdout.text()).not.toContain("unsafe.example");
    expect(stdout.text()).not.toContain("\u001B");
    expect(stdout.text()).not.toContain("\u009F");
    expect(stdout.text()).toContain("5 total issues created\n");
    expect(stdout.text()).not.toContain("\n  ...\n");
  });

  test("colors publication headings only for color-enabled stdout terminals", async () => {
    const scenarios = [
      { interactive: false, environment: {}, color: false },
      { interactive: true, environment: {}, color: true },
      { interactive: true, environment: { NO_COLOR: "1" }, color: false },
      { interactive: true, environment: { TERM: "dumb" }, color: false },
    ] as const;

    for (const scenario of scenarios) {
      const stdout = capture(scenario.interactive);
      const stderr = capture();
      const deps = dependencies({ environment: scenario.environment });
      deps.publishScan = async () => publicationResult();

      expect(
        await main(
          ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(stripVTControlCharacters(stdout.text())).toContain(
        "✓ Linear publication complete\n",
      );
      if (scenario.color) {
        expect(stdout.text()).toContain("\u001B[32m✓\u001B[39m");
        expect(stdout.text()).toContain(
          "\u001B[1mLinear publication complete\u001B[22m",
        );
      } else {
        expect(stdout.text()).not.toContain("\u001B");
      }
    }
  });

  test("preserves explicit structured output formats and prepared dry-run previews", async () => {
    for (const format of [
      { flags: ["--format", "json"], json: true },
      { flags: ["--format", "toon"], json: false },
      { flags: ["--full-output"], json: false },
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const result = publicationResult();
      const deps = dependencies();
      deps.publishScan = async () => result;

      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            ...format.flags,
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      if (format.json) {
        expect(JSON.parse(stdout.text())).toEqual(result);
      } else {
        expect(stdout.text()).toContain("scanId: scan-123");
        expect(stdout.text()).toContain("uploadId: scan-123");
      }
      expect(stdout.text()).not.toContain("Linear publication complete");
    }

    const stdout = capture();
    const stderr = capture(true);
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.publishScan = async (_scanDirectory, options) => {
      expect(options.onProgress).toBeUndefined();
      expect(options.signal).toBeInstanceOf(AbortSignal);
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
        ],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("dryRun: true");
    expect(stdout.text()).not.toContain("Linear publication complete");
    expect(stderr.text()).toBe("");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test("reports every created Linear issue with a successful exit code", async () => {
    const stdout = capture();
    const stderr = capture();
    const result = publicationResult();
    result.created.push({
      findingId: "finding-2",
      occurrenceId: "occurrence-2",
      issueIdentifier: "SEC-124",
      url: "https://linear.app/example/issue/SEC-124",
    });
    result.counts.findings = result.created.length;
    result.counts.created = result.created.length;
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({
        type: "started",
        scanId: result.scanId,
        total: result.created.length,
      });
      options.onProgress?.({
        type: "handoff_recorded",
        findingId: result.created[0]!.findingId,
        recorded: 1,
        total: result.created.length,
      });
      expect(stderr.text()).toContain(
        "[1/2] Saved Linear publication evidence.",
      );
      expect(stderr.text()).not.toContain("Created");
      for (const [index, issue] of result.created.entries()) {
        options.onProgress?.({
          type: "issue_completed",
          findingId: issue.findingId,
          issueIdentifier: issue.issueIdentifier,
          completed: index + 1,
          total: result.created.length,
        });
      }
      options.onProgress?.({
        type: "completed",
        created: result.created.length,
        failed: 0,
        total: result.created.length,
      });
      return result;
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(result);
    expect(stderr.text()).toContain("[1/2] Created SEC-123\n");
    expect(stderr.text()).toContain("[2/2] Created SEC-124\n");
    expect(stderr.text()).toContain("Published 2/2 findings.\n");
  });

  test("interactively selects a completed scan across all repositories", async () => {
    const directories = await publicationScanDirectories(2);
    const firstDirectory = directories[0]!;
    const selectedDirectory = directories[1]!;
    const root = dirname(firstDirectory);
    const missingDirectory = join(root, "missing-scan");
    const replacedDirectory = join(root, "replaced-scan");
    const linkedDirectory = join(root, "linked-scan");
    await writeFile(replacedDirectory, "this scan is now a regular file");
    await symlink(
      firstDirectory,
      linkedDirectory,
      process.platform === "win32" ? "junction" : "dir",
    );
    const stdout = capture();
    const stderr = capture(true);
    let question = "";
    let choices: readonly { label: string; short?: string; value: string }[] =
      [];
    let header: string | undefined;
    let workbenchArguments: readonly string[] | undefined;
    let publishedDirectory: string | undefined;
    const deps = dependencies({
      onWorkbench: (args) => {
        workbenchArguments = args;
        return {
          scans: [
            ...[missingDirectory, replacedDirectory, linkedDirectory].map(
              (scanDir, index) => ({
                scanId: `unavailable-scan-${index}`,
                scanDir,
                targetSummary: "unavailable-repository-must-not-expand-columns",
                completedAt: "2026-08-15T01:05:00Z",
                findingCount: 999,
                progress: { status: "complete" },
              }),
            ),
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
        options: readonly { label: string; short?: string; value: Value }[],
        presentation?: { header?: string },
      ): Promise<Value> => {
        question = message;
        choices = options;
        header = presentation?.header;
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
    expect(header).toContain("REPOSITORY");
    expect(header).toContain("SCAN ID");
    expect(header).not.toContain("unavailable");
    expect(choices[0]!.label).toContain("first-repository");
    expect(choices[0]!.label).toContain("...abc123");
    expect(choices[0]!.label).toContain("1 hour ago");
    expect(choices[0]!.label).toContain("1 finding");
    expect(choices[1]!.label).toContain("second-repository");
    expect(choices[1]!.label).toContain("...def456");
    expect(choices[1]!.label).toContain("2 minutes ago");
    expect(choices[1]!.label).toContain("3 findings");
    expect(stripVTControlCharacters(choices[1]!.short!)).toBe(
      "second-repository · ...def456",
    );
    expect(choices[0]!.label).not.toContain("11111111-2222-3333");
    expect(choices[1]!.label).not.toContain("2026-08-15T02:15:00Z");
    expect(choices[1]!.label).not.toContain("COMPLETE");
    expect(choices.every((choice) => !choice.label.includes("\n"))).toBe(true);
    expect(
      choices.every((choice) => !choice.label.includes("unavailable")),
    ).toBe(true);
    expect(publishedDirectory).toBe(selectedDirectory);
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toContain("\u001B[?1049h\u001B[?25l");
    expect(stripVTControlCharacters(stderr.text())).toContain(
      "CODEX SECURITY  ·  PUBLISH  ·  second-repository",
    );
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
    expect(stderr.text()).not.toContain("66666666-7777-8888-9999");
  });

  test("aligns repository, findings, age, and scan ID columns by visible terminal width", async () => {
    const currentTime = Date.parse("2030-01-01T12:00:00Z");
    const scans = [
      {
        repository: "tiny",
        width: 4,
        findingCount: 1,
        elapsed: 60_000,
        age: "1 minute ago",
      },
      {
        repository: "service-alpha",
        width: 13,
        findingCount: 120,
        elapsed: 4 * 24 * 60 * 60_000,
        age: "4 days ago",
      },
      {
        repository: "服务",
        width: 4,
        findingCount: 22,
        elapsed: 30_000,
        age: "30 seconds ago",
      },
      {
        repository: "cafe\u0301",
        width: 4,
        findingCount: 3,
        elapsed: 2 * 60 * 60_000,
        age: "2 hours ago",
      },
      {
        repository: "👩‍💻-api",
        width: 6,
        findingCount: 9,
        elapsed: 0,
        age: "just now",
      },
      {
        repository: "🇺🇸-edge",
        width: 7,
        findingCount: 0,
        elapsed: 8 * 24 * 60 * 60_000,
        age: "1 week ago",
      },
      {
        repository: "1️⃣-key",
        width: 6,
        findingCount: 44,
        elapsed: 32 * 24 * 60 * 60_000,
        age: "1 month ago",
      },
      {
        repository: "♥-text",
        width: 6,
        findingCount: 8,
        elapsed: 366 * 24 * 60 * 60_000,
        age: "1 year ago",
      },
      {
        repository: "♥️-emoji",
        width: 8,
        findingCount: 7,
        elapsed: -30_000,
        age: "just now",
      },
      {
        repository: "invalid-age",
        width: 11,
        findingCount: 2,
        elapsed: Number.NaN,
        age: "unknown",
      },
    ] as const;
    const repositoryWidth = Math.max(
      "REPOSITORY".length,
      ...scans.map(({ width }) => width),
    );
    const findingsWidth = Math.max(
      "FINDINGS".length,
      ...scans.map(
        ({ findingCount }) =>
          `${findingCount} finding${findingCount === 1 ? "" : "s"}`.length,
      ),
    );
    const ageWidth = Math.max(
      "AGE".length,
      ...scans.map(({ age }) => age.length),
    );
    const expectedHeader = [
      "REPOSITORY".padEnd(repositoryWidth),
      "FINDINGS".padEnd(findingsWidth),
      "AGE".padEnd(ageWidth),
      "SCAN ID",
    ].join("  ");
    const directories = await publicationScanDirectories(scans.length);

    for (const color of [true, false]) {
      let header: string | undefined;
      let choices: readonly { label: string; short?: string; value: string }[] =
        [];
      const deps = dependencies({
        environment: color ? {} : { NO_COLOR: "1" },
        onWorkbench: () => ({
          scans: scans.map(({ repository, findingCount, elapsed }, index) => ({
            scanId: `synthetic-scan-${String(index).padStart(6, "0")}`,
            scanDir: directories[index]!,
            targetSummary: repository,
            completedAt: Number.isNaN(elapsed)
              ? "not-a-timestamp"
              : new Date(currentTime - elapsed).toISOString(),
            findingCount,
            progress: { status: "complete" },
          })),
        }),
      });
      deps.now = () => currentTime;
      deps.publishPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          _message: string,
          options: readonly { label: string; short?: string; value: Value }[],
          presentation?: { header?: string },
        ): Promise<Value> => {
          header = presentation?.header;
          choices = options;
          return options[0]!.value;
        },
      };
      deps.publishScan = async () => publicationResult();

      expect(
        await main(
          ["publish", "scan", ...DESTINATION_OPTIONS, "--json"],
          capture().stream,
          capture(true).stream,
          deps,
        ),
      ).toBe(0);
      expect(header).toBe(expectedHeader);
      expect(header).not.toContain("\u001B");

      for (const [index, scan] of scans.entries()) {
        const findings = `${scan.findingCount} finding${scan.findingCount === 1 ? "" : "s"}`;
        const expectedRow = [
          `${scan.repository}${" ".repeat(repositoryWidth - scan.width)}`,
          findings.padEnd(findingsWidth),
          scan.age.padEnd(ageWidth),
          `...${String(index).padStart(6, "0")}`,
        ].join("  ");
        const label = choices[index]!.label;
        const selected = choices[index]!.short!;

        expect(stripVTControlCharacters(label)).toBe(expectedRow);
        expect(stripVTControlCharacters(selected)).toBe(
          `${scan.repository} · ...${String(index).padStart(6, "0")}`,
        );
        expect(selected).not.toContain("finding");
        expect(selected).not.toContain(" ago");
        expect(label).not.toContain("\n");
        expect(label).not.toContain(" · ");
        expect(label).not.toContain("ran ");
        if (color) {
          expect(label).toStartWith(`\u001B[1m${scan.repository}\u001B[22m`);
          expect(selected).toStartWith(`\u001B[1m${scan.repository}\u001B[22m`);
        } else {
          expect(label).not.toContain("\u001B");
          expect(selected).not.toContain("\u001B");
        }
      }
    }
  });

  test("shows actual Codex reasoning and Linear activity in a full-screen publication dashboard", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({ type: "started", scanId: "scan-123", total: 2 });
      options.onProgress?.({
        type: "codex_event",
        event: {
          type: "item.completed",
          item: {
            id: "reasoning-1",
            type: "reasoning",
            text: "Checking the connected Linear project.",
          },
        },
      });
      options.onProgress?.({
        type: "codex_event",
        event: {
          type: "item.started",
          item: {
            id: "linear-team",
            type: "mcp_tool_call",
            server: "codex_apps",
            tool: "linear_get_team",
            arguments: { query: "team-from-flags" },
          },
        },
      });
      options.onProgress?.({
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-123",
        completed: 1,
        total: 2,
      });
      options.onProgress?.({
        type: "completed",
        created: 1,
        failed: 1,
        total: 2,
      });
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

    const text = stripVTControlCharacters(stderr.text());
    expect(stderr.text()).toContain("\u001B[?1049h\u001B[?25l");
    expect(text).toContain("CODEX SECURITY  ·  PUBLISH  ·  completed-scan");
    expect(text).toContain("Checking the connected Linear project.");
    expect(text).toContain("linear_get_team");
    expect(text).toContain("Created SEC-123");
    expect(text).toContain("FINDINGS  1 / 2 processed");
    expect(text).toContain("Published 1/2 findings (1 failed).");
    expect(text).not.toContain("FILES");
    expect(text).not.toContain("TOKENS");
    expect(text).not.toContain("COST");
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stdout.text()).not.toContain("\u001B");
  });

  test("removes repository-controlled terminal escapes while retaining intentional choice emphasis", async () => {
    const directory = (await publicationScanDirectories(1))[0]!;
    for (const color of [true, false]) {
      let choice = "";
      const deps = dependencies({
        environment: color ? {} : { NO_COLOR: "1" },
        onWorkbench: () => ({
          scans: [
            {
              scanId: "prefix-\u001B[31m\u0007def456",
              scanDir: directory,
              targetSummary: "payments\u001B[2J-api\u0007\nservice\u0008",
              completedAt: "2026-08-15T01:00:00Z",
              findingCount: 1,
              progress: { status: "complete" },
            },
          ],
        }),
      });
      deps.now = () => Date.parse("2026-08-15T01:01:00Z");
      deps.publishPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          _message: string,
          options: readonly { label: string; value: Value }[],
        ): Promise<Value> => {
          choice = options[0]!.label;
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

      expect(stripVTControlCharacters(choice)).toContain(
        "payments-api service  1 finding  1 minute ago  ...def456",
      );
      expect(choice).not.toContain("\u001B[2J");
      expect(choice).not.toContain("\u001B[31m");
      expect(choice).not.toContain("\u0007");
      expect(choice).not.toContain("\u0008");
      if (color) {
        expect(choice).toStartWith("\u001B[1mpayments-api service\u001B[22m");
      } else {
        expect(choice).not.toContain("\u001B");
      }
    }
  });

  test("streams sanitized Codex progress to noninteractive stderr without terminal controls", async () => {
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
      const reasoning = {
        type: "item.completed",
        item: {
          id: "reasoning-1",
          type: "reasoning",
          text: "Preparing the Linear issue.\u001B[31m",
        },
      };
      options.onProgress?.({ type: "codex_event", event: reasoning });
      options.onProgress?.({ type: "codex_event", event: reasoning });
      options.onProgress?.({
        type: "codex_event",
        event: {
          type: "item.started",
          item: {
            id: "linear-create",
            type: "mcp_tool_call",
            server: "codex_apps",
            tool: "linear_save_issue",
            arguments: {
              description: "PRIVATE_SOURCE_SNIPPET_MUST_NOT_BE_LOGGED",
            },
          },
        },
      });
      options.onProgress?.({
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-123",
        completed: 1,
        total: 1,
      });
      options.onProgress?.({
        type: "completed",
        created: 1,
        failed: 0,
        total: 1,
      });
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

    expect(stderr.text()).toContain("Publishing 1 finding to Linear.\n");
    expect(stderr.text()).toContain("Codex: Preparing the Linear issue.");
    expect(stderr.text()).toContain("Tool: linear_save_issue\n");
    expect(stderr.text()).toContain("[1/1] Created SEC-123\n");
    expect(stderr.text()).toContain("Published 1/1 finding.\n");
    expect(stderr.text().match(/Preparing the Linear issue/gu)).toHaveLength(1);
    expect(stderr.text()).not.toContain(
      "PRIVATE_SOURCE_SNIPPET_MUST_NOT_BE_LOGGED",
    );
    expect(stderr.text()).not.toContain("\u001B");
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
  });

  test("hides source-bearing handoff commands in plain and full-screen progress", async () => {
    for (const interactive of [false, true]) {
      const stdout = capture();
      const stderr = capture(interactive);
      const deps = dependencies();
      deps.publishScan = async (_scanDirectory, options) => {
        options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
        options.onProgress?.({
          type: "codex_event",
          event: {
            type: "item.completed",
            item: {
              id: "reasoning-1",
              type: "reasoning",
              text: "Saving the verified Linear issue.",
            },
          },
        });
        options.onProgress?.({
          type: "codex_event",
          event: {
            type: "item.started",
            item: {
              id: "handoff-command",
              type: "command_execution",
              command:
                "python -c 'write(\"PRIVATE_SOURCE_SNIPPET_MUST_NOT_BE_LOGGED\")'",
            },
          },
        });
        options.onProgress?.({
          type: "codex_event",
          event: {
            type: "item.started",
            item: {
              id: "handoff-tool",
              type: "mcp_tool_call",
              server: "local-tools",
              tool: "exec",
              arguments: {
                cmd: "append PRIVATE_ISSUE_DESCRIPTION_MUST_NOT_BE_LOGGED",
              },
            },
          },
        });
        options.onProgress?.({
          type: "codex_event",
          event: {
            type: "item.started",
            item: {
              id: "linear-create",
              type: "mcp_tool_call",
              server: "codex_apps",
              tool: "linear.save_issue",
              arguments: {
                description: "PRIVATE_LINEAR_ARGUMENT_MUST_NOT_BE_LOGGED",
              },
            },
          },
        });
        options.onProgress?.({
          type: "issue_completed",
          findingId: "finding-1",
          issueIdentifier: "SEC-123",
          completed: 1,
          total: 1,
        });
        options.onProgress?.({
          type: "completed",
          created: 1,
          failed: 0,
          total: 1,
        });
        return publicationResult();
      };

      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);

      const progress = stripVTControlCharacters(stderr.text());
      expect(progress).toContain("Saving the verified Linear issue.");
      expect(progress).toContain("Saving Linear publication results");
      expect(progress).toContain("linear.save_issue");
      expect(progress).toContain("Created SEC-123");
      expect(progress).not.toContain("PRIVATE_SOURCE_SNIPPET");
      expect(progress).not.toContain("PRIVATE_ISSUE_DESCRIPTION");
      expect(progress).not.toContain("PRIVATE_LINEAR_ARGUMENT");
      expect(JSON.parse(stdout.text())).toEqual(publicationResult());
      expect(stdout.text()).not.toContain("PRIVATE_");
    }
  });

  test("restores the publication screen before reporting publisher failures", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
      throw new Error("Linear publication stopped unexpectedly.");
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);

    const restored = stderr.text().lastIndexOf("\u001B[?25h\u001B[?1049l");
    const error = stderr
      .text()
      .lastIndexOf("Linear publication stopped unexpectedly.");
    expect(restored).toBeGreaterThan(-1);
    expect(error).toBeGreaterThan(restored);
    expect(stdout.text()).toBe("");
  });

  test("uses plain progress in CI and dumb terminals even when stderr is a TTY", async () => {
    for (const environment of [{ CI: "1" }, { TERM: "dumb" }]) {
      const stdout = capture();
      const stderr = capture(true);
      const deps = dependencies({ environment });
      deps.publishScan = async (_scanDirectory, options) => {
        options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
        options.onProgress?.({
          type: "completed",
          created: 1,
          failed: 0,
          total: 1,
        });
        return publicationResult();
      };

      expect(
        await main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            "--json",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);

      expect(stderr.text()).toContain("Publishing 1 finding to Linear.");
      expect(stderr.text()).toContain("Published 1/1 finding.");
      expect(stderr.text()).not.toContain("\u001B");
      expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    }
  });

  test("restores the terminal before cancellation and waits for publication recovery", async () => {
    for (const interactive of [true, false]) {
      for (const [signal, expectedCode, expectedMessage] of [
        ["SIGINT", 130, "Publication canceled by Ctrl-C."],
        ["SIGTERM", 143, "Publication terminated by SIGTERM."],
      ] as const) {
        const stdout = capture();
        const captured = capture(interactive);
        const events: string[] = [];
        const stderr = {
          isTTY: interactive,
          write(value: string | Uint8Array): boolean {
            if (value.toString().includes("\u001B[?25h\u001B[?1049l")) {
              events.push("restored terminal");
            }
            return captured.stream.write(value);
          },
        };
        const listeners = new Map<string, () => void>();
        const removed: string[] = [];
        let enteredPublication!: () => void;
        const publicationStarted = new Promise<void>((resolve) => {
          enteredPublication = resolve;
        });
        let finishRecovery!: () => void;
        const recoveryFinished = new Promise<void>((resolve) => {
          finishRecovery = resolve;
        });
        const deps = dependencies();
        deps.addSignalListener = (name, listener) => {
          listeners.set(name, listener);
        };
        deps.removeSignalListener = (name, listener) => {
          if (listeners.get(name) === listener) listeners.delete(name);
          removed.push(name);
        };
        deps.forceExit = (name) => events.push(`forced ${name}`);
        deps.publishScan = async (_scanDirectory, options) => {
          expect(options.signal).toBeInstanceOf(AbortSignal);
          options.signal?.addEventListener("abort", () => {
            events.push(`aborted ${String(options.signal?.reason)}`);
          });
          options.onProgress?.({
            type: "started",
            scanId: "scan-123",
            total: 1,
          });
          listeners.get(signal)!();
          enteredPublication();
          await recoveryFinished;
          events.push("recovered created issues");
          throw new Error(
            "The publication handoff remains at /tmp/synthetic-handoff; recover it before retrying to avoid creating duplicate issues.",
          );
        };

        let finished = false;
        const publishing = main(
          [
            "publish",
            "scan",
            "completed-scan",
            ...DESTINATION_OPTIONS,
            ...(signal === "SIGINT" ? ["--json"] : []),
          ],
          stdout.stream,
          stderr,
          deps,
        ).then((status) => {
          finished = true;
          return status;
        });
        await publicationStarted;
        expect(finished).toBe(false);
        expect(listeners.size).toBe(2);
        expect(events).toEqual(
          interactive
            ? ["restored terminal", `aborted ${signal}`]
            : [`aborted ${signal}`],
        );
        expect(captured.text()).not.toContain(expectedMessage);
        expect(stdout.text()).toBe("");
        finishRecovery();

        expect(await publishing).toBe(expectedCode);
        expect(events).toEqual(
          interactive
            ? [
                "restored terminal",
                `aborted ${signal}`,
                "recovered created issues",
              ]
            : [`aborted ${signal}`, "recovered created issues"],
        );
        expect(captured.text()).toContain(expectedMessage);
        expect(captured.text()).toContain("recover it before retrying");
        expect(stdout.text()).toBe("");
        expect(removed).toEqual(["SIGINT", "SIGTERM"]);
        expect(listeners.size).toBe(0);
        if (interactive) {
          expect(captured.text()).toContain("\u001B[?25h\u001B[?1049l");
        } else {
          expect(captured.text()).not.toContain("\u001B");
        }
      }
    }
  });

  test("falls back to plain progress if the full-screen dashboard cannot start", async () => {
    const stdout = capture();
    const output: string[] = [];
    let failed = false;
    const stderr = {
      isTTY: true,
      write(chunk: string | Uint8Array): boolean {
        const value = chunk.toString();
        if (!failed && value.includes("\u001B[?1049h")) {
          failed = true;
          throw new Error("The terminal cannot enter full-screen mode.");
        }
        output.push(value);
        return true;
      },
    };
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
      options.onProgress?.({
        type: "completed",
        created: 1,
        failed: 0,
        total: 1,
      });
      return publicationResult();
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr,
        deps,
      ),
    ).toBe(0);

    expect(failed).toBe(true);
    expect(output.join("")).toContain("Publishing 1 finding to Linear.");
    expect(output.join("")).toContain("Published 1/1 finding.");
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
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
    expect(stripVTControlCharacters(stderr.text())).toContain(
      "CODEX SECURITY  ·  PUBLISH  ·  selected-scan",
    );
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
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
      let destination:
        | { teamId: string; projectId: string | undefined }
        | undefined;
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
