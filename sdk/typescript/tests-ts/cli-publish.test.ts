import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { stripVTControlCharacters } from "node:util";
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
        onProgress: expect.any(Function),
      },
    });
    expect(JSON.parse(stdout.text())).toEqual(publicationResult());
    expect(stderr.text()).toBe("");
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
      { flags: ["--json"], json: true },
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
    const stderr = capture();
    const deps = dependencies();
    deps.publishScan = async () => ({
      ...publicationResult(),
      dryRun: true,
      issues: [],
    });

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

  test("prints persisted issues from concurrent batches instead of malformed Codex prose", async () => {
    const stdout = capture();
    const stderr = capture();
    const persisted = publicationResult();
    persisted.created = Array.from({ length: 23 }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      issueIdentifier: `SEC-${200 + index}`,
      url: `https://linear.app/example/issue/SEC-${200 + index}`,
    }));
    persisted.counts.findings = persisted.created.length;
    persisted.counts.created = persisted.created.length;
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({
        type: "started",
        scanId: persisted.scanId,
        total: persisted.created.length,
      });
      options.onProgress?.({
        type: "codex_event",
        event: {
          type: "item.completed",
          item: {
            id: "agent-message-1",
            type: "agent_message",
            text: "Created zero issues: {invalid JSON; imaginary SEC-999999}",
          },
        },
      });

      const completionOrder = [
        ...persisted.created.slice(0, 20).reverse(),
        ...persisted.created.slice(20).reverse(),
      ];
      for (const [index, issue] of completionOrder.entries()) {
        options.onProgress?.({
          type: "issue_completed",
          findingId: issue.findingId,
          issueIdentifier: issue.issueIdentifier,
          completed: index + 1,
          total: persisted.created.length,
        });
      }
      options.onProgress?.({
        type: "completed",
        created: persisted.created.length,
        failed: 0,
        total: persisted.created.length,
      });
      return persisted;
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);

    expect(JSON.parse(stdout.text())).toEqual(persisted);
    expect(stdout.text()).not.toContain("invalid JSON");
    expect(stdout.text()).not.toContain("SEC-999999");
    expect(stderr.text()).toContain("Codex: Created zero issues:");
    expect(stderr.text()).toContain("[1/23] Created SEC-219\n");
    expect(stderr.text()).toContain("[20/23] Created SEC-200\n");
    expect(stderr.text()).toContain("[21/23] Created SEC-222\n");
    expect(stderr.text()).toContain("[23/23] Created SEC-220\n");
    expect(stderr.text()).toContain("Published 23/23 findings.\n");
  });

  test("preserves persisted successes and failures across concurrent batches", async () => {
    const stdout = capture();
    const stderr = capture();
    const failures = [
      { findingId: "finding-5", error: "The first batch issue failed." },
      { findingId: "finding-21", error: "The second batch issue failed." },
    ];
    const persisted = publicationResult(failures);
    const findings = Array.from({ length: 22 }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      issueIdentifier: `SEC-${300 + index}`,
      url: `https://linear.app/example/issue/SEC-${300 + index}`,
    }));
    persisted.created = findings.filter(
      ({ findingId }) =>
        !failures.some((failure) => failure.findingId === findingId),
    );
    persisted.counts.findings = findings.length;
    persisted.counts.created = persisted.created.length;
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      options.onProgress?.({
        type: "started",
        scanId: persisted.scanId,
        total: findings.length,
      });
      const completionOrder = [
        ...findings.slice(0, 20).reverse(),
        ...findings.slice(20).reverse(),
      ];
      for (const [index, finding] of completionOrder.entries()) {
        const failure = failures.find(
          ({ findingId }) => findingId === finding.findingId,
        );
        options.onProgress?.({
          type: "issue_completed",
          findingId: finding.findingId,
          ...(failure === undefined
            ? { issueIdentifier: finding.issueIdentifier }
            : { error: failure.error }),
          completed: index + 1,
          total: findings.length,
        });
      }
      options.onProgress?.({
        type: "completed",
        created: persisted.created.length,
        failed: failures.length,
        total: findings.length,
      });
      return persisted;
    };

    expect(
      await main(
        ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS, "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);

    expect(JSON.parse(stdout.text())).toEqual(persisted);
    expect(stderr.text()).toContain(
      "[16/22] Failed finding-5: The first batch issue failed.\n",
    );
    expect(stderr.text()).toContain("[21/22] Created SEC-321\n");
    expect(stderr.text()).toContain(
      "[22/22] Failed finding-21: The second batch issue failed.\n",
    );
    expect(stderr.text()).toContain("Published 20/22 findings (2 failed).\n");
  });

  test("interactively selects a completed scan across all repositories", async () => {
    const firstDirectory = join(tmpdir(), "first-completed-scan");
    const selectedDirectory = join(tmpdir(), "selected-completed-scan");
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
    expect(header).toBe(
      [
        "REPOSITORY".padEnd("second-repository".length),
        "FINDINGS".padEnd("3 findings".length),
        "AGE".padEnd("2 minutes ago".length),
        "SCAN ID",
      ].join("  "),
    );
    expect(choices[0]!.label).toStartWith(
      "\u001B[1mfirst-repository\u001B[22m",
    );
    expect(choices[0]!.label).toContain("...abc123");
    expect(choices[0]!.label).toContain("1 hour ago");
    expect(choices[0]!.label).toContain("1 finding");
    expect(stripVTControlCharacters(choices[0]!.short!)).toBe(
      "first-repository · ...abc123",
    );
    expect(choices[1]!.label).toStartWith(
      "\u001B[1msecond-repository\u001B[22m",
    );
    expect(choices[1]!.label).toContain("...def456");
    expect(choices[1]!.label).toContain("2 minutes ago");
    expect(choices[1]!.label).toContain("3 findings");
    expect(stripVTControlCharacters(choices[1]!.short!)).toBe(
      "second-repository · ...def456",
    );
    expect(choices[1]!.short).not.toContain("3 findings");
    expect(choices[1]!.short).not.toContain("2 minutes ago");
    const firstRow = stripVTControlCharacters(choices[0]!.label);
    const secondRow = stripVTControlCharacters(choices[1]!.label);
    expect(firstRow.indexOf("1 finding")).toBe(header!.indexOf("FINDINGS"));
    expect(secondRow.indexOf("3 findings")).toBe(header!.indexOf("FINDINGS"));
    expect(firstRow.indexOf("1 hour ago")).toBe(header!.indexOf("AGE"));
    expect(secondRow.indexOf("2 minutes ago")).toBe(header!.indexOf("AGE"));
    expect(firstRow.indexOf("...abc123")).toBe(header!.indexOf("SCAN ID"));
    expect(secondRow.indexOf("...def456")).toBe(header!.indexOf("SCAN ID"));
    expect(choices.every((choice) => !choice.label.includes("ran "))).toBe(
      true,
    );
    expect(choices.every((choice) => !choice.label.includes(" · "))).toBe(true);
    expect(choices[0]!.label).not.toContain("11111111-2222-3333");
    expect(choices[1]!.label).not.toContain("2026-08-15T02:15:00Z");
    expect(choices[1]!.label).not.toContain("COMPLETE");
    expect(choices.every((choice) => !choice.label.includes("\n"))).toBe(true);
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
        elapsed: 60_000,
        age: "1 minute ago",
      },
      {
        repository: "♥️-emoji",
        width: 8,
        findingCount: 7,
        elapsed: 60_000,
        age: "1 minute ago",
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

    for (const color of [true, false]) {
      let header: string | undefined;
      let choices: readonly { label: string; short?: string; value: string }[] =
        [];
      const deps = dependencies({
        environment: color ? {} : { NO_COLOR: "1" },
        onWorkbench: () => ({
          scans: scans.map(({ repository, findingCount, elapsed }, index) => ({
            scanId: `synthetic-scan-${String(index).padStart(6, "0")}`,
            scanDir: join(tmpdir(), `synthetic-scan-${index}`),
            targetSummary: repository,
            completedAt: new Date(currentTime - elapsed).toISOString(),
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
    for (const color of [true, false]) {
      let choice = "";
      const deps = dependencies({
        environment: color ? {} : { NO_COLOR: "1" },
        onWorkbench: () => ({
          scans: [
            {
              scanId: "prefix-\u001B[31m\u0007def456",
              scanDir: join(tmpdir(), "completed-scan"),
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

  test("restores the full-screen terminal and unregisters listeners on interruption", async () => {
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      const stdout = capture();
      const stderr = capture(true);
      const listeners = new Map<string, () => void>();
      const removed: string[] = [];
      const exited: string[] = [];
      const deps = dependencies();
      deps.addSignalListener = (name, listener) => {
        listeners.set(name, listener);
      };
      deps.removeSignalListener = (name, listener) => {
        if (listeners.get(name) === listener) listeners.delete(name);
        removed.push(name);
      };
      deps.forceExit = (name) => {
        exited.push(name);
      };
      deps.publishScan = async (_scanDirectory, options) => {
        options.onProgress?.({ type: "started", scanId: "scan-123", total: 1 });
        listeners.get(signal)!();
        return publicationResult();
      };

      expect(
        await main(
          ["publish", "scan", "completed-scan", ...DESTINATION_OPTIONS],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);

      expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
      expect(removed).toEqual(["SIGINT", "SIGTERM"]);
      expect(listeners.size).toBe(0);
      expect(exited).toEqual([signal]);
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

  test("keeps dry runs quiet even when stderr is interactive", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const deps = dependencies();
    deps.publishScan = async (_scanDirectory, options) => {
      expect(options.onProgress).toBeUndefined();
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

    expect(stderr.text()).toBe("");
    expect(JSON.parse(stdout.text())).toMatchObject({ dryRun: true });
  });

  test("formats scan choices as compact single lines with relative ages", async () => {
    const currentTime = Date.parse("2026-08-15T12:00:00Z");
    const scenarios = [
      { age: 0, expected: "just now" },
      { age: 30_000, expected: "30 seconds ago" },
      { age: 60_000, expected: "1 minute ago" },
      { age: 2 * 60_000, expected: "2 minutes ago" },
      { age: 60 * 60_000, expected: "1 hour ago" },
      { age: 4 * 24 * 60 * 60_000, expected: "4 days ago" },
      { age: 8 * 24 * 60 * 60_000, expected: "1 week ago" },
      { age: 32 * 24 * 60 * 60_000, expected: "1 month ago" },
      { age: 366 * 24 * 60 * 60_000, expected: "1 year ago" },
      { age: -30_000, expected: "just now" },
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
        `payments api  2 findings  ${scenario.expected.padEnd("30 seconds ago".length)}  ...${String(index).padStart(6, "0")}`,
      );
    }
    expect(choices.at(-1)!.label).toBe(
      `payments api  0 findings  ${"unknown".padEnd("30 seconds ago".length)}  ...999999`,
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
