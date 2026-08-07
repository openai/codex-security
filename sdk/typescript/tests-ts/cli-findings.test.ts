import { describe, expect, test } from "bun:test";
import type { JsonObject } from "../src/index.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./support/cli.js";

describe("CLI findings history", () => {
  test("lists active findings for the current repository by default", async () => {
    for (const command of [["findings"], ["findings", "list"]]) {
      const calls: Array<readonly string[]> = [];
      const stdout = capture();
      const deps = dependencies({
        onWorkbench: (args): JsonObject => {
          calls.push(args);
          if (args[0] === "list-scans") {
            return {
              scans: [
                {
                  scanId: "scan-1",
                  targetId: "target-1",
                  targetPath: "/current/repository",
                },
              ],
            };
          }
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
        ["list-scans", "--repository", "/current/repository"],
        [
          "list-global-findings",
          "--target-id",
          "target-1",
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

  test("keeps the current checkout scoped when related scan history is newer", async () => {
    const calls: Array<readonly string[]> = [];
    const deps = dependencies({
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        return args[0] === "list-scans"
          ? {
              scans: [
                {
                  scanId: "related",
                  targetId: "related-target",
                  targetPath: "/another/checkout",
                },
                {
                  scanId: "current",
                  targetId: "current-target",
                  targetPath: "/current/repository",
                },
              ],
            }
          : { findings: [], limit: 20, nextOffset: null, offset: 0 };
      },
    });

    expect(
      await main(
        ["findings", "list"],
        capture().stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls[1]).toContain("current-target");
    expect(calls[1]).not.toContain("related-target");
  });

  test("keeps stable target history isolated when an older checkout path is reused", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        ["findings", "--json"],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "current",
                      targetId: "current-target",
                      targetPath: "/current/repository",
                    },
                    {
                      scanId: "historical",
                      targetId: "current-target",
                      targetPath: "/another/reused-checkout",
                    },
                    {
                      scanId: "unrelated",
                      targetId: "reused-target",
                      targetPath: "/another/reused-checkout",
                    },
                  ],
                }
              : { findings: [], limit: 20, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);

    expect(calls[1]).toEqual([
      "list-global-findings",
      "--target-id",
      "current-target",
      "--status",
      "open",
      "--offset",
      "0",
      "--limit",
      "20",
    ]);
  });

  test("keeps historical scans visible after their registered checkout moves", async () => {
    for (const command of [["findings"], ["scans", "show"]]) {
      const calls: Array<readonly string[]> = [];
      expect(
        await main(
          [...command, "--json"],
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              if (args[0] === "list-scans") {
                return {
                  scans: [
                    {
                      scanId: "historical-scan",
                      targetId: "stable-target",
                      targetPath: "/previous/checkout",
                      currentTargetPath: "/current/repository",
                      progress: { status: "complete" },
                    },
                  ],
                };
              }
              return args[0] === "get-scan"
                ? { scan: { scanId: "historical-scan", findings: [] } }
                : { findings: [], limit: 20, nextOffset: null, offset: 0 };
            },
          }),
        ),
      ).toBe(0);

      expect(calls[1]).toContain(
        command[0] === "findings" ? "stable-target" : "historical-scan",
      );
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

  test("scopes multiple moved targets by identity instead of reusable checkout paths", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        ["findings", "--json"],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "service-a",
                      targetId: "target-a",
                      targetPath: "/current/repository/a",
                    },
                    {
                      scanId: "historical-a",
                      targetId: "target-a",
                      targetPath: "/another/reused-checkout",
                    },
                    {
                      scanId: "service-b",
                      targetId: "target-b",
                      targetPath: "/current/repository/b",
                    },
                    {
                      scanId: "unrelated",
                      targetId: "unrelated-target",
                      targetPath: "/another/reused-checkout",
                    },
                  ],
                }
              : { findings: [], limit: 20, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);

    expect(calls[1]).toEqual([
      "list-global-findings",
      "--target-id",
      "target-a",
      "--target-id",
      "target-b",
      "--status",
      "open",
      "--offset",
      "0",
      "--limit",
      "20",
    ]);
  });

  test("returns an empty repository page without querying other targets", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["findings", "--offset", "5", "--limit", "10", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return { scans: [] };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", "/current/repository"],
    ]);
    expect(JSON.parse(stdout.text())).toEqual({
      findings: [],
      limit: 10,
      nextOffset: null,
      offset: 5,
    });
  });

  test("queries every local legacy scan when history has no target ID", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["findings", "--offset", "20", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "legacy-scan",
                      targetId: null,
                      targetPath: "/current/repository",
                      progress: { status: "complete" },
                    },
                  ],
                }
              : {
                  findings: [{ occurrenceId: "occ-21" }],
                  limit: 20,
                  nextOffset: null,
                  offset: 20,
                };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", "/current/repository"],
      [
        "list-global-findings",
        "--target-path",
        "/current/repository",
        "--status",
        "open",
        "--offset",
        "20",
        "--limit",
        "20",
      ],
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      findings: [{ occurrenceId: "occ-21" }],
    });
  });

  test("never replaces a local legacy scan with a newer sibling checkout", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        ["findings", "list"],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "newer-sibling",
                      targetId: "sibling-target",
                      targetPath: "/another/checkout",
                      progress: { status: "complete" },
                    },
                    {
                      scanId: "local-legacy",
                      targetId: null,
                      targetPath: "/current/repository",
                      progress: { status: "complete" },
                    },
                  ],
                }
              : { findings: [], limit: 20, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);
    expect(calls[1]).toEqual([
      "list-global-findings",
      "--target-path",
      "/current/repository",
      "--status",
      "open",
      "--offset",
      "0",
      "--limit",
      "20",
    ]);
  });

  test("selects the containing checkout when run from a subdirectory", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        ["findings"],
        capture().stream,
        capture().stream,
        dependencies({
          currentDirectory: "/current/repository/src/nested",
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "newer-sibling",
                      targetId: "sibling-target",
                      targetPath: "/another/checkout",
                    },
                    {
                      scanId: "local",
                      targetId: "local-target",
                      targetPath: "/current/repository",
                    },
                  ],
                }
              : { findings: [], limit: 20, nextOffset: null, offset: 0 };
          },
        }),
      ),
    ).toBe(0);
    expect(calls[1]).toContain("local-target");
    expect(calls[1]).not.toContain("sibling-target");
  });

  test("prefers checkout-root scans over separately scanned subdirectories", async () => {
    for (const command of [["findings"], ["scans", "show"]]) {
      const calls: Array<readonly string[]> = [];
      expect(
        await main(
          command,
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              if (args[0] === "list-scans") {
                return {
                  scans: [
                    {
                      scanId: "newer-nested-scan",
                      targetId: "nested-target",
                      targetPath: "/current/repository/src",
                      completedAt: "2026-08-03T12:00:00Z",
                      progress: { status: "complete" },
                    },
                    {
                      scanId: "root-scan",
                      targetId: "root-target",
                      targetPath: "/current/repository",
                      completedAt: "2026-08-02T12:00:00Z",
                      progress: { status: "complete" },
                    },
                  ],
                };
              }
              return args[0] === "get-scan"
                ? { scan: { scanId: "root-scan", findings: [] } }
                : { findings: [], limit: 20, nextOffset: null, offset: 0 };
            },
          }),
        ),
      ).toBe(0);
      expect(calls[1]).toContain(
        command[0] === "findings" ? "root-target" : "root-scan",
      );
      expect(calls[1]).not.toContain(
        command[0] === "findings" ? "nested-target" : "newer-nested-scan",
      );
    }
  });

  test("includes every scanned subdirectory when the checkout has no root scan", async () => {
    for (const command of [["findings"], ["scans", "show"]]) {
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
              if (args[0] === "list-scans") {
                return {
                  scans: [
                    {
                      scanId: "newer-long-service",
                      targetId: "long-target",
                      targetPath: "/current/repository/long-service",
                      completedAt: "2026-08-03T12:00:00Z",
                      progress: { status: "complete" },
                    },
                    {
                      scanId: "older-short-service",
                      targetId: "short-target",
                      targetPath: "/current/repository/a",
                      completedAt: "2026-08-02T12:00:00Z",
                      progress: { status: "complete" },
                    },
                  ],
                };
              }
              return args[0] === "get-scan"
                ? { scan: { scanId: "newer-long-service", findings: [] } }
                : {
                    findings: [
                      { occurrenceId: "critical-long-service" },
                      { occurrenceId: "older-short-service" },
                    ],
                    limit: 20,
                    nextOffset: null,
                    offset: 0,
                  };
            },
          }),
        ),
      ).toBe(0);
      if (command[0] === "findings") {
        expect(calls[1]).toEqual([
          "list-global-findings",
          "--target-id",
          "long-target",
          "--target-id",
          "short-target",
          "--status",
          "open",
          "--offset",
          "0",
          "--limit",
          "20",
        ]);
        expect(JSON.parse(stdout.text())["findings"]).toHaveLength(2);
      } else {
        expect(calls[1]).toEqual([
          "get-scan",
          "--scan-id",
          "newer-long-service",
        ]);
      }
    }
  });

  test("does not display a sibling checkout when this checkout has no scans", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = capture();
    expect(
      await main(
        ["findings", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
          onWorkbench: (args) => {
            calls.push(args);
            return {
              scans: [
                {
                  scanId: "sibling",
                  targetId: "sibling-target",
                  targetPath: "/another/checkout",
                },
              ],
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", "/current/repository"],
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({ findings: [] });
  });

  test("recovers verified related-checkout history when the local checkout has no scan", async () => {
    for (const command of [["findings"], ["scans", "show"]]) {
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
              if (args[0] === "list-scans") {
                return {
                  scans: [
                    {
                      scanId: "related-scan",
                      targetId: "related-target",
                      targetPath: "/another/verified-checkout",
                      relatedCheckout: true,
                      progress: { status: "complete" },
                    },
                  ],
                };
              }
              return args[0] === "get-scan"
                ? { scan: { scanId: "related-scan", findings: [] } }
                : { findings: [], limit: 20, nextOffset: null, offset: 0 };
            },
          }),
        ),
      ).toBe(0);

      expect(calls[1]).toContain(
        command[0] === "findings" ? "related-target" : "related-scan",
      );
    }
  });

  test("finds scanned checkout subdirectories from the repository root", async () => {
    for (const command of [["findings"], ["scans", "show"]]) {
      const calls: Array<readonly string[]> = [];
      expect(
        await main(
          command,
          capture().stream,
          capture().stream,
          dependencies({
            onWorkbench: (args): JsonObject => {
              calls.push(args);
              if (args[0] === "list-scans") {
                return {
                  scans: [
                    {
                      scanId: "scoped-scan",
                      targetId: "scoped-target",
                      targetPath: "/current/repository/src",
                      progress: { status: "complete" },
                    },
                  ],
                };
              }
              return args[0] === "get-scan"
                ? { scan: { scanId: "scoped-scan", findings: [] } }
                : { findings: [], limit: 20, nextOffset: null, offset: 0 };
            },
          }),
        ),
      ).toBe(0);
      expect(calls[1]).toContain(
        command[0] === "findings" ? "scoped-target" : "scoped-scan",
      );
    }
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
                      },
                      {
                        scanId: "older",
                        targetPath: "/current/repository",
                        progress: { status: "complete" },
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

  test("selects the latest completed local scan instead of a newer sibling", async () => {
    const calls: Array<readonly string[]> = [];
    expect(
      await main(
        ["scans", "show"],
        capture().stream,
        capture().stream,
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            return args[0] === "list-scans"
              ? {
                  scans: [
                    {
                      scanId: "sibling",
                      targetPath: "/another/checkout",
                      completedAt: "2026-08-03T12:00:00Z",
                      progress: { status: "complete" },
                    },
                    {
                      scanId: "archived-older",
                      targetPath: "/current/repository",
                      completedAt: "2026-08-01T12:00:00Z",
                      progress: { status: "complete" },
                    },
                    {
                      scanId: "actual-latest",
                      targetPath: "/current/repository",
                      completedAt: "2026-08-02T12:00:00Z",
                      progress: { status: "complete" },
                    },
                  ],
                }
              : { scan: { scanId: "actual-latest", findings: [] } };
          },
        }),
      ),
    ).toBe(0);
    expect(calls[1]).toEqual(["get-scan", "--scan-id", "actual-latest"]);
  });

  test("does not treat a sibling completed scan as local scan history", async () => {
    const stderr = capture();
    expect(
      await main(
        ["scans", "show"],
        capture().stream,
        stderr.stream,
        dependencies({
          onWorkbench: () => ({
            scans: [
              {
                scanId: "sibling-complete",
                targetPath: "/another/checkout",
                progress: { status: "complete" },
              },
              {
                scanId: "local-running",
                targetPath: "/current/repository",
                progress: { status: "running" },
              },
            ],
          }),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("No completed scans found");
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
      ["findings", "list", "31107fbe"],
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
