import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import {
  SCAN_DIFF_IDENTITY_FIELD,
  SCAN_DIFF_IDENTITY_RULE,
} from "../src/scan-diff.js";
import { dependencies } from "./cli-fixtures.js";
import { captureCli } from "./support/cli-run.js";
import { rejecting, throwing } from "./support/errors.js";

const fixtureRoot = join(import.meta.dir, "fixtures", "scan-diff");
const scanA = join(fixtureRoot, "scan-a");
const scanB = join(fixtureRoot, "scan-b");

describe("CLI scans diff", () => {
  test("diffs fixture scan directories without the workbench or model", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = captureCli(main, "stdout");
    const deps = dependencies({
      currentDirectory: fixtureRoot,
      onWorkbench: (args) => {
        calls.push(args);
        return {};
      },
      onMatch: rejecting("scan diff must not call the model"),
    });
    deps.createSecurity = throwing("scan diff must not initialize Codex");
    expect(
      await stdout.run(["scans", "diff", scanA, scanB, "--json"], deps),
    ).toBe(0);
    expect(calls).toEqual([]);
    expect(JSON.parse(stdout.text())).toEqual({
      beforeScanId: "scan_diff_fixture_a",
      afterScanId: "scan_diff_fixture_b",
      identity: {
        field: SCAN_DIFF_IDENTITY_FIELD,
        rule: SCAN_DIFF_IDENTITY_RULE,
      },
      summary: { new: 1, resolved: 1, unchanged: 1 },
      findings: [
        {
          status: "new",
          findingId: "csf_222222222222222222222222",
          title: "Comment bodies are rendered without escaping",
          severity: "medium",
          path: "src/comments.py",
          afterOccurrenceId: "occ_dddddddddddddddddddddddd",
        },
        {
          status: "resolved",
          findingId: "csf_111111111111111111111111",
          title: "User filters are concatenated into SQL",
          severity: "critical",
          path: "src/query.py",
          beforeOccurrenceId: "occ_bbbbbbbbbbbbbbbbbbbbbbbb",
        },
        {
          status: "unchanged",
          findingId: "csf_852f90d6e1177502ff113d4a",
          title: "Archive extraction writes outside the output directory",
          severity: "high",
          path: "src/extract.py",
          beforeOccurrenceId: "occ_aaaaaaaaaaaaaaaaaaaaaaaa",
          afterOccurrenceId: "occ_cccccccccccccccccccccccc",
        },
      ],
    });
  });

  test("keeps rewritten descriptions unchanged when diffing saved scan IDs", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = captureCli(main, "stdout");
    const beforeFindings = [
      {
        findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
        occurrenceId: "occ_before",
        title: "Original title",
        severity: { level: "high" },
        locations: [{ path: "src/a.ts", startLine: 1 }],
      },
    ];
    const afterFindings = [
      {
        findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
        occurrenceId: "occ_after",
        title: "Completely rewritten title",
        severity: { level: "high" },
        locations: [{ path: "src/a.ts", startLine: 4 }],
      },
    ];
    expect(
      await stdout.run(
        ["scans", "diff", "scan-before", "scan-after", "--json"],
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            const scanId = args[2] ?? "";
            return {
              scan: {
                scanId,
                progress: { status: "complete" },
                findings:
                  scanId === "scan-before" ? beforeFindings : afterFindings,
              },
            };
          },
          onMatch: rejecting("scan diff must not call the model"),
        }),
      ),
    ).toBe(0);
    expect(calls).toEqual([
      ["get-scan", "--scan-id", "scan-before"],
      ["get-scan", "--scan-id", "scan-after"],
    ]);
    expect(JSON.parse(stdout.text())).toMatchObject({
      beforeScanId: "scan-before",
      afterScanId: "scan-after",
      summary: { new: 0, resolved: 0, unchanged: 1 },
      findings: [
        {
          status: "unchanged",
          findingId: "csf_aaaaaaaaaaaaaaaaaaaaaaaa",
          title: "Completely rewritten title",
        },
      ],
    });
  });

  test("renders a human-readable diff in the terminal", async () => {
    const stdout = captureCli(main, "stdout", true);
    expect(
      await stdout.run(
        ["scans", "diff", scanA, scanB],
        dependencies({
          currentDirectory: fixtureRoot,
          onWorkbench: throwing("fixture diffs must not use the workbench"),
          onMatch: rejecting("scan diff must not call the model"),
        }),
      ),
    ).toBe(0);
    expect(stdout.text()).toContain("SCAN DIFF");
    expect(stdout.text()).toContain("findingId");
    expect(stdout.text()).toContain(
      "Archive extraction writes outside the output directory",
    );
    expect(stdout.text()).toContain(
      "Comment bodies are rendered without escaping",
    );
    expect(stdout.text()).toContain("User filters are concatenated into SQL");
  });

  test("exits 0 when the later scan has new findings", async () => {
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scans", "diff", scanA, scanB, "--json"],
        dependencies({
          currentDirectory: fixtureRoot,
          onWorkbench: throwing("fixture diffs must not use the workbench"),
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text()).summary.new).toBe(1);
  });

  test("reports an incomplete saved scan without calling the model", async () => {
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(
        ["scans", "diff", "running-scan", "scan-after"],
        dependencies({
          onWorkbench: () => ({
            scan: {
              scanId: "running-scan",
              progress: { status: "running" },
              findings: [],
            },
          }),
          onMatch: rejecting("scan diff must not call the model"),
        }),
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Scan running-scan is not complete.");
  });

  test("pages truncated workbench findings", async () => {
    const calls: Array<readonly string[]> = [];
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["scans", "diff", "scan-before", "scan-after", "--json"],
        dependencies({
          onWorkbench: (args): JsonObject => {
            calls.push(args);
            if (args[0] === "list-findings") {
              return {
                findingsPage: {
                  findings: [
                    {
                      findingId: "csf_paged",
                      occurrenceId: "occ_after",
                      title: "Paged finding",
                    },
                  ],
                },
              };
            }
            const scanId = args[2] ?? "";
            return {
              scan: {
                scanId,
                progress: { status: "complete" },
                findingsTruncated: scanId === "scan-after",
                findings:
                  scanId === "scan-before"
                    ? [
                        {
                          findingId: "csf_paged",
                          occurrenceId: "occ_before",
                          title: "Paged finding",
                        },
                      ]
                    : [
                        {
                          findingId: "csf_truncated",
                          title: "Should be replaced by the paged list",
                        },
                      ],
              },
            };
          },
        }),
      ),
    ).toBe(0);
    expect(calls.map((args) => args[0])).toEqual([
      "get-scan",
      "get-scan",
      "list-findings",
    ]);
    expect(JSON.parse(stdout.text()).summary).toEqual({
      new: 0,
      resolved: 0,
      unchanged: 1,
    });
  });
});
