import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

function validatePreflightIssues(issues: object[]) {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  return spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sys",
        "sys.path.insert(0, sys.argv.pop(1))",
        "from workbench_cli import parse_args",
        "from workbench_progress import preflight_issues_json",
        "args = parse_args('Synthetic workbench progress')",
        "issues = json.loads(preflight_issues_json(args.preflight_issues_json))",
        "print(json.dumps({'count': len(issues), 'reasonLength': len(issues[0]['reason'])}))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      "update-progress",
      "--scan-id",
      "00000000-0000-4000-8000-000000000000",
      "--preflight-issues-json",
      JSON.stringify(issues),
    ],
    { encoding: "utf8" },
  );
}

function issue(reason = "Preflight warning") {
  return {
    capability: "delegated_workers",
    reason,
    severity: "warn",
    status: "fail",
  };
}

describe("workbench preflight progress", () => {
  test("accepts valid non-ASCII issues larger than 64 KiB", () => {
    const issues = Array.from({ length: 24 }, () => issue("€".repeat(1_000)));
    const serialized = JSON.stringify(issues);
    expect(Buffer.byteLength(serialized)).toBeGreaterThan(64 * 1024);
    expect(serialized.length).toBeLessThan(30_000);

    const result = validatePreflightIssues(issues);

    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      count: 24,
      reasonLength: 1_000,
    });
  });

  test("preserves upstream issue-count and reason-length limits", () => {
    const excessIssues = validatePreflightIssues(
      Array.from({ length: 33 }, () => issue()),
    );
    expect(excessIssues.status).not.toBe(0);
    expect(excessIssues.stderr).toContain("at most 32 objects");

    const excessReason = validatePreflightIssues([issue("€".repeat(1_201))]);
    expect(excessReason.status).not.toBe(0);
    expect(excessReason.stderr).toContain("1 to 1200 characters");
  });
});
