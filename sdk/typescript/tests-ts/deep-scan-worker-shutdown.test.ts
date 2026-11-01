import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { test } from "bun:test";

// Always keep this file in the same shard for local replay and JUnit reporting.
const it = test.skipIf(
  process.platform === "linux" &&
    process.env["CODEX_SECURITY_TEST_MCP_WORKERS_SEPARATE"] === "true",
);

for (const boundary of [
  "lifecycle",
  "runtime settings",
  "executable selection",
  "diagnostics",
]) {
  it(`Deep worker ${boundary} at the child-process boundary`, async () => {
    // Keep each portable boundary in the SDK's macOS and Windows test shards.
    const { stdout, stderr } = await promisify(execFile)(
      "node",
      [
        "--experimental-strip-types",
        "--test-reporter=tap",
        "--test-name-pattern",
        `^Deep worker ${boundary}`,
        fileURLToPath(
          new URL(
            "../../../plugins/codex-security/mcp-app/tests/test_deep_scan_executor.ts",
            import.meta.url,
          ),
        ),
      ],
      { timeout: 110_000 },
    );
    const passed = new RegExp(`^ok [0-9]+ - Deep worker ${boundary}\\r?$`, "m");
    if (!passed.test(stdout)) {
      throw Object.assign(
        new Error(`No passing Deep worker ${boundary} group.`),
        {
          stdout,
          stderr,
        },
      );
    }
  }, 120_000);
}

it("preserves worker error classification, parent sandbox denials and workbench subprocess deadlines", async () => {
  await promisify(execFile)("node", [
    "--experimental-strip-types",
    "--test",
    ...[
      "test_deep_scan_errors.ts",
      "test_deep_scan_parent_sandbox.ts",
      "test_workbench_timeouts.ts",
    ].map((file) =>
      fileURLToPath(
        new URL(
          `../../../plugins/codex-security/mcp-app/tests/${file}`,
          import.meta.url,
        ),
      ),
    ),
  ]);
}, 30_000);
