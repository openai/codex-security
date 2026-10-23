import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, test } from "bun:test";

// Keep every executor case in the SDK's macOS and Windows shards without
// putting the entire growing suite under one child-process deadline.
for (const [name, unixOnly] of [
  ["portable worker lifecycle and runtime settings", false],
  ["native worker permissions and authentication", true],
  ["native worker diagnostics and retries", true],
  ["worker executable selection and errors", false],
] as const) {
  test.skipIf(unixOnly && process.platform === "win32")(
    `Deep worker child-process boundary: ${name}`,
    async () => {
      const { stdout } = await promisify(execFile)(
        "node",
        [
          "--experimental-strip-types",
          "--test",
          "--test-reporter=tap",
          `--test-name-pattern=^${name}$`,
          fileURLToPath(
            new URL(
              "../../../plugins/codex-security/mcp-app/tests/test_deep_scan_executor.ts",
              import.meta.url,
            ),
          ),
        ],
        { timeout: 110_000 },
      );
      expect(stdout).toMatch(new RegExp(`^ok \\d+ - ${name}$`, "m"));
    },
    120_000,
  );
}
