import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { test } from "bun:test";

test("Deep worker cancellation at the child-process boundary", async () => {
  // Keep the portable child fixture in the SDK's macOS and Windows test shards.
  await promisify(execFile)(
    "node",
    [
      fileURLToPath(
        new URL(
          "../../../plugins/codex-security/mcp-app/tests/test_deep_scan_executor.mjs",
          import.meta.url,
        ),
      ),
    ],
    { timeout: 110_000 },
  );
}, 120_000);
