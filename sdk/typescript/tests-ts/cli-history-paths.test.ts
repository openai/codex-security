import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

test.skipIf(process.platform !== "win32")(
  "rejects an aliased Windows scan root before querying history",
  async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-history-root-alias-")),
    );
    try {
      const scanRoot = join(root, "history");
      const ambiguous = join(root, "history.");
      await Promise.all([mkdir(scanRoot), mkdir(ambiguous)]);
      expect(await realpath(scanRoot)).not.toBe(await realpath(ambiguous));
      let workbenchCalls = 0;
      const stderr = capture();

      expect(
        await main(
          ["scans", "list", "--scan-root", ambiguous],
          capture().stream,
          stderr.stream,
          dependencies({
            currentDirectory: root,
            onWorkbench: () => {
              workbenchCalls += 1;
              return { scans: [] };
            },
          }),
        ),
      ).toBe(2);
      expect(workbenchCalls).toBe(0);
      expect(stderr.text()).toContain("Windows-ambiguous components");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
