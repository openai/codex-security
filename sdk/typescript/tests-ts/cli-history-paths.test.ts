import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, mock } from "bun:test";
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
      const onWorkbench = mock(() => {
        return { scans: [] };
      });
      const stderr = capture();

      expect(
        await main(
          ["scans", "list", "--scan-root", ambiguous],
          capture().stream,
          stderr.stream,
          dependencies({
            currentDirectory: root,
            onWorkbench,
          }),
        ),
      ).toBe(2);
      expect(onWorkbench).toHaveBeenCalledTimes(0);
      expect(stderr.text()).toContain("Windows-ambiguous components");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
