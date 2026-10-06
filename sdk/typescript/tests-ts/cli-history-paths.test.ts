import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { captureCli } from "./support/cli-run.js";

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
      const stderr = captureCli(main, "stderr");

      expect(
        await stderr.run(
          ["scans", "list", "--scan-root", ambiguous],
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
