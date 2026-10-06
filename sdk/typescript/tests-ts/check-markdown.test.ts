import { expect, test } from "bun:test";
import {
  copyFile,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gitText, runCommand } from "./support/shell.js";

test("checks tracked Markdown including leading-dash paths and skips deleted, untracked, and linked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "markdown checks "));
  const sdk = join(root, "sdk", "typescript");
  const script = join(sdk, "scripts", "check-markdown.mjs");
  const guide = join(root, "guide with # spaces.md");
  const invalid = "# Title\n\n\n";
  try {
    await mkdir(join(sdk, "scripts"), { recursive: true });
    await copyFile(
      new URL("../scripts/check-markdown.mjs", import.meta.url),
      script,
    );
    await symlink(
      fileURLToPath(new URL("../node_modules", import.meta.url)),
      join(sdk, "node_modules"),
      "junction",
    );
    await writeFile(join(root, ".gitignore"), "node_modules/\n");
    await writeFile(join(root, "README.md"), "# Readme\n");
    await writeFile(join(root, "--plugin=fixture.md"), "# Markdown fixture\n");
    // The combined paths exceed the Windows process command-line limit.
    for (let index = 0; index < 400; index++) {
      await writeFile(
        join(root, `guide-${index}-${"x".repeat(80)}.md`),
        "# Guide\n",
      );
    }
    await writeFile(guide, invalid);
    await writeFile(join(root, "deleted.md"), invalid);
    if (process.platform !== "win32")
      await symlink("untracked.md", join(root, "linked.md"));
    gitText(["init", "--quiet"], { cwd: root });
    gitText(["add", "--", "."], { cwd: root });
    await rm(join(root, "deleted.md"));
    await writeFile(join(root, "untracked.md"), invalid);

    const failing = await runCommand("node", [script], {
      cwd: sdk,
      timeout: 30_000,
    });
    expect(failing.status).toBe(1);
    expect(failing.stdout + failing.stderr).toContain("guide with # spaces.md");

    await writeFile(guide, "# Title\n");
    const passing = await runCommand("node", [script], {
      cwd: sdk,
      timeout: 30_000,
    });
    expect(passing.status, passing.stdout + passing.stderr).toBe(0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
