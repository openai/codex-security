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
  const guide = join(sdk, "guide with # spaces.md");
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
    await writeFile(join(sdk, "README.md"), "# Readme\n");
    // The previous format command checks these folders, not all repository Markdown.
    await mkdir(join(root, "github-action"));
    await writeFile(join(root, "github-action", "README.md"), invalid);
    const outsideGuides = [
      join(root, "examples", "custom-validation", "guide.md"),
      join(root, "plugins", "codex-security", "native", "guide.md"),
    ];
    for (const path of outsideGuides) {
      await mkdir(join(path, ".."), { recursive: true });
      await writeFile(path, invalid);
      await mkdir(join(path, "..", "nested"));
      await writeFile(join(path, "..", "nested", "outside.md"), invalid);
    }
    await writeFile(join(sdk, "--plugin=fixture.md"), "# Markdown fixture\n");
    // The combined paths exceed the Windows process command-line limit.
    for (let index = 0; index < 400; index++) {
      await writeFile(
        join(sdk, `guide-${index}-${"x".repeat(80)}.md`),
        "# Guide\n",
      );
    }
    await writeFile(guide, invalid);
    await writeFile(join(sdk, "deleted.md"), invalid);
    if (process.platform !== "win32")
      await symlink("untracked.md", join(sdk, "linked.md"));
    gitText(["init", "--quiet"], { cwd: root });
    gitText(["add", "--", "."], { cwd: root });
    await rm(join(sdk, "deleted.md"));
    await writeFile(join(sdk, "untracked.md"), invalid);

    const failing = await runCommand("node", [script], {
      cwd: sdk,
      timeout: 30_000,
    });
    expect(failing.status).toBe(1);
    expect(failing.stdout + failing.stderr).toContain("guide with # spaces.md");
    for (const path of outsideGuides)
      expect(failing.stdout + failing.stderr).toContain(
        path.replaceAll("\\", "/").slice(root.length + 1),
      );

    await writeFile(guide, "# Title\n");
    for (const path of outsideGuides) await writeFile(path, "# Guide\n");
    const passing = await runCommand("node", [script], {
      cwd: sdk,
      timeout: 30_000,
    });
    expect(passing.status, passing.stdout + passing.stderr).toBe(0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
