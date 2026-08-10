import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

describe("CLI scan prompts", () => {
  test("loads scan and post-scan prompt files", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-prompts-"));
    try {
      await Promise.all([
        writeFile(join(root, "scan.md"), "Review authentication boundaries.\n"),
        writeFile(join(root, "follow-up.md"), "Draft confirmed fixes.\n"),
      ]);
      let options: unknown;
      expect(
        await main(
          [
            "scan",
            ".",
            "--scan-prompt-file",
            "scan.md",
            "--post-scan-prompt-file",
            "follow-up.md",
            "--json",
          ],
          capture().stream,
          capture().stream,
          dependencies({
            currentDirectory: root,
            onTurn: (_repository, value) => (options = value),
          }),
        ),
      ).toBe(0);
      expect(options).toMatchObject({
        scanPrompt: "Review authentication boundaries.\n",
        postScanPrompt: "Draft confirmed fixes.\n",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("combines shared and repository-specific bulk scan prompts", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-prompts-"));
    try {
      const repository = join(root, "repository");
      for (const args of [
        ["init", "-q", repository],
        [
          "-C",
          repository,
          "-c",
          "user.email=test@example.com",
          "-c",
          "user.name=Test",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "--allow-empty",
          "-qm",
          "initial",
        ],
      ]) {
        expect(spawnSync("git", args, { encoding: "utf8" }).status).toBe(0);
      }
      const revision = spawnSync(
        "git",
        ["-C", repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      ).stdout.trim();
      await Promise.all([
        writeFile(
          join(root, "repositories.csv"),
          `id,repository,revision,prompt\nsample,${repository},${revision},Focus on authorization.\n`,
        ),
        writeFile(join(root, "scan.md"), "Review authentication boundaries.\n"),
        writeFile(join(root, "follow-up.md"), "Draft confirmed fixes.\n"),
      ]);
      let options: unknown;
      expect(
        await main(
          [
            "bulk-scan",
            "repositories.csv",
            "--output-dir",
            "results",
            "--scan-prompt-file",
            "scan.md",
            "--post-scan-prompt-file",
            "follow-up.md",
            "--json",
          ],
          capture().stream,
          capture().stream,
          dependencies({
            currentDirectory: root,
            onTurn: (_repository, value) => (options = value),
          }),
        ),
      ).toBe(0);
      expect(options).toMatchObject({
        scanPrompt:
          "Review authentication boundaries.\n\nFocus on authorization.",
        postScanPrompt: "Draft confirmed fixes.\n",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
