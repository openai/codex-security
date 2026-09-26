import { spawnSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

describe("CLI scan prompts", () => {
  test("loads scan, validation, and post-scan prompt files", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-prompts-"));
    try {
      await Promise.all([
        writeFile(join(root, "scan.md"), "Review authentication boundaries.\n"),
        writeFile(
          join(root, "validation.md"),
          "Run the integration fixture.\n",
        ),
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
            "--validation-prompt-file",
            "validation.md",
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
        validationPrompt: "Run the integration fixture.\n",
        postScanPrompt: "Draft confirmed fixes.\n",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects linked prompt files without rejecting selected external files", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-prompts-"));
    try {
      const repository = join(root, "repository");
      const repositoryAlias = join(root, "repository-alias");
      const externalDirectory = join(root, "external");
      const external = join(externalDirectory, "external-prompt.md");
      const linked = join(repository, "linked-prompt.md");
      await mkdir(repository);
      await symlink(
        repository,
        repositoryAlias,
        process.platform === "win32" ? "junction" : "dir",
      );
      const physicalRepository = await realpath(repository);
      await mkdir(externalDirectory);
      await writeFile(external, "SYNTHETIC_EXTERNAL_PROMPT\n");
      await symlink(external, linked);
      await symlink(
        externalDirectory,
        join(repository, "linked-directory"),
        process.platform === "win32" ? "junction" : "dir",
      );

      for (const [option, property] of [
        ["--scan-prompt-file", "scanPrompt"],
        ["--validation-prompt-file", "validationPrompt"],
        ["--post-scan-prompt-file", "postScanPrompt"],
      ] as const) {
        for (const [directory, target, input] of [
          [repository, ".", "linked-prompt.md"],
          [repository, ".", join("linked-directory", "external-prompt.md")],
          [
            root,
            repository,
            join(repository, "linked-directory", "external-prompt.md"),
          ],
          [
            physicalRepository,
            repositoryAlias,
            join("linked-directory", "external-prompt.md"),
          ],
          [
            repositoryAlias,
            physicalRepository,
            join("linked-directory", "external-prompt.md"),
          ],
        ] as const) {
          let started = false;
          const stderr = capture();
          expect(
            await main(
              ["scan", target, option, input, "--json"],
              capture().stream,
              stderr.stream,
              dependencies({
                currentDirectory: directory,
                onTurn: () => {
                  started = true;
                },
              }),
            ),
          ).toBe(2);
          expect(stderr.text()).toContain("Input files must");
          expect(stderr.text()).not.toContain("SYNTHETIC_EXTERNAL_PROMPT");
          expect(started).toBe(false);
        }

        for (const [directory, target] of [
          [repository, "."],
          [physicalRepository, repositoryAlias],
          [repositoryAlias, physicalRepository],
        ] as const) {
          let selected: unknown;
          expect(
            await main(
              ["scan", target, option, external, "--json"],
              capture().stream,
              capture().stream,
              dependencies({
                currentDirectory: directory,
                onTurn: (_repository, value) => (selected = value),
              }),
            ),
          ).toBe(0);
          expect(selected).toMatchObject({
            [property]: "SYNTHETIC_EXTERNAL_PROMPT\n",
          });
        }
      }
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
        writeFile(
          join(root, "validation.md"),
          "Run the integration fixture.\n",
        ),
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
            "--validation-prompt-file",
            "validation.md",
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
        validationPrompt: "Run the integration fixture.\n",
        postScanPrompt: "Draft confirmed fixes.\n",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not silently drop custom validation on a saved rerun", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-cli-validation-"),
    );
    try {
      await writeFile(
        join(root, "validation.md"),
        "Validate with the fixture.\n",
      );
      let selected: unknown;
      const deps = dependencies({
        currentDirectory: root,
        onTurn: (_repository, value) => {
          selected = value;
        },
        onWorkbench: () => ({
          recipe: {
            repository: root,
            target: { kind: "repository", paths: [] },
            mode: "standard",
            config: {},
            validationMode: "custom",
          },
        }),
      });
      const error = capture();
      expect(
        await main(
          ["scans", "rerun", "saved", "--json"],
          capture().stream,
          error.stream,
          deps,
        ),
      ).toBe(2);
      expect(error.text()).toContain("--validation-prompt-file");
      expect(selected).toBeUndefined();
      expect(
        await main(
          [
            "scans",
            "rerun",
            "saved",
            "--validation-prompt-file",
            "validation.md",
            "--json",
          ],
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(0);
      expect(selected).toMatchObject({
        validationPrompt: "Validate with the fixture.\n",
      });
      await writeFile(join(root, "validation.md"), " \n");
      expect(
        await main(
          ["scan", ".", "--validation-prompt-file", "validation.md", "--json"],
          capture().stream,
          capture().stream,
          deps,
        ),
      ).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
