import { mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { runCapturedCli, captureCli } from "./support/cli-run.js";

describe("CLI scan prompts", () => {
  test("loads scan, validation, and post-scan prompt files", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-prompts-",
    );
    const root = temp.path;
    await Promise.all([
      writeFile(join(root, "scan.md"), "Review authentication boundaries.\n"),
      writeFile(join(root, "validation.md"), "Run the integration fixture.\n"),
      writeFile(join(root, "follow-up.md"), "Draft confirmed fixes.\n"),
    ]);
    let options: unknown;
    expect(
      await runCapturedCli(
        main,
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
  });

  test("rejects linked prompt files without rejecting selected external files", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-prompts-",
    );
    const root = temp.path;
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

    const promptFlags = [
      "--scan-prompt-file",
      "--validation-prompt-file",
      "--post-scan-prompt-file",
    ];
    for (const option of promptFlags) {
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
        const onTurn = mock();
        const stderr = captureCli(main, "stderr");
        expect(
          await stderr.run(
            ["scan", target, option, input, "--json"],
            dependencies({
              currentDirectory: directory,
              onTurn,
            }),
          ),
        ).toBe(2);
        expect(stderr.text()).toContain("Input files must");
        expect(stderr.text()).not.toContain("SYNTHETIC_EXTERNAL_PROMPT");
        expect(onTurn).not.toHaveBeenCalled();
      }
    }

    for (const [directory, target] of [
      [repository, "."],
      [physicalRepository, repositoryAlias],
      [repositoryAlias, physicalRepository],
    ] as const) {
      let selected: unknown;
      expect(
        await runCapturedCli(
          main,
          [
            "scan",
            target,
            ...promptFlags.flatMap((flag) => [flag, external]),
            "--json",
          ],
          dependencies({
            currentDirectory: directory,
            onTurn: (_repository, value) => (selected = value),
          }),
        ),
      ).toBe(0);
      expect(selected).toMatchObject({
        scanPrompt: "SYNTHETIC_EXTERNAL_PROMPT\n",
        validationPrompt: "SYNTHETIC_EXTERNAL_PROMPT\n",
        postScanPrompt: "SYNTHETIC_EXTERNAL_PROMPT\n",
      });
    }
  });

  test("combines shared and repository-specific bulk scan prompts", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-prompts-",
    );
    const root = temp.path;
    const repository = join(root, "repository");
    await mkdir(repository);
    git(repository, "init", "-q");
    git(
      repository,
      "commit",
      "--no-gpg-sign",
      "--allow-empty",
      "-qm",
      "initial",
    );
    const revision = git(repository, "rev-parse", "HEAD");
    await Promise.all([
      writeFile(
        join(root, "repositories.csv"),
        `id,repository,revision,prompt\nsample,${repository},${revision},Focus on authorization.\n`,
      ),
      writeFile(join(root, "scan.md"), "Review authentication boundaries.\n"),
      writeFile(join(root, "validation.md"), "Run the integration fixture.\n"),
      writeFile(join(root, "follow-up.md"), "Draft confirmed fixes.\n"),
    ]);
    let options: unknown;
    expect(
      await runCapturedCli(
        main,
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
  });

  test("does not silently drop custom validation on a saved rerun", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-validation-",
    );
    const root = temp.path;
    await writeFile(
      join(root, "validation.md"),
      "Validate with the fixture.\n",
    );
    const onTurn = mock<(repository: string, options: unknown) => void>();
    const deps = dependencies({
      currentDirectory: root,
      onTurn,
      onWorkbench: () => ({
        scanId: "saved",
        recipe: {
          repository: root,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          config: {},
          validationMode: "custom",
        },
      }),
    });
    const error = captureCli(main, "stderr");
    expect(await error.run(["scans", "rerun", "saved", "--json"], deps)).toBe(
      2,
    );
    expect(error.text()).toContain("--validation-prompt-file");
    expect(onTurn.mock.lastCall?.[1]).toBeUndefined();
    expect(
      await runCapturedCli(
        main,
        [
          "scans",
          "rerun",
          "saved",
          "--validation-prompt-file",
          "validation.md",
          "--json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(onTurn.mock.lastCall?.[1]).toMatchObject({
      validationPrompt: "Validate with the fixture.\n",
    });
    await writeFile(join(root, "validation.md"), " \n");
    expect(
      await runCapturedCli(
        main,
        ["scan", ".", "--validation-prompt-file", "validation.md", "--json"],
        deps,
      ),
    ).toBe(2);
  });
});
