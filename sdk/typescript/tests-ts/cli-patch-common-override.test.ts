import { expect, test } from "bun:test";
import {
  cp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join, relative } from "node:path";
import { selectedGitFileReference } from "../src/patch-git-controls.js";
import {
  repositoryGit,
  patchDirectories,
  directoryLinkType,
  initializePatchGit,
  observeIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

async function prepareReplacement(
  source: string,
  replacement: string,
  shared: boolean,
) {
  const lfs = join(source, "lfs");
  if (shared)
    for (const dir of ["objects", "tmp"])
      await mkdir(join(lfs, dir), { recursive: true });
  await cp(source, replacement, { recursive: true });
  if (shared) {
    await rm(join(replacement, "lfs"), { recursive: true });
    await symlink(lfs, join(replacement, "lfs"), directoryLinkType);
  }
}

for (const mode of [
  "absolute",
  "relative",
  "linked file",
  "retargeted",
  "retargeted shared storage",
] as const) {
  test(`retains storage selected through an explicit Git file: ${mode}`, async () => {
    const repository = await fixtures.create("patch-selected-file-");
    const support = await fixtures.create("patch-selected-file-support-");
    const git = initializePatchGit(repository);
    await writeFile(join(repository, "app.ts"), "before\n");
    await writeFile(
      join(repository, ".gitignore"),
      "selected.git\nadmin-alias\noriginal-alias\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic selected file baseline");
    const administration = join(support, "administration");
    await rename(join(repository, ".git"), administration);
    const alias = join(repository, "admin-alias");
    await symlink(administration, alias, directoryLinkType);
    const marker = join(repository, "selected.git");
    const contents = "gitdir: admin-alias\n";
    if (mode === "linked file") {
      await cp(administration, join(support, "admin-alias"), {
        recursive: true,
      });
      const source = join(support, "selected.git");
      await writeFile(source, contents);
      await symlink(source, marker, "file");
    } else await writeFile(marker, contents);
    // The explicitly selected Git file makes this unrelated marker inactive.
    await writeFile(
      join(repository, ".git"),
      "gitdir: missing-administration\n",
    );
    const component = join(repository, "component");
    await mkdir(component);
    const currentDirectory = mode === "relative" ? component : repository;
    const environment = {
      GIT_DIR: (mode === "relative"
        ? relative(component, marker)
        : marker
      ).replaceAll("\\", "/"),
      GIT_WORK_TREE: repository,
    };
    const selectedGit = repositoryGit(currentDirectory, environment);
    selectedGit("config", "lfs.storage", join(alias, "lfs"));
    expect(
      await selectedGitFileReference(marker, await realpath(administration)),
    ).toBe(alias);
    expect(await selectedGitFileReference(marker, repository)).toBeUndefined();
    const head = selectedGit("rev-parse", "HEAD");
    const index = await readFile(join(administration, "index"));
    const replacement = join(support, "replacement");
    const retargeted = mode.startsWith("retargeted");
    const shared = mode === "retargeted shared storage";
    if (retargeted)
      await prepareReplacement(administration, replacement, shared);
    const { outcome } = await observeIssuePatch(
      currentDirectory,
      async (output) => {
        expect(output!.appServer!.snapshotStoragePaths).toEqual([
          join(administration, "lfs"),
        ]);
        expect(output!.appServer!.permissions!.readOnlyPaths).not.toContain(
          marker,
        );
        if (retargeted) {
          await rename(alias, join(repository, "original-alias"));
          await symlink(replacement, alias, directoryLinkType);
          if (shared) {
            expect(
              await realpath(selectedGit("rev-parse", "--absolute-git-dir")),
            ).toBe(await realpath(replacement));
            expect(await realpath(join(alias, "lfs"))).toBe(
              join(administration, "lfs"),
            );
          }
        }
        await writeFile(join(repository, "app.ts"), "after\n");
      },
      environment,
    );
    expect(outcome.exitCode, outcome.stderr).toBe(retargeted ? 2 : 0);
    if (retargeted)
      expect(outcome.stderr).toContain("changed location during the patch");
    else expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readFile(marker, "utf8")).toBe(contents);
    expect(await readFile(join(administration, "index"))).toEqual(index);
    expect(git("--git-dir", administration, "rev-parse", "HEAD")).toBe(head);
  });
}

for (const mode of [
  "implicit absolute",
  "implicit relative",
  "implicit retargeted",
  "implicit retargeted shared storage",
  "overridden alias",
  "overridden missing",
] as const) {
  test(`retains selected common-directory storage under explicit GIT_DIR: ${mode}`, async () => {
    const main = await fixtures.create("patch-common-storage-main-");
    const selected = await fixtures.create("patch-common-storage-selected-");
    const git = initializePatchGit(main);
    await writeFile(join(main, "app.ts"), "before\n");
    git("add", "app.ts");
    git("commit", "-m", "Synthetic common storage baseline");
    git("worktree", "add", "--detach", selected);
    const administration = await realpath(
      repositoryGit(selected)("rev-parse", "--absolute-git-dir"),
    );
    const common = await realpath(join(main, ".git"));
    const alias = join(selected, "common-alias");
    await symlink(common, alias, directoryLinkType);
    await writeFile(
      join(common, "info", "exclude"),
      "common-alias\noriginal-common-alias\n",
    );
    const reference =
      mode === "implicit relative"
        ? relative(administration, alias)
        : mode === "overridden missing"
          ? join(selected, "missing-common")
          : alias;
    const marker = `${reference.replaceAll("\\", "/")}\n`;
    await writeFile(join(administration, "commondir"), marker);
    const overridden = mode.startsWith("overridden");
    const environment = {
      GIT_DIR: administration,
      GIT_WORK_TREE: selected,
      ...(overridden ? { GIT_COMMON_DIR: common } : {}),
    };
    git(
      "config",
      "lfs.storage",
      join(mode === "overridden missing" ? common : alias, "lfs"),
    );
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(administration, "index"));
    const replacement = await fixtures.create("patch-common-replacement-");
    const retargeted = mode.startsWith("implicit retargeted");
    const shared = mode === "implicit retargeted shared storage";
    const selectedGit = repositoryGit(selected, environment);
    if (retargeted) await prepareReplacement(common, replacement, shared);
    const { outcome, launches } = await observeIssuePatch(
      selected,
      async (output) => {
        expect(output!.appServer!.snapshotStoragePaths).toEqual(
          mode === "overridden alias" ? [] : [join(common, "lfs")],
        );
        expect(output!.appServer!.permissions!.readOnlyPaths).toContain(common);
        if (retargeted) {
          await rename(alias, join(selected, "original-common-alias"));
          await symlink(replacement, alias, directoryLinkType);
          if (shared) {
            const bound = selectedGit(
              "rev-parse",
              "--path-format=absolute",
              "--git-common-dir",
            );
            expect(await realpath(bound)).toBe(await realpath(replacement));
            expect(await realpath(join(alias, "lfs"))).toBe(
              join(common, "lfs"),
            );
          }
        }
        await writeFile(join(selected, "app.ts"), "after\n");
      },
      environment,
    );
    expect(launches).toBe(1);
    expect(outcome.exitCode, outcome.stderr).toBe(retargeted ? 2 : 0);
    if (retargeted)
      expect(outcome.stderr).toContain("changed location during the patch");
    else expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readFile(join(administration, "commondir"), "utf8")).toBe(
      marker,
    );
    expect(await readFile(join(administration, "index"))).toEqual(index);
    expect(git("rev-parse", "HEAD")).toBe(head);
  });
}

test.each([
  { relativeCommon: false, rebind: false },
  { relativeCommon: true, rebind: false },
  { relativeCommon: false, rebind: true },
])(
  "honors a common-directory override without losing marker binding (relative: $relativeCommon, rebound: $rebind)",
  async ({ relativeCommon, rebind }) => {
    const main = await fixtures.create("patch-common-main-");
    const selected = await fixtures.create("patch-common-selected-");
    const other = await fixtures.create("patch-common-other-");
    const git = initializePatchGit(main);
    await writeFile(join(main, "app.ts"), "before\n");
    git("add", "app.ts");
    git("commit", "-m", "Synthetic common-directory baseline");
    git("worktree", "add", "--detach", selected);
    git("worktree", "add", "--detach", other);
    const administration = await realpath(
      repositoryGit(selected)("rev-parse", "--absolute-git-dir"),
    );
    const otherAdministration = await realpath(
      repositoryGit(other)("rev-parse", "--absolute-git-dir"),
    );
    const common = await realpath(join(main, ".git"));
    const stale = "../../../missing-common\n";
    await writeFile(join(administration, "commondir"), stale);
    const environment = {
      GIT_COMMON_DIR: relativeCommon ? relative(selected, common) : common,
    };
    const selectedGit = repositoryGit(selected, environment);
    expect(selectedGit("status", "--porcelain")).toBe("");
    const head = selectedGit("rev-parse", "HEAD");
    const index = await readFile(join(administration, "index"));
    const otherIndex = await readFile(join(otherAdministration, "index"));
    const otherContents = await readFile(join(other, "app.ts"));
    const selectedMarker = await readFile(join(selected, ".git"));
    const otherMarker = await readFile(join(other, ".git"));
    const {
      outcome,
      launches,
      afterTurn: afterTurnCommands,
    } = await observeIssuePatch(
      selected,
      async (output) => {
        expect(output?.appServer?.permissions?.readOnlyPaths).toContain(
          administration,
        );
        expect(output?.appServer?.permissions?.readOnlyPaths).toContain(common);
        if (rebind) await writeFile(join(selected, ".git"), otherMarker);
        await writeFile(join(selected, "app.ts"), "after\n");
      },
      environment,
    );
    expect(outcome.exitCode, outcome.stderr).toBe(rebind ? 2 : 0);
    expect(launches).toBe(1);
    if (rebind) {
      expect(outcome.stderr).toContain(
        "Selected Git administration changed during the patch",
      );
      expect(
        afterTurnCommands.filter((args) =>
          args.some((arg) =>
            ["add", "read-tree", "update-index", "write-tree"].includes(arg),
          ),
        ),
      ).toEqual([]);
    } else {
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readFile(join(selected, ".git"))).toEqual(selectedMarker);
    }
    expect(selectedGit("--git-dir", administration, "rev-parse", "HEAD")).toBe(
      head,
    );
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(repositoryGit(other)("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(administration, "index"))).toEqual(index);
    expect(await readFile(join(otherAdministration, "index"))).toEqual(
      otherIndex,
    );
    expect(await readFile(join(administration, "commondir"), "utf8")).toBe(
      stale,
    );
    expect(await readFile(join(selected, "app.ts"), "utf8")).toBe("after\n");
    expect(await readFile(join(other, "app.ts"))).toEqual(otherContents);
  },
);

for (const selector of ["GIT_DIR", "GIT_COMMON_DIR"] as const) {
  test.each([{ retarget: false }, { retarget: true }])(
    `binds an explicit ${selector} alias when config is absent (retargeted: $retarget)`,
    async ({ retarget }) => {
      const root = await fixtures.create("patch-selector-alias-");
      const support = await fixtures.create("patch-selector-support-");
      const git = initializePatchGit(root);
      await writeFile(join(root, "app.ts"), "before\n");
      await writeFile(
        join(root, ".gitignore"),
        "selected-administration\noriginal-administration\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic selector baseline");
      const replacement = join(support, "replacement");
      await cp(join(root, ".git"), replacement, { recursive: true });
      await unlink(join(root, ".git", "config"));
      const hooks = join(root, "operator-hooks");
      await mkdir(hooks);
      const effect = join(support, "hook-effect");
      const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
      await writeFile(
        join(hooks, "post-index-change"),
        `#!/bin/sh\nprintf effect > ${shellPath}\n`,
        { mode: 0o755 },
      );
      git("--git-dir", replacement, "config", "core.hooksPath", hooks);
      for (const flag of ["--assume-unchanged", "--no-assume-unchanged"])
        git(
          "--git-dir",
          replacement,
          "--work-tree",
          root,
          "update-index",
          flag,
          "app.ts",
        );
      expect(await readFile(effect, "utf8")).toBe("effect");
      await unlink(effect);
      const alias = join(root, "selected-administration");
      await symlink(join(root, ".git"), alias, directoryLinkType);
      const environment = {
        [selector]: alias,
        ...(selector === "GIT_DIR" ? { GIT_WORK_TREE: root } : {}),
      };
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const otherIndex = await readFile(join(replacement, "index"));
      const {
        outcome,
        launches,
        afterTurn: afterTurnCommands,
      } = await observeIssuePatch(
        root,
        async () => {
          if (retarget) {
            await rename(alias, join(root, "original-administration"));
            await symlink(replacement, alias, directoryLinkType);
          }
          await writeFile(join(root, "app.ts"), "after\n");
        },
        environment,
      );
      expect(outcome.exitCode, outcome.stderr).toBe(retarget ? 2 : 0);
      expect(launches).toBe(1);
      if (retarget) {
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(outcome.stderr).toContain(alias);
        expect(afterTurnCommands).toEqual([]);
      } else expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(replacement, "index"))).toEqual(otherIndex);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}
