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
import { join, relative, resolve, sep } from "node:path";
import { selectedGitFileReference } from "../src/patch-git-controls.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  patchDirectories,
  directoryLinkType,
  initializePatchGit,
  runIssuePatch,
  observeIssuePatch,
  gitWithEnvironment,
  completePatches,
  patchRiskAssessment,
  publicationRepository,
  resultWithFindings,
  runWorkflow,
  savedScan,
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
      let launches = 0;
      const afterTurnCommands: string[][] = [];
      const runGit = gitWithEnvironment(environment);
      const outcome = await runIssuePatch(root, {
        environment,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (launches > 0) {
            afterTurnCommands.push([...args]);
            if (command === "git" && selector === "GIT_COMMON_DIR") {
              const boundCommon = options?.environment?.["GIT_COMMON_DIR"];
              expect(boundCommon).toBeDefined();
              expect(resolve(boundCommon!)).toBe(join(root, ".git"));
            }
          }
          return runGit(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          launches++;
          if (retarget) {
            await rename(alias, join(root, "original-administration"));
            await symlink(replacement, alias, directoryLinkType);
          }
          await writeFile(join(root, "app.ts"), "after\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(retarget ? 2 : 0);
      expect(launches).toBe(1);
      if (retarget) {
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(outcome.stderr).toContain(alias);
        expect(afterTurnCommands).toEqual([]);
      } else {
        expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      }
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(replacement, "index"))).toEqual(otherIndex);
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}

async function writeGitMarker(
  administration: string,
  marker: string,
  contents: string,
  linked: boolean,
) {
  if (!linked) return writeFile(marker, contents);
  const support = await fixtures.create("patch-selected-file-source-");
  await mkdir(join(support, "nested"));
  await cp(administration, join(support, "admin-alias"), { recursive: true });
  const source = join(support, "nested", "source.git");
  await writeFile(source, contents);
  await symlink(source, marker, "file");
}

async function expectSuccessiveStoragePatches(
  directory: string,
  environment: NodeJS.ProcessEnv,
  administration: string,
  common = administration,
  removedAfterFirst?: string,
) {
  const git = repositoryGit(directory);
  const runGit = gitWithEnvironment(environment);
  const originalHead = git("rev-parse", "HEAD");
  const originalIndex = await readFile(join(administration, "index"));
  const result = resultWithFindings(["high", "high"]);
  const grants: string[][] = [];
  const boundCommonDirectories = new Set<string>();
  const outcome = await runWorkflow(["patch", "--scan", "scan-1", "--json"], {
    currentDirectory: directory,
    environment,
    result,
    onWorkbench: () => savedScan(result, "scan-1", directory),
    onRepositoryCommand: (command, args, cwd, options) => {
      const value = options?.environment?.["GIT_COMMON_DIR"];
      if (value !== undefined)
        boundCommonDirectories.add(value.replaceAll(sep, "/"));
      return runGit(command, args, cwd, options);
    },
    onCodex: async (args, output) => {
      grants.push([...(output!.appServer!.snapshotStoragePaths ?? [])]);
      expect(output!.appServer!.permissions!.modelOnlyReadOnlyPaths).toEqual([
        join(common, "lfs", "objects"),
        join(common, "lfs", "tmp"),
      ]);
      const findings = completePatches(args, output);
      expect(findings).toHaveLength(1);
      await writeFile(
        join(directory, findings[0]!.locations[0]!.path),
        `fixed ${grants.length}\n`,
      );
      if (removedAfterFirst && grants.length === 1)
        await rm(removedAfterFirst, { recursive: true });
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(grants).toEqual([1, 2].map(() => [join(common, "lfs")]));
  expect(boundCommonDirectories).toEqual(
    new Set(
      environment["GIT_COMMON_DIR"] !== undefined
        ? [common.replaceAll(sep, "/")]
        : [],
    ),
  );
  expect(JSON.parse(outcome.stdout)).toMatchObject({
    files: ["src/finding-1.ts", "src/finding-2.ts"],
    filesChanged: 2,
  });
  expect(git("rev-parse", "HEAD")).toBe(originalHead);
  expect(await readFile(join(administration, "index"))).toEqual(originalIndex);
  expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
    "fixed 1\n",
  );
  expect(await readFile(join(directory, "src/finding-2.ts"), "utf8")).toBe(
    "fixed 2\n",
  );
}

test.each(["absolute", "relative"] as const)(
  "preserves selected common-directory aliases across finding patches: %s",
  async (selection) => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "src/finding-2.ts"), "original second\n");
    await writeFile(join(directory, ".gitignore"), "administration-alias\n");
    git("add", ".");
    git("commit", "-m", "Synthetic successive patch baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "administration-alias");
    await symlink(administration, alias, directoryLinkType);
    git("config", "lfs.storage", join(alias, "lfs"));
    const environment = {
      GIT_COMMON_DIR: selection === "absolute" ? alias : "administration-alias",
    };
    await expectSuccessiveStoragePatches(
      directory,
      environment,
      administration,
    );
  },
);

for (const selection of [
  "absolute",
  "removed marker directory",
  "linked file in removed marker directory",
  "common override",
] as const) {
  test(`preserves selected Git-file aliases across finding patches: ${selection}`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "src/finding-2.ts"), "original second\n");
    await writeFile(
      join(directory, ".gitignore"),
      "component/\nadmin-alias\ncommon-alias\nselected.git\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic successive Git-file baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "admin-alias");
    await symlink(administration, alias, directoryLinkType);
    const component = join(directory, "component");
    await mkdir(component);
    const removeMarker = selection.includes("removed marker directory");
    const markerDirectory = removeMarker ? component : directory;
    const marker = join(markerDirectory, "selected.git");
    const contents = `gitdir: ${removeMarker ? "../" : ""}admin-alias\n`;
    await writeGitMarker(
      administration,
      marker,
      contents,
      selection === "linked file in removed marker directory",
    );
    let common = administration;
    let storageAlias = alias;
    if (selection === "common override") {
      common = join(
        await fixtures.create("patch-selected-common-"),
        "metadata",
      );
      await cp(administration, common, { recursive: true });
      storageAlias = join(directory, "common-alias");
      await symlink(common, storageAlias, directoryLinkType);
    }
    const environment = {
      GIT_DIR: (selection === "absolute"
        ? marker
        : relative(directory, marker)
      ).replaceAll(sep, "/"),
      GIT_WORK_TREE: directory,
      ...(selection === "common override"
        ? { GIT_COMMON_DIR: storageAlias }
        : {}),
    };
    const selectedGit = (args: string[]) =>
      runGitRepositoryCommand("git", args, directory, {
        directory,
        environment,
      });
    expect(
      (await selectedGit(["rev-parse", "--absolute-git-dir"])).replaceAll(
        sep,
        "/",
      ),
    ).toBe(administration.replaceAll(sep, "/"));
    await selectedGit(["config", "lfs.storage", join(storageAlias, "lfs")]);
    await expectSuccessiveStoragePatches(
      directory,
      environment,
      administration,
      common,
      removeMarker ? component : undefined,
    );
  });
}

for (const linked of [false, true]) {
  test(`retains selected Git-file storage after removing its caller (linked marker: ${linked})`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const component = join(directory, "component");
    await mkdir(component);
    await writeFile(join(component, "app.ts"), "original component\n");
    await writeFile(
      join(directory, ".gitignore"),
      "admin-alias\ncomponent/selected.git\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic Git-file caller baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "admin-alias");
    await symlink(administration, alias, directoryLinkType);
    git("config", "lfs.storage", join(alias, "lfs"));
    const marker = join(component, "selected.git");
    const contents = "gitdir: ../admin-alias\n";
    await writeGitMarker(administration, marker, contents, linked);
    const environment = { GIT_DIR: "selected.git", GIT_WORK_TREE: directory };
    const originalHead = git("rev-parse", "HEAD");
    const originalIndex = await readFile(join(administration, "index"));
    let turns = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic component issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: component,
        environment,
        onRepositoryCommand: gitWithEnvironment(environment),
        onCodex: async (_args, output) => {
          turns++;
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            expect(output!.appServer!.directory).toBe(directory);
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            expect(output!.appServer!.snapshotStoragePaths).toEqual([
              join(administration, "lfs"),
            ]);
            expect(
              output!.appServer!.permissions!.modelOnlyReadOnlyPaths,
            ).toEqual([
              join(administration, "lfs", "objects"),
              join(administration, "lfs", "tmp"),
            ]);
            expect(output!.appServer!.directory).toBe(component);
            await rm(component, { recursive: true });
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            output!.stdout.write("Synthetic component patch.\n");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(turns).toBe(2);
    expect(git("rev-parse", "HEAD")).toBe(originalHead);
    expect(await readFile(join(administration, "index"))).toEqual(
      originalIndex,
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
    await expect(readFile(join(component, "app.ts"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
}

test("isolates relative credential stores selected from an external Git caller", async () => {
  const { directory } = await publicationRepository(fixtures);
  const caller = await fixtures.create("patch-credential-caller-");
  const environment = {
    GIT_DIR: join(directory, ".git"),
    GIT_WORK_TREE: directory,
    HOME: "home",
    USERPROFILE: "home",
    XDG_CONFIG_HOME: "xdg",
    GIT_CONFIG_GLOBAL: join(caller, "global.gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
  const cookie = "operator-cookies.txt";
  await runGitRepositoryCommand(
    "git",
    [
      "config",
      "--file",
      environment.GIT_CONFIG_GLOBAL,
      "http.cookieFile",
      cookie,
    ],
    caller,
    { environment },
  );
  const stores = [
    { parent: "home", name: ".git-credentials", host: "home.example.invalid" },
    {
      parent: join("xdg", "git"),
      name: "credentials",
      host: "xdg.example.invalid",
    },
  ];
  for (const { parent, name, host } of stores) {
    for (const [root, user] of [
      [caller, "caller"],
      [directory, "worktree"],
    ] as const) {
      await mkdir(join(root, parent), { recursive: true });
      await writeFile(
        join(root, parent, name),
        `https://${user}:fixture@${host}\n`,
      );
    }
    const credential = await runGitRepositoryCommand(
      "git",
      [
        "-c",
        "credential.helper=",
        "-c",
        "credential.helper=store",
        "credential",
        "fill",
      ],
      caller,
      { environment, input: `protocol=https\nhost=${host}\n\n` },
    );
    expect(credential).toContain("username=caller");
  }
  let protectedStores: readonly string[] | undefined;
  const outcome = await runIssuePatch(caller, {
    environment,
    onRepositoryCommand: gitWithEnvironment(environment),
    onCodex: async (_args, output) => {
      protectedStores = output!.appServer!.permissions!.credentialStorePaths;
      await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
      output!.stdout.write("Verified the synthetic patch.");
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  for (const { parent, name } of stores) {
    expect(protectedStores).toContain(join(caller, parent, name));
    expect(protectedStores).not.toContain(join(directory, parent, name));
  }
  for (const root of [caller, directory]) {
    expect(protectedStores).toContain(join(root, cookie));
    for (const store of [".aws/config", ".aws/credentials", ".netrc", "_netrc"])
      expect(protectedStores).toContain(join(root, "home", store));
  }
});
