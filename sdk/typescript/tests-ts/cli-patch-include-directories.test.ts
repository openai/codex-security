import { afterEach, expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { capturePatchGitControls } from "../src/patch-git-controls.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const mutation of [
  "directory",
  "file",
  "retarget",
  "fixed-directory",
] as const) {
  test(`retains include roles when optional storage is prepared: ${mutation}`, async () => {
    const repository = await fixtures.create("patch-include-storage-");
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    const target = join(repository, "cache-data");
    const alias = join(repository, "cache");
    await mkdir(target);
    await symlink(
      target,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    git(
      "config",
      mutation === "fixed-directory"
        ? "include.path"
        : "includeIf.onbranch:future-branch.path",
      "../cache/objects",
    );
    git("config", "lfs.storage", "../cache");
    const controls = await capturePatchGitControls(
      repository,
      async (_root, checkout, args, options) =>
        runGitRepositoryCommand("git", args, checkout, options),
      true,
    );
    expect(controls!.snapshotStoragePaths).toEqual([]);
    expect(controls!.modelOnlyReadOnlyPaths).toContain(join(target, "objects"));
    const objects = join(target, "objects");
    if (mutation === "file")
      await writeFile(objects, "[core]\n filemode = false\n");
    else if (mutation === "retarget") {
      const replacement = await fixtures.create(
        "patch-include-storage-replacement-",
      );
      await rm(alias, { recursive: true });
      await symlink(
        replacement,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    } else await mkdir(objects);
    if (mutation === "directory") await controls!.validate();
    else
      await expect(controls!.validate()).rejects.toThrow(
        "changed location during the patch",
      );
  });
}

for (const mode of [
  "ordinary edit",
  "rename directory",
  "remove directory",
  "replace directory",
  "becomes config file",
  "active directory",
] as const) {
  test(`preserves Git's directory include behavior: ${mode}`, async () => {
    const root = await fixtures.create("patch-include-directory-");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const directory = join(root, "src");
    const source = join(directory, "app.ts");
    await mkdir(directory);
    await writeFile(source, "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic conditional directory include");
    git(
      "config",
      `includeIf.onbranch:${mode === "active directory" ? "main" : "future-branch"}.path`,
      "../src",
    );
    const head = await readFile(join(root, ".git", "HEAD"));
    const reference = await readFile(
      join(root, ".git", "refs", "heads", "main"),
    );
    const index = await readFile(join(root, ".git", "index"));
    const configuration = await readFile(join(root, ".git", "config"));
    let nativeFailure = "";
    if (mode === "active directory") {
      try {
        git("config", "--includes", "--get-regexp", "^includeif");
        throw new Error(
          "Expected native Git to reject an active directory include",
        );
      } catch (error) {
        const failure = error as Error & { status?: number; stderr?: Buffer };
        expect(failure.status).toBe(128);
        nativeFailure = String(failure.stderr).trim();
        expect(nativeFailure).not.toBe("");
      }
    } else {
      expect(git("config", "--includes", "--get-regexp", "^includeif")).toBe(
        "includeif.onbranch:future-branch.path ../src",
      );
    }
    let launches = 0;
    let controls: readonly string[] = [];
    const afterTurn: string[][] = [];
    const replacement = "[synthetic]\n value = now-a-config-file\n";
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (launches > 0) afterTurn.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
        await writeFile(source, "after\n");
        if (
          mode === "becomes config file" ||
          mode === "rename directory" ||
          mode === "replace directory"
        ) {
          await rename(directory, join(root, "retained-src"));
          if (mode === "becomes config file")
            await writeFile(directory, replacement);
          if (mode === "replace directory") {
            await mkdir(directory);
            await writeFile(source, "replacement source\n");
          }
        }
        if (mode === "remove directory")
          await rm(directory, { recursive: true });
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    if (mode === "active directory") {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(launches).toBe(0);
      for (const line of nativeFailure.split(/\r?\n/u))
        expect(outcome.stderr).toContain(line);
      expect(afterTurn).toEqual([]);
      expect(await readFile(source, "utf8")).toBe("before\n");
    } else {
      expect(launches).toBe(1);
      expect(controls).toContain(join(root, ".git"));
      expect(controls).not.toContain(directory);
      expect(controls).not.toContain(source);
      if (mode !== "becomes config file") {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout).files).toEqual([
          ...(mode === "rename directory" || mode === "replace directory"
            ? ["retained-src/app.ts"]
            : []),
          "src/app.ts",
        ]);
        expect(afterTurn.length).toBeGreaterThan(0);
        if (mode === "rename directory" || mode === "replace directory")
          expect(
            await readFile(join(root, "retained-src", "app.ts"), "utf8"),
          ).toBe("after\n");
        if (mode === "remove directory" || mode === "rename directory")
          await expect(readFile(source)).rejects.toHaveProperty(
            "code",
            "ENOENT",
          );
        else
          expect(await readFile(source, "utf8")).toBe(
            mode === "replace directory" ? "replacement source\n" : "after\n",
          );
      } else {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Git configuration or hooks changed location during the patch",
        );
        expect(afterTurn).toEqual([]);
        expect(
          await readFile(join(root, "retained-src", "app.ts"), "utf8"),
        ).toBe("after\n");
        expect(await readFile(directory, "utf8")).toBe(replacement);
        expect(
          git(
            "-c",
            `includeIf.onbranch:main.path=${directory}`,
            "config",
            "--get",
            "synthetic.value",
          ),
        ).toBe("now-a-config-file");
      }
    }
    expect(await readFile(join(root, ".git", "HEAD"))).toEqual(head);
    expect(await readFile(join(root, ".git", "refs", "heads", "main"))).toEqual(
      reference,
    );
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(root, ".git", "config"))).toEqual(configuration);
  });
}
