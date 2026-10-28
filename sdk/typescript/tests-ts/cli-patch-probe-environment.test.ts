import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { lstat, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runGitRepositoryCommand, runWorkflow } from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each(["GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY"] as const)(
  "patch discovery preserves %s while treating ordinary nested source as data",
  async (setting) => {
    const root = await fixtures.create("patch-probe-environment-");
    const support = await fixtures.create("patch-probe-administration-");
    const globalConfig = join(support, "global-config");
    await writeFile(globalConfig, "");
    const environment = {
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: globalConfig,
      LC_ALL: "C",
    };
    const git = (args: string[], overrides: NodeJS.ProcessEnv = {}) =>
      execFileSync("git", args, {
        cwd: root,
        env: { ...process.env, ...environment, ...overrides },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    git(["init", "--initial-branch=main"]);
    git(["config", "user.name", "Synthetic User"]);
    git(["config", "user.email", "synthetic@example.test"]);
    const marker = join(root, "source", ".git");
    await mkdir(marker, { recursive: true });
    const markerHead = "ref: refs/heads/main\n";
    await writeFile(join(marker, "HEAD"), markerHead);
    if (setting === "GIT_OBJECT_DIRECTORY") await mkdir(join(marker, "refs"));
    const source = join(root, "source", "app.ts");
    await writeFile(source, "before\n");
    git(["add", "source/app.ts"]);
    git(["commit", "-m", "Synthetic environment baseline"]);
    const head = git(["rev-parse", "HEAD"]);
    const index = await readFile(join(root, ".git", "index"));
    const selectedPath =
      setting === "GIT_COMMON_DIR"
        ? join(root, ".git")
        : join(support, "selected-objects");
    if (setting === "GIT_OBJECT_DIRECTORY") {
      await rename(join(root, ".git", "objects"), selectedPath);
    }
    const selectedEnvironment: NodeJS.ProcessEnv = {
      ...environment,
      [setting]: selectedPath,
    };
    if (setting === "GIT_OBJECT_DIRECTORY")
      expect(() => git(["rev-parse", "HEAD"])).toThrow();
    expect(git(["rev-parse", "HEAD"], selectedEnvironment)).toBe(head);
    expect(() => git(["rev-parse", "--resolve-git-dir", marker])).toThrow();
    expect(
      resolve(
        git(["rev-parse", "--resolve-git-dir", marker], selectedEnvironment),
      ),
    ).toBe(marker);

    const nested = join(root, "source");
    let nestedHead: string | undefined;
    let nestedIndex: Buffer<ArrayBuffer> | undefined;
    if (setting === "GIT_OBJECT_DIRECTORY") {
      git(
        ["-C", nested, "config", "user.name", "Synthetic User"],
        selectedEnvironment,
      );
      git(
        ["-C", nested, "config", "user.email", "synthetic@example.test"],
        selectedEnvironment,
      );
      git(["-C", nested, "add", "app.ts"], selectedEnvironment);
      git(
        ["-C", nested, "commit", "-m", "Synthetic shared object baseline"],
        selectedEnvironment,
      );
      nestedHead = git(
        ["-C", nested, "rev-parse", "HEAD"],
        selectedEnvironment,
      );
      nestedIndex = await readFile(join(marker, "index"));
      expect(() => git(["-C", nested, "rev-parse", "HEAD"])).toThrow();
      await expect(lstat(join(marker, "objects"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    }

    let launches = 0;
    let rootCommands = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      environment: selectedEnvironment,
      onRepositoryCommand: (command, args, cwd, options) => {
        const effectiveEnvironment = {
          ...selectedEnvironment,
          ...options?.environment,
        };
        const objectDirectoryProbe =
          args.join(" ") ===
            "rev-parse --path-format=absolute --git-path objects" &&
          options?.environment?.["GIT_OBJECT_DIRECTORY"] === ".";
        if (
          !args.includes("--resolve-git-dir") &&
          !args.includes("-C") &&
          !objectDirectoryProbe
        ) {
          expect(effectiveEnvironment[setting]).toBeDefined();
          expect(
            resolve(options?.directory ?? cwd, effectiveEnvironment[setting]!),
          ).toBe(selectedPath);
          rootCommands++;
        }
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: effectiveEnvironment,
        });
      },
      onCodex: async (_args, output) => {
        launches++;
        const controls = output?.appServer?.permissions?.readOnlyPaths;
        expect(controls).toBeDefined();
        expect(controls).not.toContain(marker);
        await writeFile(source, "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(rootCommands).toBeGreaterThan(0);
    expect(await readFile(source, "utf8")).toBe("after\n");
    expect(await readFile(join(marker, "HEAD"), "utf8")).toBe(markerHead);
    expect(git(["rev-parse", "HEAD"], selectedEnvironment)).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    if (setting === "GIT_OBJECT_DIRECTORY") {
      expect(
        git(["-C", nested, "rev-parse", "HEAD"], selectedEnvironment),
      ).toBe(nestedHead!);
      expect(await readFile(join(marker, "index"))).toEqual(nestedIndex!);
      await expect(lstat(join(marker, "objects"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  },
);
