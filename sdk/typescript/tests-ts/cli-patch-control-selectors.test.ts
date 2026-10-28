import { afterEach, expect, test } from "bun:test";
import {
  cp,
  readFile,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const [selector, action] of [
  ["relative", "source"],
  ["absolute", "source"],
  ["common", "source"],
  ["alias", "source"],
  ["relative", "metadata"],
  ["alias", "retarget"],
] as const) {
  test(`protects outside-caller ${selector} Git selectors during ${action} replacement`, async () => {
    const root = await fixtures.create("patch-selector-worktree-");
    const caller = await fixtures.create("patch-selector-caller-");
    const metadata = join(caller, selector === "alias" ? "metadata" : "admin");
    const alias = join(caller, "admin");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main", "--separate-git-dir", metadata);
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(root, "admin"), "ordinary source\n");
    git("add", ".");
    git("commit", "-m", "Synthetic selector baseline");
    if (selector === "alias")
      await symlink(
        metadata,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    const emptyConfig = join(caller, "empty-config");
    await writeFile(emptyConfig, "");
    const environment = {
      GIT_DIR:
        selector === "absolute" || selector === "common" ? metadata : "admin",
      GIT_WORK_TREE: root,
      ...(selector === "common" ? { GIT_COMMON_DIR: "admin" } : {}),
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_CONFIG_SYSTEM: emptyConfig,
    };
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(metadata, "index"));
    const config = await readFile(join(metadata, "config"));
    const replacement = join(caller, "replacement");
    if (action !== "source")
      await cp(metadata, replacement, { recursive: true });
    let launches = 0;
    let controls: readonly string[] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: caller,
      environment,
      onRepositoryCommand: (command, args, cwd, options) =>
        runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        }),
      onCodex: async (_args, output, childEnvironment) => {
        launches++;
        controls = output!.appServer!.permissions!.readOnlyPaths;
        expect(output!.appServer!.directory).toBe(caller);
        expect(childEnvironment?.["GIT_DIR"]).toBe(environment.GIT_DIR);
        expect(childEnvironment?.["GIT_WORK_TREE"]).toBe(root);
        await writeFile(join(root, "admin.new"), "updated source\n");
        await rename(join(root, "admin.new"), join(root, "admin"));
        if (action === "metadata") {
          await rename(metadata, join(caller, "original-metadata"));
          await rename(replacement, metadata);
        } else if (action === "retarget") {
          await unlink(alias);
          await symlink(
            replacement,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
        }
        output!.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(launches).toBe(1);
    expect(controls).toContain(metadata);
    expect(controls).toContain(join(metadata, "config"));
    expect(await readFile(join(root, "admin"), "utf8")).toBe(
      "updated source\n",
    );
    expect(await readFile(join(metadata, "index"))).toEqual(index);
    expect(await readFile(join(metadata, "config"))).toEqual(config);
    expect(git("rev-parse", "HEAD")).toBe(head);
    if (action === "source") {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(controls).not.toContain(join(root, "admin"));
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["admin"],
      });
    } else {
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        action === "metadata"
          ? "Selected Git administration changed during the patch"
          : "Git configuration or hooks changed location during the patch",
      );
    }
  });
}
