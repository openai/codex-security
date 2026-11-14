import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  { included: false, replaced: false, introduced: false },
  { included: true, replaced: false, introduced: false },
  { included: true, replaced: true, introduced: false },
  { included: false, replaced: false, introduced: true },
])(
  "patches ordinary tracked data containing bare Git fixtures (included config: $included, replaced: $replaced, introduced child: $introduced)",
  async ({ included, replaced, introduced }) => {
    const root = await fixtures.create("patch-bare-fixture-");
    const source = join(root, "source");
    const child = join(source, "child");
    await mkdir(child, { recursive: true });
    const app = join(root, "app.ts");
    const nestedApp = join(source, "app.ts");
    const configuration = join(source, "bare-settings");
    await writeFile(app, "before\n");
    await writeFile(nestedApp, "ordinary source\n");
    await writeFile(join(child, "input.ts"), "child source\n");
    if (included) await writeFile(configuration, "[core]\n bare = true\n");
    const git = repositoryGit(root);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    git("add", ".");
    git("commit", "-m", "Synthetic fixture baseline");
    const administration = join(source, ".git");
    git("init", "--bare", "--initial-branch=main", administration);
    if (included) {
      git(
        "--git-dir",
        administration,
        "config",
        "include.path",
        "../bare-settings",
      );
    }
    const initializeChild = () => {
      git("init", "--initial-branch=main", child);
      git("-C", child, "config", "user.name", "Synthetic User");
      git("-C", child, "config", "user.email", "synthetic@example.test");
      git("-C", child, "add", "input.ts");
      git("-C", child, "commit", "-m", "Synthetic child baseline");
    };
    if (!introduced) initializeChild();
    expect(git("-C", source, "rev-parse", "--is-bare-repository")).toBe("true");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const bareHead = await readFile(join(administration, "HEAD"));
    const bareConfig = await readFile(join(administration, "config"));
    let launches = 0;
    const nestedCommands: string[][] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (
          [source, child, administration, join(child, ".git")].some(
            (path) => cwd === path || args.includes(path),
          )
        )
          nestedCommands.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
          administration,
        );
        if (introduced) initializeChild();
        else
          expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
            join(child, ".git"),
          );
        if (included) {
          expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
            configuration,
          );
        }
        if (replaced) {
          await rename(configuration, join(source, "original-settings"));
          await writeFile(configuration, "[core]\n bare = false\n");
        }
        await writeFile(app, "after\n");
        await writeFile(nestedApp, "updated ordinary source\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(nestedCommands).toEqual([]);
    expect(JSON.parse(outcome.stdout).files.sort()).toEqual([
      "app.ts",
      "source/app.ts",
      ...(replaced ? ["source/bare-settings", "source/original-settings"] : []),
    ]);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(administration, "HEAD"))).toEqual(bareHead);
    expect(await readFile(join(administration, "config"))).toEqual(bareConfig);
    expect(await readFile(app, "utf8")).toBe("after\n");
    expect(await readFile(nestedApp, "utf8")).toBe("updated ordinary source\n");
  },
);
