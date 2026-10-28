import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function initialize(directory: string) {
  const git = repositoryGit(directory);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  git("add", ".");
  git("commit", "-m", "Synthetic callback baseline");
  return git;
}

test("patch discovery does not execute a workspace fsmonitor rewritten by the model", async () => {
  const root = await fixtures.create("patch-fsmonitor-selected-");
  const output = await fixtures.create("patch-fsmonitor-output-");
  const nested = join(root, "source");
  const hook = join(nested, "monitor.cjs");
  const effect = join(output, "hook-effect");
  const script = (value: string) =>
    `require("node:fs").writeFileSync(${JSON.stringify(effect)}, ${JSON.stringify(value)});\nprocess.stdout.write("\\0");\n`;
  await mkdir(nested);
  await writeFile(join(root, "outer.txt"), "before\n");
  await writeFile(join(nested, "app.ts"), "selected source\n");
  await writeFile(hook, script("operator"));
  await initialize(root);
  const git = await initialize(nested);
  const commandPath = (path: string) =>
    JSON.stringify(path.replaceAll("\\", "/"));
  git(
    "config",
    "core.fsmonitor",
    `${commandPath(process.execPath)} ${commandPath(hook)}`,
  );

  git("ls-files", "--cached");
  expect(await readFile(effect, "utf8")).toBe("operator");
  await rm(effect);
  const head = git("rev-parse", "HEAD");
  const index = await readFile(join(nested, ".git", "index"));
  const nestedInventory: string[][] = [];
  let launches = 0;
  let beforeTurnEffect: string | undefined;
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: root,
    onRepositoryCommand: (command, args, cwd, options) => {
      if (args.includes(nested) && args.includes("ls-files"))
        nestedInventory.push([...args]);
      return runGitRepositoryCommand(command, args, cwd, options);
    },
    onCodex: async (args, streams) => {
      launches++;
      expect(
        args.some((arg) => arg.startsWith("permissions.codex_security_patch=")),
      ).toBe(false);
      expect(streams?.appServer?.permissions?.name).toBe(
        "codex_security_patch",
      );
      expect(streams?.appServer?.permissions?.readOnlyPaths).not.toContain(
        hook,
      );
      beforeTurnEffect = await readFile(effect, "utf8").catch(() => undefined);
      await rm(effect, { force: true });
      await writeFile(hook, script("model-rewritten"));
      await writeFile(join(root, "outer.txt"), "after\n");
      streams?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });

  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(launches).toBe(1);
  expect(nestedInventory).toEqual([]);
  expect(await readFile(effect, "utf8").catch(() => undefined)).toBeUndefined();
  expect(beforeTurnEffect).toBeUndefined();
  expect(await readFile(hook, "utf8")).toBe(script("model-rewritten"));
  expect(await readFile(join(root, "outer.txt"), "utf8")).toBe("after\n");
  expect(git("rev-parse", "HEAD")).toBe(head);
  expect(await readFile(join(nested, ".git", "index"))).toEqual(index);

  git("ls-files", "--cached");
  expect(await readFile(effect, "utf8")).toBe("model-rewritten");
});
