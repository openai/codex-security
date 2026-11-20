import { expect, test } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

async function initialize(directory: string) {
  const git = initializePatchGit(directory);
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
  const outcome = await runIssuePatch(root, {
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

test.each([
  ["scan", "checkout"],
  ["patch", "checkout"],
  ["patch", "inherited"],
])(
  "%s publication skips the %s fsmonitor during preflight and commit",
  async (command, source) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-publication-fsmonitor-");
    const effect = join(support, "callback");
    const hook = join(directory, "monitor.cjs");
    const script = (phase: string) =>
      `require("node:fs").writeFileSync(${JSON.stringify(effect)}, ${JSON.stringify(phase)}); process.stdout.write("\\0");`;
    await writeFile(hook, script("preflight"));
    git("add", "monitor.cjs");
    git("commit", "-m", "Synthetic filesystem monitor");
    const quoted = (path: string) => JSON.stringify(path.replaceAll("\\", "/"));
    const monitor = `${quoted(process.execPath)} ${quoted(hook)}`;
    git("config", "core.fsmonitor", monitor);
    const environment =
      source === "inherited"
        ? {
            GIT_CONFIG_PARAMETERS: `'core.fsmonitor'='${monitor.replaceAll("'", "'\\''")}'`,
            GIT_ALLOW_PROTOCOL: "file",
          }
        : {};
    git("status", "--porcelain");
    expect(await readFile(effect, "utf8")).toBe("preflight");
    await rm(effect);
    let beforeTurn: string | undefined;
    const result = await runWorkflow(
      command === "patch"
        ? ["patch", "Synthetic issue", "--create-pr", "--json"]
        : ["scan", directory, "--patch", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        result: resultWithFindings(["high"]),
        onCodex: async (args, output) => {
          beforeTurn = await readFile(effect, "utf8").catch(() => undefined);
          await rm(effect, { force: true });
          await writeFile(hook, script("publication"));
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          if (command === "scan") completePatches(args, output);
          else output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
        onRepositoryCommand: (tool, args, cwd, options) =>
          tool === "git"
            ? runGitRepositoryCommand(tool, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              })
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect([
      beforeTurn,
      await readFile(effect, "utf8").catch(() => undefined),
    ]).toEqual([undefined, undefined]);
    expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
  },
);
