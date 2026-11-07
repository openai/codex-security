import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawn } from "node:child_process";
import {
  lstat,
  mkdir,
  readFile,
  readlink,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function runBounded(script: string, cwd: string) {
  const child = spawn(process.execPath, ["test", script], {
    cwd,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let timedOut = false;
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  // Kill the whole synthetic process group if native Git regresses to a blocking read.
  const timer = setTimeout(() => {
    timedOut = true;
    process.kill(-child.pid!, "SIGKILL");
  }, 10_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    return { code, stdout, stderr, timedOut };
  } finally {
    clearTimeout(timer);
  }
}

for (const name of [
  "HEAD",
  "commondir",
  "config",
  "config.worktree",
  "included-config",
] as const) {
  for (const introduced of [false, true]) {
    test.skipIf(process.platform === "win32")(
      `patch leaves a ${name} FIFO in ordinary tracked fixture data unread (introduced during turn: ${introduced})`,
      async () => {
        const root = await fixtures.create("patch-special-metadata-");
        const support = await fixtures.create("patch-special-metadata-probe-");
        const nested = join(root, "source");
        await mkdir(nested);
        await writeFile(join(root, "app.ts"), "before\n");
        await writeFile(join(nested, "input.ts"), "fixture source\n");
        const git = repositoryGit(root);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("add", ".");
        git("commit", "-m", "Synthetic outer baseline");
        const nestedGit = repositoryGit(nested);
        nestedGit("init", "--initial-branch=main");
        nestedGit("config", "user.name", "Synthetic User");
        nestedGit("config", "user.email", "synthetic@example.test");
        nestedGit("add", ".");
        nestedGit("commit", "-m", "Synthetic nested baseline");
        const metadata = join(nested, ".git");
        const hook = join(metadata, "hooks", "synthetic-fsmonitor");
        await writeFile(
          hook,
          "#!/bin/sh\nprintf effect > hook-effect\nprintf '\\0'\n",
          { mode: 0o755 },
        );
        nestedGit("config", "core.fsmonitor", hook);
        if (name === "config.worktree")
          nestedGit("config", "extensions.worktreeConfig", "true");
        if (name === "included-config")
          nestedGit("config", "include.path", name);
        const index = await readFile(join(root, ".git", "index"));
        const nestedIndex = await readFile(join(metadata, "index"));
        const head = git("rev-parse", "HEAD");
        const saved = join(support, "administration");
        const moveAdministration = name === "HEAD" || name === "commondir";
        if (introduced && moveAdministration) await rename(metadata, saved);
        else if (!introduced) {
          if (name === "HEAD" || name === "config")
            await unlink(join(metadata, name));
          execFileSync("mkfifo", [join(metadata, name)]);
        }
        const script = join(support, "probe.test.ts");
        await writeFile(
          script,
          `
import { test } from "bun:test";
import { execFileSync } from "node:child_process";
import { rename, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runWorkflow, runGitRepositoryCommand } from ${JSON.stringify(new URL("./cli-patch-fixtures.ts", import.meta.url).href)};
const root = ${JSON.stringify(root)};
const nested = ${JSON.stringify(nested)};
const metadata = ${JSON.stringify(metadata)};
test("bounded special metadata probe", async () => {
let launches = 0;
const nestedCommands = [];
let controls = [];
process.stdout.write("PROBE_READY\\n");
const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
  currentDirectory: root,
  onRepositoryCommand: (command, args, cwd, options) => {
    if (args.some((arg) => arg === nested || arg.startsWith(metadata))) nestedCommands.push({ cwd, args });
    return runGitRepositoryCommand(command, args, cwd, options);
  },
  onCodex: async (_args, output) => {
    launches++;
    controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
    if (${introduced}) {
      if (${moveAdministration}) await rename(${JSON.stringify(saved)}, metadata);
      if (["HEAD", "config"].includes(${JSON.stringify(name)})) await unlink(join(metadata, ${JSON.stringify(name)}));
      execFileSync("mkfifo", [join(metadata, ${JSON.stringify(name)})]);
    }
    await writeFile(join(root, "app.ts"), "after\\n");
    output?.stdout.write("Synthetic patch complete.\\n");
    return 0;
  },
});
process.stdout.write(JSON.stringify({ ...outcome, launches, nestedCommands, controls }));
}, 30_000);
`,
        );
        const result = await runBounded(script, root);
        const readyMarker = "PROBE_READY\n";
        const readyOffset = result.stdout.indexOf(readyMarker);
        expect(readyOffset, result.stderr).toBeGreaterThanOrEqual(0);
        expect(result.timedOut, result.stderr).toBe(false);
        expect(result.code, result.stderr).toBe(0);
        const outcome: Awaited<ReturnType<typeof runWorkflow>> & {
          launches: number;
          nestedCommands: { cwd: string; args: string[] }[];
          controls: string[];
        } = JSON.parse(result.stdout.slice(readyOffset + readyMarker.length));
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(outcome.launches).toBe(1);
        expect(outcome.nestedCommands).toEqual([]);
        expect(outcome.controls).not.toContain(metadata);
        expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
        expect((await lstat(join(metadata, name))).isFIFO()).toBe(true);
        expect(
          await readFile(join(nested, "hook-effect")).catch(() => null),
        ).toBeNull();
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(root, ".git", "index"))).toEqual(index);
        expect(await readFile(join(metadata, "index"))).toEqual(nestedIndex);
        expect(await readFile(join(nested, "input.ts"), "utf8")).toBe(
          "fixture source\n",
        );
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
      },
      15_000,
    );
  }
}

test.skipIf(process.platform === "win32")(
  "patch accepts an empty nested Git configuration supplied by /dev/null",
  async () => {
    const root = await fixtures.create("patch-empty-device-config-");
    const nested = join(root, "source");
    await mkdir(nested);
    await writeFile(join(root, "app.ts"), "before\n");
    await writeFile(join(nested, "input.ts"), "fixture source\n");
    const initialize = (directory: string) => {
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("add", ".");
      git("commit", "-m", "Synthetic device config baseline");
      return git;
    };
    const git = initialize(root);
    const nestedGit = initialize(nested);
    const config = join(nested, ".git", "config");
    await unlink(config);
    await symlink("/dev/null", config);
    expect(nestedGit("rev-parse", "--show-toplevel")).toBe(nested);
    const head = git("rev-parse", "HEAD");
    const nestedHead = nestedGit("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const nestedIndex = await readFile(join(nested, ".git", "index"));
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: root,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(root, "app.ts"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readlink(config)).toBe("/dev/null");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(nested, ".git", "index"))).toEqual(nestedIndex);
    expect(await readFile(join(nested, "input.ts"), "utf8")).toBe(
      "fixture source\n",
    );
    expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
  },
);
