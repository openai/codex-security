import { expect, test } from "bun:test";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  lstat,
  mkdir,
  readFile,
  readlink,
  rename,
  symlink,
  unlink,
  writeFile,
  cp,
} from "node:fs/promises";
import { join } from "node:path";
import {
  runWorkflow,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

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
        const git = initializePatchGit(root);
        git("add", ".");
        git("commit", "-m", "Synthetic outer baseline");
        const nestedGit = initializePatchGit(nested);
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
      const git = initializePatchGit(directory);
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
    const outcome = await runIssuePatch(root, {
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

for (const layout of [
  "linked-private",
  "selected-common",
  "nested-linked-private",
] as const) {
  test.skipIf(process.platform === "win32")(
    `patch preserves an ignored configuration FIFO in ${layout} Git layout`,
    async () => {
      const root = await fixtures.create("patch-ignored-config-");
      const support = await fixtures.create("patch-ignored-config-probe-");
      const globalConfig = join(support, "global-config");
      await writeFile(globalConfig, "");
      const environment: NodeJS.ProcessEnv = {
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: globalConfig,
        LC_ALL: "C",
      };
      const git = (cwd: string, args: string[]) =>
        execFileSync("git", args, {
          cwd,
          env: { ...process.env, ...environment },
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
          timeout: 3000,
        }).trim();
      git(root, ["init", "--initial-branch=main"]);
      git(root, ["config", "user.name", "Synthetic User"]);
      git(root, ["config", "user.email", "synthetic@example.test"]);
      await writeFile(join(root, "app.ts"), "before\n");
      git(root, ["add", "app.ts"]);
      git(root, ["commit", "-m", "Synthetic configuration baseline"]);
      let selected = root;
      let observed = root;
      if (layout === "linked-private") {
        selected = await fixtures.create("patch-ignored-linked-");
        git(root, ["worktree", "add", "-b", "synthetic-linked", selected]);
        observed = selected;
      } else if (layout === "nested-linked-private") {
        observed = join(root, "nested");
        git(root, ["worktree", "add", "-b", "synthetic-linked", observed]);
        git(root, ["add", "nested"]);
        git(root, ["commit", "-m", "Synthetic linked worktree input"]);
      } else {
        const common = join(support, "common");
        await cp(join(root, ".git"), common, { recursive: true });
        environment["GIT_COMMON_DIR"] = common;
      }
      const administration = git(observed, ["rev-parse", "--absolute-git-dir"]);
      const fifo = join(administration, "config");
      if (layout === "selected-common") await unlink(fifo);
      execFileSync("mkfifo", [fifo]);
      expect(git(selected, ["status", "--porcelain"])).toBe("");
      expect(git(observed, ["status", "--porcelain"])).toBe("");
      const head = git(observed, ["rev-parse", "HEAD"]);
      const index = await readFile(join(administration, "index"));
      const rootHead = git(root, ["rev-parse", "HEAD"]);
      const rootIndex = await readFile(join(root, ".git", "index"));
      if (layout === "selected-common") {
        expect(git(selected, ["rev-parse", "--git-common-dir"])).toBe(
          environment["GIT_COMMON_DIR"]!,
        );
      }
      const script = join(support, "probe.test.ts");
      await writeFile(
        script,
        `
import { test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runWorkflow, runGitRepositoryCommand } from ${JSON.stringify(new URL("./cli-patch-fixtures.ts", import.meta.url).href)};
test("bounded ignored configuration probe", async () => {
  const environment = ${JSON.stringify(environment)};
  let launches = 0;
  let controls = [];
  process.stdout.write("PROBE_READY\\n");
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: ${JSON.stringify(selected)}, environment,
    onRepositoryCommand: (command, args, cwd, options) => runGitRepositoryCommand(command, args, cwd, {
      ...options, environment: { ...environment, ...options?.environment }
    }),
    onCodex: async (_args, output) => {
      launches++;
      controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
      await writeFile(join(${JSON.stringify(selected)}, "app.ts"), "after\\n");
      output?.stdout.write("Synthetic patch complete.\\n");
      return 0;
    }
  });
  process.stdout.write(JSON.stringify({ ...outcome, launches, controls }));
});
`,
      );
      const result = await runBounded(script, selected);
      expect(result.timedOut, result.stderr).toBe(false);
      expect(result.code, result.stderr).toBe(0);
      const marker = "PROBE_READY\n";
      const offset = result.stdout.indexOf(marker);
      expect(offset, result.stderr).toBeGreaterThanOrEqual(0);
      const outcome: Awaited<ReturnType<typeof runWorkflow>> & {
        launches: number;
        controls: string[];
      } = JSON.parse(result.stdout.slice(offset + marker.length));
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(outcome.launches).toBe(1);
      expect(outcome.controls).toContain(administration);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readFile(join(selected, "app.ts"), "utf8")).toBe("after\n");
      expect(git(observed, ["rev-parse", "HEAD"])).toBe(head);
      expect(await readFile(join(administration, "index"))).toEqual(index);
      expect(git(root, ["rev-parse", "HEAD"])).toBe(rootHead);
      expect(await readFile(join(root, ".git", "index"))).toEqual(rootIndex);
      if (layout === "nested-linked-private")
        expect(await readFile(join(observed, "app.ts"), "utf8")).toBe(
          "before\n",
        );
      expect((await lstat(fifo)).isFIFO()).toBe(true);
    },
    15_000,
  );
}

const hasLfs = spawnSync("git", ["lfs", "version"]).status === 0;

for (const used of [false, true]) {
  test.skipIf(used && !hasLfs).each(["file", "file ancestor"])(
    `non-directory LFS storage remains optional when used=${used}: %s`,
    async (mode) => {
      const root = await fixtures.create("patch-nondirectory-lfs-");
      const repository = join(root, "repository");
      await mkdir(repository);
      const git = initializePatchGit(repository);
      git("config", "core.autocrlf", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (used) {
        git("lfs", "install", "--local", "--skip-repo");
        await writeFile(
          join(repository, ".gitattributes"),
          "*.bin filter=lfs diff=lfs merge=lfs -text\n",
        );
      }
      git("add", ".");
      git("commit", "-m", "Synthetic optional storage baseline");
      const blocker = join(root, "cache-file");
      const contents = "Synthetic ordinary file\n";
      await writeFile(blocker, contents);
      const storage = mode === "file" ? blocker : join(blocker, "storage");
      git("config", "lfs.storage", storage);
      const config = await readFile(join(repository, ".git", "config"));
      const head = git("rev-parse", "HEAD");
      expect(git("status", "--porcelain")).toBe("");
      const index = await readFile(join(repository, ".git", "index"));
      let started = false;
      const outcome = await runIssuePatch(repository, {
        onCodex: async (_args, output) => {
          started = true;
          expect(output!.appServer!.snapshotStoragePaths).toEqual([]);
          expect(
            output!.appServer!.permissions!.modelOnlyReadOnlyPaths ?? [],
          ).toEqual([]);
          await writeFile(join(repository, "app.ts"), "fixed\n");
          if (used)
            await writeFile(
              join(repository, "payload.bin"),
              "Synthetic LFS payload\n",
            );
          output!.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(started, outcome.stderr).toBe(true);
      expect(outcome.exitCode, outcome.stderr).toBe(used ? 2 : 0);
      if (used) expect(outcome.stderr).toContain("clean filter 'lfs' failed");
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(await readFile(blocker, "utf8")).toBe(contents);
      expect(await readFile(join(repository, ".git", "config"))).toEqual(
        config,
      );
      expect(await readFile(join(repository, ".git", "index"))).toEqual(index);
      expect(git("rev-parse", "HEAD")).toBe(head);
    },
  );
}
