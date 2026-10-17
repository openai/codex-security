import { afterEach, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  readlink,
  readdir,
  lstat,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function repository(prefix: string) {
  const root = await fixtures.create(prefix);
  const git = repositoryGit(root);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  await mkdir(join(root, "source", "deep"), { recursive: true });
  await writeFile(join(root, "app.ts"), "before\n");
  await writeFile(join(root, "source", "deep", "input.ts"), "fixture source\n");
  git("add", ".");
  git("commit", "-m", "Synthetic discovery baseline");
  return { root, git };
}

for (const raw of [false, true]) {
  test.skipIf(raw && process.platform !== "linux")(
    `patch discovery does not traverse symlinked ancestors of ordinary tracked files${raw ? " with raw bytes" : ""}`,
    async () => {
      const selected = await repository("patch-discovery-selected-");
      const foreign = await repository("patch-discovery-foreign-");
      // A deeper checkout detects traversals that skip only the final symlink itself.
      const nestedPath = join(foreign.root, "deep");
      await mkdir(nestedPath);
      const nested = repositoryGit(nestedPath);
      nested("init", "--initial-branch=main");
      nested("config", "user.name", "Synthetic User");
      nested("config", "user.email", "synthetic@example.test");
      await writeFile(join(nestedPath, "input.ts"), "foreign source\n");
      nested("add", ".");
      nested("commit", "-m", "Synthetic nested foreign baseline");
      const foreignHead = foreign.git("rev-parse", "HEAD");
      const foreignIndex = await readFile(join(foreign.root, ".git", "index"));
      const nestedHead = nested("rev-parse", "HEAD");
      const nestedIndex = await readFile(join(nestedPath, ".git", "index"));
      const link = raw
        ? Buffer.concat([
            Buffer.from(`${selected.root}/source-`),
            Buffer.from([0xff]),
          ])
        : join(selected.root, "source");
      if (raw) {
        await rename(join(selected.root, "source"), link);
        selected.git("add", "--all");
        selected.git("commit", "-m", "Synthetic raw directory baseline");
      }
      const selectedIndex = await readFile(
        join(selected.root, ".git", "index"),
      );
      const removed = await fixtures.create("patch-discovery-removed-");
      await rename(link, join(removed, "source"));
      await symlink(
        foreign.root,
        link,
        process.platform === "win32" ? "junction" : "dir",
      );
      const originalLink = await readlink(link);
      let launches = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: selected.root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            launches++;
            await writeFile(join(selected.root, "app.ts"), "after\n");
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readlink(link)).toBe(originalLink);
      expect(await readFile(join(selected.root, ".git", "index"))).toEqual(
        selectedIndex,
      );
      expect(foreign.git("rev-parse", "HEAD")).toBe(foreignHead);
      expect(await readFile(join(foreign.root, ".git", "index"))).toEqual(
        foreignIndex,
      );
      expect(nested("rev-parse", "HEAD")).toBe(nestedHead);
      expect(await readFile(join(nestedPath, ".git", "index"))).toEqual(
        nestedIndex,
      );
      expect(await readFile(join(nestedPath, "input.ts"), "utf8")).toBe(
        "foreign source\n",
      );
      expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
        "after\n",
      );
    },
  );
}

test.each([
  {
    name: "malformed marker",
    contents: "synthetic fixture data\n",
    target: undefined,
  },
  {
    name: "missing target",
    contents: "gitdir: ../absent-administration\n",
    target: undefined,
  },
  {
    name: "non-repository directory target",
    contents: "gitdir: ../non-repository-target\n",
    target: "directory",
  },
  {
    name: "ordinary file target",
    contents: "gitdir: ../non-repository-target\n",
    target: "file",
  },
])(
  "patch discovery keeps $name fixture data usable",
  async ({ contents, target }) => {
    const selected = await repository("patch-discovery-marker-");
    const marker = join(selected.root, "source", ".git");
    if (target === "directory")
      await mkdir(join(selected.root, "non-repository-target"));
    if (target === "file")
      await writeFile(
        join(selected.root, "non-repository-target"),
        "ordinary fixture data\n",
      );
    await writeFile(marker, contents);
    const index = await readFile(join(selected.root, ".git", "index"));
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: selected.root,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(selected.root, "app.ts"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readFile(marker, "utf8")).toBe(contents);
    expect(await readFile(join(selected.root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
      "after\n",
    );
  },
);

for (const [kind, contents] of [
  ["empty directory", null],
  ["missing target", "gitdir: ../absent-administration\n"],
  ["empty target", "gitdir: "],
  ["empty target with newline", "gitdir: \n"],
] as const) {
  test.skipIf(process.platform !== "linux")(
    `patch discovery keeps a raw-byte source directory with ${kind} Git placeholder data usable`,
    async () => {
      const selected = await repository("patch-discovery-raw-placeholder-");
      const source = Buffer.concat([
        Buffer.from(`${selected.root}/source-`),
        Buffer.from([0xff]),
      ]);
      const marker = Buffer.concat([source, Buffer.from("/.git")]);
      await rename(join(selected.root, "source"), source);
      selected.git("add", "--all");
      selected.git("commit", "-m", "Synthetic raw source baseline");
      if (contents === null) await mkdir(marker);
      else await writeFile(marker, contents);
      const index = await readFile(join(selected.root, ".git", "index"));
      let launches = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: selected.root,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            launches++;
            await writeFile(join(selected.root, "app.ts"), "after\n");
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(await readFile(join(selected.root, ".git", "index"))).toEqual(
        index,
      );
      expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
        "after\n",
      );
      expect(
        await readFile(
          Buffer.concat([source, Buffer.from("/deep/input.ts")]),
          "utf8",
        ),
      ).toBe("fixture source\n");
      if (contents === null) expect(await readdir(marker)).toEqual([]);
      else expect(await readFile(marker, "utf8")).toBe(contents);
    },
  );
}

test.skipIf(process.platform !== "linux")(
  "patch discovery keeps a missing raw-byte gitfile target as ordinary fixture data",
  async () => {
    const selected = await repository("patch-discovery-raw-missing-target-");
    const marker = join(selected.root, "source", ".git");
    const contents = Buffer.concat([
      Buffer.from("gitdir: ../absent-administration-"),
      Buffer.from([0xff]),
      Buffer.from("\n"),
    ]);
    await writeFile(marker, contents);
    const index = await readFile(join(selected.root, ".git", "index"));
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: selected.root,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(selected.root, "app.ts"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readFile(marker)).toEqual(contents);
    expect(await readFile(join(selected.root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
      "after\n",
    );
  },
);

test.each([false, true])(
  "patch discovery rejects newly selected foreign Git administration before bookkeeping (invalid ancestor: %p)",
  async (invalidAncestor) => {
    const selected = await repository("patch-discovery-guard-");
    const foreign = await repository("patch-discovery-unselected-");
    foreign.git("config", "core.worktree", foreign.root);
    const selectedHead = selected.git("rev-parse", "HEAD");
    const selectedIndex = await readFile(join(selected.root, ".git", "index"));
    const foreignHead = foreign.git("rev-parse", "HEAD");
    const foreignIndex = await readFile(join(foreign.root, ".git", "index"));
    if (invalidAncestor)
      await writeFile(
        join(selected.root, "source", ".git"),
        "synthetic fixture data\n",
      );
    const marker = join(
      selected.root,
      "source",
      ...(invalidAncestor ? ["deep"] : []),
      "newrepo",
      ".git",
    );
    await mkdir(dirname(marker), { recursive: true });
    const contents = `gitdir: ${join(foreign.root, ".git")}\n`;
    let launches = 0;
    const bookkeeping: string[][] = [];
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: selected.root,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (
          launches > 0 &&
          !args.includes("core.hooksPath=/dev/null") &&
          args.some((value) =>
            ["add", "read-tree", "update-index", "write-tree"].includes(value),
          )
        )
          bookkeeping.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(selected.root, "app.ts"), "after\n");
        await writeFile(marker, contents);
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain(
      "Git metadata outside the pre-patch administration directories",
    );
    expect(launches).toBe(1);
    expect(bookkeeping).toEqual([]);
    expect(selected.git("rev-parse", "HEAD")).toBe(selectedHead);
    expect(await readFile(join(selected.root, ".git", "index"))).toEqual(
      selectedIndex,
    );
    expect(foreign.git("rev-parse", "HEAD")).toBe(foreignHead);
    expect(await readFile(join(foreign.root, ".git", "index"))).toEqual(
      foreignIndex,
    );
    expect(await readFile(marker, "utf8")).toBe(contents);
    expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
      "after\n",
    );
  },
);

for (const hostileConfig of ["malformed", "hook"] as const) {
  test.skipIf(hostileConfig === "hook" && process.platform === "win32")(
    `patch discovery checks new foreign administration without loading its ${hostileConfig} configuration`,
    async () => {
      const selected = await repository("patch-discovery-probe-selected-");
      const foreign = await repository("patch-discovery-probe-foreign-");
      const marker = join(selected.root, "source", "newrepo", ".git");
      await mkdir(dirname(marker), { recursive: true });
      const foreignAdmin = join(foreign.root, ".git");
      const effect = join(foreign.root, "hook-effect");
      const selectedIndex = await readFile(
        join(selected.root, ".git", "index"),
      );
      const foreignIndex = await readFile(join(foreignAdmin, "index"));
      const foreignHead = await readFile(join(foreignAdmin, "HEAD"));
      if (hostileConfig === "malformed") {
        await writeFile(
          join(foreignAdmin, "config"),
          "[invalid synthetic configuration\n",
        );
      } else {
        const hook = join(foreignAdmin, "hooks", "synthetic-fsmonitor");
        await writeFile(
          hook,
          "#!/bin/sh\nprintf 'effect' > hook-effect\nprintf '\\0'\n",
        );
        await chmod(hook, 0o755);
        foreign.git("config", "core.fsmonitor", hook);
      }
      let launches = 0;
      const probes: { cwd: string; args: string[] }[] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: selected.root,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (args.includes("--resolve-git-dir"))
              probes.push({ cwd, args: [...args] });
            return runGitRepositoryCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            launches++;
            await writeFile(join(selected.root, "app.ts"), "after\n");
            await writeFile(marker, `gitdir: ${foreignAdmin}\n`);
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Git metadata outside the pre-patch administration directories",
      );
      expect(launches).toBe(1);
      expect(
        probes.some(
          ({ cwd, args }) =>
            cwd === selected.root && resolve(args.at(-1)!) === marker,
        ),
      ).toBe(true);
      expect(
        await readFile(effect, "utf8").catch(() => undefined),
      ).toBeUndefined();
      expect(await readFile(join(selected.root, ".git", "index"))).toEqual(
        selectedIndex,
      );
      expect(await readFile(join(foreignAdmin, "index"))).toEqual(foreignIndex);
      expect(await readFile(join(foreignAdmin, "HEAD"))).toEqual(foreignHead);
      expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
        "after\n",
      );
      if (hostileConfig === "malformed") {
        expect(() => foreign.git("status", "--porcelain")).toThrow(
          "bad config",
        );
      } else {
        foreign.git("status", "--porcelain");
        expect(await readFile(effect, "utf8")).toBe("effect");
      }
    },
  );
}

test.each([false, true])(
  "patch discovery permits an empty Git marker directory present before the turn: %p",
  async (existing) => {
    const selected = await repository("patch-discovery-empty-marker-");
    const marker = join(selected.root, "source", ".git");
    if (existing) await mkdir(marker);
    const index = await readFile(join(selected.root, ".git", "index"));
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: selected.root,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        launches++;
        if (!existing) await mkdir(marker);
        await writeFile(join(selected.root, "app.ts"), "after\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readdir(marker)).toEqual([]);
    expect(await readFile(join(selected.root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
      "after\n",
    );
  },
);

for (const linked of [false, true]) {
  test.skipIf(process.platform === "win32")(
    `patch discovery ignores a ${linked ? "symlinked " : ""}FIFO marker without opening it`,
    async () => {
      const selected = await repository("patch-discovery-fifo-");
      const marker = join(selected.root, "source", ".git");
      const support = await fixtures.create("patch-discovery-fifo-probe-");
      const fifo = linked ? join(support, "marker-fifo") : marker;
      execFileSync("mkfifo", [fifo]);
      if (linked) await symlink(fifo, marker);
      const originalLink = linked ? await readlink(marker) : undefined;
      const index = await readFile(join(selected.root, ".git", "index"));
      const source = `
import { test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { runGitRepositoryCommand, runWorkflow } from ${JSON.stringify(new URL("./cli-patch-fixtures.ts", import.meta.url).href)};
const root = ${JSON.stringify(selected.root)};
test("bounded Git marker probe", async () => {
let launches = 0;
process.stdout.write("PROBE_READY\\n");
const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
  currentDirectory: root,
  onRepositoryCommand: runGitRepositoryCommand,
  onCodex: async (_args, output) => {
    launches++;
    await writeFile(join(root, "app.ts"), "after\\n");
    output?.stdout.write("Synthetic patch complete.\\n");
    return 0;
  },
});
process.stdout.write(JSON.stringify({ launches, ...outcome }));
}, 30_000);
`;
      const script = join(support, "probe.test.ts");
      await writeFile(script, source);
      // Keep a regression in marker probing from hanging the test runner itself.
      const result = spawnSync(process.execPath, ["test", script], {
        cwd: selected.root,
        encoding: "utf8",
        timeout: 10_000,
        killSignal: "SIGKILL",
      });
      const readyMarker = "PROBE_READY\n";
      const readyOffset = result.stdout.indexOf(readyMarker);
      expect(readyOffset, result.stderr).toBeGreaterThanOrEqual(0);
      expect(result.error, result.stderr).toBeUndefined();
      expect(result.status, result.stderr).toBe(0);
      const outcome: Awaited<ReturnType<typeof runWorkflow>> & {
        launches: number;
      } = JSON.parse(result.stdout.slice(readyOffset + readyMarker.length));
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(outcome.launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect((await lstat(fifo)).isFIFO()).toBe(true);
      if (linked) expect(await readlink(marker)).toBe(originalLink!);
      expect(await readFile(join(selected.root, ".git", "index"))).toEqual(
        index,
      );
      expect(await readFile(join(selected.root, "app.ts"), "utf8")).toBe(
        "after\n",
      );
    },
    15_000,
  );
}
