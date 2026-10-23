import { afterEach, expect, spyOn, test } from "bun:test";
import type { BigIntStats, Stats } from "node:fs";
import { readFile, rename, writeFile, type FileHandle } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  publicationRepository,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const [name, before, after] of [
  ["unchanged large identity", 2n ** 60n, 2n ** 60n],
  ["distinct small identities", 100n, 101n],
  ["colliding numeric identities", 2n ** 60n, 2n ** 60n + 1n],
] as const) {
  const title = `publication hashes the checked file with ${name}`;
  test(title, async () => {
    if (runTestInSubprocess(import.meta.path, title)) return;
    const { directory, git, remote } = await publicationRepository(fixtures);
    await writeFile(join(directory, ".gitignore"), ".env\n");
    git("add", ".gitignore");
    git("commit", "-m", "Synthetic ignored baseline");
    const path = join(directory, ".env");
    const originalContent = "SYNTHETIC_PREEXISTING_LOCAL_CONTENT\n";
    await writeFile(path, originalContent);
    const retained = join(
      await fixtures.create("publication-original-"),
      "original",
    );
    git("status", "--porcelain=v1");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    const replacing = before !== after;
    if (name === "colliding numeric identities")
      expect(Number(before)).toBe(Number(after));
    const filesystem = await import("node:fs/promises");
    const original = {
      lstat: filesystem.lstat,
      realpath: filesystem.realpath,
      open: filesystem.open,
    };
    const selected = (value: unknown) => resolve(String(value)) === path;
    const identity = (metadata: Stats | BigIntStats, value: bigint) => {
      Object.defineProperty(metadata, "ino", {
        value: typeof metadata.ino === "bigint" ? value : Number(value),
      });
      return metadata;
    };
    let replaced = false;
    const handles: FileHandle[] = [];
    const inspecting = spyOn(filesystem, "lstat").mockImplementation((async (
      ...args: Parameters<typeof original.lstat>
    ) => {
      const metadata = await original.lstat(...args);
      return selected(args[0])
        ? identity(metadata, replaced ? after : before)
        : metadata;
    }) as typeof original.lstat);
    const resolving = spyOn(filesystem, "realpath").mockImplementation((async (
      ...args: Parameters<typeof original.realpath>
    ) => {
      const canonical = await original.realpath(...args);
      if (selected(args[0]) && replacing && !replaced) {
        await rename(path, retained);
        await writeFile(path, "SYNTHETIC_REPLACEMENT_CONTENT\n");
        replaced = true;
      }
      return canonical;
    }) as typeof original.realpath);
    const opening = spyOn(filesystem, "open").mockImplementation(
      async (...args) => {
        const file = await original.open(...args);
        if (selected(args[0])) {
          handles.push(file);
          const value = replaced ? after : before;
          const stat = file.stat.bind(file);
          spyOn(file, "stat").mockImplementation((async (
            ...options: Parameters<typeof stat>
          ) => identity(await stat(...options), value)) as typeof stat);
        }
        return file;
      },
    );
    let models = 0;
    let pushes = 0;
    let creations = 0;
    try {
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("push")) pushes++;
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            if (args[1] === "create") creations++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            models++;
            await writeFile(
              join(directory, "selected.txt"),
              replacing ? originalContent : "Synthetic independent change\n",
            );
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(replacing ? 2 : 0);
      expect({ models, pushes, creations }).toEqual(
        replacing
          ? { models: 0, pushes: 0, creations: 0 }
          : { models: 1, pushes: 1, creations: 1 },
      );
      expect(replaced).toBe(replacing);
      if (replacing) {
        expect(outcome.stderr).toContain(
          "Patch publication content must remain the selected regular file.",
        );
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
        expect(repositoryGit(remote)("for-each-ref")).toBe("");
        expect(await readFile(retained, "utf8")).toBe(originalContent);
        expect(await readFile(path, "utf8")).toBe(
          "SYNTHETIC_REPLACEMENT_CONTENT\n",
        );
      } else {
        expect(git("show", "HEAD:selected.txt")).toBe(
          "Synthetic independent change",
        );
        expect(await readFile(path, "utf8")).toBe(originalContent);
      }
      expect(handles.length).toBeGreaterThan(0);
      for (const handle of handles) expect(handle.fd).toBe(-1);
    } finally {
      opening.mockRestore();
      resolving.mockRestore();
      inspecting.mockRestore();
    }
  });
}
