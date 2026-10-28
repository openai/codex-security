import assert from "node:assert/strict";
import childProcess, { execFileSync } from "node:child_process";
import { unlinkSync } from "node:fs";
import { mkdir, readFile, unlink, utimes, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const options = {
  define: {
    "import.meta.url": JSON.stringify(
      new URL(
        "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
        import.meta.url,
      ).href,
    ),
  },
};
const { changedPaths, trustedGitExecutable } = await importSource(
  "src/helpers/inventory-git.ts",
  options,
);
const { generateInventory } = await importSource(
  "src/helpers/generate-inventory.ts",
  options,
);

async function fixture(count = 3) {
  const temporary = createTemporaryDirectories(true);
  const root = await temporary.create("git-diff-batch-");
  const repo = join(root, "repository");
  await mkdir(repo);
  const command = trustedGitExecutable(repo);
  assert.ok(command);
  const git = (...args: string[]) =>
    execFileSync(command, ["-C", repo, ...args], { stdio: "pipe" });
  git("init", "-q");
  git("config", "user.name", "Fixture");
  git("config", "user.email", "fixture@example.test");
  git("config", "core.autocrlf", "false");
  const names = Array.from(
    { length: count },
    (_, index) =>
      `source${index === 1 && process.platform !== "win32" ? "\t" : "-"}${String(index).padStart(3, "0")}.txt`,
  );
  for (const name of names) await writeFile(join(repo, name), "before\n");
  git("add", ".");
  git("commit", "-qm", "batch fixture");
  for (const name of names) await writeFile(join(repo, name), "after\n");
  return { root, repo, names, git, cleanup: () => temporary.cleanup() };
}

function operation(args: string[]) {
  if (args.includes("hash-object")) return "hash-object";
  if (args.includes("ls-files") && args.includes("--stage")) return "stage";
  if (args.includes("status")) return "status";
  return undefined;
}

test("local diff batches normalization across selected text files", async () => {
  const f = await fixture(24);
  const originalSpawn = childProcess.spawn;
  try {
    const expected: string[] = [];
    for (const [index, name] of f.names.entries()) {
      if (index % 3) expected.push(name);
      else await writeFile(join(f.repo, name), "before\n");
      await utimes(join(f.repo, name), 1, 1);
    }
    const calls: string[] = [];
    childProcess.spawn = ((
      command: string,
      args: string[],
      options: childProcess.SpawnOptions,
    ) => {
      const selected = operation(args);
      if (selected) calls.push(selected);
      return originalSpawn(command, args, options);
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    const before = await readFile(join(f.repo, ".git/index"));
    const out = join(f.root, "inventory");
    assert.equal(
      await generateInventory("generate-in-scope-files", {
        repo: f.repo,
        out,
        base: "HEAD",
        head: "HEAD",
        mode: "local-patch",
      }),
      expected.length,
    );
    assert.deepEqual(
      (await readFile(out, "utf8")).trim().split("\n").sort(),
      expected.sort(),
    );
    assert.deepEqual(calls, ["hash-object", "stage", "status"]);
    assert.deepEqual(await readFile(join(f.repo, ".git/index")), before);
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

for (const contract of [
  { code: "E2BIG" },
  { code: "ENAMETOOLONG" },
  { code: "WINDOWS_PROCESS_ERROR", errno: 206 },
])
  test(`local diff retries the native ${contract.code} argument-length contract`, async () => {
    const f = await fixture();
    const originalSpawn = childProcess.spawn;
    try {
      const failures: string[] = [];
      childProcess.spawn = ((
        command: string,
        args: string[],
        options: childProcess.SpawnOptions,
      ) => {
        const selected = operation(args);
        const separator = args.indexOf("--");
        if (selected && args.length - separator - 1 === f.names.length) {
          failures.push(selected);
          throw Object.assign(
            new Error("native argument-length fixture"),
            contract,
          );
        }
        return originalSpawn(command, args, options);
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const before = await readFile(join(f.repo, ".git/index"));
      assert.equal(
        (await changedPaths(f.repo, "HEAD", "HEAD", "local-patch")).length,
        f.names.length,
      );
      assert.deepEqual(failures, ["hash-object", "stage", "status"]);
      assert.deepEqual(await readFile(join(f.repo, ".git/index")), before);
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      await f.cleanup();
    }
  });

test("local diff propagates fatal Git diagnostics without splitting", async () => {
  const f = await fixture();
  const originalSpawn = childProcess.spawn;
  try {
    let calls = 0;
    childProcess.spawn = ((
      command: string,
      args: string[],
      options: childProcess.SpawnOptions,
    ) => {
      if (operation(args) !== "hash-object")
        return originalSpawn(command, args, options);
      calls++;
      return originalSpawn(
        process.execPath,
        [
          "-e",
          "process.stderr.write('native fatal fixture diagnostic');process.exit(128)",
        ],
        options,
      );
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    await assert.rejects(
      changedPaths(f.repo, "HEAD", "HEAD", "local-patch"),
      /native fatal fixture diagnostic/,
    );
    assert.equal(calls, 1);
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

test("local diff stops splitting an unsplittable native argument failure", async () => {
  const f = await fixture(1);
  const originalSpawn = childProcess.spawn;
  const failure = Object.assign(new Error("native argument fixture"), {
    code: "E2BIG",
  });
  try {
    let calls = 0;
    childProcess.spawn = ((
      command: string,
      args: string[],
      options: childProcess.SpawnOptions,
    ) => {
      if (operation(args) === "hash-object") {
        calls++;
        throw failure;
      }
      return originalSpawn(command, args, options);
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    await assert.rejects(
      changedPaths(f.repo, "HEAD", "HEAD", "local-patch"),
      (error: unknown) => error === failure,
    );
    assert.equal(calls, 1);
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

test("local diff retains readable peers when a source disappears before hashing", async () => {
  const f = await fixture();
  const originalSpawn = childProcess.spawn;
  try {
    let removed = false;
    const gone = f.names[0]!;
    // Use the synchronous spawn boundary so removal falls after classification.
    childProcess.spawn = ((
      command: string,
      args: string[],
      options: childProcess.SpawnOptions,
    ) => {
      if (operation(args) === "hash-object" && !removed) {
        removed = true;
        unlinkSync(join(f.repo, gone));
      }
      return originalSpawn(command, args, options);
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    assert.deepEqual(
      (await changedPaths(f.repo, "HEAD", "HEAD", "local-patch"))
        .map(({ path }: { path: string }) => path)
        .sort(),
      f.names.filter((name) => name !== gone).sort(),
    );
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    await f.cleanup();
  }
});

for (const indexKind of ["symlink", "unmerged"])
  for (const modified of [false, true])
    test(
      `local diff normalizes ${modified ? "modified" : "unchanged"} text with ${indexKind} index`,
      { skip: indexKind === "symlink" && process.platform === "win32" },
      async () => {
        const f = await fixture(1);
        try {
          const name = f.names[0]!,
            source = join(f.repo, name),
            base = f.git("rev-parse", "HEAD").toString().trim();
          if (indexKind === "symlink") {
            const { symlink } = await import("node:fs/promises");
            await unlink(source);
            await symlink("destination", source);
            f.git("add", name);
            await unlink(source);
          } else {
            const branch = f
              .git("symbolic-ref", "--short", "HEAD")
              .toString()
              .trim();
            f.git("checkout", "-qb", "fixture-side");
            await writeFile(source, "side\n");
            f.git("commit", "-qam", "side fixture");
            f.git("checkout", "-q", branch);
            await writeFile(source, "main\n");
            f.git("commit", "-qam", "main fixture");
            assert.throws(() => f.git("merge", "fixture-side", "--no-edit"));
          }
          await writeFile(source, modified ? "changed\n" : "before\n");
          const out = join(f.root, "inventory");
          assert.equal(
            await generateInventory("generate-in-scope-files", {
              repo: f.repo,
              out,
              base,
              head: "HEAD",
              mode: "local-patch",
            }),
            Number(modified),
          );
        } finally {
          await f.cleanup();
        }
      },
    );
