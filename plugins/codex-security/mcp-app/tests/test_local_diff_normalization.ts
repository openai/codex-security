import assert from "node:assert/strict";
import childProcess, { execFileSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import {
  mkdir,
  open,
  readFile,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
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

for (const normalization of ["text_auto", "autocrlf", "changed_filter"])
  test(`local diff preserves index-aware conversion with ${normalization}`, async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("index-eol-inventory-");
    const repo = join(root, "repository");
    await mkdir(repo);
    const command = trustedGitExecutable(repo);
    assert.ok(command);
    const git = (...args: string[]) =>
      execFileSync(command, ["-C", repo, ...args], { stdio: "pipe" });
    try {
      git("init", "-q");
      git("config", "user.name", "Fixture");
      git("config", "user.email", "fixture@example.test");
      git("config", "core.autocrlf", "false");
      const source = join(repo, "source.txt");
      await writeFile(source, "SOURCE\r\n");
      git("add", ".");
      git("commit", "-qm", "raw CRLF fixture");
      let attributes = "**/.svn/** filter=probe\n";
      if (normalization === "text_auto") attributes += "*.txt text=auto\n";
      else if (normalization === "changed_filter")
        attributes += "source.txt filter=fixture\n";
      await writeFile(join(repo, ".gitattributes"), attributes);
      await mkdir(join(repo, ".svn"));
      await writeFile(join(repo, ".svn/source.txt"), "before\n");
      git("add", "-f", ".");
      git("commit", "-qm", "conversion fixture");
      if (normalization === "autocrlf") git("config", "core.autocrlf", "true");
      else if (normalization === "changed_filter")
        git("config", "filter.fixture.clean", "tr '[:upper:]' '[:lower:]'");
      git("config", "filter.probe.clean", "echo %f >> .git/filter-calls; cat");
      await writeFile(join(repo, ".svn/source.txt"), "after\n");
      await utimes(source, 1, 1);
      const before = await readFile(join(repo, ".git/index"));
      const expected = normalization === "changed_filter" ? ["source.txt"] : [];
      assert.deepEqual(
        (await changedPaths(repo, "HEAD", "HEAD", "local-patch")).map(
          ({ path }: { path: string }) => path,
        ),
        expected,
      );
      for (const command of [
        "generate-in-scope-files",
        "make-diff-rank-input",
      ]) {
        const out = join(root, command);
        assert.equal(
          await generateInventory(command, {
            repo,
            out,
            base: "HEAD",
            head: "HEAD",
            mode: "local-patch",
          }),
          expected.length,
        );
        const contents = (await readFile(out, "utf8")).trim();
        const rows = contents ? contents.split("\n") : [];
        assert.deepEqual(
          command === "generate-in-scope-files"
            ? rows
            : rows.map((row) => JSON.parse(row).path),
          expected,
        );
      }
      assert.deepEqual(await readFile(join(repo, ".git/index")), before);
      await assert.rejects(stat(join(repo, ".git/filter-calls")), {
        code: "ENOENT",
      });
      if (normalization === "changed_filter") {
        git(
          "config",
          "filter.fixture.clean",
          "echo 'fixture clean filter diagnostic' >&2; exit 1",
        );
        git("config", "filter.fixture.required", "true");
        await assert.rejects(
          changedPaths(repo, "HEAD", "HEAD", "local-patch"),
          /fixture clean filter diagnostic/,
        );
      }
    } finally {
      await temporary.cleanup();
    }
  });

test(
  "local diff keeps large text within Git's regular-file memory handling",
  {
    skip:
      process.platform !== "linux" ||
      childProcess.spawnSync("prlimit", ["--version"], { stdio: "ignore" })
        .status !== 0,
  },
  async () => {
    const temporary = createTemporaryDirectories(true);
    const root = await temporary.create("large-text-inventory-");
    const repo = join(root, "repository");
    await mkdir(repo);
    const command = trustedGitExecutable(repo);
    assert.ok(command);
    const git = (...args: string[]) =>
      execFileSync(command, ["-C", repo, ...args], { stdio: "pipe" });
    const originalSpawn = childProcess.spawn;
    try {
      git("init", "-q");
      git("config", "user.name", "Fixture");
      git("config", "user.email", "fixture@example.test");
      git("config", "core.bigFileThreshold", "1m");
      git("config", "core.autocrlf", "false");
      await writeFile(join(repo, "large.txt"), "before\n");
      git("add", ".");
      git("commit", "-qm", "large text fixture");
      const source = await open(join(repo, "large.txt"), "w");
      try {
        const chunk = Buffer.alloc(1024 * 1024, "a");
        for (let index = 0; index < 64; index++) await source.write(chunk);
      } finally {
        await source.close();
      }
      const statuses: Array<number | null> = [];
      childProcess.spawn = ((
        command: string,
        args: string[],
        options: childProcess.SpawnOptions,
      ) => {
        if (!args.includes("hash-object"))
          return originalSpawn(command, args, options);
        const child = originalSpawn(
          "prlimit",
          ["--as=67108864", "--", command, ...args],
          options,
        );
        child.once("close", (status) => statuses.push(status));
        return child;
      }) as typeof childProcess.spawn;
      syncBuiltinESMExports();
      const out = join(root, "inventory");
      assert.equal(
        await generateInventory("generate-in-scope-files", {
          repo,
          out,
          base: "HEAD",
          head: "HEAD",
          mode: "local-patch",
        }),
        1,
      );
      assert.equal(await readFile(out, "utf8"), "large.txt\n");
      assert.ok(statuses.length > 0);
      assert.ok(statuses.every((status) => status === 0));
    } finally {
      childProcess.spawn = originalSpawn;
      syncBuiltinESMExports();
      await temporary.cleanup();
    }
  },
);
