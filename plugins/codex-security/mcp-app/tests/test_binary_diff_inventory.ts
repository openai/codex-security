import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
const { changedPaths } = await importSource(
  "src/helpers/inventory-git.ts",
  options,
);
const { generateInventory } = await importSource(
  "src/helpers/generate-inventory.ts",
  options,
);

test("local diff classifies binary files before Git normalization", async () => {
  const temporary = createTemporaryDirectories(true);
  const root = await temporary.create("binary-diff-inventory-");
  const repo = join(root, "repository");
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repo, ...args], { stdio: "pipe" });
  try {
    await mkdir(repo);
    git("init", "-q");
    git("config", "user.name", "Fixture");
    git("config", "user.email", "fixture@example.test");
    git("config", "core.autocrlf", "false");
    await writeFile(join(repo, ".gitattributes"), "asset.bin filter=fixture\n");
    await writeFile(join(repo, "asset.bin"), Buffer.from("\0original\n"));
    const utf16 = (value: string, bigEndian = false) => {
      const contents = Buffer.from(`\ufeff${value}\n`, "utf16le");
      return bigEndian ? contents.swap16() : contents;
    };
    const names = ["source.py", "utf16be.py", "utf16le.py"];
    await writeFile(join(repo, names[0]!), "before\n");
    await writeFile(join(repo, names[1]!), utf16("before", true));
    await writeFile(join(repo, names[2]!), utf16("before"));
    git("add", ".");
    git("commit", "-qm", "binary classification fixture");
    git("config", "filter.fixture.clean", "exit 1");
    git("config", "filter.fixture.required", "true");
    const binary = Buffer.concat([
      Buffer.alloc(64 * 1024, "b"),
      Buffer.from("\0changed\n"),
    ]);
    await writeFile(join(repo, "asset.bin"), binary);
    await writeFile(join(repo, names[0]!), "after\n");
    await writeFile(join(repo, names[1]!), utf16("after", true));
    await writeFile(join(repo, names[2]!), utf16("after"));
    // Normalizing this excluded binary would fail, including with a late NUL.
    assert.notEqual(
      spawnSync(
        "git",
        ["-C", repo, "hash-object", "--path=asset.bin", "--stdin"],
        { input: binary, stdio: "pipe" },
      ).status,
      0,
    );
    assert.deepEqual(
      (await changedPaths(repo, "HEAD", "HEAD", "local-patch")).map(
        ({ path }: { path: string }) => path,
      ),
      ["asset.bin", ...names],
    );
    for (const command of ["generate-in-scope-files", "make-diff-rank-input"]) {
      const out = join(root, command);
      assert.equal(
        await generateInventory(command, {
          repo,
          out,
          base: "HEAD",
          head: "HEAD",
          mode: "local-patch",
        }),
        names.length,
      );
      const rows = (await readFile(out, "utf8")).trim().split("\n");
      assert.deepEqual(
        command === "generate-in-scope-files"
          ? rows
          : rows.map((row) => JSON.parse(row).path),
        names,
      );
    }
  } finally {
    await temporary.cleanup();
  }
});
