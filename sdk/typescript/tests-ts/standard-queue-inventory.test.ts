import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { nodeCommand } from "./support/shell.js";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";

const temporary = createTemporaryDirectoriesSync(true);
afterEach(temporary.cleanup);

function fixture() {
  const root = temporary.create("standard-inventory-");
  const repo = join(root, "repo");
  const scan = join(root, "scan");
  const context = join(scan, "artifacts", "01_context");
  const discovery = join(scan, "artifacts", "02_discovery");
  mkdirSync(join(repo, "src"), { recursive: true });
  mkdirSync(context, { recursive: true });
  mkdirSync(discovery, { recursive: true });
  expect(spawnSync("git", ["init", "-q", repo]).status).toBe(0);
  for (const file of [
    "src/hidden.ts",
    "src/ripgrep-ignored.ts",
    "src/tracked.ts",
    "src/explicit.txt",
    "src/visible.ts",
    "outside.ts",
  ])
    writeFileSync(join(repo, file), "source");
  writeFileSync(
    join(repo, ".gitignore"),
    "hidden.ts\ntracked.ts\nexplicit.txt\n",
  );
  writeFileSync(join(repo, ".ignore"), "!hidden.ts\nripgrep-ignored.ts\n");
  expect(
    spawnSync("git", ["-C", repo, "add", "-f", "src/tracked.ts"]).status,
  ).toBe(0);
  writeFileSync(
    join(context, "standard-rules.json"),
    JSON.stringify([{ path: "[.]ts$" }]),
  );
  const scopesFile = join(root, "scopes.json");
  const env = { ...process.env };
  delete env.CODEX_SECURITY_TARGET_PATHS_FILE;
  const run = (...args: string[]) => {
    const result = spawnSync(
      nodeCommand().command,
      [join(PLUGIN_ROOT, "mcp", "helpers.mjs"), ...args],
      { env, encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
  };
  const build = (...scopes: string[]) => {
    run("standard-queue", "build", scan, repo, ...scopes);
    return JSON.parse(
      readFileSync(join(context, "standard-queue.json"), "utf8"),
    ).batches.flat();
  };
  return { repo, scan, discovery, env, scopesFile, run, build };
}

for (const scope of [".", "src"]) {
  for (const prepared of [true, false]) {
    test(`Standard matches the native ${scope} inventory, prepared=${prepared}`, () => {
      const { repo, discovery, run, build } = fixture();
      if (prepared) {
        run(
          "generate-in-scope-files",
          "--repo",
          repo,
          "--scope",
          scope,
          "--out",
          join(discovery, "in_scope_files.txt"),
        );
        writeFileSync(join(repo, "src", "late.ts"), "source");
      }
      expect(build(scope)).toEqual([
        ...(scope === "." ? ["outside.ts"] : []),
        "src/hidden.ts",
        "src/tracked.ts",
        "src/visible.ts",
      ]);
    });
  }
}

for (const prepared of [true, false]) {
  test(`Standard matches the SDK's registered paths, prepared=${prepared}`, () => {
    const { repo, scan, scopesFile, env, run, build } = fixture();
    writeFileSync(scopesFile, JSON.stringify(["src", "src/explicit.txt"]));
    env.CODEX_SECURITY_TARGET_PATHS_FILE = scopesFile;
    if (prepared) {
      run(
        "make-repo-scope-input",
        "--repo",
        repo,
        "--scopes-file",
        scopesFile,
        "--out",
        join(scan, "scoped-source-input.jsonl"),
      );
      writeFileSync(join(repo, "src", "late.ts"), "source");
    }
    expect(build(".")).toEqual([
      "src/explicit.txt",
      "src/ripgrep-ignored.ts",
      "src/tracked.ts",
      "src/visible.ts",
    ]);
  });
}

test("the prepared inventory cannot widen an explicitly requested scope", () => {
  const { repo, discovery, run, build } = fixture();
  run(
    "generate-in-scope-files",
    "--repo",
    repo,
    "--scope",
    ".",
    "--out",
    join(discovery, "in_scope_files.txt"),
  );
  expect(build("src", "src/explicit.txt")).toEqual([
    "src/explicit.txt",
    "src/hidden.ts",
    "src/tracked.ts",
    "src/visible.ts",
  ]);
});
