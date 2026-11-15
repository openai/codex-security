import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { inventoryToolEnvironment } from "./support/inventory.js";
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
  const env = inventoryToolEnvironment();
  delete env["CODEX_SECURITY_TARGET_PATHS_FILE"];
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
    env["CODEX_SECURITY_TARGET_PATHS_FILE"] = scopesFile;
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

test("a managed host's scope file restricts a prepared native inventory", () => {
  const { repo, discovery, env, scopesFile, run, build } = fixture();
  writeFileSync(scopesFile, JSON.stringify(["src", "src/explicit.txt"]));
  env["CODEX_SECURITY_TARGET_PATHS_FILE"] = scopesFile;
  run(
    "generate-in-scope-files",
    "--repo",
    repo,
    "--scope",
    ".",
    "--out",
    join(discovery, "in_scope_files.txt"),
  );
  writeFileSync(join(repo, "src", "late.ts"), "source");
  expect(build(".")).toEqual([
    "src/explicit.txt",
    "src/hidden.ts",
    "src/tracked.ts",
    "src/visible.ts",
  ]);
});

test("read prepared JSONL a row at a time across a split UTF-8 name", () => {
  const { repo, scan, env, scopesFile, build } = fixture();
  writeFileSync(scopesFile, JSON.stringify(["src"]));
  env["CODEX_SECURITY_TARGET_PATHS_FILE"] = scopesFile;
  const name = "src/α.ts";
  writeFileSync(join(repo, name), "source");
  const prefix = '{"preview":"prepared-';
  const suffix = '","path":"src/';
  // The first byte of α is the last byte of the first 64 KiB read.
  const padding = "x".repeat(65535 - prefix.length - suffix.length);
  const row = prefix + padding + suffix + 'α.ts"}\r\n';
  writeFileSync(join(scan, "scoped-source-input.jsonl"), row.repeat(3));
  const preload = join(scan, "reject-monolithic-decode.cjs");
  writeFileSync(
    preload,
    `const toString = Buffer.prototype.toString;
const marker = Buffer.from(${JSON.stringify(prefix)});
Buffer.prototype.toString = function (...args) {
  if (this.length > 128 * 1024 && this.subarray(0, marker.length).equals(marker)) {
    throw new Error("The queue decoded the entire prepared inventory.");
  }
  return toString.apply(this, args);
};`,
  );
  env["NODE_OPTIONS"] = `--require ${JSON.stringify(preload)}`;
  expect(build(".")).toEqual([name]);
});

test.skipIf(process.platform !== "linux")(
  "native inventory preserves raw Linux source names",
  () => {
    const { repo, discovery, build } = fixture();
    const name = Buffer.concat([
      Buffer.from("src/"),
      Buffer.from([255]),
      Buffer.from(".ts"),
    ]);
    writeFileSync(Buffer.concat([Buffer.from(repo + "/"), name]), "source");
    writeFileSync(
      join(discovery, "in_scope_files.txt"),
      Buffer.concat([name, Buffer.from("\n")]),
    );
    expect(build("src")).toEqual(["src/\udcff.ts"]);
  },
);
