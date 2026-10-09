import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { build } from "esbuild";
import path from "node:path";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";

const execFile = promisify(nodeExecFile);
const temporaryDirectories = createTemporaryDirectories(true);

const inventory = await importSource(
  path.join(import.meta.dirname, "../src/artifact-inventory.ts"),
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
);

try {
  await testSchemasAreBoundAndExact();
  await testPrepareUsesTheExistingStandardGenerator();
  if (!["win32", "darwin"].includes(process.platform))
    await testNonUtf8InventoryPaths();
  await testPrepareListsIgnoredTrackedFilesOnce();
  await testPrepareExcludesGitMetadata();
  await testPrepareUsesOnlyAuthoritativeDiffChanges();
  await testPrepareIncludesStagedAndUnstagedChanges();
  await testInventoryChildPreservesSettingsAndCwd();
  if (process.platform !== "win32") await testInventoryChildPreservesRawPaths();
  await testInventoryChildFailuresPreserveOutput();
  await testWorkerReadsItsOwnBoundInventory();
  await testCursorDoesNotExceedInventory();
  await testEmptyInventoryIsValid();
  await testUnsafeInventoryRowsAreRejected();
  await testSymlinkedInventoryIsRejected();
  await testInventoryReadErrorsAreReported();
  await testWorkersCannotPrepareInventory();
  await testBoundScopeFailurePreservesPreviousInventory();
  await testInventoryDoesNotLaunchPython();
  await testInvalidDiffTargetPreservesPreviousInventory();
} finally {
  await temporaryDirectories.cleanup();
}

async function testSchemasAreBoundAndExact() {
  const scanId = "f84c8312-a602-4660-8e01-518a176cd75a";
  const prepare = inventory.prepareReviewItemsInputSchema;
  const parent = inventory.reviewItemsReaderInputSchema;

  assert.equal(prepare.safeParse({ scanId }).success, true);
  assert.equal(
    prepare.safeParse({ scanId, handoffClaimToken: "claim-token" }).success,
    true,
  );
  assert.equal(prepare.safeParse({}).success, false);
  assert.equal(prepare.safeParse({ scanId, path: "elsewhere" }).success, false);
  assert.equal(
    parent.safeParse({ scanId, limit: 2, cursor: "0" }).success,
    true,
  );
  assert.equal(parent.safeParse({ cursor: "0" }).success, false);
  assert.equal(parent.safeParse({ scanId, limit: 0 }).success, false);
  assert.equal(parent.safeParse({ scanId, limit: 1001 }).success, false);
  assert.equal(parent.safeParse({ scanId, cursor: "-1" }).success, false);
}

async function testPrepareUsesTheExistingStandardGenerator() {
  const fixture = await createFixture("standard repository");
  await fixture.writeRepositoryFile("src/a.ts", "export const a = 1;\n");
  await fixture.writeRepositoryFile("-source.py", "source\n");
  await fixture.writeRepositoryFile("src/résumé.ts", "export const b = 2;\n");
  for (const name of ["\uFEFF来源.ts", "name-\uFFFD.ts", "🙂.ts"])
    await fixture.writeRepositoryFile(`src/${name}`, "export {};\n");
  await fixture.writeRepositoryFile(
    ".hidden/handler.ts",
    "export const c = 3;\n",
  );

  const result = await inventory.prepareCodexSecurityReviewItems(fixture.scan);
  const stored = await readFile(fixture.scanInventory, "utf8");
  const { stdout } = await execFile(
    "rg",
    [
      "--files",
      "--hidden",
      "--glob",
      "!**/.git",
      "--glob",
      "!**/.git/**",
      "--path-separator=/",
      "--",
      ".",
    ],
    { cwd: fixture.repoRoot, encoding: "utf8" },
  );
  const expectedPaths = stdout
    .split("\n")
    .filter(Boolean)
    .sort((left, right) =>
      Buffer.compare(Buffer.from(left), Buffer.from(right)),
    );
  const expected = expectedPaths.map((line) => `${line}\n`).join("");

  assert.equal(stored, expected);
  assert.deepEqual(result, {
    reviewItemsTotal: expectedPaths.length,
  });
  const first = await inventory.listCodexSecurityReviewItems(fixture.scan, {
    limit: 2,
  });
  assert.equal(first.items.length, 2);
  assert.equal(first.nextCursor, "2");
  assert.equal(Object.hasOwn(first.items[0], "area"), false);
  assert.equal(
    first.items.every((item: { path: string }) => item.path.startsWith("./")),
    true,
  );
  const second = await inventory.listCodexSecurityReviewItems(fixture.scan, {
    cursor: first.nextCursor,
    limit: 20,
  });
  assert.equal(Object.hasOwn(second, "nextCursor"), false);
  assert.deepEqual(
    [...first.items, ...second.items].map(
      (item: { path: string }) => item.path,
    ),
    expectedPaths,
  );
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems({
      ...fixture.scan,
      scope: "-source.py",
    }),
    { reviewItemsTotal: 1 },
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "-source.py\n");
}

async function testInventoryChildPreservesSettingsAndCwd() {
  const fixture = await createFixture("inventory child settings");
  await runGit(fixture.repoRoot, "init", "-q");
  await runGit(fixture.repoRoot, "commit", "--allow-empty", "-qm", "base");
  const baseRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");
  await fixture.writeRepositoryFile("visible.py", "visible\n");
  await fixture.writeRepositoryFile("hidden.py", "hidden\n");
  const home = path.join(fixture.root, "selected home");
  const tools = path.join(fixture.root, "selected tools");
  await mkdir(home);
  await mkdir(tools);
  const ignores = path.join(fixture.root, "global-ignore");
  const config = path.join(fixture.root, "global-config");
  await writeFile(ignores, "hidden.py\n");
  await writeFile(
    config,
    `[core]\nexcludesFile = ${JSON.stringify(ignores)}\n`,
  );
  const marker = path.join(fixture.root, "child.jsonl");
  const preload = path.join(fixture.root, "preload.cjs");
  const names = [
    "HOME",
    "PATH",
    "GIT_CONFIG_GLOBAL",
    "NODE_OPTIONS",
    "CODEX_MCP_NODE_PATH",
  ];
  await writeFile(
    preload,
    `require('node:fs').appendFileSync(${JSON.stringify(marker)}, JSON.stringify({pid:process.pid,node:process.execPath,cwd:process.cwd(),argv:process.argv,env:Object.fromEntries(${JSON.stringify(names)}.map(name=>[name,process.env[name]]))})+'\\n');`,
  );
  const saved = names.map((name) => [name, process.env[name]] as const);
  const selected = {
    HOME: home,
    PATH: tools + path.delimiter + (process.env.PATH ?? ""),
    GIT_CONFIG_GLOBAL: config,
    NODE_OPTIONS: `--require ${JSON.stringify(path.relative(process.cwd(), preload).split(path.sep).join("/"))}`,
    CODEX_MCP_NODE_PATH: path.join(fixture.root, "unused-node"),
  };
  Object.assign(process.env, selected);
  try {
    const context = {
      ...fixture.scan,
      mode: "diff",
      targetContract: {
        diffTarget: {
          kind: "working_tree",
          baseRevision,
          headRevision: "HEAD",
        },
      },
    };
    assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
      reviewItemsTotal: 1,
    });
    assert.deepEqual(await inventory.listCodexSecurityReviewItems(context), {
      items: [{ path: "visible.py" }],
    });
    const records = (await readFile(marker, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const child = records.find(
      (record) =>
        record.argv[1] ===
        path.join(fixture.scan.pluginRoot, "mcp", "helpers.mjs"),
    );
    assert.ok(child);
    assert.notEqual(child.pid, process.pid);
    assert.equal(child.node, process.execPath);
    assert.equal(child.cwd, process.cwd());
    assert.deepEqual(child.env, selected);
    for (const [name, value] of Object.entries(selected))
      assert.equal(process.env[name], value);
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function testInventoryChildPreservesRawPaths() {
  const fixture = await createFixture("inventory raw child paths");
  await runGit(fixture.repoRoot, "init", "-q");
  await runGit(fixture.repoRoot, "commit", "--allow-empty", "-qm", "base");
  const baseRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");
  await fixture.writeRepositoryFile("visible.py", "visible\n");
  await fixture.writeRepositoryFile("hidden.py", "hidden\n");
  // APFS requires valid UTF-8 names; Linux also permits undecodable bytes.
  const suffix =
    process.platform === "darwin" ? Buffer.from("雪") : Buffer.from([0xff]);
  const suffixText = process.platform === "darwin" ? "雪" : "\udcff";
  const rawPath = (name: string) =>
    Buffer.concat([Buffer.from(path.join(fixture.root, name)), suffix]);
  const repo = rawPath("repository-");
  await rename(fixture.repoRoot, repo);
  const ignore = path.join(fixture.root, "global-ignore");
  await writeFile(ignore, "hidden.py\n");
  const config = rawPath("global-config-");
  await writeFile(config, `[core]\nexcludesFile = ${JSON.stringify(ignore)}\n`);
  const git = rawPath("selected-git-");
  await writeFile(git, '#!/bin/sh\nexec git "$@"\n', { mode: 0o700 });
  const context = {
    ...fixture.scan,
    repoRoot: path.join(fixture.root, "repository-") + suffixText,
    mode: "diff",
    targetContract: {
      diffTarget: { kind: "working_tree", baseRevision, headRevision: "HEAD" },
    },
  };
  const driver = path.join(fixture.root, "prepare.mjs");
  await build({
    stdin: {
      contents: `import { prepareCodexSecurityReviewItems } from ${JSON.stringify(path.resolve(import.meta.dirname, "../src/artifact-inventory.ts"))}; console.log(JSON.stringify(await prepareCodexSecurityReviewItems(${JSON.stringify(context)})));`,
      loader: "ts",
      resolveDir: import.meta.dirname,
    },
    bundle: true,
    platform: "node",
    format: "esm",
    outfile: driver,
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  });
  const octal = (value: Buffer) =>
    [...value]
      .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
      .join("");
  const { stdout } = await execFile(
    "/bin/sh",
    [
      "-c",
      [
        `GIT_CONFIG_GLOBAL=$(printf '%b' '${octal(config)}'); export GIT_CONFIG_GLOBAL`,
        `CODEX_SECURITY_GIT=$(printf '%b' '${octal(git)}'); export CODEX_SECURITY_GIT`,
        'exec "$1" "$2"',
      ].join("\n"),
      "inventory-fixture",
      process.execPath,
      driver,
    ],
    { encoding: "utf8" },
  );
  assert.deepEqual(JSON.parse(stdout), { reviewItemsTotal: 1 });
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "visible.py\n");
}

async function testInventoryChildFailuresPreserveOutput() {
  for (const signal of process.platform === "win32" ? [false] : [false, true]) {
    const fixture = await createFixture("inventory child failure");
    const pluginRoot = path.join(fixture.root, "failing plugin");
    await mkdir(path.join(pluginRoot, "mcp"), { recursive: true });
    await writeFile(
      path.join(pluginRoot, "mcp", "helpers.mjs"),
      signal
        ? 'process.kill(process.pid, "SIGTERM");'
        : 'process.stderr.write("synthetic inventory failure\\n"); process.exitCode = 23;',
    );
    await writeInventory(fixture.scanInventory, "previous.py\n");
    await assert.rejects(
      inventory.prepareCodexSecurityReviewItems({
        ...fixture.scan,
        pluginRoot,
      }),
      signal ? /SIGTERM/u : /synthetic inventory failure/u,
    );
    assert.equal(
      await readFile(fixture.scanInventory, "utf8"),
      "previous.py\n",
    );
  }
}

async function testNonUtf8InventoryPaths() {
  const fixture = await createFixture("non-UTF-8 repository names");
  const rawPath = Buffer.concat([
    Buffer.from(path.join(fixture.repoRoot, "name-")),
    Buffer.from([0xff]),
    Buffer.from(".ts"),
  ]);
  await writeFile(rawPath, "raw path\n");
  await fixture.writeRepositoryFile("name-�.ts", "Unicode path\n");
  await assert.rejects(
    inventory.prepareCodexSecurityReviewItems(fixture.scan),
    /not valid for encoding utf-8/,
  );
  assert.ok((await readFile(fixture.scanInventory)).includes(0xff));
  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan),
    /not valid for encoding utf-8/,
  );
  await unlink(rawPath);
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(fixture.scan),
    {
      reviewItemsTotal: 1,
    },
  );
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(fixture.scan), {
    items: [{ path: "./name-�.ts" }],
  });
}

async function testPrepareListsIgnoredTrackedFilesOnce() {
  const fixture = await createFixture("ignored tracked files");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile(".gitignore", "-generated/\n");
  for (const name of ["a.ts", "b.ts"]) {
    await fixture.writeRepositoryFile(
      `-generated/${name}`,
      "export const value = 1;\n",
    );
  }
  await runGit(fixture.repoRoot, "add", "--force", "--", "-generated");
  const context = { ...fixture.scan, scope: "-generated" };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 2,
  });
  const first = await inventory.listCodexSecurityReviewItems(context, {
    limit: 1,
  });
  assert.deepEqual(first, {
    items: [{ path: "-generated/a.ts" }],
    nextCursor: "1",
  });
  assert.deepEqual(
    await inventory.listCodexSecurityReviewItems(context, {
      cursor: first.nextCursor,
      limit: 1,
    }),
    { items: [{ path: "-generated/b.ts" }] },
  );
}

async function testPrepareExcludesGitMetadata() {
  const fixture = await createFixture("nested repositories");
  for (const [name, source] of [
    [".git/config", "[core]\n"],
    ["vendor/lib/.git/HEAD", "ref: refs/heads/main\n"],
    ["vendor/lib/.git/hooks/example.py", "pass\n"],
    ["vendor/lib/handler.py", "pass\n"],
    ["vendor/worktree/.git", "gitdir: ../../.git/worktrees/example\n"],
    ["vendor/worktree/handler.py", "pass\n"],
    [".gitignore", "*.skip\n"],
    [".github/workflows/check.yml", "name: example\n"],
    ["src/widget.git", "example\n"],
  ] as const) {
    await fixture.writeRepositoryFile(name, source);
  }

  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(fixture.scan),
    { reviewItemsTotal: 5 },
  );
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(fixture.scan), {
    items: [
      { path: "./.github/workflows/check.yml" },
      { path: "./.gitignore" },
      { path: "./src/widget.git" },
      { path: "./vendor/lib/handler.py" },
      { path: "./vendor/worktree/handler.py" },
    ],
  });

  const metadataScope = { ...fixture.scan, scope: "vendor/lib/.git/hooks" };
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(metadataScope),
    { reviewItemsTotal: 0 },
  );
  assert.deepEqual(
    await inventory.listCodexSecurityReviewItems(metadataScope),
    {
      items: [],
    },
  );
}

async function testPrepareUsesOnlyAuthoritativeDiffChanges() {
  const fixture = await createFixture("selected committed changes");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile(
    "src/changed.ts",
    "export const value = 1;\n",
  );
  await fixture.writeRepositoryFile(
    "src/deleted.ts",
    "export const guard = true;\n",
  );
  await fixture.writeRepositoryFile(
    "src/unrelated.ts",
    "export const unrelated = 1;\n",
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "base");
  const baseRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");

  await fixture.writeRepositoryFile(
    "src/changed.ts",
    "export const value = 2;\n",
  );
  await fixture.writeRepositoryFile(
    "src/new.ts",
    "export const added = true;\n",
  );
  await fixture.writeRepositoryFile(
    "tests/example.ts",
    "export const testSetup = true;\n",
  );
  await unlink(path.join(fixture.repoRoot, "src/deleted.ts"));
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "selected changes");
  const headRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");
  const context = {
    ...fixture.scan,
    mode: "diff",
    targetContract: {
      diffTarget: { kind: "range", baseRevision, headRevision },
    },
  };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 4,
  });
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(context), {
    items: [
      { path: "src/changed.ts" },
      { path: "src/deleted.ts" },
      { path: "src/new.ts" },
      { path: "tests/example.ts" },
    ],
  });
}

async function testPrepareIncludesStagedAndUnstagedChanges() {
  const fixture = await createFixture("selected working tree changes");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile(
    "src/changed.ts",
    "export const value = 1;\n",
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "base");
  const revision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");

  await fixture.writeRepositoryFile(
    "src/changed.ts",
    "export const value = 2;\n",
  );
  await fixture.writeRepositoryFile(
    "src/staged.ts",
    "export const staged = true;\n",
  );
  await runGit(fixture.repoRoot, "add", "src/staged.ts");
  await fixture.writeRepositoryFile(
    "src/untracked.ts",
    "export const untracked = true;\n",
  );
  const context = {
    ...fixture.scan,
    mode: "diff",
    targetContract: {
      diffTarget: {
        kind: "working_tree",
        baseRevision: revision,
        headRevision: revision,
      },
    },
  };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 3,
  });
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(context), {
    items: [
      { path: "src/changed.ts" },
      { path: "src/staged.ts" },
      { path: "src/untracked.ts" },
    ],
  });
}

async function testWorkerReadsItsOwnBoundInventory() {
  const fixture = await createFixture("isolated worker inventory");
  await writeInventory(fixture.scanInventory, "./src/parent.ts\n");
  await writeInventory(fixture.workerInventory, "./src/worker.ts\n");

  assert.deepEqual(await inventory.listCodexSecurityReviewItems(fixture.scan), {
    items: [{ path: "./src/parent.ts" }],
  });
  assert.deepEqual(
    await inventory.listCodexSecurityReviewItems(fixture.worker),
    { items: [{ path: "./src/worker.ts" }] },
  );
}

async function testCursorDoesNotExceedInventory() {
  const fixture = await createFixture("inventory paging");
  await writeInventory(fixture.scanInventory, "./src/a.ts\n./src/b.ts\n");

  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan, { cursor: "3" }),
    /cursor/i,
  );
}

async function testEmptyInventoryIsValid() {
  const fixture = await createFixture("empty repository");

  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(fixture.scan),
    { reviewItemsTotal: 0 },
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "");
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(fixture.scan), {
    items: [],
  });
}

async function testUnsafeInventoryRowsAreRejected() {
  for (const unsafe of [
    "../outside.ts",
    "/absolute.ts",
    "src/../outside.ts",
    "src\\file.ts",
  ]) {
    const fixture = await createFixture("unsafe repository path");
    await writeInventory(fixture.scanInventory, `${unsafe}\n`);
    await assert.rejects(
      inventory.listCodexSecurityReviewItems(fixture.scan),
      /inventory row 1 has an unsafe repository path/,
    );
  }
}

async function testSymlinkedInventoryIsRejected() {
  const fixture = await createFixture("symlinked artifact");
  const outside = path.join(fixture.root, "outside.txt");
  await writeFile(outside, "src/outside.ts\n");
  await mkdir(path.dirname(fixture.scanInventory), { recursive: true });
  await symlink(outside, fixture.scanInventory);

  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan),
    /safe|regular|symlink/i,
  );
}

async function testInventoryReadErrorsAreReported() {
  const fixture = await createFixture("missing inventory");

  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan),
    /review_items.*(?:unavailable|missing|read)/i,
  );
  if (process.platform !== "win32" && process.getuid?.() !== 0) {
    await writeInventory(fixture.scanInventory, "./src/a.ts\n");
    try {
      await chmod(fixture.scanInventory, 0o000);
      await assert.rejects(
        inventory.listCodexSecurityReviewItems(fixture.scan),
        (error: Error & { cause?: NodeJS.ErrnoException }) => {
          assert.equal(error.cause?.code, "EACCES");
          assert.equal(
            error.message,
            `review_items: the requested artifact cannot be read: ${error.cause.message}`,
          );
          return true;
        },
      );
    } finally {
      await chmod(fixture.scanInventory, 0o600);
    }
    assert.deepEqual(
      await inventory.listCodexSecurityReviewItems(fixture.scan),
      {
        items: [{ path: "./src/a.ts" }],
      },
    );
  }
}

async function testWorkersCannotPrepareInventory() {
  const fixture = await createFixture("worker cannot prepare");

  await assert.rejects(
    inventory.prepareCodexSecurityReviewItems(fixture.worker),
    /only a parent scan/i,
  );
}

async function testBoundScopeFailurePreservesPreviousInventory() {
  const fixture = await createFixture("invalid bound scope");
  await writeInventory(fixture.scanInventory, "./src/original.ts\n");
  const invalid = { ...fixture.scan, scope: "../outside" };

  await assert.rejects(
    inventory.prepareCodexSecurityReviewItems(invalid),
    /review_items.*(?:scope|inventory helper failed)/i,
  );
  assert.equal(
    await readFile(fixture.scanInventory, "utf8"),
    "./src/original.ts\n",
  );
}

async function testInvalidDiffTargetPreservesPreviousInventory() {
  const fixture = await createFixture("invalid selected changes");
  await writeInventory(fixture.scanInventory, "src/original.ts\n");

  for (const targetContract of [undefined, { diffTarget: { kind: "range" } }]) {
    await assert.rejects(
      inventory.prepareCodexSecurityReviewItems({
        ...fixture.scan,
        mode: "diff",
        targetContract,
      }),
      /authoritative change set/u,
    );
    assert.equal(
      await readFile(fixture.scanInventory, "utf8"),
      "src/original.ts\n",
    );
  }
  await assert.rejects(
    inventory.prepareCodexSecurityReviewItems({
      ...fixture.scan,
      mode: "diff",
      targetContract: {
        diffTarget: {
          kind: "working_tree",
          baseRevision: "HEAD\0--out\0unexpected",
          headRevision: "HEAD",
        },
      },
    }),
    /NUL/u,
  );
  assert.equal(
    await readFile(fixture.scanInventory, "utf8"),
    "src/original.ts\n",
  );
}

async function testInventoryDoesNotLaunchPython() {
  const fixture = await createFixture("unused Python selection");
  await fixture.writeRepositoryFile("source.py", "source\n");
  const pythonCommand = path.join(fixture.root, "python");
  for (const present of [false, true]) {
    if (present) await writeFile(pythonCommand, "", { mode: 0o600 });
    assert.deepEqual(
      await inventory.prepareCodexSecurityReviewItems({
        ...fixture.scan,
        pythonCommand,
      }),
      { reviewItemsTotal: 1 },
    );
    assert.equal(
      await readFile(fixture.scanInventory, "utf8"),
      "./source.py\n",
    );
  }
}

async function createFixture(label: string) {
  const root = await temporaryDirectories.create(
    "security-artifact-inventory-",
  );
  const fixtureRoot = path.join(root, label);
  const repoRoot = path.join(fixtureRoot, "repository");
  const scanRoot = path.join(fixtureRoot, "scan");
  const workerRoot = path.join(fixtureRoot, "worker");
  const pluginRoot = path.resolve(
    import.meta.dirname,
    "../../../../sdk/typescript/_bundled_plugin",
  );
  await mkdir(repoRoot, { recursive: true });
  await mkdir(scanRoot, { recursive: true });
  return {
    root,
    repoRoot,
    async writeRepositoryFile(relativePath: string, source: string) {
      return writeInventory(path.join(repoRoot, relativePath), source);
    },
    scanInventory: path.join(
      scanRoot,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    ),
    workerInventory: path.join(
      workerRoot,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    ),
    scan: {
      root: scanRoot,
      repoRoot,
      layout: "scan",
      scope: ".",
      pluginRoot,
      pythonCommand: process.env.PYTHON ?? "python3",
    },
    worker: {
      root: workerRoot,
      repoRoot,
      layout: "worker",
    },
  };
}

async function writeInventory(destination: string, source: string) {
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, source);
}

async function runGit(repository: string, ...arguments_: string[]) {
  const { stdout } = await execFile(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...arguments_,
    ],
    { cwd: repository, encoding: "utf8" },
  );
  return stdout.trim();
}

console.log("compact artifact inventory tests passed");
