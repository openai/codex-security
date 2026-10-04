import { createTemporaryDirectories } from "./support/temporary-directories.mjs";
import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import { mkdir, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { importSource } from "./import-module.mjs";

const execFile = promisify(nodeExecFile);
const temporaryDirectories = createTemporaryDirectories(true);

const inventory = await importSource(
  new URL("../src/artifact-inventory.ts", import.meta.url).pathname,
);

try {
  await testSchemasAreBoundAndExact();
  await testPrepareUsesTheExistingStandardGenerator();
  await testPrepareListsIgnoredTrackedFilesOnce();
  await testPrepareExcludesGitMetadata();
  await testPrepareUsesOnlyAuthoritativeDiffChanges();
  await testPrepareIncludesStagedAndUnstagedChanges();
  await testScansReadTheirOwnBoundInventory();
  await testCursorAndLimitAreValidated();
  await testEmptyInventoryIsValid();
  await testUnsafeInventoryRowsAreRejected();
  await testSymlinkedInventoryIsRejected();
  await testMissingInventoryIsReported();
  await testUnboundContextCannotPrepareInventory();
  await testBoundScopeFailurePreservesPreviousInventory();
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
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/a.ts",
    "export const a = 1;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/résumé.ts",
    "export const b = 2;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    ".hidden/handler.ts",
    "export const c = 3;\n",
  );

  const result = await inventory.prepareCodexSecurityReviewItems(fixture.scan);
  const stored = await readFile(fixture.scanInventory, "utf8");
  const expected = await standardInventory(fixture.repoRoot, ".");

  assert.equal(stored, expected);
  assert.deepEqual(result, {
    reviewItemsTotal: expected.split("\n").filter(Boolean).length,
  });
  const first = await inventory.listCodexSecurityReviewItems(fixture.scan, {
    limit: 2,
  });
  assert.equal(first.items.length, 2);
  assert.equal(first.nextCursor, "2");
  assert.equal(Object.hasOwn(first.items[0], "area"), false);
  assert.equal(
    first.items.every((item) => item.path.startsWith("./")),
    true,
  );
  const second = await inventory.listCodexSecurityReviewItems(fixture.scan, {
    cursor: first.nextCursor,
    limit: 20,
  });
  assert.equal(Object.hasOwn(second, "nextCursor"), false);
  assert.deepEqual(
    [...first.items, ...second.items].map((item) => item.path),
    expected.split("\n").filter(Boolean),
  );
}

async function testPrepareListsIgnoredTrackedFilesOnce() {
  const fixture = await createFixture("ignored tracked files");
  await initializeRepository(fixture.repoRoot);
  await writeRepositoryFile(fixture.repoRoot, ".gitignore", "generated/\n");
  for (const name of ["a.ts", "b.ts"]) {
    await writeRepositoryFile(
      fixture.repoRoot,
      `generated/${name}`,
      "export const value = 1;\n",
    );
  }
  await runGit(fixture.repoRoot, "add", "--force", "--", "generated");
  const context = { ...fixture.scan, scope: "generated" };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 2,
  });
  const first = await inventory.listCodexSecurityReviewItems(context, {
    limit: 1,
  });
  assert.deepEqual(first, {
    items: [{ path: "generated/a.ts" }],
    nextCursor: "1",
  });
  assert.deepEqual(
    await inventory.listCodexSecurityReviewItems(context, {
      cursor: first.nextCursor,
      limit: 1,
    }),
    { items: [{ path: "generated/b.ts" }] },
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
  ]) {
    await writeRepositoryFile(fixture.repoRoot, name, source);
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
  await initializeRepository(fixture.repoRoot);
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/changed.ts",
    "export const value = 1;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/deleted.ts",
    "export const guard = true;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/unrelated.ts",
    "export const unrelated = 1;\n",
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "base");
  const baseRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");

  await writeRepositoryFile(
    fixture.repoRoot,
    "src/changed.ts",
    "export const value = 2;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/new.ts",
    "export const added = true;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "tests/example.ts",
    "export const ignored = true;\n",
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
    reviewItemsTotal: 3,
  });
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(context), {
    items: [
      { path: "src/changed.ts" },
      { path: "src/deleted.ts" },
      { path: "src/new.ts" },
    ],
  });
}

async function testPrepareIncludesStagedAndUnstagedChanges() {
  const fixture = await createFixture("selected working tree changes");
  await initializeRepository(fixture.repoRoot);
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/changed.ts",
    "export const value = 1;\n",
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "base");
  const revision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");

  await writeRepositoryFile(
    fixture.repoRoot,
    "src/changed.ts",
    "export const value = 2;\n",
  );
  await writeRepositoryFile(
    fixture.repoRoot,
    "src/staged.ts",
    "export const staged = true;\n",
  );
  await runGit(fixture.repoRoot, "add", "src/staged.ts");
  await writeRepositoryFile(
    fixture.repoRoot,
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

async function testScansReadTheirOwnBoundInventory() {
  const first = await createFixture("first scan inventory");
  const second = await createFixture("second scan inventory");
  await writeInventory(first.scanInventory, "./src/first.ts\n");
  await writeInventory(second.scanInventory, "./src/second.ts\n");

  assert.deepEqual(await inventory.listCodexSecurityReviewItems(first.scan), {
    items: [{ path: "./src/first.ts" }],
  });
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(second.scan), {
    items: [{ path: "./src/second.ts" }],
  });
}

async function testCursorAndLimitAreValidated() {
  const fixture = await createFixture("inventory paging");
  await writeInventory(fixture.scanInventory, "./src/a.ts\n./src/b.ts\n");

  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan, { cursor: "-1" }),
    /cursor/i,
  );
  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan, { cursor: "3" }),
    /cursor/i,
  );
  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan, { limit: 0 }),
    /limit/i,
  );
  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan, { limit: 1001 }),
    /limit/i,
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

async function testMissingInventoryIsReported() {
  const fixture = await createFixture("missing inventory");

  await assert.rejects(
    inventory.listCodexSecurityReviewItems(fixture.scan),
    /review_items.*(?:unavailable|missing|read)/i,
  );
}

async function testUnboundContextCannotPrepareInventory() {
  const fixture = await createFixture("unbound context cannot prepare");

  await assert.rejects(
    inventory.prepareCodexSecurityReviewItems({
      ...fixture.scan,
      scanId: undefined,
    }),
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
}

async function createFixture(label) {
  const root = await temporaryDirectories.create(
    "security-artifact-inventory-",
  );
  const fixtureRoot = path.join(root, label);
  const repoRoot = path.join(fixtureRoot, "repository");
  const scanRoot = path.join(fixtureRoot, "scan");
  const pluginRoot = new URL("../../", import.meta.url).pathname;
  await Promise.all([
    mkdir(repoRoot, { recursive: true }),
    mkdir(scanRoot, { recursive: true }),
  ]);
  return {
    root,
    repoRoot,
    scanInventory: path.join(
      scanRoot,
      "artifacts",
      "02_discovery",
      "in_scope_files.txt",
    ),
    scan: {
      root: scanRoot,
      repoRoot,
      scanId: "f84c8312-a602-4660-8e01-518a176cd75a",
      scope: ".",
      pluginRoot,
      pythonCommand: process.env.PYTHON ?? "python3",
    },
  };
}

async function writeRepositoryFile(repository, relativePath, source) {
  const destination = path.join(repository, relativePath);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, source);
}

async function writeInventory(destination, source) {
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, source);
}

async function standardInventory(repository, scope) {
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
      scope,
    ],
    { cwd: repository, encoding: "utf8" },
  );
  return stdout
    .split("\n")
    .filter(Boolean)
    .sort((left, right) =>
      Buffer.compare(Buffer.from(left), Buffer.from(right)),
    )
    .map((line) => `${line}\n`)
    .join("");
}

async function initializeRepository(repository) {
  await runGit(repository, "init", "-q");
}

async function runGit(repository, ...arguments_) {
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
