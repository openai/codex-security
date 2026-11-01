import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import assert from "node:assert/strict";
import { execFile as nodeExecFile } from "node:child_process";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { build } from "esbuild";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
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

// EUC-JP Perl source ("日本語コメント", "テスト", "こんにちは"), encoded as
// bytes because Node has no EUC-JP encoder. Non-UTF-8 text must stay eligible.
const EUC_JP_PERL_BASE = Buffer.from(
  "2320c6fccbdcb8eca5b3a5e1a5f3a5c80a6d7920246e616d65203d2022a5c6a5b9a5c8223b0a7072696e7420226261736520246e616d655c6e223b0a",
  "hex",
);
const EUC_JP_PERL_HEAD = Buffer.from(
  "2320c6fccbdcb8eca5b3a5e1a5f3a5c80a6d7920246e616d65203d2022a5c6a5b9a5c8223b0a7072696e742022436f6e74656e742d547970653a20746578742f706c61696e5c6e5c6e223b0a7072696e742022a4b3a4f3a4cba4c1a4cf20246e616d655c6e223b0a",
  "hex",
);

try {
  await testSchemasAreBoundAndExact();
  await testPrepareUsesTheExistingStandardGenerator();
  await testPreflightUsesAuthoritativeRequestedPaths();
  await testPreflightPreservesSavedPathKinds();
  await testFailedTrackedFileDiscoveryIsNotEmpty();
  await testPreflightCombinesGitAndRipgrepIgnoreRules();
  await testPreflightMatchesCanonicalIgnoreSemantics();
  if (process.platform !== "win32")
    await testAuthoritativeScopesWithoutRipgrep();
  await testLargeAuthoritativeScopeTransport();
  await testAuthoritativeLiteralTildePath();
  if (process.platform !== "win32")
    await testPreflightCancellationReapsHelper();
  if (!["win32", "darwin"].includes(process.platform))
    await testNonUtf8InventoryPaths();
  await testPrepareListsIgnoredTrackedFilesOnce();
  await testPrepareExcludesGitMetadata();
  await testPrepareUsesOnlyAuthoritativeDiffChanges();
  await testPrepareIncludesPerlSourceWithMixedEncodings();
  await testPrepareIncludesStagedAndUnstagedChanges();
  await testEmptyDiffInventoryIsValid();
  await testInventoryChildPreservesSettingsAndCwd();
  if (process.platform !== "win32") await testInventoryChildPreservesRawPaths();
  await testInventoryChildFailuresPreserveOutput();
  await testWorkerReadsItsOwnBoundInventory();
  await testCursorDoesNotExceedInventory();
  await testEmptyInventoryIsValid();
  await testEmptyChildDoesNotInheritParentGitFiles();
  await testUnsafeInventoryRowsAreRejected();
  await testSymlinkedInventoryIsRejected();
  await testInventoryReadErrorsAreReported();
  await testWorkersCannotPrepareInventory();
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
  await fixture.writeRepositoryFile("src/a.ts", "export const a = 1;\n");
  await fixture.writeRepositoryFile("-source.py", "source\n");
  await fixture.writeRepositoryFile("src/résumé.ts", "export const b = 2;\n");
  for (const name of ["\uFEFF来源.ts", "name-\uFFFD.ts", "🙂.ts"])
    await fixture.writeRepositoryFile(`src/${name}`, "export {};\n");
  await fixture.writeRepositoryFile(
    ".hidden/handler.ts",
    "export const c = 3;\n",
  );

  const pluginRoot = path.join(fixture.root, "installed-plugin");
  for (const directory of ["mcp", "scripts"]) {
    await cp(
      path.join(fixture.scan.pluginRoot, directory),
      path.join(pluginRoot, directory),
      {
        recursive: true,
        filter: (file) => path.basename(file) !== "__pycache__",
      },
    );
  }
  const result = await inventory.prepareCodexSecurityReviewItems({
    ...fixture.scan,
    pluginRoot,
    pythonCommand: process.env.PYTHON ?? "python3",
  });
  const scripts = await readdir(path.join(pluginRoot, "scripts"), {
    recursive: true,
  });
  assert.deepEqual(
    scripts.filter((name) => name.endsWith(".pyc")),
    [],
  );
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
  const nonExecutablePython = path.join(fixture.root, "non-executable-python");
  await writeFile(nonExecutablePython, "", { mode: 0o600 });
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems({
      ...fixture.scan,
      pythonCommand: nonExecutablePython,
      scope: "-source.py",
    }),
    { reviewItemsTotal: 1 },
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "-source.py\n");
}

async function testPreflightUsesAuthoritativeRequestedPaths() {
  const fixture = await createFixture("authoritative requested paths");
  await mkdir(path.join(fixture.repoRoot, "left", "nested"), {
    recursive: true,
  });
  await mkdir(path.join(fixture.repoRoot, "right"), { recursive: true });
  await fixture.writeRepositoryFile(
    "outside-selection.py",
    "# outside the requested scope\n",
  );
  await runGit(fixture.repoRoot, "init", "-q");
  await runGit(fixture.repoRoot, "add", "outside-selection.py");
  await runGit(fixture.repoRoot, "commit", "-qm", "root source");
  const context = (
    requiredIncludePaths: string[],
    filePaths: string[] = [],
  ) => ({
    ...fixture.scan,
    targetContract: {
      scope: { requiredIncludePaths, requiredExcludePaths: [], filePaths },
    },
  });
  const prepare = async (
    requiredIncludePaths: string[],
    filePaths: string[] = [],
  ) => {
    const selected = context(requiredIncludePaths, filePaths);
    return inventory.preflightCodexSecurityReviewItems(selected);
  };

  assert.deepEqual(await prepare(["left", "right"]), { reviewItemsTotal: 0 });

  await fixture.writeRepositoryFile("left/left.py", "# left\n");
  assert.deepEqual(await prepare(["left", "right"]), { reviewItemsTotal: 1 });

  await unlink(path.join(fixture.repoRoot, "left", "left.py"));
  await fixture.writeRepositoryFile("right/right.py", "# right\n");
  assert.deepEqual(await prepare(["left", "right"]), { reviewItemsTotal: 1 });

  await fixture.writeRepositoryFile("left/left.py", "# left\n");
  assert.deepEqual(await prepare(["left", "right"]), { reviewItemsTotal: 1 });

  await fixture.writeRepositoryFile("left/nested/source.py", "# nested\n");
  assert.deepEqual(await prepare(["left", "left/nested"]), {
    reviewItemsTotal: 1,
  });
  assert.deepEqual(await prepare(["left/left.py"], ["left/left.py"]), {
    reviewItemsTotal: 1,
  });

  assert.deepEqual(await prepare([".", "left"]), {
    reviewItemsTotal: 1,
  });

  await writeInventory(fixture.scanInventory, "previous.py\n");
  await assert.rejects(
    inventory.preflightCodexSecurityReviewItems(context(["missing"])),
    /scope.*does not exist|scope path not found|ENOENT/iu,
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "previous.py\n");
}

async function testAuthoritativeLiteralTildePath() {
  const fixture = await createFixture("literal tilde requested path");
  await fixture.writeRepositoryFile("~/selected.py", "# selected\n");
  const context = {
    ...fixture.scan,
    targetContract: {
      scope: {
        requiredIncludePaths: ["~/selected.py"],
        requiredExcludePaths: [],
        filePaths: ["~/selected.py"],
      },
    },
  };

  assert.deepEqual(await inventory.preflightCodexSecurityReviewItems(context), {
    reviewItemsTotal: 1,
  });
}

async function testPreflightPreservesSavedPathKinds() {
  const fixture = await createFixture("saved path kinds");
  const selected = path.join(fixture.repoRoot, "selected");
  const context = (filePaths: string[]) => ({
    ...fixture.scan,
    targetContract: {
      scope: {
        requiredIncludePaths: ["selected"],
        requiredExcludePaths: [],
        filePaths,
      },
    },
  });

  await fixture.writeRepositoryFile("selected", "# selected file\n");
  assert.deepEqual(
    await inventory.preflightCodexSecurityReviewItems(context(["selected"])),
    { reviewItemsTotal: 1 },
  );

  await unlink(selected);
  await fixture.writeRepositoryFile("selected/descendant.py", "# child\n");
  assert.deepEqual(
    await inventory.preflightCodexSecurityReviewItems(context(["selected"])),
    { reviewItemsTotal: 0 },
  );
  assert.deepEqual(
    await inventory.preflightCodexSecurityReviewItems(context([])),
    { reviewItemsTotal: 1 },
  );

  await rm(selected, { recursive: true });
  await fixture.writeRepositoryFile("selected", "# replacement file\n");
  assert.deepEqual(
    await inventory.preflightCodexSecurityReviewItems(context([])),
    { reviewItemsTotal: 0 },
  );
}

async function testPreflightCombinesGitAndRipgrepIgnoreRules() {
  const fixture = await createFixture("combined ignore rules");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile("selected/tracked.py", "# tracked\n");
  await fixture.writeRepositoryFile("selected/ignored.py", "# ignored\n");
  await runGit(fixture.repoRoot, "add", "--force", "selected/tracked.py");
  await runGit(fixture.repoRoot, "commit", "-qm", "tracked source");
  await writeFile(
    path.join(fixture.repoRoot, ".git", "info", "exclude"),
    "/selected/tracked.py\n",
  );
  await fixture.writeRepositoryFile(".ignore", "selected/ignored.py\n");

  await assertPreflightMatchesCanonical(
    fixture,
    "selected",
    true,
    "selected/tracked.py",
  );
}

async function testPreflightMatchesCanonicalIgnoreSemantics() {
  for (const ignoreName of [".ignore", ".rgignore"]) {
    const fixture = await createFixture(`nested ${ignoreName} negation`);
    await runGit(fixture.repoRoot, "init", "-q");
    await fixture.writeRepositoryFile(
      ".gitignore",
      "selected/nested/source.py\n",
    );
    await fixture.writeRepositoryFile(
      `selected/nested/${ignoreName}`,
      "!source.py\n",
    );
    await fixture.writeRepositoryFile(
      "selected/nested/source.py",
      "# explicitly included\n",
    );
    await assertPreflightMatchesCanonical(
      fixture,
      "selected",
      true,
      "selected/nested/source.py",
    );
  }

  if (process.platform !== "win32") {
    for (const ignoreName of [".ignore", ".rgignore"]) {
      const fixture = await createFixture(`symlinked ${ignoreName} rules`);
      await runGit(fixture.repoRoot, "init", "-q");
      const rules = path.join(
        path.dirname(fixture.repoRoot),
        `${ignoreName.slice(1)}-rules`,
      );
      await writeFile(rules, "selected/source.py\n");
      await symlink(rules, path.join(fixture.repoRoot, ignoreName));
      await fixture.writeRepositoryFile("selected/source.py", "# ignored\n");
      await assertPreflightMatchesCanonical(fixture, "selected", false);
    }
  }

  for (const ignoreName of [".ignore", ".rgignore"]) {
    const fixture = await createFixture(`${ignoreName} above worktree`);
    await runGit(fixture.repoRoot, "init", "-q");
    await writeFile(
      path.join(path.dirname(fixture.repoRoot), ignoreName),
      "*.py\n",
    );
    await fixture.writeRepositoryFile("selected/source.py", "# ignored\n");
    await assertPreflightMatchesCanonical(fixture, "selected", false);
  }

  {
    const fixture = await createFixture("ripgrep configuration");
    await runGit(fixture.repoRoot, "init", "-q");
    await fixture.writeRepositoryFile("selected/source.py", "# ignored\n");
    const config = path.join(fixture.root, "ripgrep-config");
    await writeFile(config, "--glob\n!*.py\n");
    const previous = process.env.RIPGREP_CONFIG_PATH;
    process.env.RIPGREP_CONFIG_PATH = config;
    try {
      await assertPreflightMatchesCanonical(fixture, "selected", false);
    } finally {
      if (previous === undefined) delete process.env.RIPGREP_CONFIG_PATH;
      else process.env.RIPGREP_CONFIG_PATH = previous;
    }
  }

  if (process.platform !== "win32") {
    const fixture = await createFixture("unrelated unreadable ignored child");
    await runGit(fixture.repoRoot, "init", "-q");
    await fixture.writeRepositoryFile(".gitignore", "selected/unreadable/\n");
    await fixture.writeRepositoryFile("selected/source.py", "# included\n");
    const unreadable = path.join(fixture.repoRoot, "selected", "unreadable");
    await mkdir(unreadable, { recursive: true });
    await chmod(unreadable, 0);
    try {
      await assertPreflightMatchesCanonical(
        fixture,
        "selected",
        true,
        "selected/source.py",
      );
    } finally {
      await chmod(unreadable, 0o700);
    }
  }
}

async function assertPreflightMatchesCanonical(
  fixture: Awaited<ReturnType<typeof createFixture>>,
  scope: string,
  expectedNonempty: boolean,
  expectedPath?: string,
) {
  const preflight = await inventory.preflightCodexSecurityReviewItems({
    ...fixture.scan,
    targetContract: {
      scope: {
        requiredIncludePaths: [scope],
        requiredExcludePaths: [],
        filePaths: [],
      },
    },
  });
  const canonical = await inventory.prepareCodexSecurityReviewItems({
    ...fixture.scan,
    scope,
  });
  assert.equal(canonical.reviewItemsTotal > 0, expectedNonempty);
  assert.deepEqual(preflight, {
    reviewItemsTotal: canonical.reviewItemsTotal > 0 ? 1 : 0,
  });
  if (expectedPath) {
    const listed = await inventory.listCodexSecurityReviewItems(fixture.scan, {
      limit: 1_000,
    });
    assert.ok(
      listed.items.some((item: { path: string }) => item.path === expectedPath),
      `${expectedPath} must remain in the canonical inventory`,
    );
  }
}

async function testAuthoritativeScopesWithoutRipgrep() {
  const fixture = await createFixture("standalone without ripgrep");
  await fixture.writeRepositoryFile("selected/source.py", "# selected\n");
  await runGit(fixture.repoRoot, "init", "-q");
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "source");
  const { stdout } = await execFile("sh", ["-c", "command -v git"], {
    encoding: "utf8",
  });
  const tools = path.join(fixture.root, "git-only-tools");
  await mkdir(tools);
  const selectedGit = path.join(tools, "git");
  await symlink(stdout.trim(), selectedGit);
  const saved = {
    PATH: process.env.PATH,
    CODEX_SECURITY_GIT: process.env.CODEX_SECURITY_GIT,
  };
  process.env.PATH = tools;
  process.env.CODEX_SECURITY_GIT = selectedGit;
  try {
    assert.deepEqual(
      await inventory.preflightCodexSecurityReviewItems({
        ...fixture.scan,
        targetContract: {
          scope: {
            requiredIncludePaths: ["selected"],
            requiredExcludePaths: [],
          },
        },
      }),
      { reviewItemsTotal: 1 },
    );
  } finally {
    if (saved.PATH === undefined) delete process.env.PATH;
    else process.env.PATH = saved.PATH;
    if (saved.CODEX_SECURITY_GIT === undefined)
      delete process.env.CODEX_SECURITY_GIT;
    else process.env.CODEX_SECURITY_GIT = saved.CODEX_SECURITY_GIT;
  }
}

async function testLargeAuthoritativeScopeTransport() {
  const fixture = await createFixture("large authoritative scope transport");
  const requested: string[] = [];
  for (let index = 0; index < 400; index += 1) {
    const selected = `selected-${index.toString().padStart(4, "0")}-${"x".repeat(80)}.py`;
    requested.push(selected);
    await fixture.writeRepositoryFile(selected, "# selected\n");
  }
  assert.ok(JSON.stringify(requested).length > 32_768);
  assert.deepEqual(
    await inventory.preflightCodexSecurityReviewItems({
      ...fixture.scan,
      targetContract: {
        scope: {
          requiredIncludePaths: requested,
          requiredExcludePaths: [],
          filePaths: requested,
        },
      },
    }),
    { reviewItemsTotal: 1 },
  );
}

async function testPreflightCancellationReapsHelper() {
  const fixture = await createFixture("cancel blocked preflight");
  await fixture.writeRepositoryFile("selected.py", "# selected\n");
  const pluginRoot = path.join(fixture.root, "blocked-plugin");
  const helper = path.join(pluginRoot, "mcp", "helpers.mjs");
  const marker = path.join(fixture.root, "blocked-helper.json");
  await mkdir(path.dirname(helper), { recursive: true });
  await writeFile(
    helper,
    `import {spawn} from "node:child_process";import {writeFileSync} from "node:fs";const child=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"ignore"});writeFileSync(${JSON.stringify(marker)},JSON.stringify({parent:process.pid,child:child.pid}));setInterval(()=>{},1000);`,
  );
  await writeInventory(fixture.scanInventory, "previous.py\n");
  const controller = new AbortController();
  const pending = inventory.preflightCodexSecurityReviewItems(
    { ...fixture.scan, pluginRoot },
    controller.signal,
  );
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      await readFile(marker);
      break;
    } catch {
      await delay(10);
    }
  }
  const processes = JSON.parse(await readFile(marker, "utf8")) as {
    parent: number;
    child: number;
  };
  controller.abort(new Error("cancel blocked inventory"));
  await assert.rejects(pending, /cancel blocked inventory/iu);
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "previous.py\n");
  for (const pid of [processes.parent, processes.child]) {
    await assertProcessExited(pid);
  }
}

async function testFailedTrackedFileDiscoveryIsNotEmpty() {
  const fixture = await createFixture("failed tracked discovery");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile("selected/hidden.py", "# tracked\n");
  await runGit(fixture.repoRoot, "add", "selected/hidden.py");
  await runGit(fixture.repoRoot, "commit", "-qm", "tracked source");
  await writeFile(
    path.join(fixture.repoRoot, ".git", "info", "exclude"),
    "/selected/hidden.py\n",
  );
  await writeFile(path.join(fixture.repoRoot, ".git", "index"), "corrupt\n");
  await writeInventory(fixture.scanInventory, "previous.py\n");
  const context = {
    ...fixture.scan,
    targetContract: {
      scope: {
        requiredIncludePaths: ["selected"],
        requiredExcludePaths: [],
      },
    },
  };

  await assert.rejects(
    inventory.preflightCodexSecurityReviewItems(context),
    /index|git.*(?:128|failed|error)/iu,
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "previous.py\n");
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
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
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
    LD_LIBRARY_PATH: path.join(fixture.root, "selected libraries"),
    DYLD_LIBRARY_PATH: path.join(fixture.root, "selected dylibs"),
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
  const marker = path.join(fixture.root, "child.json");
  const preload = path.join(fixture.root, "preload.cjs");
  const loaderSettings = {
    LD_LIBRARY_PATH: path.join(fixture.root, "selected libraries"),
    DYLD_LIBRARY_PATH: path.join(fixture.root, "selected dylibs"),
  };
  await writeFile(
    preload,
    `const fs = require('node:fs'); fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify({stdin:fs.readFileSync(0).length,env:Object.fromEntries(${JSON.stringify(Object.keys(loaderSettings))}.map(name=>[name,process.env[name]]))}));`,
  );
  const driver = path.join(fixture.root, "prepare.mjs");
  await build({
    stdin: {
      contents: `import { prepareCodexSecurityReviewItems } from ${JSON.stringify(path.resolve(import.meta.dirname, "../src/artifact-inventory.ts"))}; Object.assign(process.env, ${JSON.stringify({ ...loaderSettings, NODE_OPTIONS: `--require ${JSON.stringify(preload)}` })}); console.log(JSON.stringify(await prepareCodexSecurityReviewItems(${JSON.stringify(context)})));`,
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
        // Raw environment bytes are valid on macOS even though APFS names are UTF-8.
        'HOME=$(printf "/fixture/home-\\377"); export HOME',
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
  assert.deepEqual(JSON.parse(await readFile(marker, "utf8")), {
    stdin: 0,
    env: loaderSettings,
  });
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
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(fixture.scan),
    {
      reviewItemsTotal: 2,
    },
  );
  assert.ok((await readFile(fixture.scanInventory)).includes(0xff));
  assert.deepEqual(
    (await inventory.listCodexSecurityReviewItems(fixture.scan)).items
      .map((item: { path: string }) => item.path)
      .sort(),
    ["./name-\udcff.ts", "./name-�.ts"],
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

async function testPrepareIncludesPerlSourceWithMixedEncodings() {
  const fixture = await createFixture("perl source extensions");
  await runGit(fixture.repoRoot, "init", "-q");
  const perlSources = [
    "lib/Util.pm",
    "t/basic.t",
    "www/cgi-bin/app.pl",
    "www/cgi-bin/index.cgi",
  ];
  for (const source of perlSources)
    await fixture.writeRepositoryFile(source, "use strict;\n1;\n");
  // Perl CGI scripts need not carry a Perl extension at all.
  await fixture.writeRepositoryFile(
    "www/cgi-bin/entrypoint",
    "#!/usr/bin/env perl\nuse strict;\n1;\n",
  );
  await fixture.writeRepositoryFile("www/cgi-bin/legacy.cgi", EUC_JP_PERL_BASE);
  // A NUL byte keeps this out even though `.pm` is a familiar source
  // extension: selection is by content, not by suffix.
  await fixture.writeRepositoryFile(
    "www/cgi-bin/binary.pm",
    Buffer.from([0x00, 0xff, 0x01]),
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "base");
  const baseRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");

  for (const source of perlSources)
    await fixture.writeRepositoryFile(source, "use strict;\n2;\n");
  await fixture.writeRepositoryFile(
    "www/cgi-bin/entrypoint",
    "#!/usr/bin/env perl\nuse strict;\n2;\n",
  );
  await fixture.writeRepositoryFile("www/cgi-bin/legacy.cgi", EUC_JP_PERL_HEAD);
  await fixture.writeRepositoryFile(
    "www/cgi-bin/binary.pm",
    Buffer.from([0x00, 0xff, 0x02]),
  );
  await runGit(fixture.repoRoot, "add", ".");
  await runGit(fixture.repoRoot, "commit", "-qm", "change");
  const headRevision = await runGit(fixture.repoRoot, "rev-parse", "HEAD");
  const context = {
    ...fixture.scan,
    mode: "diff",
    targetContract: {
      diffTarget: { kind: "range", baseRevision, headRevision },
    },
  };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 6,
  });
  assert.deepEqual(await inventory.listCodexSecurityReviewItems(context), {
    items: [
      { path: "lib/Util.pm" },
      { path: "t/basic.t" },
      { path: "www/cgi-bin/app.pl" },
      { path: "www/cgi-bin/entrypoint" },
      { path: "www/cgi-bin/index.cgi" },
      { path: "www/cgi-bin/legacy.cgi" },
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

async function testEmptyDiffInventoryIsValid() {
  const fixture = await createFixture("empty selected diff");
  await runGit(fixture.repoRoot, "init", "-q");
  await fixture.writeRepositoryFile("src/app.ts", "export const app = 1;\n");
  await runGit(fixture.repoRoot, "add", "src/app.ts");
  await runGit(fixture.repoRoot, "commit", "-qm", "initial source");
  const revision = await runGit(
    fixture.repoRoot,
    "rev-parse",
    "--verify",
    "HEAD",
  );
  const context = {
    ...fixture.scan,
    mode: "diff",
    targetContract: {
      diffTarget: {
        kind: "range",
        baseRevision: revision,
        headRevision: revision,
      },
    },
  };

  assert.deepEqual(await inventory.prepareCodexSecurityReviewItems(context), {
    reviewItemsTotal: 0,
  });
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "");
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

async function testEmptyChildDoesNotInheritParentGitFiles() {
  const fixture = await createFixture("empty selected child");
  const repository = path.dirname(fixture.repoRoot);
  await runGit(repository, "init", "-q");
  await writeFile(path.join(repository, "parent-source.ts"), "export {}\n");
  await runGit(repository, "add", "parent-source.ts");
  await runGit(repository, "commit", "-qm", "parent source");

  assert.match(
    await runGit(fixture.repoRoot, "rev-parse", "--verify", "HEAD"),
    /^[0-9a-f]+$/u,
  );
  assert.deepEqual(
    await inventory.prepareCodexSecurityReviewItems(fixture.scan),
    { reviewItemsTotal: 0 },
  );
  assert.equal(await readFile(fixture.scanInventory, "utf8"), "");
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
    async writeRepositoryFile(relativePath: string, source: string | Buffer) {
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
      pythonCommand: path.join(root, "missing-python"),
    },
    worker: {
      root: workerRoot,
      repoRoot,
      layout: "worker",
    },
  };
}

async function writeInventory(destination: string, source: string | Buffer) {
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, source);
}

async function assertProcessExited(pid: number): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return;
      throw error;
    }
    await delay(10);
  }
  assert.fail(`inventory subprocess ${pid} was not reaped`);
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
