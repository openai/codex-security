import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

function pythonExecutable(): string | null {
  return (
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

function pythonEnvironment(
  overrides: NodeJS.ProcessEnv = {},
): NodeJS.ProcessEnv {
  const executable = Bun.which("git");
  expect(executable).not.toBeNull();
  if (executable === null) throw new Error("Git is required for diff tests.");
  return {
    ...process.env,
    CODEX_SECURITY_GIT: realpathSync(executable),
    ...overrides,
  };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}

test("diff previews stay inside the selected repository", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  const nested = join(repository, "src", "nested");
  mkdirSync(nested, { recursive: true });
  git(repository, "init", "-q");
  writeFileSync(join(repository, "src", "handler.py"), "value = 1\n");
  writeFileSync(join(repository, "src", "deleted.py"), "removed = True\n");
  writeFileSync(join(repository, "src", "entry.py"), "handler.py");
  writeFileSync(join(nested, "linked.py"), "value = 1\n");
  git(repository, "add", ".");
  const originalLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${originalLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");

  writeFileSync(join(repository, "src", "handler.py"), "value = 2\n");
  writeFileSync(join(repository, "src", "entry.py"), "nested/linked.py");
  writeFileSync(join(nested, "linked.py"), "value = 2\n");
  rmSync(join(repository, "src", "deleted.py"));
  git(repository, "add", ".");
  const updatedLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${updatedLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "selected changes");
  const head = git(repository, "rev-parse", "HEAD");

  const externalFixture = join(root, "synthetic-fixture");
  mkdirSync(externalFixture);
  writeFileSync(join(externalFixture, "linked.py"), "synthetic = True\n");
  rmSync(nested, { recursive: true });
  symlinkSync(externalFixture, nested, "junction");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const output = join(root, "rank-input.jsonl");
  const result = spawnSync(
    python!,
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--mode",
      "local-patch",
      "--out",
      output,
    ],
    { encoding: "utf8", env: pythonEnvironment() },
  );

  expect(result.status, result.stderr).toBe(0);
  const rows = readFileSync(output, "utf8")
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row) as { path: string; preview: string });
  expect(rows.map((row) => row.path)).toEqual([
    "src/deleted.py",
    "src/entry.py",
    "src/handler.py",
    "src/nested/linked.py",
  ]);
  expect(rows.find((row) => row.path === "src/handler.py")?.preview).toBe(
    "value = 2",
  );
  expect(rows.find((row) => row.path === "src/nested/linked.py")?.preview).toBe(
    "",
  );
});

test("preserves Unicode Git paths and legacy-encoded commit metadata", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-unicode-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository-漢字");
  const source = join(repository, "src", "変更.py");
  mkdirSync(join(repository, "src"), { recursive: true });
  git(repository, "init", "-q");
  writeFileSync(source, "value = 1\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");
  writeFileSync(source, "value = 2\n");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "変更");
  const head = git(repository, "rev-parse", "HEAD");
  const legacyMessage = join(root, "legacy-message");
  writeFileSync(legacyMessage, Buffer.from("café\n", "latin1"));
  git(
    repository,
    "-c",
    "i18n.commitEncoding=ISO-8859-1",
    "commit",
    "--allow-empty",
    "-q",
    "-F",
    legacyMessage,
  );
  const legacyHead = git(repository, "rev-parse", "HEAD");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const output = join(root, "rank-input.jsonl");
  const rank = spawnSync(
    python!,
    [
      "-I",
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--out",
      output,
    ],
    { encoding: "utf8", env: pythonEnvironment() },
  );
  const probeSource = [
    "import json, pathlib, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_target as target",
    "import workbench_db as db",
    "repo = pathlib.Path(sys.argv[2])",
    "root, pathspec = target.git_worktree_context(repo)",
    "metadata = target.git_target_metadata(repo)",
    "diff = db.require_diff_target(repo, 'commit', None, sys.argv[3], None)",
    "print(json.dumps({'root': str(root), 'pathspec': pathspec, 'subject': metadata['commitSubject'], 'diff': diff}))",
  ].join("\n");
  const probe = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      probeSource,
      join(PLUGIN_ROOT, "scripts"),
      repository,
      legacyHead,
    ],
    { encoding: "utf8", env: pythonEnvironment() },
  );

  expect(rank.status, `${rank.stderr}\n${String(rank.error ?? "")}`).toBe(0);
  expect(
    readFileSync(output, "utf8")
      .trimEnd()
      .split("\n")
      .map((row) => JSON.parse(row) as { path: string; preview: string })
      .map(({ path, preview }) => ({ path, preview })),
  ).toEqual([{ path: "src/変更.py", preview: "value = 2" }]);
  expect(probe.status, probe.stderr).toBe(0);
  const target = JSON.parse(probe.stdout) as {
    root: string;
    pathspec: string;
    subject: string;
    diff: { kind: string; baseRevision: string; headRevision: string };
  };
  expect(basename(target.root)).toBe("repository-漢字");
  expect(target).toMatchObject({
    pathspec: ".",
    subject: "café",
    diff: { kind: "commit", baseRevision: head, headRevision: legacyHead },
  });
});

testPosix(
  "uses only the host-selected Git executable for rank and inventory helpers",
  () => {
    const root = realpathSync(
      mkdtempSync(join(tmpdir(), "codex-security-host-git-")),
    );
    temporaryRoots.push(root);
    const repository = join(root, "repository");
    const shimDirectory = join(repository, "tools");
    const shim = join(shimDirectory, "git");
    const externalBin = join(root, "external-bin");
    const ripgrep = join(externalBin, "rg");
    const marker = join(root, "shim-ran");
    mkdirSync(shimDirectory, { recursive: true });
    mkdirSync(externalBin);
    git(repository, "init", "-q");
    writeFileSync(join(repository, "source.py"), "value = 1\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "base");
    const base = git(repository, "rev-parse", "HEAD");
    writeFileSync(join(repository, "source.py"), "value = 2\n");
    git(repository, "add", ".");
    git(repository, "commit", "-qm", "head");
    const head = git(repository, "rev-parse", "HEAD");
    writeFileSync(shim, '#!/bin/sh\n: > "$GIT_SHIM_MARKER"\nexit 99\n');
    chmodSync(shim, 0o700);
    symlinkSync(shim, join(externalBin, "git"));
    writeFileSync(ripgrep, "#!/bin/sh\nprintf './source.py\\n'\n");
    chmodSync(ripgrep, 0o700);

    const python = pythonExecutable();
    expect(python).not.toBeNull();
    const rankOutput = join(root, "rank.jsonl");
    const inventoryOutput = join(root, "inventory.txt");
    const environment = {
      PATH: `${externalBin}:${process.env["PATH"] ?? ""}`,
      GIT_SHIM_MARKER: marker,
    };
    const rankArguments = [
      "-I",
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--out",
      rankOutput,
    ];

    const unavailable = spawnSync(python!, rankArguments, {
      encoding: "utf8",
      env: pythonEnvironment({ ...environment, CODEX_SECURITY_GIT: "" }),
    });
    expect(unavailable.status).not.toBe(0);

    const rejected = spawnSync(python!, rankArguments, {
      encoding: "utf8",
      env: pythonEnvironment({ ...environment, CODEX_SECURITY_GIT: shim }),
    });
    expect(rejected.status).not.toBe(0);
    expect(rejected.stderr).toContain("outside the protected repository");

    const rank = spawnSync(python!, rankArguments, {
      encoding: "utf8",
      env: pythonEnvironment(environment),
    });
    expect(rank.status, rank.stderr).toBe(0);

    const inventory = spawnSync(
      python!,
      [
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-head",
        head,
        "--out",
        inventoryOutput,
      ],
      { encoding: "utf8", env: pythonEnvironment(environment) },
    );
    expect(inventory.status, inventory.stderr).toBe(0);
    expect(readFileSync(inventoryOutput, "utf8")).toBe("source.py\n");

    const codebaseInventory = spawnSync(
      python!,
      [
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "generate_in_scope_files.py"),
        "--repo",
        repository,
        "--scope",
        ".",
        "--out",
        inventoryOutput,
      ],
      { encoding: "utf8", env: pythonEnvironment(environment) },
    );
    expect(codebaseInventory.status, codebaseInventory.stderr).toBe(0);
    expect(readFileSync(inventoryOutput, "utf8")).toContain("./source.py\n");
    expect(existsSync(marker)).toBe(false);
  },
);
