import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  realpath,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join, relative, sep } from "node:path";
import { runGitRepositoryCommand, runWorkflow } from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

function quoted(path: string): string {
  return `"${[...Buffer.from(path)]
    .map((byte) =>
      byte >= 32 && byte < 127 && byte !== 34 && byte !== 92
        ? String.fromCharCode(byte)
        : `\\${byte.toString(8).padStart(3, "0")}`,
    )
    .join("")}"`;
}

async function repository() {
  const root = await fixtures.create("patch-alternate-");
  const support = await fixtures.create("patch-alternate-support-");
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    GIT_DIR: undefined,
    GIT_WORK_TREE: undefined,
    GIT_OBJECT_DIRECTORY: undefined,
    GIT_ALTERNATE_OBJECT_DIRECTORIES: undefined,
    GIT_CONFIG_GLOBAL: "",
    GIT_CONFIG_SYSTEM: "",
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const git = (args: string[], cwd = root, overrides = {}) =>
    execFileSync("git", args, {
      cwd,
      env: { ...environment, ...overrides },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  git(["init", "--initial-branch=main"]);
  git(["config", "user.name", "Synthetic User"]);
  git(["config", "user.email", "synthetic@example.test"]);
  git(["config", "commit.gpgsign", "false"]);
  await writeFile(join(root, "app.ts"), "before\n");
  git(["add", "."]);
  git(["commit", "-m", "Synthetic alternate baseline"]);
  const pool = join(support, "pool");
  await mkdir(pool);
  const payload = join(support, "payload");
  await writeFile(payload, "Synthetic alternate-only object\n");
  const object = git(["hash-object", "-w", payload], root, {
    GIT_OBJECT_DIRECTORY: pool,
  });
  return { root, support, pool, environment, git, object };
}

async function patch(
  fixture: Awaited<ReturnType<typeof repository>>,
  cwd = fixture.root,
  worktree = fixture.root,
) {
  const { root, environment, git, object } = fixture;
  const beforeEnvironment = { ...environment };
  const ambient = process.env["GIT_ALTERNATE_OBJECT_DIRECTORIES"];
  const index = await readFile(join(root, ".git", "index"));
  expect(git(["cat-file", "-p", object], cwd)).toBe(
    "Synthetic alternate-only object",
  );
  const nativeAlternates = git(
    ["-c", "core.quotePath=false", "count-objects", "-v"],
    cwd,
  )
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("alternate: "))
    .map((line) => line.slice("alternate: ".length));
  let controls: readonly string[] = [];
  let launches = 0;
  const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
    currentDirectory: cwd,
    environment,
    onRepositoryCommand: (command, args, directory, options) =>
      runGitRepositoryCommand(command, args, directory, {
        ...options,
        environment: { ...environment, ...options?.environment },
      }),
    onCodex: async (_args, output, childEnvironment) => {
      launches++;
      controls = output?.appServer?.permissions?.readOnlyPaths ?? [];
      expect(childEnvironment?.["GIT_ALTERNATE_OBJECT_DIRECTORIES"]).toBe(
        environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"],
      );
      await writeFile(join(worktree, "app.ts"), "after\n");
      output?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(launches).toBe(1);
  expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
  expect(await readFile(join(root, ".git", "index"))).toEqual(index);
  expect(environment).toEqual(beforeEnvironment);
  expect(process.env["GIT_ALTERNATE_OBJECT_DIRECTORIES"]).toBe(ambient);
  return {
    controls: controls.map((path) => path.replaceAll("\\", "/")),
    nativeAlternates,
  };
}

test.each([
  "quoted multiple pools",
  "relative from discovered subdirectory",
  "relative with explicit Git directory",
  "directory link parent traversal",
  "absolute native drive spelling",
  "ignored and C-quoted entries",
  "repository-authored indirect pools",
])("patch grants caller-selected alternate objects: %s", async (mode) => {
  const fixture = await repository();
  const { root, support, environment } = fixture;
  let pool = fixture.pool;
  let cwd = root;
  let worktree = root;
  let value = quoted(pool);
  const expected: string[] = [];
  const excluded: string[] = [];
  if (mode === "quoted multiple pools") {
    pool = join(support, `pool${delimiter}é`);
    await rename(fixture.pool, pool);
    const second = join(support, "second ü pool");
    await mkdir(second);
    value = [quoted(pool), quoted(second)].join(delimiter);
    expected.push(second);
  } else if (mode.startsWith("relative")) {
    cwd = join(root, "component");
    await mkdir(cwd);
    const explicit = mode === "relative with explicit Git directory";
    if (explicit) {
      environment["GIT_DIR"] = join(root, ".git");
      worktree = cwd;
      await writeFile(join(worktree, "app.ts"), "before\n");
    }
    value = relative(explicit ? cwd : root, pool);
  } else if (mode === "directory link parent traversal") {
    const physical = join(support, "physical");
    await mkdir(join(physical, "child"), { recursive: true });
    const physicalPool = join(physical, "pool");
    if (process.platform === "win32") {
      await mkdir(physicalPool);
      excluded.push(physicalPool);
    } else {
      pool = physicalPool;
      await rename(fixture.pool, pool);
      await mkdir(fixture.pool);
      excluded.push(fixture.pool);
    }
    const link = join(support, "alias");
    await symlink(
      join(physical, "child"),
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    value = quoted(`${link}${sep}..${sep}pool`);
  } else if (mode === "absolute native drive spelling") {
    value = quoted(pool.replaceAll("\\", "/"));
  } else if (mode === "ignored and C-quoted entries") {
    const notDirectory = join(support, "not-directory");
    await writeFile(notDirectory, "Synthetic ordinary file\n");
    value = [
      `${quoted(pool).slice(0, -1)}\\000ignored"`,
      "#ignored",
      "",
      quoted(join(support, "missing")),
      quoted(notDirectory),
      `${quoted(support).slice(0, -1)}/invalid-\\377"`,
      '"unterminated',
    ].join(delimiter);
  } else if (mode === "repository-authored indirect pools") {
    for (const owner of [join(root, ".git", "objects"), pool]) {
      const indirect = join(support, `indirect-${excluded.length}`);
      await mkdir(indirect);
      await mkdir(join(owner, "info"), { recursive: true });
      await writeFile(
        join(owner, "info", "alternates"),
        `${quoted(indirect)}\n`,
      );
      excluded.push(indirect);
    }
  }
  environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = value;
  expected.push(pool);
  const { controls, nativeAlternates } = await patch(fixture, cwd, worktree);
  for (const path of expected) {
    const canonical = (await realpath(path)).replaceAll("\\", "/");
    expect(nativeAlternates).toContain(canonical);
    expect(controls).toContain(canonical);
  }
  for (const path of excluded) {
    const canonical = (await realpath(path)).replaceAll("\\", "/");
    expect(controls).not.toContain(canonical);
    if (mode === "repository-authored indirect pools")
      expect(nativeAlternates).toContain(canonical);
  }
});

test("concurrent patches retain separate caller-selected alternate pools", async () => {
  const pair = await Promise.all([repository(), repository()]);
  for (const fixture of pair)
    fixture.environment["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = quoted(
      fixture.pool,
    );
  const results = await Promise.all(pair.map((fixture) => patch(fixture)));
  for (const [index, result] of results.entries()) {
    expect(result.controls).toContain(pair[index]!.pool.replaceAll("\\", "/"));
    expect(result.controls).not.toContain(
      pair[1 - index]!.pool.replaceAll("\\", "/"),
    );
  }
});
