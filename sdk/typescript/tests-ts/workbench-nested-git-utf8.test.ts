import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function git(directory: string, ...args: string[]): void {
  const result = spawnSync("git", ["-C", directory, ...args], {
    encoding: "utf8",
    windowsHide: true,
  });
  expect(result.status, result.stderr).toBe(0);
}

function pythonExecutable(): string | null {
  return (
    process.env["PYTHON"] ??
    Bun.which("python3") ??
    Bun.which("python") ??
    Bun.which("py")
  );
}

test("writes nested Git pointers as UTF-8 independently of the locale", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-nested-git-utf8-")),
  );
  temporaryDirectories.push(root);
  const repository = join(root, "repository");
  const nested = join(repository, "nested-漢字");
  const checkout = join(root, "checkout");
  mkdirSync(nested, { recursive: true });
  git(repository, "init", "-q");
  git(nested, "init", "-q");

  const python = pythonExecutable();
  expect(python).not.toBeNull();
  const probe = [
    "import pathlib, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_target as target",
    "original_open = pathlib.Path.open",
    "def locale_open(self, mode='r', buffering=-1, encoding=None, errors=None, newline=None):",
    "    if 'b' not in mode and encoding is None:",
    "        encoding = 'cp1252'",
    "    return original_open(self, mode, buffering, encoding, errors, newline)",
    "pathlib.Path.open = locale_open",
    "target.copy_git_worktree_files(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), ())",
  ].join("\n");
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(PLUGIN_ROOT, "scripts"),
      repository,
      checkout,
    ],
    { encoding: "utf8", windowsHide: true },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(join(checkout, "nested-漢字", ".git"), "utf8")).toContain(
    "nested-漢字",
  );
});
