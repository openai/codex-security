import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function probe(program: string, ...args: string[]): void {
  const python = Bun.which("python3") ?? Bun.which("python");
  if (python === null)
    throw new Error("Python is required for workbench tests.");
  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts"), ...args],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, result.stderr.toString()).toBe(0);
}

test("normalizes absolute Windows scopes without accepting escapes", () => {
  probe(
    [
      "import sys",
      "from pathlib import PureWindowsPath",
      "from types import SimpleNamespace",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "class WindowsPath(PureWindowsPath):",
      "    def resolve(self): return self",
      "    def is_dir(self): return True",
      "workbench.Path = WindowsPath",
      "workbench.os = SimpleNamespace(name='nt')",
      "target = WindowsPath('C:/repository')",
      "assert workbench.require_scope(r'C:\\repository\\src', 'standard', target) == 'src'",
      "assert workbench.require_scope('src/nested', 'standard', target) == 'src/nested'",
      "assert workbench.require_scope(r'C:\\repository', 'deep', target) == '.'",
      "for scope, mode in [(r'src\\nested', 'standard'), (r'C:\\other', 'standard'), (r'C:\\repository\\..\\other', 'standard'), ('src', 'deep')]:",
      "    try: workbench.require_scope(scope, mode, target)",
      "    except SystemExit: pass",
      "    else: raise AssertionError((scope, mode))",
    ].join("\n"),
  );
});

test("verifies LF and CRLF patches with Git line-ending conversion enabled", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-line-endings-")),
  );
  directories.push(root);
  probe(
    [
      "import hashlib, os, sys",
      "from pathlib import Path",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "os.environ.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='core.autocrlf', GIT_CONFIG_VALUE_0='true')",
      "root = Path(sys.argv[2])",
      "for index, ending in enumerate((b'\\n', b'\\r\\n')):",
      "    target, scan_dir = root / f'target-{index}', root / f'scan-{index}'",
      "    target.mkdir(); scan_dir.mkdir(mode=0o700)",
      "    source = target / 'source.txt'",
      "    source.write_bytes(b'vulnerable' + ending)",
      "    base = workbench.directory_content_digest(target)",
      "    patch = b'diff --git a/source.txt b/source.txt\\n--- a/source.txt\\n+++ b/source.txt\\n@@ -1 +1 @@\\n-vulnerable\\n+fixed\\n'",
      "    patch_path = scan_dir / 'remediation.patch'",
      "    patch_path.write_bytes(patch)",
      "    applied = workbench.git_command(target, 'apply', '--no-index', str(patch_path), text=True)",
      "    assert applied.returncode == 0, applied.stderr",
      "    scan = {'target_path': str(target), 'target_inode': target.stat().st_ino, 'target_revision': 'unversioned', 'scan_dir': str(scan_dir)}",
      "    remediation = {'base_revision': 'unversioned', 'base_content_digest': base, 'patch_digest': 'sha256:' + hashlib.sha256(patch).hexdigest()}",
      "    current = workbench.directory_content_digest(target)",
      "    assert workbench.require_reviewed_patch_applied(scan, remediation, patch_path.name) == current",
      "    assert workbench.directory_content_digest(target) == current",
      "    (target / 'unrelated.txt').write_bytes(b'unrelated\\n')",
      "    try: workbench.require_reviewed_patch_applied(scan, remediation, patch_path.name)",
      "    except SystemExit as error: assert 'changes outside the reviewed patch' in str(error)",
      "    else: raise AssertionError('unrelated changes were accepted')",
    ].join("\n"),
    root,
  );
});
