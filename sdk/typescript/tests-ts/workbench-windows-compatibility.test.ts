import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { PLUGIN_PYTHON_PROBE } from "../src/plugin-python-probe.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import * as pythonProbe from "./support/python-probe.js";
import { pythonExecutable } from "./support/python.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories(true);

afterEach(directories.cleanup);

function probe(program: string, ...args: string[]): void {
  const python = pythonExecutable();
  if (python === null)
    throw new Error("Python is required for workbench tests.");
  const result = pythonProbe.runPython(python, [
    "-c",
    program,
    join(PLUGIN_ROOT, "scripts"),
    ...args,
  ]);
  expect(result.exitCode, result.stderr.toString()).toBe(0);
}

test("uses a configured Python executable and discovers one for an empty override", () => {
  const previous = process.env["PYTHON"];
  try {
    const discovered = pythonExecutable(false);
    process.env["PYTHON"] = "";
    expect(pythonExecutable()).toBe(discovered);
    process.env["PYTHON"] = "  synthetic python  ";
    expect(pythonExecutable()).toBe("synthetic python");
    expect(pythonExecutable(false)).toBe(discovered);
  } finally {
    if (previous === undefined) delete process.env["PYTHON"];
    else process.env["PYTHON"] = previous;
  }
});

test.skipIf(process.platform !== "win32")(
  "falls back to the Python launcher after a timeout and an unusable Windows alias",
  () => {
    const python = pythonExecutable();
    expect(python).not.toBeNull();
    using _which = spyOn(Bun, "which").mockImplementation((name) =>
      name === "py" ? python : process.execPath,
    );
    using probes = spyOn(pythonProbe, "runNodePython").mockReturnValueOnce({
      pid: 0,
      output: [],
      stdout: "",
      stderr: "",
      signal: "SIGTERM",
      status: null,
      error: Object.assign(new Error("Timed out"), { code: "ETIMEDOUT" }),
    });
    expect(pythonExecutable(false)).toBe(python);
    expect(probes.mock.calls.map((call) => call[2]?.timeout)).toEqual([
      30_000, 30_000, 30_000,
    ]);
  },
);

test("the Python probe rejects unsupported versions and checks tomli on Python 3.10", () => {
  const python = pythonExecutable();
  expect(python).not.toBeNull();
  for (const [minor, tomli, status] of [
    [9, true, 1],
    [10, false, 1],
    [10, true, 0],
    [11, false, 0],
  ] as const) {
    const program = [
      "import importlib.util, sys",
      `sys.version_info = (3, ${minor})`,
      `importlib.util.find_spec = lambda name: object() if name == 'tomli' and ${tomli ? "True" : "False"} else None`,
      PLUGIN_PYTHON_PROBE,
    ].join("\n");
    expect(pythonProbe.runPython(python!, ["-c", program]).exitCode).toBe(
      status,
    );
  }
});

test("normalizes absolute Windows scopes without accepting escapes", () => {
  probe(
    [
      "import sys",
      "from pathlib import PureWindowsPath",
      "from types import SimpleNamespace",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_setup as workbench",
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
  const root = await directories.create("codex-security-line-endings-");
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
