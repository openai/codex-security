import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;
const testWindows = process.platform === "win32" ? test : test.skip;
let windowsUserSid: string | undefined;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-workbench-state-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function runPython(stateDirectory: string, args: string[]) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");
  return spawnSync(python, ["-I", "-B", ...args], {
    encoding: "utf8",
    timeout: 30_000,
    env: {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    },
  });
}

function connectDirectly(stateDirectory: string) {
  return runPython(stateDirectory, [
    "-c",
    [
      "import sys",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "workbench.connect().close()",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
  ]);
}

function windowsSystemDirectory(): string {
  return join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
}

function currentWindowsUserSid(): string {
  if (windowsUserSid !== undefined) return windowsUserSid;
  const result = spawnSync(
    join(windowsSystemDirectory(), "whoami.exe"),
    ["/user", "/fo", "csv", "/nh"],
    { encoding: "utf8", windowsHide: true },
  );
  expect(result.status).toBe(0);
  const sid = /"(S-1-(?:\d+-)*\d+)"\s*$/u.exec(result.stdout)?.[1];
  expect(sid).toBeDefined();
  windowsUserSid = sid!;
  return windowsUserSid;
}

function runIcacls(path: string, args: string[]) {
  const result = spawnSync(
    join(windowsSystemDirectory(), "icacls.exe"),
    [path, ...args],
    { encoding: "utf8", windowsHide: true },
  );
  expect(result.status).toBe(0);
}

function protectWindowsDirectory(path: string): void {
  runIcacls(path, [
    "/inheritance:r",
    "/grant:r",
    `*${currentWindowsUserSid()}:(OI)(CI)F`,
    "*S-1-5-18:(OI)(CI)F",
    "*S-1-5-32-544:(OI)(CI)F",
  ]);
}

function windowsAclSddl(path: string): string {
  const powershell = join(
    windowsSystemDirectory(),
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
  const result = spawnSync(
    powershell,
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH | Microsoft.PowerShell.Utility\\Select-Object -ExpandProperty Sddl",
    ],
    {
      encoding: "utf8",
      env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: path },
      windowsHide: true,
    },
  );
  expect(result.status).toBe(0);
  return result.stdout.trim();
}

function expectPrivateWindowsDirectory(path: string): void {
  const descriptor = windowsAclSddl(path);
  expect(descriptor).toMatch(/D:[A-Z_]*P/u);
  expect(descriptor).toContain(`;FA;;;${currentWindowsUserSid()})`);
  expect(descriptor).toContain("OICI");
}

test("direct workbench initialization creates and pins private state", async () => {
  const root = await temporaryDirectory();
  const actual = join(root, "actual");
  const alias = join(root, "alias");
  await mkdir(actual, { mode: 0o700 });
  await symlink(
    actual,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  for (const mask of [0o002, 0o700]) {
    const nested = `nested-${mask.toString(8)}`;
    const state = `${alias}${sep}.${sep}${nested}${sep}state`;
    const canonical = join(actual, nested, "state");
    const result = runPython(state, [
      "-c",
      [
        "import json, os, sys",
        "os.umask(int(sys.argv[2], 8))",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "workbench.connect().close()",
        'print(json.dumps({"state": str(workbench.state_dir()), "configured": os.environ["CODEX_SECURITY_STATE_DIR"]}))',
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      mask.toString(8),
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const paths = JSON.parse(result.stdout) as {
      state: string;
      configured: string;
    };
    expect(paths.configured).toBe(paths.state);
    expect(await realpath(paths.state)).toBe(await realpath(canonical));
    expect(existsSync(join(canonical, "workbench.sqlite3"))).toBe(true);
    if (process.platform !== "win32") {
      expect((await stat(join(actual, nested))).mode & 0o777).toBe(0o700);
      expect((await stat(canonical)).mode & 0o777).toBe(0o700);
      expect(
        (await stat(join(canonical, "workbench.sqlite3"))).mode & 0o777,
      ).toBe(0o600);
    }
  }
});

test("Windows state creation ACLs distinguish metadata from directory writes", () => {
  const result = runPython("", [
    "-c",
    [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "user = 'S-1-5-21-1-2-3-1001'",
      "results = {}",
      "for mask in (0x10, 0x100, 0x2, 0x4, 0x40, 0x40000000):",
      "    record = {'owner': user, 'control': workbench.WINDOWS_DACL_PRESENT, 'rules': [{'type': 0, 'flags': 0, 'mask': mask, 'sid': 'S-1-1-0'}]}",
      "    try:",
      "        workbench.require_windows_state_acl(record, user, 'creation-parent')",
      "    except RuntimeError:",
      "        results[hex(mask)] = 'rejected'",
      "    else:",
      "        results[hex(mask)] = 'accepted'",
      "print(json.dumps(results, sort_keys=True))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({
    "0x10": "accepted",
    "0x100": "accepted",
    "0x2": "rejected",
    "0x4": "rejected",
    "0x40": "rejected",
    "0x40000000": "rejected",
  });
});

test("Windows state inspection tolerates both missing Get-Acl sidecar errors", () => {
  const result = runPython("", [
    "-c",
    [
      "import json, sys",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "scripts = []",
      "def inspect(command, arguments, environment):",
      "    scripts.append(arguments[-1])",
      "    return json.dumps({'kind': 'root'})",
      "context = (Path('powershell.exe'), Path('icacls.exe'), 'S-1-5-21-1-2-3-1001', {})",
      "with patch.object(workbench, 'run_windows_state_acl_command', side_effect=inspect):",
      "    workbench.windows_state_acl_records(Path('state'), context, workbench_files=True)",
      "print(json.dumps({'missing': 'GetAcl_PathNotFound*' in scripts[0], 'narrow': 'GetAcl_PathNotFound,*' in scripts[0]}))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({ missing: true, narrow: false });
});

testWindows(
  "direct workbench rejects unsafe Windows state without changing its ACL",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    await mkdir(state);
    protectWindowsDirectory(root);
    protectWindowsDirectory(state);
    runIcacls(state, ["/grant", "*S-1-1-0:(OI)(CI)R"]);
    const before = windowsAclSddl(state);
    const command = [
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "list-scans",
      "--repository",
      root,
    ];

    const unsafeRoot = runPython(state, command);
    expect(unsafeRoot.status).not.toBe(0);
    expect(unsafeRoot.stderr).toContain("state directory is unsafe");
    expect(windowsAclSddl(state)).toBe(before);
    expect(existsSync(join(state, "workbench.sqlite3"))).toBe(false);

    runIcacls(state, ["/remove:g", "*S-1-1-0"]);
    const sidecar = join(state, "workbench.sqlite3-wal");
    await writeFile(sidecar, "unsafe sidecar\n", "utf8");
    runIcacls(sidecar, ["/grant", "*S-1-1-0:R"]);
    const sidecarBefore = windowsAclSddl(sidecar);
    const unsafeSidecar = runPython(state, command);
    expect(unsafeSidecar.status).not.toBe(0);
    expect(unsafeSidecar.stderr).toContain("state directory is unsafe");
    expect(windowsAclSddl(sidecar)).toBe(sidecarBefore);
    expect(existsSync(join(state, "workbench.sqlite3"))).toBe(false);
  },
);

testWindows(
  "direct workbench gives missing Windows state a private protected ACL",
  async () => {
    const root = await temporaryDirectory();
    const component = join(root, "nested");
    const state = join(component, "state");
    protectWindowsDirectory(root);
    const result = connectDirectly(state);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(existsSync(join(state, "workbench.sqlite3"))).toBe(true);
    for (const directory of [component, state]) {
      expectPrivateWindowsDirectory(directory);
    }
  },
);

testWindows(
  "direct workbench rejects writable ACLs inherited by missing Windows state",
  async () => {
    const root = await temporaryDirectory();
    const parent = join(root, "parent");
    const state = join(parent, "state");
    await mkdir(parent);
    protectWindowsDirectory(root);
    protectWindowsDirectory(parent);
    runIcacls(parent, ["/grant", "*S-1-1-0:(CI)(IO)F"]);
    const before = windowsAclSddl(parent);
    const result = connectDirectly(state);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("state directory is unsafe");
    expect(windowsAclSddl(parent)).toBe(before);
    expect(existsSync(state)).toBe(false);
  },
);

testWindows(
  "direct workbench skips unrelated Windows state while preserving its ACL",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    await mkdir(state);
    protectWindowsDirectory(root);
    protectWindowsDirectory(state);
    const unrelated = join(state, "codex-home");
    await mkdir(unrelated);
    runIcacls(unrelated, ["/grant", "*S-1-1-0:(OI)(CI)R"]);
    const before = windowsAclSddl(state);
    const unrelatedBefore = windowsAclSddl(unrelated);
    const result = connectDirectly(state);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(windowsAclSddl(state)).toBe(before);
    expect(windowsAclSddl(unrelated)).toBe(unrelatedBefore);
    expectPrivateWindowsDirectory(state);
    expect(existsSync(join(state, "workbench.sqlite3"))).toBe(true);
    const accessed = runPython(state, [
      "-c",
      [
        "import sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "workbench.require_canonical_scan_directory(Path(sys.argv[2]))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      unrelated,
    ]);
    expect(accessed.status).not.toBe(0);
    expect(accessed.stderr).toContain("unsafe Windows ACL");
    expect(windowsAclSddl(unrelated)).toBe(unrelatedBefore);
  },
);

testWindows(
  "direct workbench tolerates Windows SQLite sidecar churn",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    protectWindowsDirectory(root);
    const initialized = connectDirectly(state);
    expect(initialized.status).toBe(0);
    const result = runPython(state, [
      "-c",
      [
        "import sys, threading",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "sidecar = workbench.state_dir() / 'workbench.sqlite3-wal'",
        "started = threading.Event()",
        "stop = threading.Event()",
        "def churn():",
        "    started.set()",
        "    while not stop.is_set():",
        "        try:",
        "            sidecar.write_bytes(b'wal')",
        "        except PermissionError:",
        "            pass",
        "        try:",
        "            sidecar.unlink()",
        "        except (FileNotFoundError, PermissionError):",
        "            pass",
        "thread = threading.Thread(target=churn)",
        "thread.start()",
        "started.wait()",
        "try:",
        "    context = workbench.windows_state_acl_context()",
        "    for _ in range(8):",
        "        workbench.require_private_windows_state_directory(workbench.state_dir(), context)",
        "finally:",
        "    stop.set()",
        "    thread.join()",
        "    sidecar.unlink(missing_ok=True)",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
  },
);

test("direct workbench validates a competing private initializer", async () => {
  const root = await temporaryDirectory();
  const component = join(root, "nested");
  const state = join(component, "state");
  const result = runPython(state, [
    "-c",
    [
      "import json, sys",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "component = Path(sys.argv[2])",
      "original_mkdir = Path.mkdir",
      "def competing_mkdir(path, *args, **kwargs):",
      "    if path == component and not path.exists():",
      "        original_mkdir(path, *args, **kwargs)",
      "        raise FileExistsError(str(path))",
      "    return original_mkdir(path, *args, **kwargs)",
      'with patch.object(Path, "mkdir", competing_mkdir), patch.object(workbench, "require_canonical_scan_directory", wraps=workbench.require_canonical_scan_directory) as validate:',
      "    workbench.connect().close()",
      "    print(json.dumps([str(call.args[0]) for call in validate.call_args_list]))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
    component,
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toContain(component);
  expect(existsSync(join(state, "workbench.sqlite3"))).toBe(true);
});

testPosix(
  "direct workbench rejects unsafe state before opening its database",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const shared = join(root, "shared");
    const nestedState = join(shared, "state");
    const missingState = join(shared, "missing", "state");
    await mkdir(state, { mode: 0o700 });
    await mkdir(nestedState, { recursive: true, mode: 0o700 });
    await chmod(shared, 0o775);
    const command = [
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "list-scans",
      "--repository",
      root,
    ];

    for (const mode of [0o755, 0o1777]) {
      await chmod(state, mode);
      const actualMode = (await stat(state)).mode & 0o7777;
      const result = runPython(state, command);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("state directory");
      expect((await stat(state)).mode & 0o7777).toBe(actualMode);
      expect(existsSync(join(state, "workbench.sqlite3"))).toBe(false);
    }

    const nested = runPython(nestedState, command);
    expect(nested.status).not.toBe(0);
    expect(nested.stderr).toContain("group- or world-writable");
    expect((await stat(shared)).mode & 0o7777).toBe(0o775);
    expect((await stat(nestedState)).mode & 0o7777).toBe(0o700);
    expect(existsSync(join(nestedState, "workbench.sqlite3"))).toBe(false);
    const missing = runPython(missingState, command);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain("group- or world-writable");
    expect(existsSync(join(shared, "missing"))).toBe(false);
  },
);

testPosix(
  "direct workbench rejects unsafe lexical and chained state aliases",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const shared = join(root, "shared");
    const trusted = join(root, "trusted");
    const unsafeLink = join(shared, "state-link");
    const nextLink = join(trusted, "next-link");
    const alias = join(root, "alias");
    const dottedAlias = join(root, "dotted-alias");
    const dottedState = `${shared}${sep}..${sep}state`;
    const missing = join(alias, "missing", "state");
    await mkdir(state, { mode: 0o700 });
    await mkdir(shared, { mode: 0o700 });
    await mkdir(trusted, { mode: 0o700 });
    await chmod(shared, 0o775);
    await symlink(state, unsafeLink, "dir");
    await symlink(unsafeLink, nextLink, "dir");
    await symlink(`${nextLink}${sep}`, alias, "dir");
    await symlink(dottedState, dottedAlias, "dir");
    const command = [
      join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
      "list-scans",
      "--repository",
      root,
    ];

    for (const path of [
      unsafeLink,
      nextLink,
      alias,
      dottedAlias,
      dottedState,
      missing,
    ]) {
      const result = runPython(path, command);
      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("state directory is unsafe");
      expect(result.stderr).toContain("group- or world-writable");
    }
    expect((await stat(shared)).mode & 0o7777).toBe(0o775);
    expect((await stat(state)).mode & 0o7777).toBe(0o700);
    expect(await readdir(state)).toEqual([]);
    expect(await readdir(shared)).toEqual(["state-link"]);
    expect(await readdir(trusted)).toEqual(["next-link"]);
    expect(existsSync(missing)).toBe(false);
  },
);

testPosix(
  "direct workbench rejects untrusted state-link ownership before creation",
  async () => {
    const root = await temporaryDirectory();
    const state = join(root, "state");
    const alias = join(root, "alias");
    await mkdir(state, { mode: 0o700 });
    await symlink(state, alias, "dir");
    const result = runPython(alias, [
      "-c",
      [
        "import os, sys",
        "from pathlib import Path",
        "from unittest.mock import patch",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_db as workbench",
        "original_lstat = os.lstat",
        "def synthetic_lstat(path, *args, **kwargs):",
        "    metadata = original_lstat(path, *args, **kwargs)",
        "    if os.fspath(path) == sys.argv[2]:",
        "        values = list(metadata)",
        "        values[4] = os.geteuid() + 1",
        "        return os.stat_result(values)",
        "    return metadata",
        "with (",
        '    patch.object(os, "lstat", synthetic_lstat),',
        '    patch.object(Path, "mkdir", side_effect=AssertionError("unexpected creation")),',
        '    patch.object(workbench.sqlite3, "connect", side_effect=AssertionError("unexpected database access")),',
        "):",
        "    try:",
        "        workbench.connect()",
        "    except SystemExit as error:",
        "        print(error)",
        "    else:",
        '        raise AssertionError("untrusted state link was accepted")',
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      alias,
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("state directory is unsafe");
    expect(result.stdout).toContain("trusted owner");
    expect((await stat(state)).mode & 0o7777).toBe(0o700);
    expect(await readdir(state)).toEqual([]);
  },
);

test("direct workbench preserves unresolved home expansion failures", () => {
  const result = runPython("", [
    "-c",
    [
      "import json, os, sys",
      "from pathlib import Path",
      "from unittest.mock import patch",
      "sys.path.insert(0, sys.argv[1])",
      "import workbench_db as workbench",
      "errors = []",
      "with (",
      '    patch.object(os.path, "expanduser", side_effect=lambda path: path),',
      '    patch.object(Path, "mkdir", side_effect=AssertionError("unexpected creation")),',
      '    patch.object(workbench.sqlite3, "connect", side_effect=AssertionError("unexpected database access")),',
      "):",
      "    for environment in (",
      '        {"CODEX_SECURITY_STATE_DIR": "~unresolved/state"},',
      '        {"CODEX_SECURITY_STATE_DIR": "", "CODEX_HOME": "~/home"},',
      "    ):",
      "        with patch.dict(os.environ, environment, clear=True):",
      "            for select in (workbench.state_dir, workbench.connect):",
      "                try:",
      "                    select()",
      "                except RuntimeError as error:",
      "                    errors.append(str(error))",
      "                else:",
      '                    raise AssertionError("unresolved home was accepted")',
      "print(json.dumps(errors))",
    ].join("\n"),
    join(PLUGIN_ROOT, "scripts"),
  ]);

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual(
    Array(4).fill("Could not determine home directory."),
  );
});
