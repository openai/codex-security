import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];
const testCaseSensitive = process.platform === "linux" ? test : test.skip;
const testPosix = process.platform === "win32" ? test.skip : test;
const testWindows = process.platform === "win32" ? test : test.skip;

const simulatedPathProbe = [
  "import json, ntpath, os, posixpath, sys",
  "from pathlib import PurePosixPath, PureWindowsPath",
  "from types import SimpleNamespace",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep_scan",
  "mode = sys.argv[2]",
  "if mode == 'windows':",
  "    path_type, path_module = PureWindowsPath, ntpath",
  "    root, supplied, resolved = 'D:/Scan', 'd:/sCaN/pRoMpT', 'D:/Scan/Prompt'",
  "else:",
  "    path_type, path_module = PurePosixPath, posixpath",
  "    root, supplied, resolved = '/scan', '/scan/prompt', '/scan/Prompt'",
  "class SimulatedPath(path_type):",
  "    def expanduser(self):",
  "        return self",
  "    def absolute(self):",
  "        return self",
  "    def resolve(self, strict=False):",
  "        return type(self)(resolved)",
  "    def is_file(self):",
  "        return True",
  "deep_scan.Path = SimulatedPath",
  "deep_scan.os = SimpleNamespace(path=path_module)",
  "deep_scan.require_canonical_scan_directory = lambda path: path",
  "try:",
  "    result = deep_scan.deep_scan_path({'scan_dir': root}, supplied, 'Worker prompt path', kind='file')",
  "except SystemExit:",
  "    accepted = False",
  "    result = None",
  "else:",
  "    accepted = True",
  "print(json.dumps({'accepted': accepted, 'nativePathEquality': path_type(supplied) == path_type(resolved), 'resolvedPath': result}))",
].join("\n");

const caseSensitiveWindowsHistoryProbe = [
  "import json, sqlite3, sys",
  "from pathlib import PureWindowsPath",
  "from types import SimpleNamespace",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_scan_history as history",
  "import workbench_target_state as target_state",
  "class WindowsPath(PureWindowsPath):",
  "    def expanduser(self):",
  "        return self",
  "    def resolve(self, strict=False):",
  "        return self",
  "history.Path = WindowsPath",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT, current_path TEXT, repository_identity TEXT);",
  "CREATE TABLE scans (id TEXT, target_id TEXT, target_path TEXT, repository_generation TEXT, status TEXT, started_at TEXT);",
  "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
  "''')",
  "def target(identifier, path, identity):",
  "    return connection.execute('SELECT ? AS target_id, ? AS target_path, ? AS repository_identity, ? AS repository_generation', (identifier, str(WindowsPath(path)), identity, identity)).fetchone()",
  "upper_root = target('upper-root', 'D:/Repository', 'root-upper')",
  "lower_root = target('lower-root', 'D:/repository', 'root-lower')",
  "upper_scope = target('upper-scope', 'D:/Repository/Service', 'scope-upper')",
  "lower_scope = target('lower-scope', 'D:/Repository/service', 'scope-lower')",
  "linked_scope = target('linked-scope', 'E:/Linked/Service', 'scope-upper')",
  "clone_scope = target('clone-scope', 'D:/Clone/Service', 'scope-clone')",
  "same_path = target('same-path', 'D:/Repository/Service', None)",
  "targets = [upper_root, lower_root, upper_scope, lower_scope, linked_scope, clone_scope]",
  "identities = {entry['target_path']: entry['repository_identity'] for entry in targets}",
  "def inspect(database, target_id, path, stored, **kwargs):",
  "    identity = identities.get(path)",
  "    repository = target_state.GitRepositoryIdentity(identity, WindowsPath(path).name, 'synthetic', 1, 2, 3) if identity else None",
  "    return target_state.RepositoryTargetState(target_id, path, stored, resolved_path=str(WindowsPath(path)), repository=repository, ownership_matches=True, strict_owner_matches=True)",
  "target_state._inspect_repository_target = inspect",
  "target_state.repository_origin = lambda path: ('example.test', 'synthetic/repository')",
  "for entry in targets:",
  "    connection.execute('INSERT INTO security_targets VALUES (?, ?, ?)', (entry['target_id'], entry['target_path'], entry['repository_identity']))",
  "cache = history.RepositoryIdentityCache(connection)",
  "checks = {",
  "    'nativeWindowsScopeEquality': WindowsPath(upper_scope['target_path']) == WindowsPath(lower_scope['target_path']),",
  "    'nativeWindowsRootEquality': WindowsPath(upper_root['target_path']) == WindowsPath(lower_root['target_path']),",
  "    'caseSensitiveScopesMatch': cache.scope(lower_scope['target_id']).generation == cache.scope(upper_scope['target_id']).generation,",
  "    'caseSensitiveRootsMatch': cache.scope(lower_root['target_id']).generation == cache.scope(upper_root['target_id']).generation,",
  "    'linkedWorktreeMatches': cache.scope(linked_scope['target_id']).generation == cache.scope(upper_scope['target_id']).generation,",
  "    'sameOriginCloneMatches': cache.scope(clone_scope['target_id']).generation == cache.scope(upper_scope['target_id']).generation,",
  "    'exactResolvedPathMatches': history._same_repository(connection, same_path, upper_scope, identities=cache),",
  "}",
  "connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)', ('lower-scan', lower_scope['target_id'], lower_scope['target_path'], lower_scope['repository_generation'], 'complete', '2026-08-15T00:00:00Z'))",
  "history._same_repository = lambda *args, **kwargs: False",
  "selected = history.list_unmatched_scan_pairs(connection, SimpleNamespace(repository=upper_scope['target_path'], force=False), backfill_finding_details=lambda *args: None, read_coverage=lambda scan: {})",
  "checks['caseSensitiveUnmatchedScanCount'] = selected['scanCount']",
  "print(json.dumps(checks))",
].join("\n");

const realFilesystemProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep_scan",
  "import finalize_scan_contract as finalizer",
  "import workbench_db as workbench",
  "mode = sys.argv[2]",
  "scan_dir = Path(sys.argv[3])",
  "if mode == 'windows':",
  "    alias_scan_dir = Path(str(scan_dir).swapcase())",
  "    alias_directory = alias_scan_dir / 'pRoMpTs'",
  "    artifact_name = 'pRoMpTs/PrOmPt.TxT'",
  "    candidate_name = 'PrOmPt.TxT'",
  "else:",
  "    alias_scan_dir = Path(sys.argv[4])",
  "    alias_directory = scan_dir / 'prompts'",
  "    artifact_name = 'prompts/prompt.txt'",
  "    candidate_name = 'prompt.txt'",
  "deep_scan.require_canonical_scan_directory = workbench.require_canonical_scan_directory",
  "def accepted(action):",
  "    try:",
  "        action()",
  "    except (SystemExit, finalizer.ContractError):",
  "        return False",
  "    return True",
  "checks = {",
  "    'deepScanPath': accepted(lambda: deep_scan.deep_scan_path({'scan_dir': str(scan_dir)}, str(alias_directory / candidate_name), 'Worker prompt path', kind='file')),",
  "    'finalizerScanDirectory': accepted(lambda: finalizer._require_scan_directory(alias_scan_dir)),",
  "    'finalizerOutputParent': accepted(lambda: finalizer._validate_scan_local_output_path(scan_dir, alias_directory / 'output.json', f'{alias_directory.name}/output.json')),",
  "    'workbenchArtifact': accepted(lambda: workbench.artifact_path(scan_dir, artifact_name, required=True)),",
  "    'workbenchScanDirectory': accepted(lambda: workbench.require_canonical_scan_directory(alias_scan_dir)),",
  "}",
  "print(json.dumps(checks))",
].join("\n");

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-canonical-paths-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

function runPythonProbe(
  program: string,
  ...args: string[]
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for workbench path tests.",
    );
  }

  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts"), ...args],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled workbench canonical paths", () => {
  test("reads Unicode commit subjects regardless of locale or Git log encoding", async () => {
    const repository = await temporaryDirectory();
    expect(
      runPythonProbe(
        [
          "import json, subprocess, sys",
          "from pathlib import Path",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_target as target",
          "repository = Path(sys.argv[2])",
          "def git(*args):",
          "    subprocess.run(['git', '-C', str(repository), *args], check=True, capture_output=True)",
          "git('init', '-q')",
          "subjects = [('UTF-8', 'docs: \\u65e5\\u672c\\u8a9e \\ud55c\\uad6d\\uc5b4 \\U0001f527'), ('ISO-8859-1', 'docs: caf\\u00e9')]",
          "for log_encoding, subject in subjects:",
          "    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', subject)",
          "    git('config', 'i18n.logOutputEncoding', log_encoding)",
          "    for encoding in ('cp932', 'cp949'):",
          "        subprocess._text_encoding = lambda: encoding",
          "        assert target.git_target_metadata(repository)['commitSubject'] == subject",
          "        assert target.git_bytes(repository, 'show', '-s', '--format=%s', 'HEAD') == (subject + '\\n').encode('utf-8')",
          "print(json.dumps({'subjects': len(subjects), 'locales': 2}))",
        ].join("\n"),
        repository,
      ),
    ).toEqual({ subjects: 2, locales: 2 });
  });

  testPosix(
    "rejects private scan directories under insecure shared parents",
    async () => {
      const root = await temporaryDirectory();
      const scanDirectory = join(root, "scan");
      await mkdir(scanDirectory, { mode: 0o700 });
      await chmod(root, 0o777);

      try {
        expect(
          runPythonProbe(
            [
              "import json, sys",
              "from pathlib import Path",
              "sys.path.insert(0, sys.argv[1])",
              "import workbench_db as workbench",
              "try:",
              "    workbench.require_canonical_scan_directory(Path(sys.argv[2]))",
              "except SystemExit as error:",
              "    print(json.dumps({'accepted': False, 'error': str(error)}))",
              "else:",
              "    print(json.dumps({'accepted': True}))",
            ].join("\n"),
            scanDirectory,
          ),
        ).toMatchObject({
          accepted: false,
          error: expect.stringContaining("sticky bit"),
        });
      } finally {
        await chmod(root, 0o700);
      }
    },
  );

  test("preserves native Windows case-insensitive path comparison", () => {
    expect(runPythonProbe(simulatedPathProbe, "windows")).toMatchObject({
      accepted: true,
      nativePathEquality: true,
    });
  });

  test("rejects case-differing POSIX symlink resolution", () => {
    expect(runPythonProbe(simulatedPathProbe, "posix")).toMatchObject({
      accepted: false,
      nativePathEquality: false,
    });
  });

  test("keeps case-sensitive Windows repository roots and scopes distinct", () => {
    expect(runPythonProbe(caseSensitiveWindowsHistoryProbe)).toEqual({
      nativeWindowsScopeEquality: true,
      nativeWindowsRootEquality: true,
      caseSensitiveScopesMatch: false,
      caseSensitiveRootsMatch: false,
      linkedWorktreeMatches: true,
      sameOriginCloneMatches: false,
      exactResolvedPathMatches: true,
      caseSensitiveUnmatchedScanCount: 0,
    });
  });

  testCaseSensitive(
    "rejects case-differing symlinks at every workbench and finalizer boundary",
    async () => {
      const root = await temporaryDirectory();
      const parent = join(root, "Scans");
      const aliasParent = join(root, "scans");
      const scanDirectory = join(parent, "Scan");
      const promptDirectory = join(scanDirectory, "Prompts");
      await mkdir(promptDirectory, { recursive: true });
      await writeFile(join(promptDirectory, "prompt.txt"), "worker prompt\n");
      await symlink(parent, aliasParent, "dir");
      await symlink(promptDirectory, join(scanDirectory, "prompts"), "dir");

      expect(
        runPythonProbe(
          realFilesystemProbe,
          "posix",
          scanDirectory,
          join(aliasParent, "Scan"),
        ),
      ).toEqual({
        deepScanPath: false,
        finalizerScanDirectory: false,
        finalizerOutputParent: false,
        workbenchArtifact: false,
        workbenchScanDirectory: false,
      });
    },
  );

  testWindows(
    "accepts mixed-case Windows paths at every workbench and finalizer boundary",
    async () => {
      const root = await temporaryDirectory();
      const scanDirectory = join(root, "ScanRoot");
      const promptDirectory = join(scanDirectory, "Prompts");
      await mkdir(promptDirectory, { recursive: true });
      await writeFile(join(promptDirectory, "prompt.txt"), "worker prompt\n");

      expect(
        runPythonProbe(realFilesystemProbe, "windows", scanDirectory),
      ).toEqual({
        deepScanPath: true,
        finalizerScanDirectory: true,
        finalizerOutputParent: true,
        workbenchArtifact: true,
        workbenchScanDirectory: true,
      });
    },
  );
});
