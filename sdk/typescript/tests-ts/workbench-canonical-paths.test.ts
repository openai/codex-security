import { chmod, mkdir, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runPython } from "./support/python-probe.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-canonical-paths-",
);
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
  "deep_scan.configure(deep_scan)",
  "try:",
  "    result = deep_scan.deep_scan_path({'scan_dir': root}, supplied, 'Worker prompt path', kind='file')",
  "except SystemExit:",
  "    accepted = False",
  "    result = None",
  "else:",
  "    accepted = True",
  "print(json.dumps({'accepted': accepted, 'nativePathEquality': path_type(supplied) == path_type(resolved), 'resolvedPath': result}))",
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
  "deep_scan.configure(deep_scan)",
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

afterEach(cleanup);

function runPythonProbe(
  program: string,
  ...args: string[]
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();

  const result = runPython(python!, [
    "-c",
    program,
    join(PLUGIN_ROOT, "scripts"),
    ...args,
  ]);
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("bundled workbench canonical paths", () => {
  const nativeCaseAliases =
    runPythonProbe(
      [
        "import json, sys, tempfile",
        "from pathlib import Path",
        "with tempfile.TemporaryDirectory(dir=sys.argv[2]) as directory:",
        "    target = Path(directory) / 'component'",
        "    target.mkdir()",
        "    alias = target.with_name('COMPONENT')",
        "    print(json.dumps({'supported': alias.exists() and alias.samefile(target)}))",
      ].join("\n"),
      tmpdir(),
    )["supported"] === true;

  test.skipIf(!nativeCaseAliases)(
    "hashes and inventories native filesystem case aliases for Git roots and components",
    async () => {
      const root = await temporaryDirectory();
      expect(
        runPythonProbe(
          [
            "import json, subprocess, sys",
            "from pathlib import Path",
            "sys.path.insert(0, sys.argv[1])",
            "import workbench_target as target",
            "root = Path(sys.argv[2])",
            "repository = root / 'repository'",
            "repository.mkdir()",
            "subprocess.run(['git', 'init', '-q', str(repository)], check=True, capture_output=True)",
            "component = repository / 'component'",
            "component.mkdir()",
            "(component / 'app.py').write_text('print(1)\\n')",
            "(repository / 'root.py').write_text('print(2)\\n')",
            "scopes = root / 'scopes.json'",
            "scopes.write_text(json.dumps(['.']))",
            "output = root / 'inventory.jsonl'",
            "cases = [(root / 'REPOSITORY', repository, ['component/app.py', 'root.py']), (repository / 'COMPONENT', component, ['app.py'])]",
            "for selected, original, expected in cases:",
            "    assert selected.samefile(original)",
            "    assert target.directory_content_digest(selected) == target.directory_content_digest(original)",
            "    subprocess.run([sys.executable, str(Path(sys.argv[1]) / 'generate_rank_input.py'), 'make-repo-scope-input', '--repo', str(selected), '--scopes-file', str(scopes), '--out', str(output)], check=True, capture_output=True)",
            "    assert [json.loads(line)['path'] for line in output.read_text().splitlines()] == expected",
            "print(json.dumps({'targetsChecked': len(cases)}))",
          ].join("\n"),
          root,
        ),
      ).toEqual({ targetsChecked: 2 });
    },
  );

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

  test("discovers and runs host Git after a batch shim without a host binding", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const shims = join(root, "shims");
    await mkdir(join(repository, ".git"), { recursive: true });
    await mkdir(shims);
    await writeFile(join(shims, "git.cmd"), "@exit /b 99\r\n");
    await writeFile(join(shims, "git.bat"), "@exit /b 99\r\n");
    const hostGit = Bun.which("git");
    expect(hostGit).not.toBeNull();
    const result = runPythonProbe(
      [
        "import json, os, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_target as target",
        "os.environ.pop('CODEX_SECURITY_GIT', None)",
        "os.environ['PATH'] = os.pathsep.join(sys.argv[3:])",
        "result = target.git_command(Path(sys.argv[2]), '--version', text=True)",
        "print(json.dumps({'code': result.returncode, 'version': result.stdout, 'command': result.args[0]}))",
      ].join("\n"),
      repository,
      shims,
      dirname(hostGit!),
    );
    expect(result["code"]).toBe(0);
    expect(result["version"]).toMatch(/^git version /u);
    expect(result["command"]).toBe(
      join(await realpath(dirname(hostGit!)), basename(hostGit!)),
    );
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
