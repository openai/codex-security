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

const realFilesystemProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import finalize_scan_contract as finalizer",
  "import workbench_db as workbench",
  "mode = sys.argv[2]",
  "scan_dir = Path(sys.argv[3])",
  "if mode == 'windows':",
  "    alias_scan_dir = Path(str(scan_dir).swapcase())",
  "    alias_directory = alias_scan_dir / 'pRoMpTs'",
  "    artifact_name = 'pRoMpTs/PrOmPt.TxT'",
  "else:",
  "    alias_scan_dir = Path(sys.argv[4])",
  "    alias_directory = scan_dir / 'prompts'",
  "    artifact_name = 'prompts/prompt.txt'",
  "def accepted(action):",
  "    try:",
  "        action()",
  "    except (SystemExit, finalizer.ContractError):",
  "        return False",
  "    return True",
  "checks = {",
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
        finalizerScanDirectory: true,
        finalizerOutputParent: true,
        workbenchArtifact: true,
        workbenchScanDirectory: true,
      });
    },
  );
});
