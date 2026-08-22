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
  test("does not follow repository parent symlinks during inventory or snapshots", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const outside = join(root, "outside");
    await mkdir(repository);
    await mkdir(outside);
    await mkdir(join(repository, "selected"));
    await writeFile(
      join(repository, "selected", "public.py"),
      "public = True\n",
    );
    await writeFile(join(outside, "private.py"), "private = True\n");
    await symlink(
      outside,
      join(repository, "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await mkdir(join(repository, "cyclic"));
    await mkdir(join(repository, "nested-checkout"));
    await mkdir(join(repository, "internal-source"));
    await writeFile(
      join(repository, "internal-source", "public.py"),
      "public = True\n",
    );
    await symlink(
      outside,
      join(repository, "nested-checkout", "linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await symlink(
      join(repository, "internal-source"),
      join(repository, "nested-checkout", "safe-linked"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await mkdir(join(repository, "selected", "nested-checkout"));
    await symlink(
      join(repository, "internal-source"),
      join(repository, "selected", "nested-checkout", "sibling-linked"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const result = runPythonProbe(
      [
        "import contextlib, io, json, sys, unicodedata",
        "from pathlib import Path",
        "from types import SimpleNamespace",
        "sys.path.insert(0, sys.argv[1])",
        "import generate_in_scope_files as inventory",
        "import generate_rank_input as ranking",
        "import rank_preview as previews",
        "import workbench_target as workbench",
        "repository = Path(sys.argv[2])",
        "output = Path(sys.argv[3])",
        "candidate = repository / 'linked' / 'private.py'",
        "outside = repository.parent / 'outside'",
        "safe_fallback_digest = workbench.directory_content_digest(repository / 'internal-source', _selected_target=repository).startswith('codex-security-snapshot/v1:sha256:')",
        "try:",
        "    workbench.directory_content_digest(outside, _selected_target=repository)",
        "except SystemExit:",
        "    outside_digest_rejected = True",
        "else:",
        "    outside_digest_rejected = False",
        "outside_progress_skipped = workbench.git_directory_snapshot_paths(outside, skip_unsafe_paths=True, _selected_target=repository) == []",
        "reads = []",
        "def preview(path, *_):",
        "    contents = path.read_text()",
        "    if not path.resolve().is_relative_to(repository):",
        "        reads.append(contents)",
        "    return '', False",
        "previews.preview_for = preview",
        "ranking.preview_for = preview",
        "inventories = {}",
        "for status in ('M', 'D'):",
        "    ranking.git_changed_paths = lambda *_: [(candidate, status)]",
        "    try:",
        "        inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "        inventories[status] = output.read_text()",
        "    except inventory.InventoryError as error:",
        "        inventories[status] = str(error)",
        "inventory.committed_changed_paths = lambda *_: [(candidate, 'M')]",
        "workbench.git_blob_bytes = lambda _, names: [b'private = True\\n' for _ in names]",
        "inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'revisions', output)",
        "inventories['revisions'] = output.read_text()",
        "original_resolve = Path.resolve",
        "def cyclic_resolve(path, *args, **kwargs):",
        "    if path.name == 'cyclic':",
        "        raise RuntimeError('symlink loop')",
        "    return original_resolve(path, *args, **kwargs)",
        "Path.resolve = cyclic_resolve",
        "ranking.git_changed_paths = lambda *_: [(repository / 'cyclic' / 'private.py', 'M')]",
        "try:",
        "    inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "    inventories['cyclic'] = output.read_text()",
        "except inventory.InventoryError as error:",
        "    inventories['cyclic'] = str(error)",
        "Path.resolve = original_resolve",
        "ranking.git_changed_paths = lambda *_: [(repository / 'missing-parent' / 'added.py', 'A')]",
        "inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "inventories['missingParent'] = output.read_text()",
        "ranking.git_changed_paths = lambda *_: [(repository / 'linked' / 'vanished.py', 'A')]",
        "try:",
        "    inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "    inventories['vanishedExternalParent'] = output.read_text()",
        "except inventory.InventoryError as error:",
        "    inventories['vanishedExternalParent'] = str(error)",
        "blocked_parent = repository / 'not-a-directory'",
        "blocked_parent.write_text('not a directory\\n')",
        "ranking.git_changed_paths = lambda *_: [(blocked_parent / 'nested' / 'added.py', 'A')]",
        "inventory.generate_diff_in_scope_files(repository, 'base', 'head', 'local-patch', output)",
        "inventories['notDirectoryParent'] = output.read_text()",
        "workbench.git_output = lambda *_: str(repository)",
        "workbench.git_worktree_context = lambda _: (repository, '.')",
        "workbench.git_bytes = lambda *_: b'linked/private.py\\0'",
        "try:",
        "    workbench.git_directory_snapshot_paths(repository)",
        "except SystemExit:",
        "    snapshot_rejected = True",
        "else:",
        "    snapshot_rejected = False",
        "unsafe_progress_count = workbench.directory_snapshot_regular_file_count(repository)",
        "nested_repository = repository / 'nested-checkout'",
        "workbench.git_worktree_context = lambda target: (target, '.')",
        "workbench.git_output = lambda target, *_: str(target)",
        "workbench.git_bytes = lambda target, *_: b'nested-checkout\\0' if target == repository else b'linked/private.py\\0'",
        "nested_unsafe_progress_count = workbench.directory_snapshot_regular_file_count(repository)",
        "workbench.git_bytes = lambda target, *_: b'nested-checkout\\0' if target == repository else b'safe-linked/public.py\\0'",
        "nested_safe_paths = [path.relative_to(repository).as_posix() for path in workbench.git_directory_snapshot_paths(repository)]",
        "def nested_digest_bytes(target, *args, **kwargs):",
        "    if args[0] == 'diff':",
        "        return b''",
        "    if '--cached' in args:",
        "        return b'safe-linked/public.py\\0'",
        "    return b'nested-checkout\\0'",
        "workbench.git_bytes = nested_digest_bytes",
        "nested_safe_digest = workbench.worktree_content_digest_for_context(repository, '.').startswith('codex-security-snapshot/v1:sha256:')",
        "selected_nested = repository / 'selected' / 'nested-checkout'",
        "workbench.git_output = lambda target, *_: str(target) if target == selected_nested else str(repository)",
        "workbench.git_worktree_context = lambda target: (target, '.') if target == selected_nested else (repository, 'selected')",
        "def selected_nested_bytes(target, *args, **kwargs):",
        "    if args[0] == 'diff':",
        "        return b''",
        "    if target == repository:",
        "        return b'selected/nested-checkout\\0'",
        "    return b'sibling-linked/public.py\\0'",
        "workbench.git_bytes = selected_nested_bytes",
        "try:",
        "    workbench.worktree_content_digest_for_context(repository, 'selected')",
        "except SystemExit:",
        "    selected_nested_rejected = True",
        "else:",
        "    selected_nested_rejected = False",
        "if sys.platform == 'win32':",
        "    (selected_nested / 'sibling-linked').rmdir()",
        "else:",
        "    (selected_nested / 'sibling-linked').unlink()",
        "selected_nested.rmdir()",
        "workbench.git_output = lambda *_: str(repository)",
        "workbench.git_worktree_context = lambda _: (repository, '.')",
        "workbench.git_bytes = lambda *_: b'nested-checkout\\0'",
        "def cyclic_directory_resolve(path, *args, **kwargs):",
        "    if path == nested_repository:",
        "        raise RuntimeError('junction loop')",
        "    return original_resolve(path, *args, **kwargs)",
        "Path.resolve = cyclic_directory_resolve",
        "cyclic_progress_count = workbench.directory_snapshot_regular_file_count(repository)",
        "Path.resolve = original_resolve",
        "workbench.git_worktree_context = lambda _: (repository, '.')",
        "workbench.git_output = lambda *_: str(repository)",
        "workbench.git_bytes = lambda *_: b'linked/missing.py\\0'",
        "missing_skipped = workbench.git_directory_snapshot_paths(repository) == []",
        "selected = repository / 'selected'",
        "workbench.git_worktree_context = lambda _: (repository, 'selected')",
        "workbench.git_bytes = lambda *_: b'selected\\0'",
        "selected_paths = [path.relative_to(selected).as_posix() for path in workbench.git_directory_snapshot_paths(selected)]",
        "unicode_directory = repository / unicodedata.normalize('NFD', 'café')",
        "unicode_directory.mkdir()",
        "(unicode_directory / 'public.py').write_text('public = True\\n')",
        "unicode_alias = repository / unicodedata.normalize('NFC', 'café')",
        "unicode_accepted = True",
        "if unicode_alias.exists():",
        "    workbench.git_worktree_context = lambda _: (repository, unicode_directory.name)",
        "    workbench.git_bytes = lambda *_: (unicode_alias.name + '\\0' + unicode_alias.name + '/public.py\\0').encode()",
        "    unicode_accepted = len(workbench.git_directory_snapshot_paths(unicode_directory)) == 2",
        "case_alias_accepted = True",
        "case_alias_changes_accepted = True",
        "if sys.platform == 'darwin' and (repository / 'SELECTED').exists():",
        "    (selected / 'actual').mkdir()",
        "    (selected / 'actual' / 'public.py').write_text('public = True\\n')",
        "    (selected / 'internal').symlink_to(repository / 'SELECTED' / 'actual', target_is_directory=True)",
        "    workbench.git_worktree_context = lambda _: (repository, 'selected')",
        "    workbench.git_bytes = lambda *_: b'selected/internal/public.py\\0'",
        "    case_alias_accepted = len(workbench.git_directory_snapshot_paths(selected)) == 1",
        "    internal = selected / 'internal' / 'public.py'",
        "    ranking.git_changed_paths = lambda *_: [(internal, 'M')]",
        "    inventory.generate_diff_in_scope_files(selected, 'base', 'head', 'local-patch', output)",
        "    case_alias_changes_accepted = output.read_text() == 'internal/public.py\\n'",
        "    args = SimpleNamespace(repo=selected, base='base', head='head', mode='local-patch', area='.', preview_bytes=1024, out=output)",
        "    with contextlib.redirect_stdout(io.StringIO()):",
        "        ranking.make_diff_rank_input(args)",
        "    case_alias_changes_accepted = case_alias_changes_accepted and len(output.read_text().splitlines()) == 1",
        "workbench.git_worktree_context = lambda _: (repository, '.')",
        "workbench.git_bytes = lambda *_: b'linked\\0'",
        "try:",
        "    workbench.git_directory_snapshot_paths(repository)",
        "except SystemExit:",
        "    direct_link_rejected = True",
        "else:",
        "    direct_link_rejected = False",
        "print(json.dumps({'inventories': inventories, 'externalReads': reads, 'safeFallbackDigest': safe_fallback_digest, 'outsideDigestRejected': outside_digest_rejected, 'outsideProgressSkipped': outside_progress_skipped, 'snapshotRejected': snapshot_rejected, 'unsafeProgressCount': unsafe_progress_count, 'nestedUnsafeProgressCount': nested_unsafe_progress_count, 'nestedSafePaths': nested_safe_paths, 'nestedSafeDigest': nested_safe_digest, 'selectedNestedRejected': selected_nested_rejected, 'cyclicProgressCount': cyclic_progress_count, 'missingSkipped': missing_skipped, 'selectedPaths': selected_paths, 'unicodeAccepted': unicode_accepted, 'caseAliasAccepted': case_alias_accepted, 'caseAliasChangesAccepted': case_alias_changes_accepted, 'directLinkRejected': direct_link_rejected}))",
      ].join("\n"),
      repository,
      join(root, "inventory.txt"),
    );

    expect(result).toEqual({
      inventories: {
        M: "changed Git working-tree paths must stay inside the selected target",
        D: "changed Git working-tree paths must stay inside the selected target",
        revisions: "linked/private.py\n",
        cyclic: "could not inspect a changed Git working-tree path",
        missingParent: "",
        vanishedExternalParent:
          "changed Git working-tree paths must stay inside the selected target",
        notDirectoryParent: "",
      },
      externalReads: [],
      safeFallbackDigest: true,
      outsideDigestRejected: true,
      outsideProgressSkipped: true,
      snapshotRejected: true,
      unsafeProgressCount: 0,
      nestedUnsafeProgressCount: 0,
      nestedSafePaths: [
        "nested-checkout",
        "nested-checkout/safe-linked/public.py",
      ],
      nestedSafeDigest: true,
      selectedNestedRejected: true,
      cyclicProgressCount: 0,
      missingSkipped: true,
      selectedPaths: [".", "public.py"],
      unicodeAccepted: true,
      caseAliasAccepted: true,
      caseAliasChangesAccepted: true,
      directLinkRejected: process.platform === "win32",
    });
  });

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
