import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readdir,
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
const testPosix = process.platform === "win32" ? test.skip : test;

// The streaming helper spools `git diff --binary` to a temporary file so the framed
// value length is known before hashing. This probe recomputes the same digest with the
// buffered framing the helper replaced, which pins the compatibility requirement:
// recorded digests are compared against freshly computed ones when a selection is
// revalidated, so the two must agree byte for byte.
const digestProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_target as target",
  "try:",
  "    import resource",
  "except ImportError:",
  "    resource = None",
  "def peak():",
  "    if resource is None:",
  "        return None",
  "    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss",
  "    return value if sys.platform == 'darwin' else value * 1024",
  "repository = Path(sys.argv[2])",
  "before = peak()",
  "streamed = target.worktree_content_digest(repository)",
  "after = peak()",
  "def buffered_field(digest, label, tree, *args, git_dir=None, work_tree=None):",
  "    value = target.git_bytes(tree, *args, git_dir=git_dir, work_tree=work_tree)",
  "    if value is None:",
  "        return False",
  "    target.update_digest_field(digest, label, value)",
  "    return True",
  "target.git_digest_field = buffered_field",
  "buffered = target.worktree_content_digest(repository)",
  "patch = target.git_bytes(repository, 'diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', 'HEAD', '--', '.')",
  "print(json.dumps({",
  "    'streamed': streamed,",
  "    'buffered': buffered,",
  "    'sentinel': target.clean_worktree_content_digest(),",
  "    'patchBytes': len(patch),",
  "    'peakRssIncreaseBytes': None if before is None else after - before,",
  "}))",
].join("\n");

// The streaming helper reports Git failure as `False` rather than the `None` the
// buffered helper returned, so the caller's guard has to reject a falsy value. A guard
// that still tests `is None` accepts `False` and records a digest over an empty patch,
// which is a wrong snapshot rather than a visible error.
const failureProbe = [
  "import json, sys",
  "from pathlib import Path",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_target as target",
  "repository = Path(sys.argv[2])",
  "try:",
  "    result = {'digest': target.worktree_content_digest(repository)}",
  "except SystemExit as exc:",
  "    result = {'exit': str(exc)}",
  "print(json.dumps(result))",
].join("\n");

interface DigestProbeResult {
  streamed: string;
  buffered: string;
  sentinel: string;
  patchBytes: number;
  peakRssIncreaseBytes: number | null;
}

interface FailureProbeResult {
  digest?: string;
  exit?: string;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-content-digest-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

function git(repository: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: repository,
    encoding: "utf8",
  }).trim();
}

async function repository(): Promise<string> {
  const root = await temporaryDirectory();
  const path = join(root, "repo");
  await mkdir(path, { recursive: true });
  git(path, "init", "-b", "main");
  git(path, "config", "user.email", "test@example.com");
  git(path, "config", "user.name", "Test");
  await writeFile(join(path, "README.md"), "baseline\n");
  git(path, "add", ".");
  git(path, "commit", "-m", "initial");
  return path;
}

// Deterministic incompressible bytes, so the binary patch cannot be shrunk by zlib.
function incompressible(size: number, seed: number): Uint8Array {
  const bytes = new Uint8Array(size);
  let state = seed;
  for (let index = 0; index < size; index += 1) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    bytes[index] = (state >>> 16) & 0xff;
  }
  return bytes;
}

async function runProbe(source: string, target: string): Promise<string> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for content digest tests.",
    );
  }

  // A private temporary directory proves the spool file does not outlive the digest.
  const spoolDirectory = await temporaryDirectory();
  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", source, join(PLUGIN_ROOT, "scripts"), target],
    {
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        TMPDIR: spoolDirectory,
        TMP: spoolDirectory,
        TEMP: spoolDirectory,
      },
    },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  expect(await readdir(spoolDirectory)).toEqual([]);
  return new TextDecoder().decode(result.stdout);
}

async function runDigestProbe(target: string): Promise<DigestProbeResult> {
  return JSON.parse(await runProbe(digestProbe, target)) as DigestProbeResult;
}

describe("bundled workbench content digests", () => {
  test("streams the tracked patch without changing the recorded digest", async () => {
    const clean = await repository();
    const cleanResult = await runDigestProbe(clean);

    expect(cleanResult.streamed).toBe(cleanResult.buffered);
    // The hardcoded clean-worktree sentinel must still describe an unchanged tree.
    expect(cleanResult.streamed).toBe(cleanResult.sentinel);

    const text = await repository();
    await writeFile(join(text, "README.md"), "baseline\nmodified line\n");
    const textResult = await runDigestProbe(text);

    expect(textResult.streamed).toBe(textResult.buffered);
    expect(textResult.streamed).not.toBe(textResult.sentinel);

    const binary = await repository();
    await writeFile(join(binary, "payload.bin"), incompressible(64 * 1024, 7));
    git(binary, "add", ".");
    git(binary, "commit", "-m", "payload");
    await writeFile(join(binary, "payload.bin"), incompressible(64 * 1024, 11));
    const binaryResult = await runDigestProbe(binary);

    expect(binaryResult.streamed).toBe(binaryResult.buffered);
    expect(binaryResult.patchBytes).toBeGreaterThan(64 * 1024);

    const untracked = await repository();
    await writeFile(join(untracked, "README.md"), "baseline\nedited\n");
    await writeFile(join(untracked, "new.txt"), "untracked content\n");
    await mkdir(join(untracked, "nested"));
    await writeFile(join(untracked, "nested", "inner.txt"), "inner\n");
    if (process.platform !== "win32") {
      await symlink("README.md", join(untracked, "link.txt"));
    }
    const untrackedResult = await runDigestProbe(untracked);

    expect(untrackedResult.streamed).toBe(untrackedResult.buffered);
  });

  test("refuses to record a digest when Git cannot emit the tracked patch", async () => {
    // An unborn branch has no HEAD, so `git diff HEAD` exits non-zero and writes no
    // patch. Streaming has to reject that as firmly as buffering did: the spool would
    // otherwise be hashed as an empty value and pass for a clean worktree.
    const root = await temporaryDirectory();
    const unborn = join(root, "repo");
    await mkdir(unborn, { recursive: true });
    git(unborn, "init", "-b", "main");
    git(unborn, "config", "user.email", "test@example.com");
    git(unborn, "config", "user.name", "Test");
    await writeFile(join(unborn, "README.md"), "unborn\n");

    const result = JSON.parse(
      await runProbe(failureProbe, unborn),
    ) as FailureProbeResult;

    expect(result.digest).toBeUndefined();
    expect(result.exit).toBe(
      "Could not snapshot the selected working-tree changes.",
    );
  });

  // Roughly 4 MiB of incompressible content, which Git expands into a binary patch
  // several times that size. Kept small deliberately: the fixture costs about a
  // second, and the buffering regression it guards is proportional, not threshold-based.
  testPosix("hashes a large binary patch without buffering it", async () => {
    const large = await repository();
    await writeFile(
      join(large, "large.bin"),
      incompressible(4 * 1024 * 1024, 3),
    );
    git(large, "add", ".");
    git(large, "commit", "-m", "large payload");
    await writeFile(
      join(large, "large.bin"),
      incompressible(4 * 1024 * 1024, 5),
    );

    const result = await runDigestProbe(large);

    expect(result.streamed).toBe(result.buffered);
    expect(result.patchBytes).toBeGreaterThan(4 * 1024 * 1024);
    expect(result.peakRssIncreaseBytes).not.toBeNull();
    // Buffering the patch would grow the process by at least the patch size; streaming
    // holds one chunk at a time.
    expect(result.peakRssIncreaseBytes as number).toBeLessThan(
      result.patchBytes / 2,
    );
  });
});
