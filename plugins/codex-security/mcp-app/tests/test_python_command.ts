import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  isUsablePythonExecutable,
  missingPythonHelperMessage,
  resolvePythonCommand,
} from "../src/python_command.ts";

const windowsHome = "C:\\Users\\fixture";
const windowsRoot = path.win32.join(
  windowsHome,
  ".cache",
  "codex-runtimes",
  "codex-primary-runtime",
  "dependencies",
  "python",
);
const windowsCandidates = [
  path.win32.join(windowsRoot, "python.exe"),
  path.win32.join(windowsRoot, "python", "python.exe"),
  path.win32.join(windowsRoot, "bin", "python.exe"),
];
for (const [candidateIndex, expectedCandidate] of windowsCandidates.entries()) {
  const checkedCandidates: string[] = [];
  assert.equal(
    await resolvePythonCommand({
      cacheDirectory: "",
      configuredPython: "",
      homeDirectory: windowsHome,
      isUsableExecutable: async (candidate: string) => {
        checkedCandidates.push(candidate);
        return candidate === expectedCandidate;
      },
      platform: "win32",
    }),
    expectedCandidate,
  );
  assert.deepEqual(
    checkedCandidates,
    windowsCandidates.slice(0, candidateIndex + 1),
  );
}
assert.equal(
  await resolvePythonCommand({
    cacheDirectory: "",
    configuredPython: "",
    homeDirectory: windowsHome,
    isUsableExecutable: async () => false,
    platform: "win32",
  }),
  "python",
);

const unixHome = "/home/fixture";
const unixRoot = path.posix.join(
  unixHome,
  ".cache",
  "codex-runtimes",
  "codex-primary-runtime",
  "dependencies",
  "python",
);
const unixCandidates = [
  path.posix.join(unixRoot, "bin", "python3"),
  path.posix.join(unixRoot, "bin", "python"),
];
const checkedUnixCandidates: string[] = [];
assert.equal(
  await resolvePythonCommand({
    configuredPython: "",
    homeDirectory: unixHome,
    cacheDirectory: "",
    isUsableExecutable: async (candidate: string) => {
      checkedUnixCandidates.push(candidate);
      return false;
    },
    platform: "linux",
  }),
  "python3",
);
assert.deepEqual(checkedUnixCandidates, unixCandidates);

for (const platform of ["darwin", "linux", "win32"] as const) {
  const pathImplementation = platform === "win32" ? path.win32 : path.posix;
  const cacheDirectory =
    platform === "win32" ? "D:\\Custom Cache" : "/custom/cache";
  const managedPython = pathImplementation.join(
    cacheDirectory,
    "codex-runtimes",
    "codex-primary-runtime",
    "dependencies",
    "python",
    ...(platform === "win32" ? ["python.exe"] : ["bin", "python3"]),
  );
  const previousCache = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = cacheDirectory;
  try {
    for (const configuredCache of [cacheDirectory, undefined]) {
      assert.equal(
        await resolvePythonCommand({
          configuredPython: "",
          homeDirectory: platform === "win32" ? windowsHome : unixHome,
          cacheDirectory: configuredCache,
          platform,
          isUsableExecutable: async (candidate) => candidate === managedPython,
        }),
        managedPython,
      );
    }
  } finally {
    if (previousCache === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = previousCache;
  }
}

let overrideProbeCount = 0;
assert.equal(
  await resolvePythonCommand({
    configuredPython: "  /custom/python  ",
    isUsableExecutable: async () => {
      overrideProbeCount += 1;
      return false;
    },
  }),
  "/custom/python",
);
assert.equal(overrideProbeCount, 0);

const executableFixtureRoot = await mkdtemp(
  path.join(tmpdir(), "codex-security-python-command-"),
);
try {
  const directoryCandidate = path.join(executableFixtureRoot, "directory");
  const fileCandidate = path.join(executableFixtureRoot, "python3");
  await mkdir(directoryCandidate);
  await writeFile(fileCandidate, "#!/bin/sh\n", { mode: 0o644 });
  assert.equal(
    await isUsablePythonExecutable(directoryCandidate, "linux"),
    false,
  );
  if (process.platform !== "win32") {
    assert.equal(await isUsablePythonExecutable(fileCandidate, "linux"), false);
    await chmod(fileCandidate, 0o755);
    assert.equal(await isUsablePythonExecutable(fileCandidate, "linux"), true);
    await chmod(fileCandidate, 0o644);
  }
  assert.equal(await isUsablePythonExecutable(fileCandidate, "win32"), true);
} finally {
  await rm(executableFixtureRoot, { force: true, recursive: true });
}

const pythonCommand = "/selected/python";
for (const code of ["ENOENT", "EACCES", "ENOEXEC", "UNKNOWN"]) {
  assert.match(
    missingPythonHelperMessage({ code, path: pythonCommand }, pythonCommand)!,
    /could not start its Python 3 helper/,
  );
}
assert.equal(
  missingPythonHelperMessage({ code: 1, path: pythonCommand }, pythonCommand),
  undefined,
);
assert.equal(
  missingPythonHelperMessage(
    { code: "ENOENT", path: "/different/python" },
    pythonCommand,
  ),
  undefined,
);
