import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [new URL("../src/python_command.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const {
  isUsablePythonExecutable,
  missingPythonHelperMessage,
  resolvePythonCommand
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

const windowsHome = "C:\\Users\\fixture";
const windowsRoot = path.win32.join(
  windowsHome,
  ".cache",
  "codex-runtimes",
  "codex-primary-runtime",
  "dependencies",
  "python"
);
const windowsCandidates = [
  path.win32.join(windowsRoot, "python.exe"),
  path.win32.join(windowsRoot, "python", "python.exe"),
  path.win32.join(windowsRoot, "bin", "python.exe")
];
for (const [candidateIndex, expectedCandidate] of windowsCandidates.entries()) {
  const checkedCandidates = [];
  assert.equal(await resolvePythonCommand({
    configuredPython: "",
    homeDirectory: windowsHome,
    isUsableExecutable: async (candidate) => {
      checkedCandidates.push(candidate);
      return candidate === expectedCandidate;
    },
    platform: "win32"
  }), expectedCandidate);
  assert.deepEqual(checkedCandidates, windowsCandidates.slice(0, candidateIndex + 1));
}
assert.equal(await resolvePythonCommand({
  configuredPython: "",
  homeDirectory: windowsHome,
  isUsableExecutable: async () => false,
  platform: "win32"
}), "python");

const unixHome = "/home/fixture";
const unixRoot = path.posix.join(
  unixHome,
  ".cache",
  "codex-runtimes",
  "codex-primary-runtime",
  "dependencies",
  "python"
);
const unixCandidates = [
  path.posix.join(unixRoot, "bin", "python3"),
  path.posix.join(unixRoot, "bin", "python")
];
const checkedUnixCandidates = [];
assert.equal(await resolvePythonCommand({
  configuredPython: "",
  homeDirectory: unixHome,
  isUsableExecutable: async (candidate) => {
    checkedUnixCandidates.push(candidate);
    return false;
  },
  platform: "linux"
}), "python3");
assert.deepEqual(checkedUnixCandidates, unixCandidates);

let overrideProbeCount = 0;
assert.equal(await resolvePythonCommand({
  configuredPython: "  /custom/python  ",
  isUsableExecutable: async () => {
    overrideProbeCount += 1;
    return false;
  }
}), "/custom/python");
assert.equal(overrideProbeCount, 0);

const executableFixtureRoot = await mkdtemp(path.join(tmpdir(), "codex-security-python-command-"));
try {
  const directoryCandidate = path.join(executableFixtureRoot, "directory");
  const fileCandidate = path.join(executableFixtureRoot, "python3");
  await mkdir(directoryCandidate);
  await writeFile(fileCandidate, "#!/bin/sh\n", { mode: 0o644 });
  assert.equal(await isUsablePythonExecutable(directoryCandidate, "linux"), false);
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
    missingPythonHelperMessage({ code, path: pythonCommand }, pythonCommand),
    /could not start its Python 3 helper/
  );
}
assert.equal(missingPythonHelperMessage({ code: 1, path: pythonCommand }, pythonCommand), undefined);
assert.equal(missingPythonHelperMessage({ code: "ENOENT", path: "/different/python" }, pythonCommand), undefined);
