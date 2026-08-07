import { spawn } from "node:child_process";
import { readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const testDirectory = fileURLToPath(new URL("../tests-ts/", import.meta.url));
const testFiles = (
  await Promise.all(
    (await readdir(testDirectory))
      .filter((name) => name.endsWith(".test.ts"))
      .map(async (name) => ({
        name,
        size: (await stat(join(testDirectory, name))).size,
      })),
  )
).sort(
  (left, right) =>
    right.size - left.size || left.name.localeCompare(right.name),
);
const configuredWorkers = Number.parseInt(
  process.env["CODEX_SECURITY_WINDOWS_TEST_WORKERS"] ?? "4",
  10,
);
if (!Number.isSafeInteger(configuredWorkers) || configuredWorkers < 1) {
  throw new Error("CODEX_SECURITY_WINDOWS_TEST_WORKERS must be positive");
}
const workerCount = Math.min(configuredWorkers, testFiles.length);
const groups = Array.from({ length: workerCount }, () => ({
  files: [],
  size: 0,
}));
for (const testFile of testFiles) {
  const group = groups.reduce((smallest, candidate) =>
    candidate.size < smallest.size ? candidate : smallest,
  );
  group.files.push(testFile.name);
  group.size += testFile.size;
}
const preload = process.env["CODEX_SECURITY_TEST_PRELOAD"];
const running = new Set();
let failed = false;
let interrupted = false;

const stop = () => {
  interrupted = true;
  for (const child of running) child.kill();
};
process.once("SIGINT", stop);
process.once("SIGTERM", stop);

const runTestGroup = (files) =>
  new Promise((resolve) => {
    const argumentsList = ["test", "--timeout", "30000"];
    if (preload !== undefined) argumentsList.push("--preload", preload);
    argumentsList.push(...files.map((file) => join(testDirectory, file)));
    const child = spawn("bun", argumentsList, {
      stdio: "inherit",
      windowsHide: true,
    });
    running.add(child);
    child.once("error", (error) => {
      running.delete(child);
      console.error(`Could not start test worker: ${error.message}`);
      resolve(false);
    });
    child.once("close", (code, signal) => {
      running.delete(child);
      resolve(code === 0 && signal === null);
    });
  });

console.error(
  `Running ${testFiles.length} Windows test files with ${workerCount} workers.`,
);
const results = await Promise.all(
  groups.map(({ files }) => runTestGroup(files)),
);
failed = results.some((passed) => !passed);
if (failed || interrupted) process.exitCode = 1;
