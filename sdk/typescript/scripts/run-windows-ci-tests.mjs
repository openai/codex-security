import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const testsDirectory = new URL("../tests-ts/", import.meta.url);
const packageDirectory = fileURLToPath(new URL("../", import.meta.url));
const tests = (await readdir(testsDirectory))
  .filter(
    (file) =>
      file.endsWith(".test.ts") && file !== "windows-machine-policy.test.ts",
  )
  .sort();
const shardSeeds = [
  ["api-credentials.test.ts"],
  ["api.test.ts"],
  ["runtime.test.ts"],
  ["cli-authentication.test.ts"],
  ["scan-recovery.test.ts"],
  [],
  [],
];
const assigned = new Set(shardSeeds.flat());
for (const file of assigned) {
  if (!tests.includes(file)) {
    throw new Error("Windows CI test shard references a missing file: " + file);
  }
}
const unassigned = tests.filter((file) => !assigned.has(file));
const slowRemainderFiles = new Set([
  "deep-scan-workbench.test.ts",
  "release-automation.test.ts",
  "scan-comparison.test.ts",
]);
for (const [index, file] of unassigned.entries()) {
  shardSeeds[slowRemainderFiles.has(file) ? 6 : 5 + (index % 2)].push(file);
}

const assignments = shardSeeds.flat();
if (
  assignments.length !== tests.length ||
  new Set(assignments).size !== tests.length
) {
  throw new Error("Windows CI test shards must run every test file once.");
}

const requestedShard =
  process.argv[2] === undefined ? undefined : Number(process.argv[2]);
if (
  requestedShard !== undefined &&
  (!Number.isSafeInteger(requestedShard) ||
    requestedShard < 1 ||
    requestedShard > shardSeeds.length)
) {
  throw new Error("Usage: node scripts/run-windows-ci-tests.mjs [1-7]");
}
const selectedShards =
  requestedShard === undefined
    ? shardSeeds.map((files, index) => ({ files, index }))
    : [{ files: shardSeeds[requestedShard - 1], index: requestedShard - 1 }];

const results = await Promise.all(
  selectedShards.map(
    ({ files, index }) =>
      new Promise((resolve, reject) => {
        const paths = files.map((file) => "./tests-ts/" + file);
        console.log(
          "Windows CI test shard " +
            (index + 1) +
            "/" +
            shardSeeds.length +
            ": " +
            paths.join(" "),
        );
        // Native Windows credential and document checks can exceed 30 seconds.
        // The workflow still bounds each complete shard to ten minutes.
        const child = spawn("bun", ["test", "--timeout", "120000", ...paths], {
          cwd: packageDirectory,
          stdio: "inherit",
          windowsHide: true,
        });
        child.once("error", reject);
        child.once("close", (code) => {
          resolve(code ?? 1);
        });
      }),
  ),
);

if (results.some((code) => code !== 0)) {
  process.exitCode = 1;
}
