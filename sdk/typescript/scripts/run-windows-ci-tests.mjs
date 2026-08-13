import { spawn } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const testsDirectory = new URL("../tests-ts/", import.meta.url);
const packageDirectory = fileURLToPath(new URL("../", import.meta.url));
const tests = (await readdir(testsDirectory))
  .filter((file) => file.endsWith(".test.ts"))
  .sort();
const slowApiTestNames = [
  "keeps a private preflight snapshot isolated from persistent credentials",
  "reuses keyring-compatible credentials across separate scan clients",
  "serializes parallel scans sharing a managed credential home",
  "reuses the managed runtime when scan authentication changes",
  "does not reimport ambient credentials after an explicit logout",
];
const apiTestSource = await readFile(
  new URL("../tests-ts/api.test.ts", import.meta.url),
  "utf8",
);
for (const testName of slowApiTestNames) {
  if (!apiTestSource.includes(`test("${testName}"`)) {
    throw new Error("Windows CI slow API shard references a missing test.");
  }
}
const slowApiTests = slowApiTestNames.join("|");
const shardSeeds = [
  {
    files: ["api.test.ts"],
    testNamePattern: slowApiTests,
  },
  {
    files: ["api.test.ts"],
    testNamePattern: `^(?!.*(?:${slowApiTests})).*$`,
  },
  { files: ["runtime.test.ts"] },
  { files: ["cli-authentication.test.ts"] },
  { files: ["scan-recovery.test.ts"] },
  { files: [] },
  { files: [] },
];
const assigned = new Set(shardSeeds.flatMap(({ files }) => files));
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
  shardSeeds[slowRemainderFiles.has(file) ? 6 : 5 + (index % 2)].files.push(
    file,
  );
}

const assignments = new Map();
for (const { files } of shardSeeds) {
  for (const file of files) {
    assignments.set(file, (assignments.get(file) ?? 0) + 1);
  }
}
for (const file of tests) {
  const expectedAssignments = file === "api.test.ts" ? 2 : 1;
  if (assignments.get(file) !== expectedAssignments) {
    throw new Error("Windows CI test shards must run every test file.");
  }
}

const requestedShard =
  process.argv[2] === undefined
    ? undefined
    : Number.parseInt(process.argv[2], 10);
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
    ? shardSeeds.map((shard, index) => ({ ...shard, index }))
    : [{ ...shardSeeds[requestedShard - 1], index: requestedShard - 1 }];

const results = await Promise.all(
  selectedShards.map(
    ({ files, index, testNamePattern }) =>
      new Promise((resolve, reject) => {
        const paths = files.map((file) => "./tests-ts/" + file);
        console.log(
          "Windows CI test shard " +
            (index + 1) +
            "/" +
            shardSeeds.length +
            ": " +
            paths.join(" ") +
            (testNamePattern === undefined
              ? ""
              : " --test-name-pattern " + testNamePattern),
        );
        const args = ["test", "--timeout", "30000"];
        if (testNamePattern !== undefined) {
          args.push("--test-name-pattern", testNamePattern);
        }
        args.push(...paths);
        const child = spawn("bun", args, {
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
