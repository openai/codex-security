import { spawn } from "node:child_process";
import { randomInt } from "node:crypto";
import { mkdir, readFile, readdir } from "node:fs/promises";
import { bunTestOptions } from "./bun-test-timeout.mts";
import { partitionTests, type TestTimings } from "./test-shards.mts";

const selection = /^([1-9]\d*)\/([1-9]\d*)$/.exec(process.argv[2] ?? "");
const shard = Number(selection?.[1]);
const count = Number(selection?.[2]);
if (!Number.isSafeInteger(count) || shard > count) {
  throw new Error(
    "Usage: node --experimental-strip-types scripts/run-ci-tests.mts <shard>/<count> [bun test options]",
  );
}
const tests = (await readdir(new URL("../tests-ts/", import.meta.url)))
  .filter(
    (file) =>
      file.endsWith(".test.ts") && file !== "windows-machine-policy.test.ts",
  )
  .sort();
// The checked-in snapshot keeps every job in this run on the same assignment.
// Discovery remains authoritative, including files without timing history.
const timings = JSON.parse(
  await readFile(new URL("./test-timings.json", import.meta.url), "utf8"),
) as TestTimings;
const selected = partitionTests(tests, count, timings, process.platform)[
  shard - 1
]!;
if (selected.length === 0) {
  throw new Error(`Test shard ${shard}/${count} is empty.`);
}
const windows = process.platform === "win32";
const defaultTestTimeoutMs = windows ? "120000" : "30000";
console.log(`Test shard ${shard}/${count}: ${selected.join(" ")}`);
await mkdir(new URL("../reports/", import.meta.url), { recursive: true }).catch(
  () => {
    // Bun warns about report write failures without changing the test result.
  },
);
const testArguments = [
  "test",
  "--timeout",
  defaultTestTimeoutMs,
  "--reporter=junit",
  `--reporter-outfile=reports/junit-${shard}.xml`,
  ...process.argv.slice(3),
  ...selected.map((file) => `./tests-ts/${file}`),
];
const { seed: requestedSeed, timeout } = bunTestOptions(testArguments);
const seed = requestedSeed ?? String(randomInt(2 ** 32));
if (requestedSeed === undefined) testArguments.splice(1, 0, `--seed=${seed}`);
console.log(`Bun test seed: ${seed}`);
const child = spawn("bun", testArguments, {
  cwd: new URL("../", import.meta.url),
  env: {
    ...process.env,
    CODEX_SECURITY_TEST_TIMEOUT_MS: timeout,
  },
  stdio: "inherit",
  windowsHide: true,
});
child.once("error", console.error);
child.once("close", (code) => {
  process.exitCode = code ?? 1;
});
