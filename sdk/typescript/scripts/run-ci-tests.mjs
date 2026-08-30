import { spawn } from "node:child_process";
import { mkdir, readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { shardTestFiles } from "./test-shards.mjs";

const selection = /^([1-9]\d*)\/([1-9]\d*)$/.exec(process.argv[2] ?? "");
const shard = Number(selection?.[1]);
const count = Number(selection?.[2]);
if (
  !Number.isSafeInteger(shard) ||
  !Number.isSafeInteger(count) ||
  shard > count
) {
  throw new Error(
    "Usage: node scripts/run-ci-tests.mjs <shard>/<count> [bun test options]",
  );
}
const packageDirectory = fileURLToPath(new URL("../", import.meta.url));
const tests = (await readdir(new URL("../tests-ts/", import.meta.url))).filter(
  (file) =>
    file.endsWith(".test.ts") && file !== "windows-machine-policy.test.ts",
);
const timings = JSON.parse(
  await readFile(new URL("./ci-test-durations.json", import.meta.url), "utf8"),
);
const windows = process.platform === "win32";
const assignments = shardTestFiles(
  tests,
  count,
  timings[windows ? "windows" : "unix"],
);
const selected = assignments[shard - 1];
if (selected.files.length === 0) {
  throw new Error(`Test shard ${shard}/${count} is empty.`);
}
console.log(
  `Test shard ${shard}/${count} (estimated ${selected.seconds.toFixed(1)}s): ${selected.files.join(" ")}`,
);
await mkdir(new URL("../reports/", import.meta.url), { recursive: true }).catch(
  () => {
    // Bun warns about report write failures without changing the test result.
  },
);
const child = spawn(
  "bun",
  [
    "test",
    "--timeout",
    windows ? "120000" : "30000",
    "--reporter=junit",
    `--reporter-outfile=reports/junit-${shard}.xml`,
    ...process.argv.slice(3),
    ...selected.files.map((file) => `./tests-ts/${file}`),
  ],
  { cwd: packageDirectory, stdio: "inherit", windowsHide: true },
);
child.once("error", (error) => {
  console.error(error);
  process.exitCode = 1;
});
child.once("close", (code) => {
  process.exitCode = code ?? 1;
});
