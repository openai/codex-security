import { spawn } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bunTestTimeout } from "./bun-test-timeout.mts";
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
// Bun's text coverage writer can abort on a backpressured stderr pipe before
// writing JUnit/LCOV reports. Preserve its diagnostics in a regular file, then
// relay them live with Node's stream backpressure while keeping the test exit status.
const outputDirectory = await mkdtemp(
  join(tmpdir(), "codex-security-ci-output-"),
);
const outputPath = join(outputDirectory, "stderr.log");
const output = await open(outputPath, "w");
const reader = await open(outputPath, "r");
const buffer = Buffer.allocUnsafe(64 * 1024);
let offset = 0;
let flushing: Promise<void> | undefined;
let relayFailed = false;
// A disconnected diagnostic consumer must not replace the test process result.
process.stderr.on("error", () => {
  relayFailed = true;
});
const flush = (): Promise<void> => {
  flushing ??= (async () => {
    while (!relayFailed) {
      const { bytesRead } = await reader.read(buffer, 0, buffer.length, offset);
      if (bytesRead === 0) return;
      offset += bytesRead;
      await new Promise<void>((resolve) => {
        process.stderr.write(buffer.subarray(0, bytesRead), (error) => {
          if (error) relayFailed = true;
          resolve();
        });
      });
    }
  })()
    .catch(() => {
      relayFailed = true;
    })
    .finally(() => {
      flushing = undefined;
    });
  return flushing;
};
// Keep diagnostics visible before an interrupted or timed-out child exits.
const relay = setInterval(() => {
  void flush();
}, 100);
relay.unref();
try {
  const child = spawn("bun", testArguments, {
    cwd: new URL("../", import.meta.url),
    env: {
      ...process.env,
      CODEX_SECURITY_TEST_TIMEOUT_MS: bunTestTimeout(testArguments),
    },
    stdio: ["inherit", "inherit", output.fd],
    windowsHide: true,
  });
  process.exitCode = await new Promise<number>((resolve) => {
    child.once("error", (error) => {
      console.error(error);
      resolve(1);
    });
    child.once("close", (code) => resolve(code ?? 1));
  });
} finally {
  clearInterval(relay);
  await flushing;
  await flush();
  await Promise.allSettled([reader.close(), output.close()]);
  // A lingering Windows file lock only affects these temporary diagnostics.
  await rm(outputDirectory, { recursive: true, force: true }).catch(() => {});
}
