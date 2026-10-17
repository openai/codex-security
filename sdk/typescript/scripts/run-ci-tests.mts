import { spawn } from "node:child_process";
import { mkdir, readdir } from "node:fs/promises";
import { parseArgs } from "node:util";

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
// Match Bun 1.3.14's sorted round-robin assignment for startup diagnostics.
// https://github.com/oven-sh/bun/blob/bun-v1.3.14/src/cli/test_command.zig
const selected = tests.filter((_, index) => index % count === shard - 1);
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
  `--shard=${shard}/${count}`,
  "--timeout",
  defaultTestTimeoutMs,
  "--reporter=junit",
  `--reporter-outfile=reports/junit-${shard}.xml`,
  ...process.argv.slice(3),
  ...tests.map((file) => `./tests-ts/${file}`),
];
// Keep arities aligned with the pinned Bun's test_params:
// https://github.com/oven-sh/bun/blob/bun-v1.3.14/src/cli/Arguments.zig
const optionalBunOptions = {
  bail: { type: "string" },
  changed: { type: "string" },
  parallel: { type: "string" },
  inspect: { type: "string" },
  "inspect-wait": { type: "string" },
  "inspect-brk": { type: "string" },
  config: { type: "string", short: "c" },
} as const;
const parsingArguments = [...testArguments];
let parsed;
let bareOptional;
do {
  parsed = parseArgs({
    args: parsingArguments,
    allowPositionals: true,
    strict: false,
    tokens: true,
    // Bun options that consume values must not turn those values into timeouts.
    options: {
      ...optionalBunOptions,
      timeout: { type: "string" },
      "test-name-pattern": { type: "string", short: "t" },
      grep: { type: "string" },
      "rerun-each": { type: "string" },
      retry: { type: "string" },
      seed: { type: "string" },
      "coverage-reporter": { type: "string" },
      "coverage-dir": { type: "string" },
      reporter: { type: "string" },
      "reporter-outfile": { type: "string" },
      "max-concurrency": { type: "string" },
      "path-ignore-patterns": { type: "string" },
      "parallel-delay": { type: "string" },
      shard: { type: "string" },
      preload: { type: "string", short: "r" },
      require: { type: "string" },
      import: { type: "string" },
      "cpu-prof-name": { type: "string" },
      "cpu-prof-dir": { type: "string" },
      "cpu-prof-interval": { type: "string" },
      "heap-prof-name": { type: "string" },
      "heap-prof-dir": { type: "string" },
      install: { type: "string" },
      eval: { type: "string", short: "e" },
      print: { type: "string", short: "p" },
      port: { type: "string" },
      origin: { type: "string" },
      conditions: { type: "string" },
      "fetch-preconnect": { type: "string" },
      "max-http-header-size": { type: "string" },
      "dns-result-order": { type: "string" },
      title: { type: "string" },
      "unhandled-rejections": { type: "string" },
      "console-depth": { type: "string" },
      "user-agent": { type: "string" },
      "cron-title": { type: "string" },
      "cron-period": { type: "string" },
      "main-fields": { type: "string" },
      "extension-order": { type: "string" },
      "tsconfig-override": { type: "string" },
      define: { type: "string", short: "d" },
      drop: { type: "string" },
      feature: { type: "string" },
      loader: { type: "string", short: "l" },
      "jsx-factory": { type: "string" },
      "jsx-fragment": { type: "string" },
      "jsx-import-source": { type: "string" },
      "jsx-runtime": { type: "string" },
      "env-file": { type: "string" },
      cwd: { type: "string" },
    },
  });
  // Bun leaves a following flag outside an optional value; parseArgs does not.
  bareOptional = parsed.tokens.find(
    (token): token is Extract<typeof token, { kind: "option" }> =>
      token.kind === "option" &&
      Object.hasOwn(optionalBunOptions, token.name) &&
      !token.inlineValue &&
      token.value?.startsWith("-")!,
  );
  if (bareOptional) {
    parsingArguments[bareOptional.index] = `--${bareOptional.name}=`;
  }
} while (bareOptional);
const child = spawn("bun", testArguments, {
  cwd: new URL("../", import.meta.url),
  env: {
    ...process.env,
    CODEX_SECURITY_TEST_TIMEOUT_MS: parsed.values.timeout as string | undefined,
  },
  stdio: "inherit",
  windowsHide: true,
});
child.once("error", console.error);
child.once("close", (code) => {
  process.exitCode = code ?? 1;
});
