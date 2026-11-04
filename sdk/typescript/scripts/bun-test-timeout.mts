import { parseArgs } from "node:util";

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

export function bunTestTimeout(testArguments: readonly string[]) {
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
  return parsed.values.timeout as string | undefined;
}
