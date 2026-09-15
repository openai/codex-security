# MCP tests

From `sdk/typescript`, install both packages' dependencies, prepare the [universal native payload](../native/README.md#package-inputs), and run `pnpm run test:mcp`. That command builds the bundled plugin before testing it. To rerun only the tests after a build, run `pnpm run test:mcp` from this directory.

Node's test runner discovers `tests/test_*.mjs` and runs at most two files at once, each in a separate process. Assertions within a file remain sequential. Keep shared helpers outside that filename pattern. A failing script fails the command. The reporter streams Node's TAP output and then tries to write Node's JUnit report to `reports/junit.xml`; an unavailable report path warns without changing the test result. CI uploads that file with the Node 22 reports.

For a serial comparison, run:

```sh
node --test --test-concurrency=1 "tests/test_*.mjs"
```

Use the existing injected clocks for retry policy tests. Keep real timers, subprocesses, SQLite files, and isolated temporary directories in the lifecycle, locking, permissions, and stdio tests. Do not share writable fixtures between test files or rebuild the bundled plugin while another test is reading it.

## Build for the local host

For a local or CI plugin that only runs on the build host, install the MCP app dependencies and the toolchain declared in `../native/rust-toolchain.toml`. Windows also requires the MSVC C++ build tools. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm run build:native
node scripts/build_mcp_app.mjs --output .preview/mcp --native host
```

`build:native` compiles the native TypeScript tools with this package's existing dependencies, runs the locked Cargo build, and prepares dependency notices. It does not require the SDK source tree. Native outputs stay in ignored `../native/dist` and `../native/target` directories; `CARGO_TARGET_DIR` can select another Cargo cache.

`--native host` copies the current OS, CPU, and Linux libc target from `native/dist`, together with all shared notices. It requires a fresh `build:native` run after native source changes and fails if the host binary is missing. Build again on each execution platform; a host build is not a portable release artifact.

The default, `--native universal`, still requires the complete verified `native/prebuilt` payload. Package and release validation keep checking every supported platform. For distributing GNU Linux binaries, retain the glibc 2.28 build environment and the compatibility checks described in the [native README](../native/README.md).
