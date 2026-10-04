# Native OS primitives

These internal bindings supply OS operations that Node does not expose. The `resolve-security-md` helper uses native account lookup on Unix and native path, file, and directory operations on Windows.

The Unix Node-API 8 binding is typed in `binding.mts`. `userHome` looks up raw username bytes through the operating system and returns raw home-directory bytes or a missing result, without Git.

Install the pinned Rust toolchain and the existing TypeScript dependencies, then run from the repository root:

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build:ci
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/proof.mjs
cargo +1.97.1 fmt --check --manifest-path plugins/codex-security/native/Cargo.toml
cargo +1.97.1 clippy --locked --manifest-path plugins/codex-security/native/Cargo.toml -- -D warnings
```

The proof runs without Python. It checks current and named account lookup, missing accounts, and embedded-NUL rejection. CI invokes it with an empty `PATH`.

Build outputs stay under ignored `target` and `dist` directories. Linux output directories include the C runtime: `linux-x64-gnu`, `linux-arm64-gnu`, `linux-x64-musl`, and `linux-arm64-musl`. The dependency-free `platform.mts` helper distinguishes glibc from musl using the Node diagnostic report header, without a subprocess. macOS and Windows retain their platform and architecture directories. Source, Cargo registry, and compiler paths are remapped before compilation; actual payload bytes are checked for private paths. Before an artifact is uploaded, run:

```sh
node plugins/codex-security/native/check.mjs
```

GNU Linux artifacts must import no glibc version newer than 2.28. Musl artifacts must be ELF images for the current architecture, depend on that architecture's musl library, and have no version requirements from glibc. GCC's own `GLIBC_2.0` compatibility exports are attributed to `libgcc_s.so.1`, not the C library. Musl has no glibc-style symbol version floor, so its runtime compatibility also requires the load proofs below. macOS artifacts must declare a deployment target of 11.0 or earlier. A build from a newer GNU Linux workstation can pass the behavioral proof and still fail this distribution check.

The `native-unix` workflow builds Linux artifacts in digest-pinned manylinux 2.28 images. It mounts the pinned Rust toolchain and fetched Cargo registry, builds offline, and blocks Python commands during compilation. macOS builds set `MACOSX_DEPLOYMENT_TARGET=11.0`. CI verifies separate x64 and arm64 artifacts on both platforms using Node 20.0.0 and 22.13.0.

The `native-musl` workflow uses native x64 and arm64 Ubuntu workers with digest-pinned Rust 1.97.1 Alpine compiler images. Musl builds disable static CRT linkage so Node can load the shared library. After the ELF and private-path checks, each unchanged artifact runs the full proof in pinned Node 20.0.0 Alpine 3.17 and Node 22.13.0 Alpine 3.21 images, with musl 1.2.3 and 1.2.5 respectively. Compilation uses the locked registry offline; runtime containers mount only the source and artifact read-only. Python is absent, and proof processes receive an empty `PATH`.

Windows uses `windows-binding.mts` and the same Rust crate. `WindowsHandle` owns a non-inheritable handle through Rust's `File`; explicit `close()` and garbage collection release it. Handles never cross into Node's CRT descriptor table. Paths and returned names are UTF-16LE buffers without a NUL terminator, preserving lone surrogates. Volume identities are decimal strings; file IDs retain all 128 bits in a buffer.

The binding exposes synchronous file and recursive directory creation, attributes and reparse tags, identity and final/opened names, read/write, and exact-handle rename and deletion. Rust's `File` supplies ordinary I/O. Calls return numeric Windows errors, including 6 for closed handles. Buffer ranges and path encoding are checked before use. Overlapped handles are unsupported because pending operations could retain native buffers beyond the call. Path authorization, ancestor traversal, and reparse-point policy remain the caller's responsibility.

Four additional operations preserve Windows strings at the Node boundary. `windowsArguments` returns the complete OS argument vector, including the executable and Node options, using Rust's CRT-compatible parser. `windowsEnvironment` reads one wide environment name and distinguishes an absent value (`null`) from an empty buffer. `windowsAbsolutePath` resolves against the native current directory and drive directories without requiring the destination to exist. `windowsDirectoryEntries` uses `std::fs::read_dir` and cached `DirEntry::file_type()` values without opening each child; names remain UTF-16LE, and construction or iteration failures return their numeric Windows error and an empty array. Directory symlinks and junctions have both directory and symbolic-link flags. The typed adapter exposes this enumerator through `entriesWithTypes`, which `resolve-security-md --list` uses on Windows.

`windows-files.mts` uses native absolute and final paths, preserving raw UTF-16 and the returned device prefix. Non-strict `realpath` resolves the nearest existing ancestor of a missing path; dangling links and other access errors remain errors. Callers must check containment independently. It follows native Windows path behavior rather than emulating Python's special cases for device names, whitespace, verbatim dot segments, and prefix removal. `stat(path, false)` retains exact symbolic-link and reparse-point metadata so callers can reject junction traversal independently of the enumerator's link label. The SDK's public runtime floor remains Node 22.13.0. Node 20.0.0 is an additional native-foundation compatibility proof; it does not change the SDK engine requirement.

Build on Windows after compiling the TypeScript tools, then run:

```sh
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/check.mjs
node --expose-gc plugins/codex-security/native/proof-windows.mjs
```

The `native-windows` workflow builds x64 and arm64 with MSVC and a static CRT. It checks PE architecture and private paths, then runs the same artifact on Node 22.13.0 and 20.0.0 with an empty `PATH`. The proof covers handle lifetime and garbage collection, ancestor replacement, junctions, exact-handle operations, raw UTF-16 and long paths, and numeric errors.

The build also compiles the test-only `windows-wide-launcher` Rust example. It starts a Node proof child with lone surrogates in arguments, environment values, and its working directory. That child checks complete directory iteration, distinct surrogate and replacement-character files, canonical paths, bounded reads, output truncation, and recursive long paths through the typed adapter. A Rust file guard with sharing disabled remains open while the child enumerates its name; an explicit data read fails with a sharing violation. Attribute-only access is not blocked by Windows file sharing. Adapter path and I/O tests run on the same matrix. The launcher cleans up the wide fixtures and is never included in the uploaded or bundled native payloads.

Creating file and directory symbolic links requires Windows Developer Mode or the symbolic-link privilege. Without it, the proofs still run their other assertions, including directory junctions, and report the skipped symbolic-link assertions as `false` in their JSON output. CI requires real symbolic links on both architectures and also forces the restricted case to exercise both paths.

## Package inputs

With the pinned Rust toolchain installed, build the plugin on its own:

```sh
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
node plugins/codex-security/mcp-app/scripts/build_native.mjs
node plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs --output plugins/codex-security/mcp --native host
```

`build_native.mjs` uses the MCP app's dependencies to compile the TypeScript tools, fetches the locked Cargo dependencies, and writes the host binary and license notices to `native/dist`. `--native host` packages those files for the current platform and architecture under `mcp/`, where the plugin launcher expects them. CI tests this build without the SDK on Linux, macOS, and Windows.

For plugin and npm releases, use the default `--native universal`. It requires all eight verified binaries in `native/prebuilt`.

The `native-artifacts` workflow calls all three platform workflows and combines their eight verified payloads into `native-universal-<commit>`. PR validation jobs share one artifact assembled by `node-ci`; release and standalone validation runs assemble their own. By default, the standalone MCP builder and npm package include the same complete `mcp/native` tree; neither compiles nor downloads code at runtime.

The GNU x64 job also runs `notices.mjs` against the locked Cargo metadata. It collects crate licenses and the pinned Rust standard-library notices for both package surfaces. The NAPI crates omit license files from their registry archives, so `licenses/napi.txt` preserves their [pinned upstream license](https://github.com/napi-rs/napi-rs/blob/956e4525fea6a676ea3680b711382f167b899af9/LICENSE). Review that override when upgrading those dependencies.

For universal builds, SDK tests, or Docker builds, select a successful run for the checkout's native sources. You can run `native-artifacts` manually on a pushed branch. Use the artifact name shown by that run; pull-request artifacts use the tested merge commit. From the repository root:

```sh
gh run download <run-id> --name native-universal-<commit> --dir plugins/codex-security/native/prebuilt
```

The ignored `prebuilt` directory must contain all eight platform directories and the shared notices. Refresh it after changing the native source or build toolchain. Missing payloads fail the build, including on hosts that only load one of them. Installed-package checks load the matching artifact with an empty `PATH`.
