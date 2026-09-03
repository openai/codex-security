# Native OS primitives

This foundation supplies the OS operations that Node does not expose. The SDK and CLI continue to use their existing helpers while universal package assembly and migration proofs are completed.

The nine Node-API 8 functions are typed in `binding.mts`. Paths remain byte buffers. `statAt` never follows the final symlink; device and inode numbers are decimal strings so JavaScript does not round them. `openAt` and `duplicate` create descriptors with close-on-exec set. Node owns subsequent reads, writes, `fstat`, `fsync`, and close calls. `userHome` looks up raw username bytes through the operating system and returns raw home-directory bytes or a missing result, without Git.

`openAt` and `fileLock` retry EINTR, matching the current Python helpers. Other operations return their native errno. `readDescriptor` retries one interrupted Node read without losing earlier chunks. Blocking locks must run outside the main JavaScript event loop; a process that holds a lock releases it on close or exit. A Python signal handler can raise during a blocked call, so later routing must preserve cancellation through the worker lifecycle.

Install the pinned Rust toolchain and the existing TypeScript dependencies, then run from the repository root:

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build:ci
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/proof.mjs
cargo +1.97.1 fmt --check --manifest-path plugins/codex-security/native/Cargo.toml
cargo +1.97.1 clippy --locked --manifest-path plugins/codex-security/native/Cargo.toml -- -D warnings
```

The proof runs without Python. It checks directory replacement, byte paths, unreadable-file metadata, long raw symlinks, descriptor duplication, Node descriptor I/O, account lookup, contention, unlock, and process-death release. Linux exercises undecodable filename bytes; macOS uses valid UTF-8 filenames required by APFS. CI invokes it with an empty `PATH`. During migration, the same protocol can compare the existing Python lock helper:

```sh
node plugins/codex-security/native/proof.mjs python3 plugins/codex-security/scripts
```

Build outputs stay under ignored `target` and `dist` directories. Source, Cargo registry, and compiler paths are remapped before compilation; actual payload bytes are checked for private paths. Before an artifact is uploaded, run:

```sh
node plugins/codex-security/native/check.mjs
```

Linux artifacts must import no glibc version newer than 2.28. macOS artifacts must declare a deployment target of 11.0 or earlier. A build from a newer Linux workstation can pass the behavioral proof and still fail this distribution check.

The `native-unix` workflow builds Linux artifacts in digest-pinned manylinux 2.28 images. It mounts the pinned Rust toolchain and fetched Cargo registry, builds offline, and blocks Python commands during compilation. macOS builds set `MACOSX_DEPLOYMENT_TARGET=11.0`. CI verifies separate x64 and arm64 artifacts on both platforms using Node 20.0.0 and 22.13.0. These artifacts are inputs to the later universal-package gate.

Windows uses `windows-binding.mts` and the same Rust crate. `WindowsHandle` owns a non-inheritable Win32 handle; explicit `close()` and garbage collection release it. Handles never cross into Node's CRT descriptor table. Paths and returned names are UTF-16LE buffers without a NUL terminator, preserving lone surrogates. Volume identities and file positions are decimal strings; file IDs retain all 128 bits in a buffer.

The binding exposes synchronous file and directory creation, attributes and reparse tags, identity and final/opened names, read/write/seek/size/EOF/flush, exact-handle rename and deletion, and byte-range locking. Calls return numeric Windows errors. Buffer ranges, path encoding, and 64-bit arguments are checked before FFI calls. Overlapped handles are unsupported because pending operations could retain native buffers beyond the call. Path authorization, ancestor traversal, and reparse-point policy remain the caller's responsibility.

Build on Windows after compiling the TypeScript tools, then run:

```sh
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/check.mjs
node --expose-gc plugins/codex-security/native/proof-windows.mjs
```

The `native-windows` workflow builds x64 and arm64 with MSVC and a static CRT. It checks PE architecture and private paths, then runs the same artifact on Node 22.13.0 and 20.0.0 with an empty `PATH`. The proof covers handle lifetime and garbage collection, ancestor replacement, junctions, exact-handle operations, raw UTF-16 and long paths, numeric errors, and cross-process byte-zero locking and release. Blocking locks run in child processes. Comparison with the existing Python `msvcrt` lock remains a separate migration gate before production routing.
