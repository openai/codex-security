---
name: unsafe-rust-review
description: Review Rust unsafe code and safe abstractions for soundness, undefined behavior, and security impact, or review and write their safety documentation. Applies to unsafe operations, unsafe trait implementations, FFI, and safe APIs that uphold unsafe invariants.
---

# Unsafe Rust Review

Read [the upstream review method](references/unsafe-rust-review.md) and apply its proof obligations to the actual code, including safe callers, callbacks, traits, constructors, mutation, drop, and panic paths. During an existing security scan, add these soundness checks to the full security review of Rust files. Continue the calling workflow's other vulnerability checks, including application logic and trust boundaries. The calling workflow retains its target, permissions, scan ownership, reporting format, and validation responsibilities. Do not start another scan or produce a second set of scan reports.

## Review intent

For security scans, use safety comments and documentation as claims to verify, not as a documentation checklist. Find concrete unsoundness, undefined behavior, and correctness failures with a plausible security impact. Missing comments, stylistic differences, or an incomplete written proof alone are not vulnerabilities. Establish what safe, type-correct callers or external inputs can actually trigger. Caller-provided safe traits and callbacks may lie, panic, reenter, or mutate accessible state; their semantic promises cannot justify unchecked memory operations. Conversely, a caller violating a genuine unsafe precondition does not by itself demonstrate an unsound abstraction.

Distinguish a correctness bug from a security vulnerability by stating the attacker capability, trust boundary, supported configuration, and resulting compromise. Do not label every instance of UB as remote code execution or invent a deployment. A public safe library API may be a meaningful boundary when untrusted inputs or safe caller implementations can reach the failure. Put non-security bugs, documentation observations, and unresolved questions in the calling workflow's existing non-finding output. For a standalone review, state those distinctions directly. When the user explicitly asks for safety documentation, also apply the upstream writing and comment-formatting guidance; edit source only when requested.

## Sources and environment

Use the repository's selected toolchain, lockfile, enabled features, and supported targets to identify the contracts being reviewed. Consult the Rust Reference, standard-library documentation, and the exact dependency API contracts. Read dependency implementations when the proof requires them; do not infer undocumented guarantees from current implementation behavior. Include cfg-gated code, macro-generated interfaces, and FFI contracts when they affect the reviewed invariant.

Use available local documentation, standard-library source, and Cargo registry/Git sources first. When required material is missing, the scan owner or standalone reviewer prepares it through the host's existing setup and permissions. `rust-src` provides standard-library source; `rust-docs` provides local documentation. Use components matching the selected toolchain. Cargo can fetch registry and Git dependency sources: use `cargo fetch --locked` when the repository has a usable lockfile. If it has none, resolve dependencies in the authorized disposable copy and state the resolution used. Do not change the reviewed repository's lockfile or silently substitute a different dependency version. Account for project-specific registries, Git dependencies, local path dependencies, and native libraries; fetching a Rust wrapper does not necessarily provide the linked native implementation.

Preparation is subject to existing network and execution permissions. `cargo fetch` does not build package build scripts or expand proc macros, but Cargo configuration can invoke credential providers and other tools. Compilation, documentation generation, and macro expansion can execute build scripts or proc macros. Use the host's authorized execution workspace. In an offline or source-only worker, use supplied local sources and return the missing contract or environment requirement to the owner. Missing sources narrow the evidence; they do not prove either soundness or a vulnerability.

## Reproduce and validate

For each concrete candidate, trace the triggering safe API or external-input path, the violated contract, and the strongest counterevidence. The calling workflow's validation owner performs runtime validation in its authorized execution workspace; source-review subagents return candidates and proposed reproductions. Read-only or offline execution restrictions remain in force; this skill does not elevate a worker or authorize network access.

Attempt a minimal reproduction against the actual library or application when runtime validation can clarify a concrete candidate. Prefer an existing test harness or a small consumer using the real dependency. Use Miri for Rust UB that it can model, and ASan or another applicable sanitizer for native/FFI or unsupported paths. Preserve the reviewed code in a disposable copy and capture the input, command, selected toolchain/features/target, and observed result. Miri needs a compatible nightly toolchain and may need setup before an offline run. Its unsupported operations, FFI limitations, or setup failures are not a clean validation result. A passing run covers that execution, not all inputs or a proof of soundness.

When only a scratch directory is writable, direct build output there with `CARGO_TARGET_DIR` and prepare Miri's sysroot there with `MIRI_SYSROOT=<scratch-sysroot> cargo +<nightly> miri setup`. Use the same prepared `MIRI_SYSROOT` for the reproduction; setting it during `miri run` skips automatic setup. Preserve the existing toolchain and dependency configuration, and use available local caches where possible. Prepare missing components and dependencies before an offline run, subject to the owner's network permissions.

Connect a Miri or sanitizer failure to the actual violated Rust or native contract and the stated threat model. A small reproduction of a safe API's memory error can validate that failure without demonstrating full exploitation; state what was and was not demonstrated. If runtime validation is unavailable, retain a source-backed finding with its precise proof gap and calibrated confidence rather than claiming a test ran or suppressing it solely for lack of a PoC.

Use the calling workflow's existing evidence and artifact storage. A standalone review that creates retained artifacts follows [artifact storage](../../references/artifact-storage.md); a review answered only in chat needs no artifact collection. Keep proposed reproduction steps distinct from executed results.

The detailed method is vendored from Google's `rust-skills` project. See [upstream attribution, licensing, and update notes](references/UPSTREAM.md).
