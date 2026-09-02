import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { binaryPath, output, root } from "./binding.mjs";
import { checkPrivatePaths } from "./check.mjs";

const extension = process.platform === "darwin" ? "dylib" : "so";
const cargoHome = resolve(
  root,
  process.env["CARGO_HOME"] ?? join(homedir(), ".cargo"),
);
const sysroot = execFileSync("rustc", ["--print", "sysroot"], {
  cwd: root,
  encoding: "utf8",
}).trim();
const inheritedFlags =
  process.env["CARGO_ENCODED_RUSTFLAGS"]?.split("\u001f") ??
  process.env["RUSTFLAGS"]?.split(/\s+/u).filter(Boolean) ??
  [];
const flags = [
  ...inheritedFlags,
  `--remap-path-prefix=${root}=codex-security-native`,
  `--remap-path-prefix=${cargoHome}=cargo`,
  `--remap-path-prefix=${sysroot}=rust-toolchain`,
];
const target = resolve(root, process.env["CARGO_TARGET_DIR"] ?? "target");
execFileSync("cargo", ["build", "--release", "--locked"], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    CARGO_ENCODED_RUSTFLAGS: flags.join("\u001f"),
    ...(process.platform === "darwin"
      ? { MACOSX_DEPLOYMENT_TARGET: "11.0" }
      : {}),
  },
});
const library = join(
  target,
  "release",
  `libcodex_security_native_unix.${extension}`,
);
checkPrivatePaths(readFileSync(library), [root, cargoHome, sysroot]);
mkdirSync(output, { recursive: true });
copyFileSync(library, binaryPath);
console.log(`Built ${process.platform}-${process.arch} Node-API 8 primitives.`);
