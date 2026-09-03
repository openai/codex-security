import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { binaryPath, output, root } from "./binding.mjs";
import { checkPrivatePaths } from "./check.mjs";

let windowsTarget: string | undefined;
if (process.platform === "win32") {
  const architecture =
    process.arch === "arm64"
      ? "aarch64"
      : process.arch === "x64"
        ? "x86_64"
        : undefined;
  if (architecture === undefined)
    throw new Error("Windows native builds support x64 and arm64.");
  windowsTarget = `${architecture}-pc-windows-msvc`;
}
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
  ...(windowsTarget === undefined ? [] : ["-C", "target-feature=+crt-static"]),
  `--remap-path-prefix=${root}=codex-security-native`,
  `--remap-path-prefix=${cargoHome}=cargo`,
  `--remap-path-prefix=${sysroot}=rust-toolchain`,
];
const target = resolve(root, process.env["CARGO_TARGET_DIR"] ?? "target");
const args = ["build", "--release", "--locked"];
if (windowsTarget !== undefined) args.push("--target", windowsTarget);
execFileSync("cargo", args, {
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
  ...(windowsTarget === undefined ? [] : [windowsTarget]),
  "release",
  windowsTarget === undefined
    ? `libcodex_security_native.${process.platform === "darwin" ? "dylib" : "so"}`
    : "codex_security_native.dll",
);
checkPrivatePaths(readFileSync(library), [root, cargoHome, sysroot, target]);
mkdirSync(output, { recursive: true });
copyFileSync(library, binaryPath);
console.log(`Built ${process.platform}-${process.arch} Node-API 8 primitives.`);
