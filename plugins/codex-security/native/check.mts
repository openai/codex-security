import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { binaryPath } from "./binding.mjs";
import { libc } from "./platform.mjs";

export function checkPrivatePaths(
  bytes: Buffer,
  buildPaths: string[] = [],
): void {
  for (const marker of [
    "/Users/",
    "/home/dev-user",
    "/tmp/codex-security-python-",
    ...buildPaths,
  ]) {
    if (
      bytes.includes(Buffer.from(marker)) ||
      bytes.includes(Buffer.from(marker, "utf16le"))
    ) {
      throw new Error("Native payload contains a private build path.");
    }
  }
}

function versionAfter(value: string, floor: string): boolean {
  const actual = value.split(".").map(Number);
  const maximum = floor.split(".").map(Number);
  for (
    let index = 0;
    index < Math.max(actual.length, maximum.length);
    index++
  ) {
    const difference = (actual[index] ?? 0) - (maximum[index] ?? 0);
    if (difference !== 0) return difference > 0;
  }
  return false;
}

if (
  process.argv[1] !== undefined &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  const bytes = readFileSync(binaryPath);
  checkPrivatePaths(bytes);
  let floor: string;
  if (process.platform === "linux") {
    const versions = execFileSync("readelf", ["--version-info", binaryPath], {
      encoding: "utf8",
    });
    const required = [...versions.matchAll(/\bGLIBC_(\d+(?:\.\d+)*)/gu)].map(
      (match) => match[1]!,
    );
    if (libc === "musl") {
      const architecture =
        process.arch === "x64"
          ? { machine: 62, name: "x86_64" }
          : process.arch === "arm64"
            ? { machine: 183, name: "aarch64" }
            : undefined;
      const dynamic = execFileSync("readelf", ["--dynamic", binaryPath], {
        encoding: "utf8",
      });
      const dependencies = [
        ...dynamic.matchAll(/\(NEEDED\)[^\n]*\[([^\]]+)\]/gu),
      ].map((match) => match[1]!);
      // libgcc uses GLIBC_2.0 for its own compatibility exports on aarch64.
      const requiresGlibc = [
        ...versions.matchAll(/\bFile:\s+(\S+)([\s\S]*?)(?=\bFile:|$)/gu),
      ].some(
        (match) =>
          match[1] !== "libgcc_s.so.1" && /\bName:\s+GLIBC_/u.test(match[2]!),
      );
      if (
        architecture === undefined ||
        bytes.toString("latin1", 0, 4) !== "\x7fELF" ||
        bytes[4] !== 2 ||
        bytes[5] !== 1 ||
        bytes.readUInt16LE(18) !== architecture.machine ||
        !dependencies.includes(`libc.musl-${architecture.name}.so.1`) ||
        requiresGlibc
      ) {
        throw new Error(
          "Native payload is not a musl ELF image for this architecture, or imports glibc.",
        );
      }
      floor = "musl; Node 20 and 22 load proofs required";
    } else {
      if (
        required.length === 0 ||
        required.some((version) => versionAfter(version, "2.28"))
      ) {
        throw new Error(
          "Native payload requires glibc newer than 2.28, or has no inspectable glibc requirements.",
        );
      }
      floor = "glibc 2.28";
    }
  } else if (process.platform === "darwin") {
    const commands = execFileSync("otool", ["-l", binaryPath], {
      encoding: "utf8",
    });
    const minimum =
      /cmd LC_BUILD_VERSION\s+[\s\S]*?\bminos ([\d.]+)/u.exec(commands)?.[1] ??
      /cmd LC_VERSION_MIN_MACOSX\s+[\s\S]*?\bversion ([\d.]+)/u.exec(
        commands,
      )?.[1];
    if (minimum === undefined || versionAfter(minimum, "11.0")) {
      throw new Error(
        "Native payload does not declare a compatible macOS 11.0 deployment target.",
      );
    }
    floor = "macOS 11.0";
  } else if (process.platform === "win32") {
    const header = bytes.readUInt32LE(0x3c);
    const machine = process.arch === "arm64" ? 0xaa64 : 0x8664;
    if (
      bytes.toString("ascii", 0, 2) !== "MZ" ||
      bytes.toString("ascii", header, header + 4) !== "PE\0\0" ||
      bytes.readUInt16LE(header + 4) !== machine
    ) {
      throw new Error(
        "Native payload is not a PE image for this architecture.",
      );
    }
    floor = "Windows MSVC; Node 20 and 22 load proofs required";
  } else {
    throw new Error(
      "This foundation verifies Linux, macOS, and Windows artifacts only.",
    );
  }
  console.log(
    JSON.stringify({
      platform: process.platform,
      arch: process.arch,
      libc,
      nodeApi: 8,
      floor,
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    }),
  );
}
