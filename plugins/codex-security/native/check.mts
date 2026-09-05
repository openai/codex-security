import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { binaryPath } from "./binding.mjs";

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
    if (bytes.includes(Buffer.from(marker))) {
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
    if (
      required.length === 0 ||
      required.some((version) => versionAfter(version, "2.28"))
    ) {
      throw new Error(
        "Native payload requires glibc newer than 2.28, or has no inspectable glibc requirements.",
      );
    }
    floor = "glibc 2.28";
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
  } else {
    throw new Error("This foundation verifies Linux and macOS artifacts only.");
  }
  console.log(
    JSON.stringify({
      platform: process.platform,
      arch: process.arch,
      nodeApi: 8,
      floor,
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    }),
  );
}
