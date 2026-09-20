import { closeSync, readFileSync } from "node:fs";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import { normalizeCandidatesCommand } from "./src/helpers/normalize-candidates";

let commandLine = process.argv.slice(2);
if (process.platform === "win32") {
  const original = windowsBinding().windowsArguments();
  commandLine = original
    .slice(original.length - commandLine.length)
    .map((argument) => argument.toString("utf16le"));
}
let posixHome = process.env.HOME;
if (commandLine[0] === "--helper") {
  if (process.platform === "win32") {
    commandLine = commandLine.slice(1);
  } else {
    const encoded = readFileSync(3, "ascii");
    closeSync(3);
    const [homeSet, home, ...args] = decodePosixBytes(
      Buffer.from(encoded.trim(), "hex"),
    )
      .split("\0")
      .slice(0, -1);
    posixHome = homeSet ? home : undefined;
    commandLine = args;
  }
}
const [command, ...args] = commandLine;
if (command === "resolve-security-md") {
  process.exitCode = resolveSecurityMdCommand(args, posixHome);
} else if (command === "normalize-candidates") {
  process.exitCode = normalizeCandidatesCommand(args, posixHome);
} else {
  console.error(
    "Usage: launch_codex_security_mcp[.cmd] --helper <resolve-security-md | normalize-candidates> [options]",
  );
  process.exitCode = 2;
}
