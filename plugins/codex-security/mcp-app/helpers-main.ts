import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";
import { resolve } from "node:path";
import { collectFeedbackCommand } from "./src/helpers/collect-feedback.js";

let commandLine = process.argv.slice(2);
if (process.platform === "win32") {
  const original = windowsBinding().windowsArguments();
  commandLine = original
    .slice(original.length - commandLine.length)
    .map((argument) => argument.toString("utf16le"));
}
let posixHome = process.env.HOME;
const helperIndex = commandLine.indexOf("--helper");
if (helperIndex !== -1) {
  commandLine = commandLine.slice(helperIndex);
  if (process.platform === "win32") {
    commandLine = commandLine.slice(1);
  } else {
    const [homeSet, home, ...args] = decodePosixBytes(
      Buffer.from(commandLine[1] ?? "", "hex"),
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
} else if (command === "collect-feedback") {
  collectFeedbackCommand(resolve(__dirname, "..")).then(
    (code) => { process.exitCode = code; },
    (error: unknown) => {
      console.error("Codex Security feedback collector failed to start:", error);
      process.exitCode = 1;
    }
  );
} else {
  console.error(
    "Usage: launch_codex_security_mcp[.cmd] --helper <resolve-security-md|collect-feedback> [options]",
  );
  process.exitCode = 2;
}
