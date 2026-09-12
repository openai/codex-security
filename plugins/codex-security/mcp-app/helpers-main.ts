import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
export { parseCanonicalScanDraft } from "./src/artifact-scan-draft.js";
export { resumeSelectedDeepScan } from "./src/deep-scan/finalization.js";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";

// Importing the bundled helper from the SDK does not invoke its CLI adapter.
const entryPath = import.meta.url.startsWith("file:") ? fileURLToPath(import.meta.url) : import.meta.url;
if (process.argv[1] && resolve(process.argv[1]) === entryPath) runHelper();

function runHelper(): void {
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
  } else {
    console.error(
      "Usage: launch_codex_security_mcp[.cmd] --helper resolve-security-md [options]",
    );
    process.exitCode = 2;
  }
}
