import { readFileSync } from "node:fs";
import {
  deepScanPermissionProfileFallbackError,
  preflightDeepScanWorkerPermissionProfile,
  type DeepScanPermissionProfilePreflightOptions,
} from "./src/deep-scan/permission-profile-preflight";
import { resolveSecurityMdCommand } from "./src/helpers/resolve-security-md";
import { decodePosixBytes } from "./src/helpers/posix-path";
import { windowsBinding } from "./src/native";

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
} else if (
  command === "dependency-permission-profile" ||
  command === "dependency-permission-warning"
) {
  void dependencyPermissionCommand(command).catch((error: unknown) => {
    console.error(
      error instanceof Error && !(error instanceof SyntaxError)
        ? error.message.replaceAll("Deep Scan", "Dependency assessment")
        : "Could not read dependency assessment permission settings.",
    );
    process.exitCode = 1;
  });
} else {
  console.error(
    "Usage: launch_codex_security_mcp[.cmd] --helper resolve-security-md [options]",
  );
  process.exitCode = 2;
}

async function dependencyPermissionCommand(command: string): Promise<void> {
  const input = JSON.parse(readFileSync(0, "utf8")) as Omit<
    DeepScanPermissionProfilePreflightOptions,
    "signal" | "env"
  > & { message?: unknown };
  if (command === "dependency-permission-warning") {
    const error = deepScanPermissionProfileFallbackError(
      input.message,
      input.profileId,
    );
    if (error) throw error;
    return;
  }
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  process.once("SIGTERM", abort);
  process.once("SIGINT", abort);
  try {
    await preflightDeepScanWorkerPermissionProfile({
      codexPath: input.codexPath,
      cwd: input.cwd,
      profileId: input.profileId,
      configOverrides: input.configOverrides,
      expectedProfile: input.expectedProfile,
      signal: controller.signal,
    });
  } finally {
    process.off("SIGTERM", abort);
    process.off("SIGINT", abort);
  }
}
