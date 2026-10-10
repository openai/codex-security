import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { win32 } from "node:path";
import { fileURLToPath } from "node:url";

// Windows cannot execute the POSIX fixture's shebang. Preserve the selected
// native executable and its options, inserting only the deterministic protocol
// script, as in the worker launch tests. Every other child runs unchanged.
const executable = win32.toNamespacedPath(process.env.PACKAGE_DEEP_EXECUTABLE);
const script = fileURLToPath(
  new URL("package-deep-codex.mjs", import.meta.url),
);
const spawn = childProcess.spawn;
childProcess.spawn = (command, args, options) =>
  spawn(
    command,
    win32.toNamespacedPath(command) === executable ? [script, ...args] : args,
    options,
  );
syncBuiltinESMExports();
