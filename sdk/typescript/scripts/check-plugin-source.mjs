import { execFile } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultPackageRoot = resolve(scriptDirectory, "..");

export async function assertGeneratedPluginUntracked({
  packageRoot = defaultPackageRoot,
} = {}) {
  const { stdout } = await execFileAsync(
    "git",
    ["-C", packageRoot, "ls-files", "--cached", "-z", "--", "_bundled_plugin"],
    { encoding: "utf8" },
  );
  const tracked = stdout.split("\0").filter(Boolean).sort();
  if (tracked.length > 0) {
    throw new Error(
      `Generated plugin payload must not be tracked: ${tracked.join(", ")}`,
    );
  }
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  pathToFileURL(resolve(invokedPath)).href === import.meta.url
) {
  assertGeneratedPluginUntracked()
    .then(() => {
      console.log("Verified _bundled_plugin contains no tracked files.");
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
}
