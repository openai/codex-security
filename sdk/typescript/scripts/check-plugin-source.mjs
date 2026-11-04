import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";
import { isMain } from "./is-main.mjs";

const execFileAsync = promisify(execFile);
const defaultPackageRoot = resolve(import.meta.dirname, "..");

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

if (isMain(import.meta.url)) {
  assertGeneratedPluginUntracked()
    .then(() => {
      console.log("Verified _bundled_plugin contains no tracked files.");
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
}
