import { execFileSync, spawnSync } from "node:child_process";
import { lstatSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], {
  cwd: root,
  encoding: "utf8",
})
  .split("\0")
  .filter(
    (path) =>
      path && lstatSync(join(root, path), { throwIfNoEntry: false })?.isFile(),
  );

if (files.length > 0) {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(import.meta.resolve("prettier/bin/prettier.cjs")),
      "--check",
      "--",
      ...files,
    ],
    { cwd: root, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}
