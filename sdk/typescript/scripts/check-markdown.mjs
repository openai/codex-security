import { execFileSync } from "node:child_process";
import { lstatSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const files = execFileSync("git", ["ls-files", "-z", "--", "*.md"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: Infinity,
})
  .split("\0")
  .filter(
    (path) =>
      path && lstatSync(join(root, path), { throwIfNoEntry: false })?.isFile(),
  );

if (files.length > 0) {
  process.chdir(root);
  process.argv = [
    process.execPath,
    fileURLToPath(import.meta.resolve("prettier/bin/prettier.cjs")),
    "--check",
    "--",
    ...files,
  ];
  await import("prettier/bin/prettier.cjs");
}
