import { execFileSync } from "node:child_process";
import { closeSync, mkdirSync, openSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";
import { isMain } from "../../sdk/typescript/scripts/is-main.mjs";

export function extractApplication(repository, sha, destination) {
  const git = (args) =>
    execFileSync("git", args, { cwd: repository, maxBuffer: Infinity });
  // Read committed blobs directly: export-ignore and export-subst must not alter scan input.
  const entries = new TextDecoder("utf-8", { fatal: true })
    .decode(git(["ls-tree", "-rz", `${sha}:examples/invoice-desk/app`]))
    .split("\0")
    .filter(Boolean)
    .map((entry) => {
      const tab = entry.indexOf("\t");
      const [mode, type, oid] = entry.slice(0, tab).split(" ");
      const path = entry.slice(tab + 1);
      const output = resolve(destination, path);
      if (!["100644", "100755"].includes(mode) || type !== "blob") {
        throw new Error(
          "The application source must contain only regular files.",
        );
      }
      if (!output.startsWith(resolve(destination) + sep)) {
        throw new Error("The application source contains an unsafe path.");
      }
      return { oid, output };
    });
  if (entries.length === 0) throw new Error("The application source is empty.");
  mkdirSync(destination);
  for (const { oid, output } of entries) {
    mkdirSync(dirname(output), { recursive: true });
    const descriptor = openSync(output, "w");
    try {
      execFileSync("git", ["cat-file", "blob", oid], {
        cwd: repository,
        stdio: ["ignore", descriptor, "pipe"],
      });
    } finally {
      closeSync(descriptor);
    }
  }
  return entries.length;
}

if (isMain(import.meta.url)) {
  const count = extractApplication(
    process.env.SOURCE_REPOSITORY,
    process.env.SOURCE_SHA,
    process.env.SCAN_SOURCE,
  );
  console.log(`Extracted ${count} committed application files.`);
}
