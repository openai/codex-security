import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { copyFile, lstat, mkdir, rename, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  createWindowsOutputDirectory,
  requirePrivateDirectory,
  requireTrustedOutputAncestor,
} from "./runtime.js";

// The OS pins the child's working directory at launch. Relative writes continue
// to address that directory after an archive, even when its old name is reused.
const [, , expected, stage] = process.argv;
const root = await lstat(".", { bigint: true });
if (`${root.dev}:${root.ino}` !== expected)
  throw new Error(
    "The scan output directory changed before rollout publication.",
  );

// Enter each verified directory before touching its children. An archive or
// substituted link cannot redirect relative mkdir, copies, or rollback.
for (const name of ["artifacts", "rollout-sessions"]) {
  if (process.platform === "win32")
    await createWindowsOutputDirectory(resolve(name), true);
  else {
    requireTrustedOutputAncestor(await lstat("."), ".");
    try {
      await mkdir(name, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
  }
  const selected = await lstat(name, { bigint: true });
  if (!selected.isDirectory() || selected.ino === 0n)
    throw new Error("The rollout output must remain a directory.");
  process.chdir(name);
  const opened = await lstat(".", { bigint: true });
  if (opened.dev !== selected.dev || opened.ino !== selected.ino)
    throw new Error("The rollout directory changed before publication.");
}
await requirePrivateDirectory(
  await lstat("."),
  process.platform === "win32" ? process.cwd() : ".",
  "rollout artifact directory",
);
let input = "";
for await (const chunk of process.stdin) input += chunk;
const segments = JSON.parse(input);
const created = [];
const temporary = `.index-${randomUUID()}.tmp`;
try {
  for (const name of [...segments, "index.json"]) {
    const destination = name === "index.json" ? temporary : name;
    await copyFile(join(stage, name), destination, constants.COPYFILE_EXCL);
    created.push(destination);
  }
  await rename(temporary, "index.json");
  created.length = 0;
} finally {
  await Promise.all(created.map((path) => rm(path, { force: true })));
}
