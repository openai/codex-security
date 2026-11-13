import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { copyFile, lstat, rename, rm } from "node:fs/promises";
import { join } from "node:path";

// The OS pins the child's working directory at launch. Relative writes continue
// to address that directory after an archive, even when its old name is reused.
const [, , expected, stage] = process.argv;
const root = await lstat(".", { bigint: true });
if (`${root.dev}:${root.ino}` !== expected)
  throw new Error(
    "The scan output directory changed before rollout publication.",
  );

const directory = join("artifacts", "rollout-sessions");
for (const path of ["artifacts", directory]) {
  if (!(await lstat(path)).isDirectory())
    throw new Error("The rollout output must remain a directory.");
}
let input = "";
for await (const chunk of process.stdin) input += chunk;
const segments = JSON.parse(input);
const created = [];
const temporary = join(directory, `.index-${randomUUID()}.tmp`);
try {
  for (const name of [...segments, "index.json"]) {
    const destination =
      name === "index.json" ? temporary : join(directory, name);
    await copyFile(join(stage, name), destination, constants.COPYFILE_EXCL);
    created.push(destination);
  }
  await rename(temporary, join(directory, "index.json"));
  created.length = 0;
} finally {
  await Promise.all(created.map((path) => rm(path, { force: true })));
}
