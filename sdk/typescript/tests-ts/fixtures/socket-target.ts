import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readlink, rename, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { basename, join } from "node:path";
import { normalizeTarget } from "../../src/targets.js";

const root = process.argv[2]!;
async function expectSpecialFile(path: string) {
  await assert.rejects(normalizeTarget(root, [path]), {
    name: "InvalidTargetError",
    message: `Path target is not a regular file or directory: ${path}`,
  });
}

const socket = join(root, "target.sock");
const alias = join(root, "alias");
const server = createServer();
try {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen("target.sock", resolve);
  });
  await symlink(socket, alias);
  await expectSpecialFile(socket);
  await expectSpecialFile(alias);
} finally {
  server.close();
}

if (process.platform === "linux") {
  // A descriptor label or a decoded byte name can also name an ordinary file.
  const label = await readlink("/proc/self/fd/0");
  if (basename(label) === label) await writeFile(label, "sibling");
  await symlink("/proc/self/fd/0", "input-link");
  await expectSpecialFile("input-link");

  const fifo = Buffer.concat([Buffer.from("doc-"), Buffer.from([0xff])]);
  execFileSync("mkfifo", ["queue"]);
  await rename("queue", fifo);
  await symlink(fifo, "queue-link");
  const ordinary = "doc-\uFFFD";
  await writeFile(ordinary, "sibling");
  await expectSpecialFile("queue-link");
  await rename(fifo, "old-queue");
  await writeFile(fifo, "different file");
  await assert.rejects(normalizeTarget(root, ["queue-link"]), {
    name: "InvalidTargetError",
    message: "Path target cannot be represented as UTF-8: queue-link",
  });
  await symlink(ordinary, "ordinary-link");
  assert.deepEqual(
    (await normalizeTarget(root, [ordinary, "ordinary-link"])).paths,
    [ordinary],
  );
}
