import assert from "node:assert/strict";
import { symlink } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { normalizeTarget } from "../../src/targets.js";

const root = process.argv[2]!;
const socket = join(root, "target.sock");
const alias = join(root, "alias");
const server = createServer();
try {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });
  await symlink(socket, alias);
  for (const path of [socket, alias]) {
    await assert.rejects(normalizeTarget(root, [path]), {
      name: "InvalidTargetError",
      message: `Path target is not a regular file or directory: ${path}`,
    });
  }
} finally {
  server.close();
}
