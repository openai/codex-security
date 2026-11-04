"use strict";

// src/runtime-cleanup.ts
var import_promises = require("node:fs/promises");
var import_node_path = require("node:path");
var MARKER = ".codex-security-action-owned";
var ROOT_PREFIX = "codex-security-runtime-";
async function cleanupRuntime(root2, tempRoot2) {
  if (!(0, import_node_path.isAbsolute)(root2) || !(0, import_node_path.isAbsolute)(tempRoot2)) throw new Error("Cleanup requires absolute owned paths.");
  const base = await (0, import_promises.realpath)(tempRoot2);
  const info = await (0, import_promises.lstat)(root2).catch((error) => {
    if (error.code === "ENOENT") return void 0;
    throw error;
  });
  if (!info) return;
  const canonical = await (0, import_promises.realpath)(root2);
  const child = (0, import_node_path.relative)(base, canonical);
  if (!info.isDirectory() || info.isSymbolicLink() || (0, import_node_path.dirname)(canonical) !== base || !child.startsWith(ROOT_PREFIX) || child.includes(import_node_path.sep) || (0, import_node_path.resolve)(root2) !== canonical) throw new Error("Refusing to clean a path outside the owned runtime root.");
  const marker = (0, import_node_path.join)(canonical, MARKER);
  if (!(await (0, import_promises.lstat)(marker)).isFile() || await (0, import_promises.readFile)(marker, "utf8") !== "codex-security-action-v1\n") throw new Error("Refusing to clean a directory without the ownership marker.");
  await (0, import_promises.rm)(canonical, { recursive: true, force: false });
}

// src/post.ts
var root = process.env["STATE_runtime-root"];
var tempRoot = process.env["STATE_runtime-temp-root"];
if (root && tempRoot) {
  void cleanupRuntime(root, tempRoot).catch(() => {
    process.exitCode = 1;
    process.stdout.write("::error::Codex Security temporary runtime cleanup failed.\n");
  });
}
