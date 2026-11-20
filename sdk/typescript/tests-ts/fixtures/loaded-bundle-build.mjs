import { once } from "node:events";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { basename, dirname, join } from "node:path";
import { Worker } from "node:worker_threads";
import { buildBundledPlugin } from "../../scripts/build-plugin.mjs";

const [root, mode] = process.argv.slice(2);
const source = join(root, "source");
const destination = join(root, "_bundled_plugin");
const nativePath = `mcp/native/win32-${process.arch}/windows.node`;
const binding = join(destination, nativePath);
await fs.mkdir(dirname(binding), { recursive: true });
await fs.copyFile(
  new URL(`../../_bundled_plugin/${nativePath}`, import.meta.url),
  binding,
);

const reader = new Worker(
  `const { parentPort, workerData } = require("node:worker_threads");
   require(workerData);
   parentPort.on("message", () => {});
   parentPort.postMessage(process.version);`,
  { eval: true, execArgv: [], workerData: binding },
);
try {
  const [readerVersion] = await once(reader, "message");
  let lockCode;
  const remove = fs.rm;
  fs.rm = async (...args) => {
    try {
      return await remove(...args);
    } catch (error) {
      if (
        error.syscall === "unlink" &&
        basename(error.path) === "windows.node"
      ) {
        lockCode = error.code;
        if (mode === "released") await reader.terminate();
      }
      throw error;
    }
  };
  syncBuiltinESMExports();
  const files = await buildBundledPlugin({
    source,
    destination,
    contractPath: join(source, "contract.json"),
  });
  console.log(JSON.stringify({ files, lockCode, nativePath, readerVersion }));
} finally {
  await reader.terminate();
}
