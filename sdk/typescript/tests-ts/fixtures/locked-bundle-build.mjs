import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { basename, join } from "node:path";
import timers from "node:timers/promises";
import { buildBundledPlugin } from "../../scripts/build-plugin.mjs";

const [root, mode] = process.argv.slice(2);
const manifest = ".codex-plugin/plugin.json";
const source = join(root, "source");
const destination = join(root, "_bundled_plugin");
const rename = fs.rename;
const delay = timers.setTimeout;
const failed = new Set();
let waitingToRestore = false;

// Lock a real descendant during the first rename of each directory. Persistent
// cases also hold a file during every subsequent publication or restore attempt.
fs.rename = async (from, to) => {
  const step = basename(from);
  const locked =
    !failed.has(step) ||
    (step === "bundle" && mode !== "released") ||
    (step === "previous" && mode === "unrestorable");
  const handle = locked ? await fs.open(join(from, manifest), "r") : undefined;
  try {
    await rename(from, to);
    if (step === "previous") waitingToRestore = false;
  } catch (error) {
    failed.add(step);
    waitingToRestore = step === "previous";
    throw error;
  } finally {
    await handle?.close();
  }
};
timers.setTimeout = async (...args) => {
  if (!waitingToRestore) {
    assert.equal(
      await fs.readFile(join(destination, manifest), "utf8"),
      "previous",
    );
  }
  return delay(...args);
};
syncBuiltinESMExports();

let code;
try {
  await buildBundledPlugin({
    source,
    destination,
    contractPath: join(source, "contract.json"),
  });
} catch (error) {
  if (
    mode === "released" ||
    !["EPERM", "EACCES", "EBUSY"].includes(error.code)
  ) {
    throw error;
  }
  code = error.code;
}
console.log(JSON.stringify({ code, failed: [...failed] }));
