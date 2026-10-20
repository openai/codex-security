import assert from "node:assert/strict";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { join } from "node:path";

const fs = createRequire(import.meta.url)("node:fs");
const [root, scenario] = process.argv.slice(2);
const archive = join(root, "plugin.zip");
const destination = join(root, "extracted");
const controller = new AbortController();
const operationError = new Error("Synthetic ZIP operation failure.");
const closeError = new Error("Synthetic ZIP close failure.");
const abortError = new Error("Synthetic ZIP cancellation.");
const original = {
  open: fs.open,
  read: fs.read,
  close: fs.close,
  createWriteStream: fs.createWriteStream,
  promiseOpen: fs.promises.open,
};
const descriptors = new Set();
let replaced = false;
let injected = false;

if (scenario === "initial-fifo") {
  fs.renameSync(join(root, "replacement.fifo"), archive);
} else if (scenario === "constructor-error") {
  const bytes = fs.readFileSync(archive);
  bytes.writeUInt16LE(1, bytes.length - 22 + 4);
  fs.writeFileSync(archive, bytes);
}

function afterRead(buffer, bytesRead) {
  if (!injected && (scenario === "read-error" || scenario === "close-error")) {
    injected = true;
    throw operationError;
  }
  if (
    !replaced &&
    scenario.startsWith("replace-") &&
    bytesRead >= 4 &&
    buffer.readUInt32LE(0) === 0x02014b50
  ) {
    // Move the open archive aside so replacement also works on Windows.
    fs.renameSync(archive, join(root, "checked.zip"));
    fs.renameSync(
      join(
        root,
        scenario === "replace-fifo" ? "replacement.fifo" : "replacement.zip",
      ),
      archive,
    );
    replaced = true;
  }
}

// Instrument both APIs so the regression also exercises the previous opener.
fs.promises.open = async function (path, ...args) {
  const handle = await original.promiseOpen.call(this, path, ...args);
  if (path !== archive) return handle;
  const descriptor = handle.fd;
  descriptors.add(descriptor);
  const read = handle.read.bind(handle);
  const close = handle.close.bind(handle);
  handle.read = async (...readArgs) => {
    const result = await read(...readArgs);
    afterRead(result.buffer, result.bytesRead);
    return result;
  };
  handle.close = async () => {
    await close();
    descriptors.delete(descriptor);
    if (scenario === "close-error") throw closeError;
  };
  return handle;
};
fs.open = function (path, flags, ...args) {
  const callback = args.pop();
  return original.open.call(this, path, flags, ...args, (error, fd) => {
    if (!error && path === archive) descriptors.add(fd);
    callback(error, fd);
  });
};
fs.read = function (fd, buffer, ...args) {
  const callback = args.pop();
  return original.read.call(
    this,
    fd,
    buffer,
    ...args,
    (error, bytesRead, output) => {
      if (!error && descriptors.has(fd)) {
        try {
          afterRead(output, bytesRead);
        } catch (failure) {
          callback(failure);
          return;
        }
      }
      callback(error, bytesRead, output);
    },
  );
};
for (const symbol of Object.getOwnPropertySymbols(original.read)) {
  Object.defineProperty(
    fs.read,
    symbol,
    Object.getOwnPropertyDescriptor(original.read, symbol),
  );
}
fs.close = function (fd, callback) {
  const owned = descriptors.has(fd);
  return original.close.call(this, fd, (error) => {
    if (!error) descriptors.delete(fd);
    callback(owned && scenario === "close-error" ? closeError : error);
  });
};
fs.createWriteStream = function (...args) {
  const stream = original.createWriteStream.apply(this, args);
  if (scenario === "abort" || scenario === "write-error") {
    stream.once("pipe", () => {
      injected = true;
      queueMicrotask(() => {
        if (scenario === "abort") controller.abort(abortError);
        else stream.destroy(operationError);
      });
    });
  }
  return stream;
};
syncBuiltinESMExports();

const { extractPluginZip } = await import("../../src/runtime.ts");
let result;
let failure;
try {
  result = await extractPluginZip(archive, destination, controller.signal);
} catch (error) {
  failure = error;
}
if (scenario.startsWith("replace-")) {
  if (failure !== undefined) throw failure;
  assert.equal(replaced, true);
  const manifest = JSON.parse(
    fs.readFileSync(join(result, ".codex-plugin/plugin.json"), "utf8"),
  );
  assert.equal(manifest.version, "1.2.3");
} else {
  assert.ok(failure);
  assert.equal(fs.existsSync(destination), false);
  if (scenario === "abort") {
    assert.equal(failure, abortError);
  } else {
    assert.equal(failure.name, "PluginBootstrapError");
    if (scenario === "initial-fifo") {
      assert.match(failure.cause.message, /missing end of central directory/);
    } else if (scenario === "constructor-error") {
      assert.match(
        failure.cause.message,
        /multi-disk zip files are not supported/,
      );
    } else {
      assert.equal(injected, true);
      assert.equal(
        failure.cause,
        scenario === "close-error" ? closeError : operationError,
      );
    }
  }
}
assert.equal(
  fs
    .readdirSync(root)
    .some((name) => name.startsWith(".codex-security-plugin-")),
  false,
);
process.once("beforeExit", () => {
  assert.equal(descriptors.size, 0);
  process.stdout.write(JSON.stringify({ scenario, passed: true }) + "\n");
});
