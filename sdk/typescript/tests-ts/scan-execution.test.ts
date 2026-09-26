import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  link,
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { acquireScanExecution } from "../src/scan-execution.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

test("Node and Bun serialize one parent; release and owner death permit recovery", async () => {
  const root = await mkdtemp(join(tmpdir(), "scan-ownership-"));
  roots.push(root);
  const state = join(root, "state");
  const first = join(root, "first");
  const other = join(root, "other");
  await Promise.all([mkdir(first), mkdir(other)]);
  // Node 20 cannot import TypeScript; transpile the complete module unchanged.
  const modulePath = join(root, "scan-execution.mjs");
  await writeFile(
    modulePath,
    new Bun.Transpiler({ loader: "ts", target: "node" }).transformSync(
      await readFile(
        new URL("../src/scan-execution.ts", import.meta.url),
        "utf8",
      ),
    ),
  );
  const module = pathToFileURL(modulePath).href;
  const child = spawn(
    "node",
    [
      "--input-type=module",
      "--eval",
      `import {acquireScanExecution} from ${JSON.stringify(module)};
    import {createInterface} from "node:readline";
    const acquire = () => acquireScanExecution(${JSON.stringify(state)}, ${JSON.stringify(first)}, ${JSON.stringify(PLUGIN_ROOT)});
    let release = await acquire();
    console.log("owned");
    for await (const command of createInterface({input: process.stdin})) {
      if (command === "release") { release(); console.log("released"); }
      else if (command === "acquire") { release = await acquire(); console.log("owned"); }
      else if (command === "contend") {
        try { (await acquire())(); console.log("unexpectedly acquired"); }
        catch (error) {
          if (!error.message.includes("already running")) throw error;
          console.log("contended");
        }
      }
      else throw new Error("Unknown fixture command");
    }`,
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const lines = createInterface({ input: child.stdout! });
  const output = lines[Symbol.asyncIterator]();
  const exited = once(child, "exit");
  try {
    expect((await output.next()).value).toBe("owned");
    await expect(
      acquireScanExecution(state, first, PLUGIN_ROOT),
    ).rejects.toThrow("already running");
    const releaseOther = await acquireScanExecution(state, other, PLUGIN_ROOT);
    releaseOther();
    child.stdin!.write("release\n");
    expect((await output.next()).value).toBe("released");
    const release = await acquireScanExecution(state, first, PLUGIN_ROOT);
    try {
      await expect(
        acquireScanExecution(state, first, PLUGIN_ROOT),
      ).rejects.toThrow("already running");
      child.stdin!.write("contend\n");
      expect((await output.next()).value).toBe("contended");
    } finally {
      release();
    }
    child.stdin!.write("acquire\n");
    expect((await output.next()).value).toBe("owned");
    child.kill();
    await exited;
    (await acquireScanExecution(state, first, PLUGIN_ROOT))();
  } finally {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await exited;
    }
  }
});

test.each(["directory", "hard link"] as const)(
  "rejects a lock path replaced by a %s",
  async (kind) => {
    const root = await mkdtemp(join(tmpdir(), "scan-ownership-"));
    roots.push(root);
    const state = join(root, "state");
    const scan = join(root, "scan");
    await mkdir(scan);
    (await acquireScanExecution(state, scan, PLUGIN_ROOT))();
    const directory = join(state, "scan-execution");
    const entries = await readdir(directory);
    expect(entries).toHaveLength(1);
    const lock = join(directory, entries[0]!);
    await rm(lock);
    const target = join(root, "synthetic-file");
    await writeFile(target, "synthetic contents");
    if (kind === "directory") await mkdir(lock);
    else await link(target, lock);
    await expect(
      acquireScanExecution(state, scan, PLUGIN_ROOT),
    ).rejects.toThrow("ordinary file");
    expect(await readFile(target, "utf8")).toBe("synthetic contents");
  },
);
