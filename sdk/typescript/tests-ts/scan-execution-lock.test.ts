import { join } from "node:path";
import { mkdir } from "node:fs/promises";
import { afterEach, expect, test } from "bun:test";
import { acquireScanExecutionLock } from "../src/scan-execution-lock.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("scan execution excludes a second process and recovers after the owner exits", async () => {
  const root = await temporaryDirectory();
  const state = join(root, "state");
  const scan = join(root, "scan");
  await mkdir(scan);
  const module = new URL("../src/scan-execution-lock.ts", import.meta.url).href;
  const child = Bun.spawn(
    [
      process.execPath,
      "--eval",
      `
    const { acquireScanExecutionLock } = await import(${JSON.stringify(module)});
    await acquireScanExecutionLock(${JSON.stringify(state)}, ${JSON.stringify(scan)});
    console.log("locked");
    process.stdin.resume();
  `,
    ],
    { stdin: "pipe", stdout: "pipe", stderr: "pipe" },
  );
  try {
    const reader = child.stdout.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe(
      "locked\n",
    );
    reader.releaseLock();
    await expect(acquireScanExecutionLock(state, scan)).rejects.toThrow(
      "already running",
    );
  } finally {
    child.kill();
    await child.exited;
  }
  const release = await acquireScanExecutionLock(state, scan);
  try {
    await expect(acquireScanExecutionLock(state, scan)).rejects.toThrow(
      "already running",
    );
  } finally {
    release();
  }
  (await acquireScanExecutionLock(state, scan))();
});
