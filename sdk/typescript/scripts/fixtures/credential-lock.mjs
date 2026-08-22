import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";

const [runtimeUrl, directory, mode] = process.argv.slice(2);
const {
  acquireCodexSecurityCredentialHomeLock: acquire,
  prepareCodexSecurityCredentialHome: prepare,
} = await import(runtimeUrl);

if (mode === "hold") {
  const release = await acquire(directory);
  process.stdout.write("locked\n");
  await once(process.stdin, "data");
  await new Promise((resolve) => process.stdout.write("blocked\n", resolve));
  // Stall the actual owner, including any JavaScript heartbeat it might run.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  await release();
} else {
  const home = await prepare({ CODEX_SECURITY_STATE_DIR: directory });
  const lock = join(home, ".codex-security-scan.lock");
  const ownerPath = join(lock, "owner.json");
  const holder = spawn(
    process.execPath,
    [process.argv[1], runtimeUrl, home, "hold"],
    {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      timeout: 20_000,
      killSignal: "SIGKILL",
    },
  );
  const exited = once(holder, "exit");
  let stderr = "";
  holder.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  const lines = createInterface({ input: holder.stdout });
  const output = lines[Symbol.asyncIterator]();
  async function expectOutput(expected) {
    const line = await Promise.race([
      output.next(),
      exited.then(() => {
        throw new Error(`Credential-lock holder exited early: ${stderr}`);
      }),
    ]);
    assert.equal(line.value, expected);
  }

  let release;
  try {
    await expectOutput("locked");
    holder.stdin.write("block\n");
    await expectOutput("blocked");
    const owner = JSON.parse(await readFile(ownerPath, "utf8"));
    const stale = new Date(Date.now() - 60_000);
    await utimes(lock, stale, stale);

    const controller = new AbortController();
    // Wait longer than the former five-second stale-heartbeat grace period.
    const timeout = setTimeout(() => controller.abort(), 6_000);
    try {
      await assert.rejects(
        async () => {
          release = await acquire(home, controller.signal);
        },
        { name: "AbortError" },
      );
    } finally {
      clearTimeout(timeout);
    }
    assert.deepEqual(JSON.parse(await readFile(ownerPath, "utf8")), owner);

    holder.kill("SIGKILL");
    await exited;
    // Reuse a known live PID without relying on the OS to recycle one in a test.
    await writeFile(ownerPath, JSON.stringify({ ...owner, pid: process.pid }));
    const recovery = new AbortController();
    const recoveryTimeout = setTimeout(() => recovery.abort(), 5_000);
    try {
      release = await acquire(home, recovery.signal);
    } finally {
      clearTimeout(recoveryTimeout);
    }
    await release();
    release = undefined;
    console.log(
      "Paused owner protected; crashed owner with reused PID recovered.",
    );
  } finally {
    holder.kill("SIGKILL");
    await exited;
    lines.close();
    await release?.();
  }
}
