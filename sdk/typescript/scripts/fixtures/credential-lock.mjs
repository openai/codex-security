import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";

const [runtimeUrl, directory, mode] = process.argv.slice(2);
const {
  acquireCodexSecurityCredentialHomeLock: acquire,
  prepareCodexSecurityCredentialHome: prepare,
} = await import(runtimeUrl);

if (mode === "hold") {
  const release = await acquire(directory);
  const block = once(process.stdin, "data");
  process.stdout.write("locked\n");
  await block;
  await new Promise((resolve) => process.stdout.write("blocked\n", resolve));
  // Stall the owner and any JavaScript heartbeat. Bound the wait so the holder
  // can exit if its parent dies.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120_000);
  await release();
} else if (mode === "legacy") {
  const start = once(process.stdin, "data");
  process.stdout.write("ready\n");
  await start;
  const lock = join(directory, ".codex-security-scan.lock");
  const ownerPath = join(lock, "owner.json");
  const original = await lstat(lock);
  assert.ok(Date.now() - original.mtimeMs >= 30_000);
  process.kill(JSON.parse(await readFile(ownerPath, "utf8")).pid, 0);

  // Released heartbeat-only clients check for a heartbeat before reclaiming an
  // aged directory. Observe it directly instead of racing process timers.
  const deadline = Date.now() + 8_000;
  let refreshed = original;
  while (refreshed.mtimeMs <= original.mtimeMs && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    refreshed = await lstat(lock);
  }
  if (refreshed.mtimeMs > original.mtimeMs) {
    process.stdout.write("legacy blocked\n");
  } else {
    const quarantine = `${lock}.stale-legacy-fixture`;
    await rename(lock, quarantine);
    await rm(quarantine, { recursive: true, force: true });
    await mkdir(lock, { mode: 0o700 });
    await writeFile(
      ownerPath,
      `${JSON.stringify({ pid: process.pid, token: "legacy-fixture" })}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    process.stdout.write("legacy acquired\n");
  }
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
    },
  );
  const exited = once(holder, "exit");
  const started = Date.now();
  let phase = "holder startup";
  let watchdogExpired = false;
  // The parent controls normal teardown. This is only an emergency bound, not
  // a holder lifetime that competes with slow process startup or ACL work.
  const watchdog = setTimeout(() => {
    watchdogExpired = true;
    holder.kill("SIGKILL");
  }, 90_000);
  let stderr = "";
  holder.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  const lines = createInterface({ input: holder.stdout });
  const output = lines[Symbol.asyncIterator]();
  const ownerExited = exited.then(([code, signal]) => {
    throw new Error(
      `Credential-lock holder exited during ${phase} after ${Date.now() - started}ms (code=${code}, signal=${signal}, watchdog=${watchdogExpired}): ${stderr}`,
    );
  });
  // Keep observing exits between awaits without an unhandled rejection.
  ownerExited.catch(() => {});
  const whileOwned = (operation) => Promise.race([operation, ownerExited]);
  async function expectOutput(expected) {
    const line = await whileOwned(output.next());
    assert.equal(line.value, expected);
  }

  let release;
  let legacy;
  let legacyExited;
  let legacyLines;
  const controller = new AbortController();
  try {
    await expectOutput("locked");
    const activeOwner = await readFile(ownerPath, "utf8");
    const stale = new Date(Date.now() - 60_000);
    phase = "legacy contender startup";
    legacy = spawn(
      process.execPath,
      [process.argv[1], runtimeUrl, home, "legacy"],
      { stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
    );
    legacyExited = once(legacy, "exit");
    let legacyStderr = "";
    legacy.stderr.setEncoding("utf8").on("data", (chunk) => {
      legacyStderr += chunk;
    });
    legacyLines = createInterface({ input: legacy.stdout });
    const legacyOutput = legacyLines[Symbol.asyncIterator]();
    assert.equal((await whileOwned(legacyOutput.next())).value, "ready");
    // Age the directory only once the contender has imported the runtime. A
    // heartbeat during slow startup must not invalidate its initial observation.
    await utimes(lock, stale, stale);
    phase = "legacy heartbeat observation";
    legacy.stdin.end("start\n");
    assert.equal(
      (await whileOwned(legacyOutput.next())).value,
      "legacy blocked",
      `Legacy contender failed: ${legacyStderr}`,
    );
    assert.deepEqual(await whileOwned(legacyExited), [0, null], legacyStderr);
    assert.equal(await readFile(ownerPath, "utf8"), activeOwner);

    phase = "paused owner exclusion";
    holder.stdin.end("block\n");
    await expectOutput("blocked");
    const owner = JSON.parse(await readFile(ownerPath, "utf8"));
    await utimes(lock, stale, stale);

    // Wait longer than the former five-second stale-heartbeat grace period.
    const timeout = setTimeout(() => controller.abort(), 6_000);
    try {
      await whileOwned(
        assert.rejects(
          async () => {
            release = await acquire(home, controller.signal);
          },
          { name: "AbortError" },
        ),
      );
    } finally {
      clearTimeout(timeout);
    }
    assert.deepEqual(JSON.parse(await readFile(ownerPath, "utf8")), owner);

    phase = "intentional owner termination";
    clearTimeout(watchdog);
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
      "Active owner protected from released clients; paused owner protected; crashed owner with reused PID recovered.",
    );
  } finally {
    clearTimeout(watchdog);
    controller.abort();
    legacy?.kill("SIGKILL");
    holder.kill("SIGKILL");
    await exited;
    await legacyExited;
    legacyLines?.close();
    lines.close();
    await release?.();
  }
}
