import { getEventListeners } from "node:events";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { mock } from "bun:test";
import * as runtime from "../../src/runtime.js";

const signal = process.argv[2] === "SIGTERM" ? "SIGTERM" : "SIGINT";
const root = await mkdtemp(join(tmpdir(), "verify-fix-auth-signal-"));
const ambientHome = join(root, "ambient");
const repository = join(root, "repository");
const environment = {
  CODEX_HOME: ambientHome,
  CODEX_SECURITY_STATE_DIR: join(root, "state"),
};
await mkdir(ambientHome, { recursive: true, mode: 0o700 });
await mkdir(repository, { recursive: true });
await writeFile(join(ambientHome, "auth.json"), '{"auth_mode":"chatgpt"}\n', {
  mode: 0o600,
});
const credentialHome =
  await runtime.prepareCodexSecurityCredentialHome(environment);
const acquireCredentialLock =
  runtime.acquireCodexSecurityCredentialHomeLock.bind(runtime);
const release = await acquireCredentialLock(credentialHome);
const ownerPath = join(
  credentialHome,
  ".codex-security-scan.lock",
  "owner.json",
);
const originalOwner = await readFile(ownerPath, "utf8");
const controller = new AbortController();
const lockAttempted = Promise.withResolvers<void>();
let lockAttempts = 0;
mock.module("../../src/runtime.js", () => ({
  ...runtime,
  acquireCodexSecurityCredentialHomeLock: async (
    ...args: Parameters<typeof runtime.acquireCodexSecurityCredentialHomeLock>
  ) => {
    if (args[0] === credentialHome) {
      lockAttempts += 1;
      if ((await readFile(ownerPath, "utf8")) !== originalOwner) {
        throw new Error("Credential lock owner changed before contention");
      }
      const contending = acquireCredentialLock(...args);
      lockAttempted.resolve();
      return await contending;
    }
    return await acquireCredentialLock(...args);
  },
}));
const { runCodexSkillCommand } = await import("../../src/cli.js");
const sink = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});
const initialInterruptListeners = process.listenerCount("SIGINT");
const initialTerminateListeners = process.listenerCount("SIGTERM");
const pending = runCodexSkillCommand(
  [],
  {
    auth: "chatgpt",
    command: "verify-fix",
    directory: repository,
    stdout: sink,
    stderr: sink,
    signal: controller.signal,
    appServer: {
      directory: repository,
      prompt: "Synthetic verification prompt",
      threadSource: "security_validation",
      sandbox: "read-only",
    },
  },
  { command: process.execPath },
  environment,
);
const outcome = pending.catch((error: unknown) => error);
// The wrapped lock call proves contention; these timers only bound failures.
const bounded = async <T>(
  promise: Promise<T>,
  message: string,
  timeoutMilliseconds: number,
): Promise<T> => {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new Error(message)),
          timeoutMilliseconds,
        );
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
};
let released = false;

try {
  await bounded(
    lockAttempted.promise,
    "credential lock attempt timeout",
    10_000,
  );
  if (lockAttempts !== 1) {
    throw new Error(
      `Expected one credential lock attempt, received ${lockAttempts}`,
    );
  }
  process.stdout.write("LOCK_CONTENDER_ATTEMPTED\n");
  controller.abort(signal);
  const result = await bounded(
    outcome,
    "credential lock cancellation timeout",
    2_000,
  );
  if (result !== signal) throw new Error(String(result));
  if ((await readFile(ownerPath, "utf8")) !== originalOwner) {
    throw new Error("Credential lock owner changed during cancellation");
  }
  process.stdout.write("LOCK_OWNER_PRESERVED\n");
  if (getEventListeners(controller.signal, "abort").length !== 0) {
    throw new Error("Credential lock cancellation leaked an abort listener");
  }
  process.stdout.write("ABORT_LISTENERS_0\n");
  if (
    process.listenerCount("SIGINT") !== initialInterruptListeners ||
    process.listenerCount("SIGTERM") !== initialTerminateListeners
  ) {
    throw new Error("Credential lock cancellation leaked a process listener");
  }
  process.stdout.write("SIGNAL_LISTENERS_0_0\n");
  process.stdout.write(`PREPARATION_ABORT_${signal}\n`);
  await release();
  released = true;
  const releaseReacquired = await acquireCredentialLock(credentialHome);
  await releaseReacquired();
  process.stdout.write("LOCK_REACQUIRED\n");
} finally {
  controller.abort(signal);
  if (!released) await release();
  await outcome;
  await rm(root, { recursive: true, force: true });
}
