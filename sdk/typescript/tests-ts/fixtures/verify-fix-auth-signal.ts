import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runCodexSkillCommand } from "../../src/cli.js";
import {
  acquireCodexSecurityCredentialHomeLock,
  prepareCodexSecurityCredentialHome,
} from "../../src/runtime.js";

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
const credentialHome = await prepareCodexSecurityCredentialHome(environment);
const release = await acquireCodexSecurityCredentialHomeLock(credentialHome);
const controller = new AbortController();
const sink = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});
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

try {
  await new Promise((resolve) => setImmediate(resolve));
  controller.abort(signal);
  let timeout: NodeJS.Timeout | undefined;
  const result = await Promise.race([
    outcome,
    new Promise((resolve) => {
      timeout = setTimeout(() => resolve("credential lock timeout"), 1_000);
    }),
  ]);
  if (timeout !== undefined) clearTimeout(timeout);
  if (result !== signal) throw new Error(String(result));
  process.stdout.write(`PREPARATION_ABORT_${signal}\n`);
} finally {
  controller.abort(signal);
  await release();
  await outcome;
  await rm(root, { recursive: true, force: true });
}
