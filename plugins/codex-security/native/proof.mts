import assert from "node:assert/strict";
import { closeSync, mkdtempSync, openSync, rmSync } from "node:fs";
import { constants, tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadBinding } from "./binding.mjs";

const native = loadBinding();
class NativeError extends Error {
  constructor(readonly errno: number) {
    super(`Native operation failed: errno ${errno}`);
  }
}
function checked<T extends { errno: number }>(result: T): T {
  if (result.errno !== 0) throw new NativeError(result.errno);
  return result;
}

function accountProof() {
  let currentHomeMatches: boolean | null = null;
  try {
    const current = userInfo({ encoding: "buffer" });
    assert.deepEqual(
      checked(native.userHome(current.username)).value,
      current.homedir,
    );
    currentHomeMatches = true;
  } catch (error) {
    // A container can run a numeric UID with no account database entry.
    const system = error as { code?: string; info?: { code?: string } };
    assert.equal(system.code, "ERR_SYSTEM_ERROR");
    assert.equal(system.info?.code, "ENOENT");
  }
  const other = checked(native.userHome(Buffer.from("root"))).value;
  assert(other !== null && other[0] === 0x2f);
  assert.equal(
    checked(native.userHome(Buffer.from(`codex-${randomUUID().slice(0, 8)}`)))
      .value,
    null,
  );
  assert.throws(() => native.userHome(Buffer.from([0])));
  return {
    currentHomeMatches,
    namedHomeWithoutGit: true,
    missingAccount: true,
  };
}

function lockProof() {
  const root = mkdtempSync(join(tmpdir(), "codex-security-lock-"));
  const held = new Set<number>();
  try {
    const path = join(root, "owner.lock");
    const first = openSync(path, "w+", 0o600);
    held.add(first);
    const second = openSync(path, "r+");
    held.add(second);
    assert.equal(checked(native.fileLock(first, false, true)).value, 0);
    const blocked = native.fileLock(second, false, true);
    assert.equal(blocked.value, -1);
    assert(
      [constants.errno.EAGAIN, constants.errno.EWOULDBLOCK].includes(
        blocked.errno,
      ),
    );
    assert.equal(checked(native.fileLock(first, true, false)).value, 0);
    assert.equal(checked(native.fileLock(second, false, true)).value, 0);
    closeSync(second);
    held.delete(second);
    assert.equal(checked(native.fileLock(first, false, true)).value, 0);
    for (const fd of [second, -1])
      assert.deepEqual(native.fileLock(fd, false, true), {
        value: -1,
        errno: constants.errno.EBADF,
      });
    return {
      nonblockingContention: true,
      unlockAndCloseReleaseOwnership: true,
      numericInvalidAndClosedErrors: true,
    };
  } finally {
    for (const fd of held) closeSync(fd);
    rmSync(root, { recursive: true, force: true });
  }
}

function environmentProof(): Record<string, boolean> {
  const script = [
    "value=$(printf '\\377\\376\\012.'); value=${value%.}",
    'CODEX_SECURITY_ENV_PROOF_RAW="$value"; export CODEX_SECURITY_ENV_PROOF_RAW',
    "CODEX_SECURITY_ENV_PROOF_EMPTY=''; export CODEX_SECURITY_ENV_PROOF_EMPTY",
    "unset CODEX_SECURITY_ENV_PROOF_ABSENT",
    'exec "$1" "$2" environment-child',
  ].join("\n");
  const child = spawnSync(
    "/bin/sh",
    [
      "-c",
      script,
      "environment-proof",
      process.execPath,
      fileURLToPath(import.meta.url),
    ],
    { encoding: "utf8" },
  );
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, "");
  return JSON.parse(child.stdout) as Record<string, boolean>;
}

if (process.argv[2] === "environment-child") {
  assert.deepEqual(
    native.unixEnvironment(Buffer.from("CODEX_SECURITY_ENV_PROOF_RAW")),
    Buffer.from([255, 254, 10]),
  );
  assert.deepEqual(
    native.unixEnvironment(Buffer.from("CODEX_SECURITY_ENV_PROOF_EMPTY")),
    Buffer.alloc(0),
  );
  assert.equal(
    native.unixEnvironment(Buffer.from("CODEX_SECURITY_ENV_PROOF_ABSENT")),
    null,
  );
  assert.throws(() => native.unixEnvironment(Buffer.from([0])));
  console.log(
    JSON.stringify({
      rawBytes: true,
      emptyAndUnset: true,
      rejectsNulNames: true,
    }),
  );
} else
  console.log(
    JSON.stringify(
      {
        node: process.version,
        platform: process.platform,
        architecture: process.arch,
        nodeApi: 8,
        accounts: accountProof(),
        locks: lockProof(),
        environment: environmentProof(),
      },
      null,
      2,
    ),
  );
