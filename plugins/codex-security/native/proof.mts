import assert from "node:assert/strict";
import { userInfo } from "node:os";
import { randomUUID } from "node:crypto";
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

console.log(
  JSON.stringify(
    {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      nodeApi: 8,
      accounts: accountProof(),
    },
    null,
    2,
  ),
);
