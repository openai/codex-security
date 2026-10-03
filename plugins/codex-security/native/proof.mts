import assert from "node:assert/strict";
import { constants, tmpdir, userInfo } from "node:os";
import { randomUUID } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  opendirSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { loadBinding } from "./binding.mjs";

const native = loadBinding();
const errno = constants.errno;
const rawPath = (parent: string, name: Buffer) =>
  Buffer.concat([Buffer.from(parent + "/"), name]);
// APFS requires valid UTF-8 names; Linux also exercises undecodable bytes.
const fixtureName = (prefix: string, byte: number) =>
  process.platform === "darwin"
    ? Buffer.from(`${prefix}-\u00e9`)
    : Buffer.from([prefix.charCodeAt(0), byte]);
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

function directoryProof(root: string) {
  const directory = rawPath(root, fixtureName("e", 0xf9));
  mkdirSync(directory);
  const names = [
    fixtureName("f", 0xf8),
    Buffer.from("nested"),
    Buffer.from("directory-link"),
    fixtureName("l", 0xf7),
  ];
  const child = (name: Buffer) =>
    Buffer.concat([directory, Buffer.from("/"), name]);
  writeFileSync(child(names[0]!), "file");
  mkdirSync(child(names[1]!));
  symlinkSync(names[1]!, child(names[2]!));
  symlinkSync(Buffer.from("missing"), child(names[3]!));
  const expected = new Map(
    names.map((name, index) => [
      name.toString("hex"),
      {
        name,
        isDirectory: index === 1,
        isSymbolicLink: index >= 2,
        errno: 0,
      },
    ]),
  );
  const typed = checked(native.directoryEntries(directory, true)).value;
  assert.equal(typed.length, names.length);
  for (const entry of typed)
    assert.deepEqual(entry, expected.get(entry.name.toString("hex")));
  assert.deepEqual(native.directoryEntries(child(names[1]!), true), {
    errno: 0,
    value: [],
  });

  // Node's unknown-type fallback cannot handle raw names. Use ASCII here to
  // compare filesystem order without that fallback changing the path bytes.
  const orderDirectory = join(root, "directory-order");
  mkdirSync(orderDirectory);
  for (const name of ["z-last", "a-first", "middle"])
    writeFileSync(join(orderDirectory, name), "file");
  const reference = opendirSync(orderDirectory);
  const order: Buffer[] = [];
  try {
    for (let entry; (entry = reference.readSync()) !== null;)
      order.push(Buffer.from(entry.name));
  } finally {
    reference.closeSync();
  }
  assert.deepEqual(
    checked(
      native.directoryEntries(Buffer.from(orderDirectory), true),
    ).value.map((entry) => entry.name),
    order,
  );
  const namesOnly = typed.map(({ name }) => ({
    name,
    isDirectory: false,
    isSymbolicLink: false,
    errno: 0,
  }));
  assert.deepEqual(
    checked(native.directoryEntries(directory, false)).value,
    namesOnly,
  );
  let nonsearchableTypes: { cached: number; denied: number } | null = null;
  chmodSync(directory, 0o400);
  try {
    assert.deepEqual(
      checked(native.directoryEntries(directory, false)).value,
      namesOnly,
    );
    if (process.geteuid?.() !== 0) {
      assert.throws(() => lstatSync(child(names[1]!)), { code: "EACCES" });
      const withoutSearch = checked(
        native.directoryEntries(directory, true),
      ).value;
      assert.equal(withoutSearch.length, typed.length);
      for (const [index, entry] of withoutSearch.entries())
        assert.deepEqual(
          entry,
          entry.errno === errno.EACCES
            ? {
                name: typed[index]!.name,
                isDirectory: false,
                isSymbolicLink: false,
                errno: errno.EACCES,
              }
            : typed[index],
        );
      nonsearchableTypes = {
        cached: withoutSearch.filter((entry) => entry.errno === 0).length,
        denied: withoutSearch.filter((entry) => entry.errno === errno.EACCES)
          .length,
      };
      chmodSync(directory, 0);
      assert.deepEqual(native.directoryEntries(directory, false), {
        errno: errno.EACCES,
        value: [],
      });
    }
  } finally {
    chmodSync(directory, 0o700);
  }
  const descriptors =
    process.platform === "linux" ? "/proc/self/fd" : "/dev/fd";
  const descriptorCount = readdirSync(descriptors).length;
  for (const withTypes of [false, true]) {
    assert.deepEqual(native.directoryEntries(child(names[0]!), withTypes), {
      errno: errno.ENOTDIR,
      value: [],
    });
    assert.deepEqual(native.directoryEntries(child(names[3]!), withTypes), {
      errno: errno.ENOENT,
      value: [],
    });
    assert.throws(() => native.directoryEntries(Buffer.from([0]), withTypes));
    for (let index = 0; index < 32; index++)
      checked(native.directoryEntries(directory, withTypes));
  }
  assert.equal(readdirSync(descriptors).length, descriptorCount);
  return {
    rawNamesAndPath: true,
    filesystemOrder: true,
    directoryAndSymlinkTypes: true,
    namesOnly: true,
    nonsearchableTypes,
    enumerationErrors: true,
    descriptorsClosed: true,
  };
}

const root = mkdtempSync(join(tmpdir(), "codex-native-proof-"));
try {
  console.log(
    JSON.stringify(
      {
        node: process.version,
        platform: process.platform,
        architecture: process.arch,
        nodeApi: 8,
        accounts: accountProof(),
        directories: directoryProof(root),
      },
      null,
      2,
    ),
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
