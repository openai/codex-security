import { execFile, spawnSync } from "node:child_process";
import * as childProcess from "node:child_process";
import { EventEmitter, once } from "node:events";
import { existsSync } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as fsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PassThrough } from "node:stream";
import { setImmediate as nextTurn } from "node:timers/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import {
  acquireCodexSecurityCredentialHomeLock,
  codexSecurityCredentialAllowsAmbientImport,
  codexSecurityCredentialHome,
  codexSecurityHasStoredFileCredentials,
  inspectWindowsCredentialAcl,
  inspectWindowsCredentialAclSnapshot,
  prepareCodexSecurityCredentialHome,
  requirePrivateCredentialHome,
  requirePrivateCredentialFile,
  requireSecureCredentialHome,
  requireSecureOutputAncestry,
  setCodexSecurityCredentialLogout,
  streamWindowsCredentialAclDescriptors,
} from "../src/runtime.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const temporaryDirectories: string[] = [];
const testPosix = process.platform === "win32" ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(
  prefix = "codex-security-runtime-",
): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryDirectories.push(path);
  return path;
}

function windowsCredentialAclOutput(descriptors: readonly string[]): string {
  return `${descriptors.join("\n")}\nCODEX_SECURITY_ACL_COMPLETE:${descriptors.length}\n`;
}

async function plantCredentialHomeLock(
  home: string,
  pid: number,
  modifiedAt?: Date,
): Promise<string> {
  const lock = join(home, ".codex-security-scan.lock");
  await mkdir(lock, { mode: 0o700 });
  await writeFile(
    join(lock, "owner.json"),
    `${JSON.stringify({ pid, token: "planted-owner" })}\n`,
    { mode: 0o600 },
  );
  if (modifiedAt !== undefined) await utimes(lock, modifiedAt, modifiedAt);
  return lock;
}

async function acquireCredentialHomeLockWithTimeout(
  home: string,
): Promise<() => Promise<void>> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new DOMException("timed out", "AbortError")),
    10_000,
  );
  timeout.unref();
  try {
    return await acquireCodexSecurityCredentialHomeLock(
      home,
      controller.signal,
    );
  } finally {
    clearTimeout(timeout);
  }
}

describe("runtime directories and plugin Python boundary", () => {
  test("prepares one private, reusable managed-credential home", async () => {
    const root = await temporaryDirectory();
    const environment = { CODEX_SECURITY_STATE_DIR: join(root, "state") };
    const expectedHome = join(root, "state", "codex-home");

    expect(codexSecurityCredentialHome(environment)).toBe(expectedHome);
    expect(await prepareCodexSecurityCredentialHome(environment)).toBe(
      expectedHome,
    );
    await writeFile(join(expectedHome, "existing-state"), "preserved\n");
    expect(await prepareCodexSecurityCredentialHome(environment)).toBe(
      expectedHome,
    );
    expect(await readFile(join(expectedHome, "existing-state"), "utf8")).toBe(
      "preserved\n",
    );
    if (process.platform !== "win32") {
      expect((await stat(expectedHome)).mode & 0o777).toBe(0o700);
    }
  });

  testPosix("rejects unsafe persistent credential homes", async () => {
    const root = await temporaryDirectory();
    const stateDirectory = join(root, "state");
    const environment = { CODEX_SECURITY_STATE_DIR: stateDirectory };
    const credentialHome =
      await prepareCodexSecurityCredentialHome(environment);
    await chmod(credentialHome, 0o755);
    await expect(
      prepareCodexSecurityCredentialHome(environment),
    ).rejects.toThrow("must not be accessible to other users");
    await chmod(credentialHome, 0o700);
    await rm(credentialHome, { recursive: true, force: true });

    const redirectedHome = join(root, "redirected-home");
    await mkdir(redirectedHome, { mode: 0o700 });
    await symlink(redirectedHome, credentialHome);
    await expect(
      prepareCodexSecurityCredentialHome(environment),
    ).rejects.toThrow("credential home is not a directory");
  });

  testPosix(
    "rejects credential homes under a non-sticky shared parent directory",
    async () => {
      const root = await temporaryDirectory();
      const shared = join(root, "shared");
      await mkdir(shared, { mode: 0o777 });
      await chmod(shared, 0o777);
      expect((await lstat(shared)).mode & 0o1000).toBe(0);
      const environment = { CODEX_SECURITY_STATE_DIR: join(shared, "state") };

      await expect(
        prepareCodexSecurityCredentialHome(environment),
      ).rejects.toThrow("sticky bit");
      await expect(
        requireSecureOutputAncestry(join(shared, "state")),
      ).rejects.toThrow("sticky bit");
    },
  );

  testPosix(
    "accepts credential homes under a sticky shared parent directory",
    async () => {
      const root = await temporaryDirectory();
      // Some filesystems (notably user dirs on macOS APFS) ignore sticky on
      // chmod; fall back to the process temp root when it is already sticky.
      let stickyParent = join(root, "shared");
      await mkdir(stickyParent, { mode: 0o1777 });
      await chmod(stickyParent, 0o1777);
      if (((await lstat(stickyParent)).mode & 0o1000) === 0) {
        stickyParent = await realpath(tmpdir());
        if (((await lstat(stickyParent)).mode & 0o1000) === 0) {
          return;
        }
      }
      const stateDirectory = join(
        stickyParent,
        `codex-security-sticky-${process.pid}-${Date.now()}`,
      );
      temporaryDirectories.push(stateDirectory);
      await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      });
      await expect(requireSecureCredentialHome(home)).resolves.toBeDefined();
      await expect(requireSecureOutputAncestry(home)).resolves.toBeUndefined();
    },
  );

  testPosix(
    "rejects a credential home that is no longer private to the current user",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      await chmod(home, 0o755);
      await expect(requireSecureCredentialHome(home)).rejects.toThrow(
        "must not be accessible to other users",
      );
      await expect(
        acquireCodexSecurityCredentialHomeLock(home),
      ).rejects.toThrow("must not be accessible to other users");
    },
  );

  testPosix(
    "pins credential-home identity for the duration of a lock session",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const release = await acquireCodexSecurityCredentialHomeLock(home);
      const stolen = join(root, "stolen-home");
      await rename(home, stolen);
      await mkdir(home, { recursive: true, mode: 0o700 });
      await chmod(home, 0o700);
      await expect(release()).rejects.toThrow("credential home was replaced");
      const releaseRecovered =
        await acquireCredentialHomeLockWithTimeout(stolen);
      await releaseRecovered();
    },
  );

  testPosix(
    "rejects stale credential-home metadata after canonical target replacement",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const stale = await lstat(home, { bigint: true });
      await rename(home, join(root, "original-home"));
      await mkdir(home, { mode: 0o700 });

      await expect(
        requireSecureCredentialHome(home, { metadata: stale }),
      ).rejects.toThrow("credential home was replaced");
    },
  );

  testPosix(
    "rejects world-writable or symlink stored authentication files",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const authPath = join(home, "auth.json");
      await writeFile(authPath, '{"token":"test"}\n', { mode: 0o600 });
      expect(await codexSecurityHasStoredFileCredentials(home)).toBe(true);

      await chmod(authPath, 0o644);
      await expect(codexSecurityHasStoredFileCredentials(home)).rejects.toThrow(
        "must not be accessible to other users",
      );
      await rm(authPath);

      const target = join(home, "auth-target.json");
      await writeFile(target, '{"token":"test"}\n', { mode: 0o600 });
      await symlink(target, authPath);
      await expect(codexSecurityHasStoredFileCredentials(home)).rejects.toThrow(
        "not a regular file",
      );

      expect(() =>
        requirePrivateCredentialFile(
          { mode: 0o100644, uid: 1000 },
          authPath,
          1000,
        ),
      ).toThrow("must not be accessible to other users");
    },
  );

  test("identifies a credential home that already exists as a regular file", async () => {
    const root = await temporaryDirectory();
    const stateDirectory = join(root, "state");
    await mkdir(stateDirectory);
    await writeFile(join(stateDirectory, "codex-home"), "not a directory\n");

    await expect(
      prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      }),
    ).rejects.toThrow("credential home is not a directory");
  });

  test("serializes and releases persistent credential-home locks", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const releaseFirst = await acquireCodexSecurityCredentialHomeLock(home);
    const database = join(home, ".codex-security-scan.sqlite3");
    const original = await stat(database);
    let secondAcquired = false;
    const second = acquireCodexSecurityCredentialHomeLock(home).then(
      (release) => {
        secondAcquired = true;
        return release;
      },
    );

    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(secondAcquired).toBe(false);
    await releaseFirst();
    const releaseSecond = await second;
    expect(secondAcquired).toBe(true);
    await releaseSecond();
    expect(existsSync(join(home, ".codex-security-scan.lock"))).toBe(false);
    // Removing this file would let waiters lock different inodes.
    expect((await stat(database)).ino).toBe(original.ino);
  });

  testPosix(
    "initializes the credential-lock database without a descriptor or permission race",
    async () => {
      if (
        runTestInSubprocess(
          import.meta.path,
          "initializes the credential-lock database without a descriptor or permission race",
        )
      ) {
        return;
      }
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const database = join(home, ".codex-security-scan.sqlite3");
      const originalLstat = fsPromises.lstat;
      const originalWriteFile = fsPromises.writeFile;
      let separateDatabaseCreates = 0;
      let observedMode: number | undefined;
      let paused = false;
      let reportPaused!: () => void;
      let resumeCreator!: () => void;
      const creatorPaused = new Promise<void>((resolve) => {
        reportPaused = resolve;
      });
      const creatorResumed = new Promise<void>((resolve) => {
        resumeCreator = resolve;
      });
      mock.module("node:fs/promises", () => ({
        ...fsPromises,
        lstat: async (...args: Parameters<typeof originalLstat>) => {
          const metadata = await originalLstat(...args);
          if (args[0] === database && !paused) {
            paused = true;
            observedMode = Number(metadata.mode) & 0o777;
            reportPaused();
            await creatorResumed;
          }
          return metadata;
        },
        writeFile: async (...args: Parameters<typeof originalWriteFile>) => {
          if (args[0] === database) separateDatabaseCreates += 1;
          return await originalWriteFile(...args);
        },
      }));

      let first: Promise<() => Promise<void>> | undefined;
      let releaseSecond: (() => Promise<void>) | undefined;
      try {
        first = acquireCredentialHomeLockWithTimeout(home);
        await Promise.race([
          creatorPaused,
          first.then(() => {
            throw new Error("Credential-lock initialization did not pause");
          }),
        ]);

        // Pause the creator at its first post-open inspection. A contender must
        // see the final mode and acquire normally instead of rejecting it.
        releaseSecond = await acquireCredentialHomeLockWithTimeout(home);
        await releaseSecond();
        releaseSecond = undefined;
        resumeCreator();
        const releaseFirst = await first;
        await releaseFirst();
        first = undefined;
      } finally {
        resumeCreator();
        await releaseSecond?.();
        const pendingRelease = await first?.catch(() => undefined);
        await pendingRelease?.();
        mock.module("node:fs/promises", () => ({
          ...fsPromises,
          lstat: originalLstat,
          writeFile: originalWriteFile,
        }));
      }

      // Closing another descriptor for this inode can release SQLite's
      // process-owned POSIX lock, so SQLite must create its own guard file.
      expect(separateDatabaseCreates).toBe(0);
      expect(observedMode).toBe(0o600);
      expect((await stat(database)).mode & 0o777).toBe(0o600);
    },
  );

  test("keeps a fresh live credential-home lock and cancels the waiter", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const release = await acquireCodexSecurityCredentialHomeLock(home);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 100);

    try {
      const waiting = acquireCodexSecurityCredentialHomeLock(
        home,
        controller.signal,
      );
      await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
      expect(existsSync(join(home, ".codex-security-scan.lock"))).toBe(true);
    } finally {
      clearTimeout(timeout);
      await release();
    }
    expect(existsSync(join(home, ".codex-security-scan.lock"))).toBe(false);
    const releaseAgain = await acquireCredentialHomeLockWithTimeout(home);
    await releaseAgain();
  });

  test("releases the native credential lock when legacy-lock inspection fails", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const lock = join(home, ".codex-security-scan.lock");
    await writeFile(lock, "not a directory", { mode: 0o600 });
    await expect(acquireCodexSecurityCredentialHomeLock(home)).rejects.toThrow(
      "not a directory",
    );
    await rm(lock);
    const release = await acquireCredentialHomeLockWithTimeout(home);
    await release();
  });

  test("protects active and stalled credential-lock owners and recovers after a crash with a reused PID", async () => {
    const root = await temporaryDirectory();
    await promisify(execFile)(
      process.execPath,
      [
        fileURLToPath(
          new URL("../scripts/fixtures/credential-lock.mjs", import.meta.url),
        ),
        new URL("../src/runtime.ts", import.meta.url).href,
        join(root, "state"),
      ],
      { timeout: 25_000, windowsHide: true },
    );
  });

  test("does not rewrite Windows credential ACLs while polling a held lock", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "credential-home");
    await mkdir(home, { mode: 0o700 });
    const validations: string[] = [];
    const securityOptions = {
      platform: "win32" as const,
      secureWindowsHome: async (path: string) => {
        const lock = join(path, ".codex-security-scan.lock");
        expect(existsSync(lock) && !existsSync(join(lock, "owner.json"))).toBe(
          false,
        );
        validations.push(path);
      },
    };
    const release = await acquireCodexSecurityCredentialHomeLock(
      home,
      undefined,
      securityOptions,
    );
    const controller = new AbortController();
    const waiting = acquireCodexSecurityCredentialHomeLock(
      home,
      controller.signal,
      securityOptions,
    );

    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(validations).toHaveLength(3);
      controller.abort(new DOMException("canceled", "AbortError"));
      await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    } finally {
      await release();
    }
  });

  test("recovers credential-home locks left by exited processes", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const exited = spawnSync(process.execPath, ["--eval", ""], {
      encoding: "utf8",
      windowsHide: true,
    });
    expect(exited.status).toBe(0);
    expect(typeof exited.pid).toBe("number");
    const lock = join(home, ".codex-security-scan.lock");
    await mkdir(lock, { mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      `${JSON.stringify({ pid: exited.pid, token: "exited-process" })}\n`,
      { mode: 0o600 },
    );

    const release = await acquireCodexSecurityCredentialHomeLock(home);
    expect(existsSync(lock)).toBe(true);
    await release();
    expect(existsSync(lock)).toBe(false);
  });

  test("preserves a legacy live owner beyond the stale-heartbeat grace period", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const stale = new Date(Date.now() - 10 * 60_000);
    const lock = await plantCredentialHomeLock(home, process.pid, stale);
    const owner = await readFile(join(lock, "owner.json"), "utf8");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6_000);
    let release: (() => Promise<void>) | undefined;

    try {
      await expect(
        (async () => {
          release = await acquireCodexSecurityCredentialHomeLock(
            home,
            controller.signal,
          );
        })(),
      ).rejects.toMatchObject({ name: "AbortError" });
      expect(await readFile(join(lock, "owner.json"), "utf8")).toBe(owner);
    } finally {
      clearTimeout(timeout);
      if (release !== undefined) await release();
    }
  });

  test("preserves a legacy owner when PID inspection is denied", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const stale = new Date(Date.now() - 10 * 60_000);
    const lock = await plantCredentialHomeLock(home, process.pid, stale);
    const controller = new AbortController();
    const inspectOwner = spyOn(process, "kill").mockImplementation((() => {
      controller.abort();
      const error = new Error(
        "operation not permitted",
      ) as NodeJS.ErrnoException;
      error.code = "EPERM";
      throw error;
    }) as typeof process.kill);

    try {
      await expect(
        acquireCodexSecurityCredentialHomeLock(home, controller.signal),
      ).rejects.toMatchObject({ name: "AbortError" });
      expect(inspectOwner).toHaveBeenCalledWith(process.pid, 0);
      expect(existsSync(lock)).toBe(true);
    } finally {
      inspectOwner.mockRestore();
    }
  });

  testPosix(
    "rejects linked and repairs non-private credential-lock database files",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const database = join(home, ".codex-security-scan.sqlite3");
      const target = join(home, "target");
      await writeFile(target, "unchanged", { mode: 0o600 });
      for (const createLink of [symlink, link]) {
        await createLink(target, database);
        await expect(
          acquireCodexSecurityCredentialHomeLock(home),
        ).rejects.toThrow("regular file");
        expect(await readFile(target, "utf8")).toBe("unchanged");
        await rm(database);
      }
      // Recover the state left if a creator exits after SQLite opens the guard
      // but before it tightens the default mode.
      await writeFile(database, "", { mode: 0o600 });
      await chmod(database, 0o644);
      const release = await acquireCodexSecurityCredentialHomeLock(home);
      await release();
      expect((await stat(database)).mode & 0o777).toBe(0o600);
    },
  );

  test("recovers credential-home locks whose owner names no process", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });
    const lock = join(home, ".codex-security-scan.lock");
    for (const pid of [0, -1, 0.5, 2 ** 31, 2 ** 53]) {
      await mkdir(lock, { mode: 0o700 });
      await writeFile(
        join(lock, "owner.json"),
        `${JSON.stringify({ pid, token: "unidentifiable-owner" })}\n`,
        { mode: 0o600 },
      );
      const aged = new Date(Date.now() - 10 * 60_000);
      await utimes(lock, aged, aged);

      const release = await acquireCredentialHomeLockWithTimeout(home);
      expect(existsSync(lock)).toBe(true);
      await release();
      expect(existsSync(lock)).toBe(false);
    }
  });

  test("prevents ambient credential imports after an explicit logout", async () => {
    const root = await temporaryDirectory();
    const home = await prepareCodexSecurityCredentialHome({
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    });

    expect(await codexSecurityCredentialAllowsAmbientImport(home)).toBe(true);
    await setCodexSecurityCredentialLogout(home, true);
    expect(await codexSecurityCredentialAllowsAmbientImport(home)).toBe(false);
    if (process.platform !== "win32") {
      expect(
        (await stat(join(home, ".codex-security-logged-out"))).mode & 0o777,
      ).toBe(0o600);
    }
    await setCodexSecurityCredentialLogout(home, false);
    expect(await codexSecurityCredentialAllowsAmbientImport(home)).toBe(true);
  });

  test("requires a real private-ACL operation for Windows credential homes", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const metadata = await lstat(home);
    const secured: string[] = [];

    await requirePrivateCredentialHome(metadata, home, {
      platform: "win32",
      secureWindowsHome: async (path) => {
        secured.push(path);
      },
    });

    expect(secured).toEqual([home]);
    await expect(
      requirePrivateCredentialHome(metadata, home, {
        platform: "win32",
        secureWindowsHome: async () => {
          throw new Error("ACL could not be secured");
        },
      }),
    ).rejects.toThrow("private Windows credential home");
  });

  test.each(["created", "removed"] as const)(
    "inspects Windows credentials once while private descendants are %s",
    async (change) => {
      const root = await temporaryDirectory();
      const home = join(root, "home");
      const inspectionCount = join(root, "inspection-count");
      const temporary = join(home, ".auth-temporary");
      await mkdir(home);
      await writeFile(join(home, "auth.json"), "credential\n");
      if (change === "removed") await writeFile(temporary, "temporary\n");
      const sid = "S-1-5-21-111-222-333-1001";
      const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
      const file = `O:${sid}G:SYD:P(A;;FA;;;${sid})`;
      const ancestors: string[] = [];
      for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
        ancestors.push(directory);
        if (ancestor === dirname(ancestor)) break;
      }
      const script = [
        'const fs = require("node:fs")',
        `fs.appendFileSync(${JSON.stringify(inspectionCount)}, "inspection\\n")`,
        change === "created"
          ? `fs.writeFileSync(${JSON.stringify(temporary)}, "temporary")`
          : `fs.rmSync(${JSON.stringify(temporary)})`,
        `const descriptors = [...${JSON.stringify([...ancestors, directory])}, ...fs.readdirSync(${JSON.stringify(home)}).map(() => ${JSON.stringify(file)})]`,
        'process.stdout.write(descriptors.join("\\n") + "\\nCODEX_SECURITY_ACL_COMPLETE:" + descriptors.length + "\\n")',
      ].join("; ");

      const snapshot = await inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: ["--eval", script],
      });

      expect(snapshot.home).toMatchObject({
        owner: sid,
        protected: true,
        grantsCurrentUserAccess: true,
        untrustedPrincipals: [],
      });
      expect(snapshot.descendantsArePrivate).toBe(true);
      expect(await readFile(inspectionCount, "utf8")).toBe("inspection\n");
    },
  );

  test("inspects Windows credential ancestry and the home even without descendants", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const sid = "S-1-5-21-111-222-333-1001";
    const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
    const ancestors: string[] = [];
    for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
      ancestors.push(directory);
      if (ancestor === dirname(ancestor)) break;
    }
    const descriptors = [...ancestors, directory];

    await expect(
      inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: [
          "--eval",
          `process.stdout.write(${JSON.stringify(windowsCredentialAclOutput(descriptors))})`,
        ],
      }),
    ).resolves.toMatchObject({
      home: { owner: sid, protected: true },
      descendantsArePrivate: true,
    });
  });

  test
    .skipIf(process.platform !== "win32")
    .each([
      "transient missing descendant",
      "persistent missing descendant",
      "access denied",
      "unexpected error",
      "missing home",
    ] as const)("replays Windows credential ACL %s", async (kind) => {
    if (
      runTestInSubprocess(
        import.meta.path,
        `replays Windows credential ACL ${kind}`,
      )
    ) {
      return;
    }
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    await requireSecureCredentialHome(home);
    const descendant = join(home, ".auth-replay.tmp");
    await writeFile(descendant, "synthetic credential\n", { mode: 0o600 });
    const missing = kind.includes("missing");
    const exception = missing
      ? "System.IO.FileNotFoundException"
      : kind === "access denied"
        ? "System.UnauthorizedAccessException"
        : "System.InvalidOperationException";
    const errorId = missing
      ? "System.IO.FileNotFoundException,Microsoft.PowerShell.Commands.GetAclCommand"
      : kind === "access denied"
        ? "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetAclCommand"
        : "SyntheticCredentialAclFailure";
    const category =
      kind === "access denied"
        ? "PermissionDenied"
        : missing
          ? "NotSpecified"
          : "ObjectNotFound";
    const failurePath = kind === "missing home" ? home : descendant;
    // Replay the native error without relying on racing a filesystem deletion.
    const injection = `if ($path -eq '${failurePath.replaceAll("'", "''")}') { throw [System.Management.Automation.ErrorRecord]::new([${exception}]::new('synthetic credential ACL error'), '${errorId}', [System.Management.Automation.ErrorCategory]::${category}, $path) };`;
    const marker = "function Write-CredentialAcl($path) {";
    const originalSpawn = childProcess.spawn;
    let attempts = 0;
    mock.module("node:child_process", () => ({
      ...childProcess,
      spawn: (...spawnArgs: Parameters<typeof childProcess.spawn>) => {
        const [command, args, options] = spawnArgs;
        if (
          options?.env?.["CODEX_SECURITY_CREDENTIAL_ACL_PATH"] !== home ||
          !Array.isArray(args)
        ) {
          return originalSpawn(...spawnArgs);
        }
        const scriptIndex = args.indexOf("-Command") + 1;
        const script = args[scriptIndex];
        if (typeof script !== "string" || !script.includes(marker)) {
          return originalSpawn(...spawnArgs);
        }
        attempts += 1;
        if (kind === "transient missing descendant" && attempts > 1) {
          return originalSpawn(...spawnArgs);
        }
        expect(script.split(marker)).toHaveLength(2);
        const replayArgs = [...args];
        replayArgs[scriptIndex] = script.replace(
          marker,
          `${marker} ${injection}`,
        );
        return originalSpawn(command, replayArgs, options);
      },
    }));
    try {
      if (kind === "transient missing descendant") {
        await requireSecureCredentialHome(home);
        expect(attempts).toBe(2);
      } else {
        await expect(requireSecureCredentialHome(home)).rejects.toThrow(
          kind === "persistent missing descendant"
            ? "Windows credential descendants could not be verified"
            : "synthetic credential ACL error",
        );
        expect(attempts).toBe(kind === "persistent missing descendant" ? 3 : 1);
      }
    } finally {
      mock.module("node:child_process", () => ({
        ...childProcess,
        spawn: originalSpawn,
      }));
    }
  });

  test("retries interrupted Windows credential ACL enumeration", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const inspectionCount = join(root, "inspection-count");
    const temporary = join(home, ".auth-temporary");
    await mkdir(home);
    await writeFile(join(home, "auth.json"), "credential\n");
    await writeFile(temporary, "temporary credential\n");
    const sid = "S-1-5-21-111-222-333-1001";
    const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
    const file = `O:${sid}G:SYD:P(A;;FA;;;${sid})`;
    const descriptors: string[] = [];
    for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
      descriptors.push(directory);
      if (ancestor === dirname(ancestor)) break;
    }
    descriptors.push(directory, file);
    const script = [
      'const fs = require("node:fs")',
      `fs.appendFileSync(${JSON.stringify(inspectionCount)}, "inspection\\n")`,
      `const interrupted = fs.existsSync(${JSON.stringify(temporary)})`,
      `if (interrupted) fs.unlinkSync(${JSON.stringify(temporary)})`,
      `process.stdout.write(interrupted ? ${JSON.stringify(`${descriptors.join("\n")}\n`)} : ${JSON.stringify(windowsCredentialAclOutput(descriptors))})`,
      "process.exitCode = interrupted ? 2 : 0",
    ].join("; ");

    await expect(
      inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: ["--eval", script],
      }),
    ).resolves.toMatchObject({
      home: { owner: sid, protected: true },
      descendantsArePrivate: true,
    });
    expect(await readFile(inspectionCount, "utf8")).toBe(
      "inspection\ninspection\n",
    );
  });

  test.each([
    [2, 3, "Windows credential descendants could not be verified"],
    [1, 1, "Windows credential ACL inspection failed with exit code 1"],
  ] as const)(
    "rejects Windows ACL subprocess exit %i after %i attempts",
    async (exitCode, attempts, message) => {
      const root = await temporaryDirectory();
      const home = join(root, "home");
      const inspectionCount = join(root, "inspection-count");
      await mkdir(home);
      const script = [
        `require("node:fs").appendFileSync(${JSON.stringify(inspectionCount)}, "inspection\\n")`,
        `process.exitCode = ${exitCode}`,
      ].join("; ");

      await expect(
        inspectWindowsCredentialAclSnapshot(home, "S-1-5-21-111-222-333-1001", {
          command: process.execPath,
          args: ["--eval", script],
        }),
      ).rejects.toThrow(message);
      expect(await readFile(inspectionCount, "utf8")).toBe(
        "inspection\n".repeat(attempts),
      );
    },
  );

  test.each(["safe", "unsafe"] as const)(
    "drains Windows credential callbacks before retrying %s snapshots",
    async (kind) => {
      if (
        runTestInSubprocess(
          import.meta.path,
          `drains Windows credential callbacks before retrying ${kind} snapshots`,
        )
      ) {
        return;
      }
      const home = join(await temporaryDirectory(), "home");
      const sid = "S-1-5-21-111-222-333-1001";
      const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
      const descriptors: string[] = [];
      for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
        descriptors.push(directory);
        if (ancestor === dirname(ancestor)) break;
      }
      descriptors.push(directory);
      const firstDescriptors = [...descriptors];
      if (kind === "unsafe") {
        firstDescriptors[0] = `${directory}(A;OICI;FA;;;WD)`;
      }

      const makeChild = () =>
        Object.assign(new EventEmitter(), {
          stdout: new PassThrough(),
          stderr: new PassThrough(),
          exitCode: null as number | null,
          signalCode: null,
          kill: () => true,
        });
      const first = makeChild();
      let enterCallback!: () => void;
      const callbackEntered = new Promise<void>((resolve) => {
        enterCallback = resolve;
      });
      let releaseCallback!: () => void;
      const callbackReleased = new Promise<void>((resolve) => {
        releaseCallback = resolve;
      });
      let paused = false;
      let callbackFinished = false;
      let attempts = 0;
      const originalSpawn = childProcess.spawn;
      mock.module("node:child_process", () => ({
        ...childProcess,
        spawn: () => {
          attempts += 1;
          if (attempts === 1) return first;
          expect(attempts).toBe(2);
          expect(callbackFinished).toBe(true);
          const child = makeChild();
          queueMicrotask(() => {
            child.stdout.end(windowsCredentialAclOutput(descriptors));
            child.stderr.end();
            child.exitCode = 0;
            child.emit("close", 0, null);
          });
          return child;
        },
      }));
      let settled = false;
      const outcome = inspectWindowsCredentialAclSnapshot(home, sid, {
        command: "synthetic-credential-inspector",
        args: [],
        resolveDescriptorAliases: async () => {
          if (paused) return;
          paused = true;
          enterCallback();
          await callbackReleased;
          callbackFinished = true;
        },
      }).then(
        (value) => {
          settled = true;
          return { value, error: undefined };
        },
        (error: unknown) => {
          settled = true;
          return { value: undefined, error };
        },
      );
      try {
        first.stdout.write(`${firstDescriptors.join("\n")}\n`);
        await Promise.race([
          callbackEntered,
          outcome.then(() => {
            throw new Error(
              "Credential inspection settled before its callback",
            );
          }),
        ]);
        const ended = once(first.stdout, "end");
        first.stdout.end();
        first.stderr.end();
        await ended;
        first.exitCode = 2;
        first.emit("close", 2, null);
        await nextTurn();
        expect(settled).toBe(false);
        expect(attempts).toBe(1);
        releaseCallback();
        const result = await outcome;
        if (kind === "unsafe") {
          expect(result.error).toMatchObject({
            message:
              "Windows credential-home ancestor allows another identity to replace the directory",
          });
          expect(attempts).toBe(1);
        } else {
          expect(result.error).toBeUndefined();
          expect(result.value).toMatchObject({
            home: { owner: sid, protected: true },
            descendantsArePrivate: true,
          });
          expect(attempts).toBe(2);
        }
      } finally {
        releaseCallback();
        first.stdout.destroy();
        first.stderr.destroy();
        mock.module("node:child_process", () => ({
          ...childProcess,
          spawn: originalSpawn,
        }));
      }
    },
  );

  test("rejects unsafe Windows credential ancestry during combined ACL inspection", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const sid = "S-1-5-21-111-222-333-1001";
    const unsafe = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})(A;OICI;FA;;;WD)`;

    await expect(
      inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: [
          "--eval",
          `process.stdout.write(${JSON.stringify(`${unsafe}\n`)})`,
        ],
      }),
    ).rejects.toThrow(
      "Windows credential-home ancestor allows another identity to replace the directory",
    );
  });

  test("rejects incomplete combined Windows credential ACL inspections", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const sid = "S-1-5-21-111-222-333-1001";
    const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;

    await expect(
      inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: [
          "--eval",
          `process.stdout.write(${JSON.stringify(`${directory}\n`)})`,
        ],
      }),
    ).rejects.toThrow("Windows credential-home ancestry could not be verified");
  });

  test("rejects incomplete or failed Windows credential descendant streams", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const sid = "S-1-5-21-111-222-333-1001";
    const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
    const file = `O:${sid}G:SYD:P(A;;FA;;;${sid})`;
    const descriptors: string[] = [];
    for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
      descriptors.push(directory);
      if (ancestor === dirname(ancestor)) break;
    }
    descriptors.push(directory, file);
    const complete = windowsCredentialAclOutput(descriptors);
    for (const { output, exitCode, error } of [
      {
        output: `${descriptors.join("\n")}\n`,
        exitCode: 0,
        error: "Windows credential descendants could not be verified",
      },
      {
        output: `${descriptors.slice(0, -1).join("\n")}\nCODEX_SECURITY_ACL_COMPLETE:${descriptors.length}\n`,
        exitCode: 0,
        error: "Windows credential descendants could not be verified",
      },
      {
        output: `${complete}${file}\n`,
        exitCode: 0,
        error: "Windows credential ACL inspection continued after completion",
      },
      {
        output: complete,
        exitCode: 1,
        error: "Windows credential ACL inspection failed",
      },
    ]) {
      await expect(
        inspectWindowsCredentialAclSnapshot(home, sid, {
          command: process.execPath,
          args: [
            "--eval",
            `process.stdout.write(${JSON.stringify(output)}); process.exitCode = ${exitCode}`,
          ],
        }),
      ).rejects.toThrow(error);
    }
  });

  test("detects unsafe descendants during combined Windows credential ACL inspections", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    await writeFile(join(home, "auth.json"), "credential\n");
    const sid = "S-1-5-21-111-222-333-1001";
    const directory = `O:${sid}G:SYD:P(A;OICI;FA;;;${sid})`;
    const unsafeFile = `O:${sid}G:SYD:P(A;;FA;;;${sid})(A;;FR;;;WD)`;
    const ancestors: string[] = [];
    for (let ancestor = dirname(home); ; ancestor = dirname(ancestor)) {
      ancestors.push(directory);
      if (ancestor === dirname(ancestor)) break;
    }
    const descriptors = [...ancestors, directory, unsafeFile];

    await expect(
      inspectWindowsCredentialAclSnapshot(home, sid, {
        command: process.execPath,
        args: [
          "--eval",
          `process.stdout.write(${JSON.stringify(windowsCredentialAclOutput(descriptors))})`,
        ],
      }),
    ).resolves.toMatchObject({ descendantsArePrivate: false });
  });

  test("streams Windows credential ACL output larger than the subprocess buffer", async () => {
    const descriptor =
      "O:S-1-5-21-111-222-333-1001G:SYD:P(A;;FA;;;S-1-5-21-111-222-333-1001)";
    const expected = Math.ceil((1024 * 1024) / (descriptor.length + 1)) + 1;
    let observed = 0;

    const count = await streamWindowsCredentialAclDescriptors(
      process.execPath,
      [
        "--eval",
        `process.stdout.write(${JSON.stringify(`${descriptor}\n`)}.repeat(${expected}))`,
      ],
      async (received) => {
        if (observed === 0 || observed === expected - 1) {
          expect(received).toBe(descriptor);
        }
        observed += 1;
      },
    );

    expect(count).toBe(expected);
    expect(observed).toBe(expected);
  });

  test("preserves Windows credential ACL subprocess failures while streaming", async () => {
    await expect(
      streamWindowsCredentialAclDescriptors(
        process.execPath,
        [
          "--eval",
          'process.stderr.write("synthetic ACL inspection failure"); process.exitCode = 1',
        ],
        async () => {},
      ),
    ).rejects.toMatchObject({ stderr: "synthetic ACL inspection failure" });
  });

  test("accepts managed Windows ACLs with trusted system principals", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const descriptor =
      `O:${user}G:${user}D:AI` +
      `(A;OICIID;FA;;;${user})` +
      "(A;OICIID;FA;;;SY)" +
      "(A;OICIID;FA;;;BA)";

    expect(inspectWindowsCredentialAcl(descriptor, user)).toEqual({
      owner: user,
      protected: false,
      grantsCurrentUserAccess: true,
      untrustedPrincipals: [],
      deniedPrincipals: [],
    });
    expect(
      inspectWindowsCredentialAcl(
        `O:BAG:SYD:P(A;OICI;FA;;;${user})(A;OICI;FA;;;SY)`,
        user,
      ),
    ).toMatchObject({
      owner: "S-1-5-32-544",
      protected: true,
      untrustedPrincipals: [],
    });
  });

  test("identifies Windows ancestor grants that can replace credential homes", () => {
    const user = "S-1-5-21-111-222-333-1001";
    for (const rights of [
      "FA",
      "GA",
      "FW",
      "GW",
      "GAGX",
      "GXGA",
      "GWGX",
      "GXGW",
      "FAGX",
      "FWGX",
      "SD",
      "WD",
      "WO",
      "DC",
      "0x40",
      "0x10000",
      "0x40000",
      "0x80000",
      "0x1301bf",
    ]) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:SYD:(A;OICI;FA;;;${user})(A;;${rights};;;WD)`,
          user,
          { scope: "ancestor" },
        ).untrustedPrincipals,
      ).toEqual(["S-1-1-0"]);
    }

    for (const [flags, rights] of [
      ["", "FR"],
      ["", "FRGX"],
      ["", "GRGX"],
      ["", "0x1200a9"],
      ["IO", "FA"],
    ] as const) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:SYD:(A;OICI;FA;;;${user})(A;${flags};${rights};;;WD)`,
          user,
          { scope: "ancestor" },
        ).untrustedPrincipals,
      ).toEqual([]);
    }

    const service = "S-1-5-80-111-222-333-444-555";
    for (const [principal, expected] of [
      ["LS", "S-1-5-19"],
      ["NS", "S-1-5-20"],
      [service, service],
    ] as const) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:SYD:(A;OICI;FA;;;${user})(A;;DC;;;${principal})`,
          user,
          { scope: "ancestor" },
        ).untrustedPrincipals,
      ).toEqual([expected]);
    }
    expect(() =>
      inspectWindowsCredentialAcl(
        `O:${service}G:SYD:(A;OICI;FA;;;${user})`,
        user,
        { scope: "ancestor" },
      ),
    ).toThrow("owner is not a trusted principal");

    const installer =
      "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    expect(
      inspectWindowsCredentialAcl(
        `O:${installer}G:SYD:(A;OICI;FA;;;${installer})(A;OICI;FA;;;${user})`,
        user,
        { scope: "ancestor" },
      ).untrustedPrincipals,
    ).toEqual([]);
    expect(() =>
      inspectWindowsCredentialAcl(
        `O:${installer}G:SYD:(A;OICI;FA;;;${user})`,
        user,
      ),
    ).toThrow("owner is not a trusted principal");
  });

  test("accepts private credential-file ACLs without inheritance flags", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const descriptor = `O:${user}G:SYD:P(A;;FA;;;${user})(A;;FA;;;SY)`;

    expect(inspectWindowsCredentialAcl(descriptor, user)).toMatchObject({
      grantsCurrentUserAccess: false,
    });
    expect(
      inspectWindowsCredentialAcl(descriptor, user, { scope: "file" }),
    ).toMatchObject({
      grantsCurrentUserAccess: true,
      untrustedPrincipals: [],
    });
  });

  test("identifies broad, foreign, and inherited Windows ACL grants", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const stranger = "S-1-5-21-111-222-333-1002";
    for (const [principal, expected] of [
      ["WD", "S-1-1-0"],
      ["BU", "S-1-5-32-545"],
      ["AU", "S-1-5-11"],
      ["CO", "S-1-3-0"],
      ["CG", "S-1-3-1"],
      ["OW", "S-1-3-4"],
      ["AC", "S-1-15-2-1"],
      ["AN", "S-1-5-7"],
      ["IU", "S-1-5-4"],
      ["SU", "S-1-5-6"],
      ["RD", "S-1-5-32-555"],
      ["DA", "S-1-5-21-111-222-333-512"],
      ["DU", "S-1-5-21-111-222-333-513"],
      [stranger, stranger],
    ] as const) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:${user}D:AI(A;OICIID;FA;;;${user})(A;OICIID;FR;;;${principal})`,
          user,
          {
            resolvedAliases: {
              DA: "S-1-5-21-111-222-333-512",
              DU: "S-1-5-21-111-222-333-513",
            },
          },
        ).untrustedPrincipals,
      ).toEqual([expected]);
    }
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(D;OICI;FR;;;WD)(A;OICI;FA;;;${user})`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: false,
      untrustedPrincipals: [],
      deniedPrincipals: ["S-1-1-0"],
    });
  });

  test("requires effective, inheritable Windows credential access", () => {
    const user = "S-1-5-21-111-222-333-1001";
    for (const [flags, rights] of [
      ["OICI", "FR"],
      ["OICI", "FW"],
      ["", "FA"],
      ["OI", "FA"],
      ["CI", "FA"],
      ["OICIIO", "FA"],
      ["OICINP", "FA"],
      ["OICINPID", "FA"],
      ["CIIOID", "FA"],
    ] as const) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:${user}D:P(A;${flags};${rights};;;${user})`,
          user,
        ).grantsCurrentUserAccess,
      ).toBe(false);
    }

    for (const rights of ["FA", "GA", "0x1f01ff", "0x10000000"]) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${user}G:${user}D:P(A;OICI;${rights};;;${user})`,
          user,
        ).grantsCurrentUserAccess,
      ).toBe(true);
    }

    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(A;;FA;;;${user})(A;OICIIO;FA;;;${user})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(true);
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(A;CIOI;FA;;;${user})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(true);
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(A;;FA;;;${user})(A;OINP;FA;;;${user})(A;CI;FA;;;${user})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(false);
  });

  test("normalizes built-in Windows user and service SID aliases", () => {
    for (const [alias, user] of [
      ["SY", "S-1-5-18"],
      ["LS", "S-1-5-19"],
      ["NS", "S-1-5-20"],
      ["LA", "S-1-5-21-111-222-333-500"],
      ["LG", "S-1-5-21-111-222-333-501"],
    ] as const) {
      expect(
        inspectWindowsCredentialAcl(
          `O:${alias}G:SYD:P(A;OICI;FA;;;${alias})(A;OICI;FA;;;BA)`,
          user,
          {
            resolvedAliases:
              alias === "LA" || alias === "LG" ? { [alias]: user } : {},
          },
        ),
      ).toMatchObject({
        owner: user,
        protected: true,
        grantsCurrentUserAccess: true,
        untrustedPrincipals: [],
        deniedPrincipals: [],
      });
    }
  });

  test("does not confuse domain accounts with local Administrator or Guest", () => {
    const administrator = "S-1-5-21-111-222-333-500";
    const guest = "S-1-5-21-111-222-333-501";
    const localAdministrator = "S-1-5-21-444-555-666-500";
    const localGuest = "S-1-5-21-444-555-666-501";

    expect(
      inspectWindowsCredentialAcl(
        `O:LAG:SYD:P(A;OICI;FA;;;LA)(A;OICI;FA;;;BA)`,
        administrator,
        { resolvedAliases: { LA: localAdministrator } },
      ),
    ).toMatchObject({
      owner: localAdministrator,
      grantsCurrentUserAccess: false,
    });
    expect(
      inspectWindowsCredentialAcl(
        `O:${guest}G:SYD:P(A;OICI;FA;;;${guest})(A;OICI;FA;;;LG)`,
        guest,
        { resolvedAliases: { LG: localGuest } },
      ).untrustedPrincipals,
    ).toEqual([localGuest]);
    expect(() =>
      inspectWindowsCredentialAcl(
        `O:LGG:SYD:P(A;OICI;FA;;;${guest})(A;OICI;FA;;;LG)`,
        guest,
        { resolvedAliases: { LG: localGuest } },
      ),
    ).toThrow("owner is not a trusted principal");
  });

  test("resolves domain and forest aliases against their actual SID domain", () => {
    const currentUser = "S-1-5-21-111-222-333-1001";
    const joinedDomainAdmins = "S-1-5-21-444-555-666-512";
    const forestRootAdmins = "S-1-5-21-777-888-999-519";
    const domainRasServers = "S-1-5-21-444-555-666-553";

    expect(
      inspectWindowsCredentialAcl(
        `O:${currentUser}G:SYD:P(A;OICI;FA;;;${currentUser})(A;OICI;FR;;;DA)(A;OICI;FR;;;EA)(A;OICI;FR;;;RS)`,
        currentUser,
        {
          resolvedAliases: {
            DA: joinedDomainAdmins,
            EA: forestRootAdmins,
            RS: domainRasServers,
          },
        },
      ).untrustedPrincipals,
    ).toEqual([joinedDomainAdmins, forestRootAdmins, domainRasServers]);
  });

  test("classifies conditional Windows access rules without trusting callbacks", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const condition = '(@User.department == "(Managed;QA)")';

    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(A;OICI;FA;;;${user})(XA;OICI;FR;;;WD;${condition})`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: true,
      untrustedPrincipals: ["S-1-1-0"],
    });
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(XA;OICI;FA;;;${user};${condition})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(false);
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(A;OICI;FA;;;${user})(ZA;OICI;FR;;;WD;${condition})`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: true,
      untrustedPrincipals: ["S-1-1-0"],
    });
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(ZA;OICI;FA;;;${user};${condition})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(false);
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(A;OICI;FA;;;${user})(XD;OICI;FR;;;WD;${condition})`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: false,
      deniedPrincipals: ["S-1-1-0"],
    });
  });

  test("classifies object-specific Windows ACLs without treating them as unrestricted", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const guid = "bf967aba-0de6-11d0-a285-00aa003049e2";

    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(A;OICI;FA;;;${user})(OA;OICI;FR;${guid};;WD)`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: true,
      untrustedPrincipals: ["S-1-1-0"],
    });
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(OA;OICI;FA;${guid};;${user})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(false);
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:SYD:P(A;OICI;FA;;;${user})(OD;OICI;FR;;${guid};WD)`,
        user,
      ),
    ).toMatchObject({
      grantsCurrentUserAccess: false,
      deniedPrincipals: ["S-1-1-0"],
    });
  });

  test("rejects incomplete, unowned, and unsupported Windows ACLs", () => {
    const user = "S-1-5-21-111-222-333-1001";
    const stranger = "S-1-5-21-111-222-333-1002";
    for (const descriptor of [
      `G:${user}D:P(A;OICI;FA;;;${user})`,
      `O:${user}G:${user}`,
      `O:${user}G:${user}D:NO_ACCESS_CONTROL`,
      `O:${user}G:${user}D:P`,
      `O:${stranger}G:${user}D:P(A;OICI;FA;;;${user})`,
      `O:${user}G:${user}D:P(XA;OICI;FA;;;${user})`,
      `O:${user}G:${user}D:P(A;OIN;FA;;;${user})`,
      `O:${user}G:${user}D:P(A;ZZ;FA;;;${user})`,
      `O:${user}G:${user}D:P(OA;OICI;FA;not-a-guid;;${user})`,
      `O:${user}G:${user}D:P(A;OICI;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;${user})`,
      `O:${user}G:${user}D:P(A;OICI;FA;;;${user};(@User.Department == \"QA\"))`,
    ]) {
      expect(() => inspectWindowsCredentialAcl(descriptor, user)).toThrow();
    }
    expect(() =>
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(A;OICI;FA;;;${user})`,
        "not-a-sid",
      ),
    ).toThrow("current Windows user SID");
    expect(
      inspectWindowsCredentialAcl(
        `O:${user}G:${user}D:P(A;OICIIO;FA;;;${user})`,
        user,
      ).grantsCurrentUserAccess,
    ).toBe(false);
  });

  test("preserves Windows ACL subprocess failures", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const metadata = await lstat(home);
    const underlying = Object.assign(new Error("PowerShell failed"), {
      stderr:
        "Method invocation is supported only on core types in this language mode. " +
        "token=sk-proj-SYNTHETIC_WINDOWS_ACL_SECRET_123",
    });

    try {
      await requirePrivateCredentialHome(metadata, home, {
        platform: "win32",
        secureWindowsHome: async () => {
          throw underlying;
        },
      });
      throw new Error("expected the Windows ACL operation to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toContain("core types");
      expect((error as Error).message).toContain(
        "token=sk-proj-SYNTHETIC_WINDOWS_ACL_SECRET_123",
      );
      expect((error as Error).cause).toBe(underlying);
    }
  });

  test("rejects replacement credential homes when numeric identities collide", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const canonicalHome = await realpath(home);
    const originalLstat = fsPromises.lstat;
    const firstExactIdentity = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    let homeInspections = 0;
    const inspectHome = spyOn(fsPromises, "lstat").mockImplementation(
      async (path, options) => {
        const stats = await originalLstat(path, options as never);
        if (String(path) !== home && String(path) !== canonicalHome) {
          return stats as never;
        }
        const exactIdentity =
          firstExactIdentity + (homeInspections++ === 0 ? 0n : 1n);
        return Object.assign(
          Object.create(Object.getPrototypeOf(stats)),
          stats,
          {
            ino:
              typeof stats.ino === "bigint"
                ? exactIdentity
                : Number(exactIdentity),
          },
        ) as never;
      },
    );

    try {
      await expect(
        requireSecureCredentialHome(home, {
          platform: "win32",
          secureWindowsHome: async () => {},
        }),
      ).rejects.toThrow("credential home was replaced");
    } finally {
      inspectHome.mockRestore();
    }
  });

  test("revalidates the Windows credential ACL every time the home is used", async () => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home);
    const validations: string[] = [];

    await requireSecureCredentialHome(home, {
      platform: "win32",
      secureWindowsHome: async (path) => {
        validations.push(path);
      },
    });

    expect(validations).toEqual([home]);
    await expect(
      requireSecureCredentialHome(home, {
        platform: "win32",
        secureWindowsHome: async () => {
          throw new Error("ACL changed after preparation");
        },
      }),
    ).rejects.toThrow("private Windows credential home");
  });

  test.skipIf(process.platform !== "win32")(
    "rejects Windows credential-home junctions even if their targets disappear",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const outside = join(root, "outside");
      await mkdir(outside);
      const credential = join(outside, "auth.json");
      await writeFile(credential, "synthetic outside credential\n");
      await symlink(outside, join(home, "linked-cache"), "junction");

      await expect(requireSecureCredentialHome(home)).rejects.toThrow(
        "Windows credential home contains a symbolic link or junction",
      );
      expect(await readFile(credential, "utf8")).toBe(
        "synthetic outside credential\n",
      );
      await rename(outside, join(root, "moved-outside"));
      await expect(requireSecureCredentialHome(home)).rejects.toThrow(
        "Windows credential home contains a symbolic link or junction",
      );
    },
  );

  test.skipIf(process.platform !== "win32")(
    "creates credential homes with a verified managed-compatible Windows ACL",
    async () => {
      const root = await temporaryDirectory();
      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      });
      const powershell = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      );
      const command = [
        "$ErrorActionPreference = 'Stop'",
        "$path = [Environment]::GetEnvironmentVariable('CODEX_SECURITY_TEST_ACL_PATH', 'Process')",
        "$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        "$acl = [System.IO.Directory]::GetAccessControl($path)",
        "$trusted = @($identity, 'S-1-5-18', 'S-1-5-32-544')",
        "$unexpected = @($acl.Access | Where-Object { $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $trusted -notcontains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })",
        "[pscustomobject]@{ unexpected = $unexpected.Count } | ConvertTo-Json -Compress",
      ].join("; ");
      const result = await promisify(execFile)(
        powershell,
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        {
          encoding: "utf8",
          env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: home },
          timeout: 20_000,
          windowsHide: true,
        },
      );

      expect(JSON.parse(result.stdout)).toEqual({ unexpected: 0 });
    },
  );

  test.skipIf(process.platform !== "win32")(
    "preserves SYSTEM and Administrators when protecting inherited access",
    async () => {
      const root = await temporaryDirectory();
      const state = join(root, "state");
      await mkdir(state);
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const user = spawnSync(
        join(systemDirectory, "whoami.exe"),
        ["/user", "/fo", "csv", "/nh"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(user.status).toBe(0);
      const sid = /"(S-1-(?:\d+-)*\d+)"\s*$/u.exec(user.stdout)?.[1];
      expect(sid).toBeDefined();
      const configured = spawnSync(
        join(systemDirectory, "icacls.exe"),
        [
          state,
          "/inheritance:r",
          "/grant:r",
          `*${sid}:(OI)(CI)F`,
          "*S-1-5-18:(OI)(CI)F",
          "*S-1-5-32-544:(OI)(CI)F",
        ],
        { encoding: "utf8", windowsHide: true },
      );
      expect(configured.status).toBe(0);

      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: state,
      });
      const descriptor = spawnSync(
        join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$acl = [System.IO.Directory]::GetAccessControl($env:CODEX_SECURITY_TEST_ACL_PATH)",
            "$allowed = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })",
            "$denied = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })",
            "$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
            "$principals = @($allowed | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })",
            "$deniedPrincipals = @($denied | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value })",
            "$fullControl = @($allowed | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $env:CODEX_SECURITY_TEST_USER_SID -and ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and ($_.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0 -and ($_.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0 -and $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None })",
            "[pscustomobject]@{ owner = $owner; protected = $acl.AreAccessRulesProtected; principals = $principals; deniedPrincipals = $deniedPrincipals; grantsCurrentUserAccess = ($fullControl.Count -gt 0 -and $denied.Count -eq 0) } | ConvertTo-Json -Compress",
          ].join("; "),
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_SECURITY_TEST_ACL_PATH: home,
            CODEX_SECURITY_TEST_USER_SID: sid!,
          },
          windowsHide: true,
        },
      );
      expect(descriptor.status).toBe(0);
      const access = JSON.parse(descriptor.stdout) as {
        owner: string;
        protected: boolean;
        principals: string[];
        deniedPrincipals: string[];
        grantsCurrentUserAccess: boolean;
      };
      expect(access).toMatchObject({
        protected: true,
        deniedPrincipals: [],
        grantsCurrentUserAccess: true,
      });
      expect(access.principals).toEqual(
        expect.arrayContaining([sid!, "S-1-5-18", "S-1-5-32-544"]),
      );
      expect([sid!, "S-1-5-18", "S-1-5-32-544"]).toContain(access.owner);
      expect(new Set(access.principals)).toEqual(
        new Set([sid!, "S-1-5-18", "S-1-5-32-544"]),
      );
    },
  );

  test.skipIf(process.platform !== "win32")(
    "removes unsafe inherited Windows credential-home permissions",
    async () => {
      const root = await temporaryDirectory();
      const state = join(root, "state");
      await mkdir(state);
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const shared = spawnSync(
        join(systemDirectory, "icacls.exe"),
        [state, "/grant", "*S-1-1-0:(OI)(CI)R"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(shared.status).toBe(0);

      const home = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: state,
      });
      const result = spawnSync(
        join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$acl = [System.IO.Directory]::GetAccessControl($env:CODEX_SECURITY_TEST_ACL_PATH)",
            "$everyone = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })",
            "[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; everyone = $everyone.Count } | ConvertTo-Json -Compress",
          ].join("; "),
        ],
        {
          encoding: "utf8",
          env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: home },
          windowsHide: true,
        },
      );
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        protected: true,
        everyone: 0,
      });
    },
  );

  test.skipIf(process.platform !== "win32")(
    "removes explicit foreign Windows credential-home grants",
    async () => {
      const root = await temporaryDirectory();
      const state = join(root, "state");
      const home = join(state, "codex-home");
      await mkdir(home, { recursive: true });
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const configured = spawnSync(
        join(systemDirectory, "icacls.exe"),
        [home, "/grant", "*S-1-1-0:(OI)(CI)R"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(configured.status).toBe(0);

      expect(
        await prepareCodexSecurityCredentialHome({
          CODEX_SECURITY_STATE_DIR: state,
        }),
      ).toBe(await realpath(home));
      const result = spawnSync(
        join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$acl = [System.IO.Directory]::GetAccessControl($env:CODEX_SECURITY_TEST_ACL_PATH)",
            "$everyone = @($acl.Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })",
            "[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; everyone = $everyone.Count } | ConvertTo-Json -Compress",
          ].join("; "),
        ],
        {
          encoding: "utf8",
          env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: home },
          windowsHide: true,
        },
      );
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        protected: true,
        everyone: 0,
      });
    },
  );

  test.skipIf(process.platform !== "win32")(
    "rejects attacker-writable Windows credential-home ancestry without changing it",
    async () => {
      const root = await temporaryDirectory();
      const state = join(root, "state");
      await mkdir(state);
      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const identity = spawnSync(
        join(systemDirectory, "whoami.exe"),
        ["/user", "/fo", "csv", "/nh"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(identity.status).toBe(0);
      const sid = /"(S-1-(?:\d+-)*\d+)"\s*$/u.exec(identity.stdout)?.[1];
      expect(sid).toBeDefined();
      for (const ancestor of [root, state]) {
        const owned = spawnSync(
          join(systemDirectory, "icacls.exe"),
          [ancestor, "/setowner", `*${sid}`],
          { encoding: "utf8", windowsHide: true },
        );
        expect(owned.status).toBe(0);
        const writable = spawnSync(
          join(systemDirectory, "icacls.exe"),
          [ancestor, "/grant", "*S-1-1-0:(OI)(CI)M"],
          { encoding: "utf8", windowsHide: true },
        );
        expect(writable.status).toBe(0);
      }

      await expect(
        prepareCodexSecurityCredentialHome({
          CODEX_SECURITY_STATE_DIR: state,
        }),
      ).rejects.toThrow(
        "Windows credential-home ancestor allows another identity to replace the directory",
      );

      for (const ancestor of [root, state]) {
        const inspection = spawnSync(
          join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
          [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            [
              "$acl = [System.IO.Directory]::GetAccessControl($env:CODEX_SECURITY_TEST_ACL_PATH)",
              "$everyone = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' })",
              "[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; everyone = $everyone.Count } | ConvertTo-Json -Compress",
            ].join("; "),
          ],
          {
            encoding: "utf8",
            env: { ...process.env, CODEX_SECURITY_TEST_ACL_PATH: ancestor },
            windowsHide: true,
          },
        );
        expect(inspection.status).toBe(0);
        expect(JSON.parse(inspection.stdout).everyone).toBeGreaterThan(0);
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "repairs unsafe ACLs on existing nested Windows credential files",
    async () => {
      const root = await temporaryDirectory();
      const state = join(root, "state");
      const home = join(state, "codex-home");
      const nested = join(home, "sessions");
      await mkdir(nested, { recursive: true });
      const auth = join(home, "auth.json");
      const nestedAuth = join(nested, "credentials.json");
      await writeFile(auth, '{"token":"synthetic-root"}\n');
      await writeFile(nestedAuth, '{"token":"synthetic-nested"}\n');

      const systemDirectory = join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
      );
      const identity = spawnSync(
        join(systemDirectory, "whoami.exe"),
        ["/user", "/fo", "csv", "/nh"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(identity.status).toBe(0);
      const sid = /"(S-1-(?:\d+-)*\d+)"\s*$/u.exec(identity.stdout)?.[1];
      expect(sid).toBeDefined();

      for (const credential of [auth, nestedAuth]) {
        const unsafe = spawnSync(
          join(systemDirectory, "icacls.exe"),
          [credential, "/inheritance:r", "/grant:r", `*${sid}:F`, "*S-1-1-0:R"],
          { encoding: "utf8", windowsHide: true },
        );
        expect(unsafe.status).toBe(0);
      }

      expect(
        await prepareCodexSecurityCredentialHome({
          CODEX_SECURITY_STATE_DIR: state,
        }),
      ).toBe(await realpath(home));

      const inspection = spawnSync(
        join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          [
            "$paths = @($env:CODEX_SECURITY_TEST_AUTH_PATH, $env:CODEX_SECURITY_TEST_NESTED_AUTH_PATH)",
            "$unexpected = @($paths | ForEach-Object { $acl = Get-Acl -LiteralPath $_; $acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' } })",
            "[pscustomobject]@{ unexpected = $unexpected.Count } | ConvertTo-Json -Compress",
          ].join("; "),
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_SECURITY_TEST_AUTH_PATH: auth,
            CODEX_SECURITY_TEST_NESTED_AUTH_PATH: nestedAuth,
          },
          windowsHide: true,
        },
      );
      expect(inspection.status).toBe(0);
      expect(JSON.parse(inspection.stdout)).toEqual({ unexpected: 0 });
      expect(await readFile(auth, "utf8")).toContain("synthetic-root");
      expect(await readFile(nestedAuth, "utf8")).toContain("synthetic-nested");
    },
  );
});
