import { expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  DependencyAttemptStore,
  dependencyRecordHash,
  type StoredClaim,
} from "../src/exploitability/attempt-store.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("an attempt reopens with its original evidence and atomically replays a write", async () => {
  await using directory = await scopedTemporaryDirectory("dependency-attempt-");
  const file = join(directory.path, "attempt.sqlite");
  const identity = {
    runId: "sample",
    attemptId: "first",
    inputDigest: "fixture",
  };
  const input = { version: "1.0.0", path: "package.json" };
  const store = new DependencyAttemptStore(file);
  try {
    store.bindIdentity(identity);
    expect(() =>
      store.mutate("save", "record", input, () => {
        store.set("evidence", "package", input);
        store.recordClaim("version", input);
        throw new Error("interrupted");
      }),
    ).toThrow("interrupted");
    expect(store.get("evidence", "package")).toBeUndefined();
    expect(store.claim("version")).toBeUndefined();
    store.mutate("save", "record", input, () => {
      store.set("evidence", "package", input);
      return store.recordClaim("version", input, 0);
    });
  } finally {
    store.close();
  }
  const reopened = new DependencyAttemptStore(file, { create: false });
  try {
    reopened.bindIdentity({
      inputDigest: "fixture",
      runId: "sample",
      attemptId: "first",
    });
    expect(() =>
      reopened.bindIdentity({ ...identity, inputDigest: "different" }),
    ).toThrow(/different investigation/);
    const unexpectedWrite = (): StoredClaim<typeof input> => {
      throw new Error("repeated write");
    };
    const previous = reopened.mutate(
      "save",
      "record",
      { path: input.path, version: input.version },
      unexpectedWrite,
    );
    expect(previous).toEqual({
      id: "version",
      revision: 1,
      hash: dependencyRecordHash(input),
      value: input,
    });
    expect(reopened.get("evidence", "package")).toEqual(input);
    expect(() =>
      reopened.mutate("save", "another-command", input, unexpectedWrite),
    ).toThrow(/different request/);
    expect(() =>
      reopened.mutate("save", "record", {}, unexpectedWrite),
    ).toThrow(/different request/);
  } finally {
    reopened.close();
  }
});

test("asynchronous database callbacks cannot commit a mutation receipt", async () => {
  const store = new DependencyAttemptStore(":memory:");
  try {
    const deferredWrite = async () => {
      await Promise.resolve();
      store.set("evidence", "deferred", "written outside the transaction");
      throw new Error("deferred failure");
    };
    // @ts-expect-error JavaScript callers can supply an async function.
    expect(() => store.mutate("save", "record", {}, deferredWrite)).toThrow(
      /synchronous/,
    );
    // @ts-expect-error Read snapshots also expire when the callback returns.
    expect(() => store.read(deferredWrite)).toThrow(/synchronous/);
    const returnsPromise = () => {
      store.set("evidence", "initial", "written before returning a promise");
      return Promise.reject(new Error("rejected write"));
    };
    // @ts-expect-error An ordinary function returning a promise is asynchronous too.
    expect(() => store.transaction(returnsPromise)).toThrow(/synchronous/);
    await Promise.resolve();
    expect(store.keys("evidence")).toEqual([]);
    expect(store.operation("save", "record", {})).toBeUndefined();
    expect(store.mutate("save", "record", {}, () => "retried")).toBe("retried");
  } finally {
    store.close();
  }
});

test("two processes replacing the same claim revision leave one winner and preserve history", async () => {
  await using directory = await scopedTemporaryDirectory("claim-revision-");
  const path = join(directory.path, "attempt.sqlite");
  const store = new DependencyAttemptStore(path);
  try {
    const first = store.recordClaim("version", { version: "initial" });
    expect(store.recordClaim("version", first.value)).toEqual(first);
    expect(() =>
      store.recordClaim("version", { version: "different" }),
    ).toThrow(/expected revision/);
    const module = new URL(
      "../src/exploitability/attempt-store.ts",
      import.meta.url,
    ).href;
    const contender = `
      const { DependencyAttemptStore } = await import(${JSON.stringify(module)});
      const [file, version] = process.argv.slice(1);
      const store = new DependencyAttemptStore(file, {create: false});
      try {
        console.log(JSON.stringify(store.recordClaim("version", {version}, 1)));
      } catch (error) {
        if (!String(error).includes("expected revision")) throw error;
        console.log("null");
      } finally {
        store.close();
      }
    `;
    const outcomes = await Promise.all(
      ["left", "right"].map(async (version) =>
        JSON.parse(
          (
            await promisify(execFile)(process.execPath, [
              "-e",
              contender,
              path,
              version,
            ])
          ).stdout,
        ),
      ),
    );
    const winners = outcomes.filter(Boolean);
    expect(winners).toHaveLength(1);
    expect(store.claim("version", 1)).toEqual(first);
    expect(store.claim("version")?.revision).toBe(2);
    expect(store.claims()).toEqual(winners);
  } finally {
    store.close();
  }
});

test("refuses to initialize over an unrelated file", async () => {
  await using directory = await scopedTemporaryDirectory("unrelated-state-");
  const file = join(directory.path, "existing.data");
  await writeFile(file, "a different file");
  expect(() => new DependencyAttemptStore(file)).toThrow();
  expect(await readFile(file, "utf8")).toBe("a different file");
});
