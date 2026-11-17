import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DependencyAttemptStore } from "../src/dependency-attempt-store.js";
import {
  createDependencyClaims,
  type DependencyClaimReference,
  type PreparedDependencyClaim,
} from "../src/dependency-claims.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const context = { cve: "CVE-2024-1000", attempt: "local" };
const excerpt = {
  path: "version.txt",
  startLine: 1,
  endLine: 1,
  text: "1.0\n",
};
const draft = (
  id: string,
  dependencies: DependencyClaimReference[] = [],
): PreparedDependencyClaim => ({
  id,
  scope: "fixture",
  payload: "uses 1.0",
  dependencies,
  excerpts: [excerpt],
  receipts: [],
});

test("independent commands can reopen exact recorded claims without acquiring review approval", async () => {
  await using dir = await scopedTemporaryDirectory("claim-state-");
  const path = join(dir.path, "run.sqlite");
  const setup = new DependencyAttemptStore(path);
  const claims = createDependencyClaims(
    context,
    undefined,
    setup,
    "single_agent",
  );
  const original = claims.reference(claims.propose(draft("version")).record);
  const child = claims.reference(
    claims.propose(draft("use", [original])).record,
  );
  setup.close();

  const processResult = spawnSync(
    process.execPath,
    [
      "-e",
      `
    const { DependencyAttemptStore } = await import(${JSON.stringify(new URL("../src/dependency-attempt-store.ts", import.meta.url).href)});
    const { createDependencyClaims } = await import(${JSON.stringify(new URL("../src/dependency-claims.ts", import.meta.url).href)});
    const db = new DependencyAttemptStore(${JSON.stringify(path)}, { create: false });
    const claims = createDependencyClaims(${JSON.stringify(context)}, undefined, db, "single_agent");
    const ref = claims.currentReference("use");
    console.log(JSON.stringify({ ref, record: claims.get(ref), isUsable: claims.isUsable(ref), isApproved: claims.isApproved(ref) }));
    db.close();
  `,
    ],
    { encoding: "utf8" },
  );
  expect(processResult.status, processResult.stderr).toBe(0);
  expect(JSON.parse(processResult.stdout)).toMatchObject({
    ref: child,
    record: {
      state: "recorded",
      dependencies: [original],
      excerpts: [excerpt],
    },
    isUsable: true,
    isApproved: false,
  });

  const db = new DependencyAttemptStore(path, { create: false });
  try {
    expect(() =>
      createDependencyClaims(context, undefined, db, "reviewed"),
    ).toThrow(/policy/);
    expect(() =>
      createDependencyClaims(
        { cve: "CVE-2024-1001" },
        undefined,
        db,
        "single_agent",
      ),
    ).toThrow(/context/);
    const reopened = createDependencyClaims(
      context,
      undefined,
      db,
      "single_agent",
    );
    const newer = reopened.reference(
      reopened.propose({ ...draft("version"), payload: "updated" }, 1).record,
    );
    expect(reopened.isUsable(newer)).toBe(true);
    expect(reopened.get(original)?.state).toBe("stale");
    expect(reopened.isUsable(child)).toBe(false);
    expect(reopened.get(child)?.state).toBe("stale");
    expect(reopened.lease(newer)).toBeUndefined();
  } finally {
    db.close();
  }
});

test("a failing batch rolls back claims, transitive invalidation and receipts together", () => {
  const db = new DependencyAttemptStore(":memory:");
  try {
    const claims = createDependencyClaims(
      context,
      undefined,
      db,
      "single_agent",
    );
    const base = claims.reference(claims.propose(draft("base")).record);
    const dependent = claims.reference(
      claims.propose(draft("dependent", [base])).record,
    );
    expect(() =>
      db.transaction(() => {
        claims.propose({ ...draft("base"), payload: "changed" }, 1);
        db.set("receipts", "batch", { applied: true });
        claims.propose(draft("absent"), 3);
      }),
    ).toThrow(/expected revision/);
    expect(claims.currentReference("base")).toEqual(base);
    expect(claims.isUsable(dependent)).toBe(true);
    expect(db.get("receipts", "batch")).toBeUndefined();
  } finally {
    db.close();
  }
});

test("opening unrelated SQLite data fails without modifying it", async () => {
  await using dir = await scopedTemporaryDirectory("unrelated-state-");
  const path = join(dir.path, "work.sqlite");
  const other = new Database(path);
  other.exec(
    "CREATE TABLE unrelated (value TEXT); INSERT INTO unrelated VALUES ('data')",
  );
  other.close();
  const original = readFileSync(path);
  expect(() => new DependencyAttemptStore(path)).toThrow(/unrecognized/i);
  expect(readFileSync(path)).toEqual(original);
});

test("only the handle owning a live review can complete it", async () => {
  await using dir = await scopedTemporaryDirectory("review-lease-");
  const path = join(dir.path, "run.sqlite");
  const first = new DependencyAttemptStore(path);
  const second = new DependencyAttemptStore(path, { create: false });
  try {
    const owner = createDependencyClaims(context, undefined, first);
    const other = createDependencyClaims(context, undefined, second);
    const ref = owner.reference(owner.propose(draft("use")).record);
    const decision = { accepted: true, reason: "Verified", evidenceKeys: [] };
    expect(owner.lease(ref)).toBeDefined();
    expect(other.lease(ref)).toBeUndefined();
    expect(other.complete(ref, decision)).toBe(false);
    first.close();
    expect(other.lease(ref)).toBeDefined();
    expect(other.complete(ref, decision)).toBe(true);
    expect(other.isApproved(ref)).toBe(true);
  } finally {
    first.close();
    second.close();
  }
});
