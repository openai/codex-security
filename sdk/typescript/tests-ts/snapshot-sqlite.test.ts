import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { readSqliteRows } from "./support/read-sqlite";
import { runCommand } from "./support/shell";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const roots: string[] = [];
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "snapshot-sqlite-")));
  roots.push(root);
  return {
    root,
    source: join(root, "source.sqlite3"),
    destination: join(root, "snapshot.sqlite3"),
  };
}
function create(path: string) {
  const db = new Database(path);
  db.exec(
    "CREATE TABLE records(value TEXT NOT NULL); INSERT INTO records(rowid,value) VALUES(41,'sealed'),(99,'retained')",
  );
  return db;
}
function rows(path: string) {
  return readSqliteRows(
    path,
    "SELECT rowid, value FROM records ORDER BY rowid",
  );
}
function run(root: string, args: string[], env = process.env) {
  return runCommand(node, [helper, "snapshot-sqlite", ...args], {
    cwd: root,
    env: { ...env, PATH: "" },
    timeout: 10_000,
  });
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("SQLite snapshots", () => {
  test("copies committed WAL rows into a populated standalone database without renumbering rowids", async () => {
    const f = fixture();
    const source = new Database(f.source);
    source.exec(
      "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE records(value TEXT NOT NULL); INSERT INTO records(rowid,value) VALUES(41,'sealed'),(99,'retained')",
    );
    source.exec("BEGIN; INSERT INTO records VALUES('uncommitted')");
    const destination = new Database(f.destination);
    destination.exec(
      "CREATE TABLE obsolete(value); INSERT INTO obsolete VALUES('old')",
    );
    destination.close();
    if (process.platform !== "win32") chmodSync(f.destination, 0o644);
    try {
      expect(statSync(`${f.source}-wal`).size).toBeGreaterThan(0);
      const result = await run(f.root, [f.source, f.destination]);
      expect({
        status: result.status,
        out: result.stdout,
        err: result.stderr,
      }).toEqual({ status: 0, out: "", err: "" });
      expect(rows(f.destination)).toEqual([
        { rowid: 41, value: "sealed" },
        { rowid: 99, value: "retained" },
      ]);
      expect(
        readSqliteRows(
          f.destination,
          "SELECT name FROM sqlite_master WHERE name='obsolete'",
        ),
      ).toEqual([]);
      const standalone = join(f.root, "standalone.sqlite3");
      copyFileSync(f.destination, standalone);
      expect(rows(standalone)).toEqual(rows(f.destination));
      if (process.platform !== "win32")
        expect(statSync(f.destination).mode & 0o777).toBe(0o600);
      expect(
        source.query("SELECT count(*) AS count FROM records").get(),
      ).toEqual({ count: 3 });
    } finally {
      source.exec("ROLLBACK");
      source.close();
    }
  });

  test("expands homes, quotes URI characters, and creates nested destination parents", async () => {
    const f = fixture();
    const source = join(
      f.root,
      "source # percent% ? 東京.sqlite3".replaceAll(
        "?",
        process.platform === "win32" ? "q" : "?",
      ),
    );
    const db = create(source);
    db.close();
    const name = source.slice(f.root.length + 1);
    const result = await run(
      f.root,
      [`~/${name}`, "~/new/nested/snapshot.sqlite3"],
      {
        ...process.env,
        HOME: f.root,
        USERPROFILE: f.root,
      },
    );
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(rows(join(f.root, "new/nested/snapshot.sqlite3"))).toEqual(
      rows(source),
    );
  });

  test("resolves source directory links and writes through destination directory links", async () => {
    const f = fixture();
    const source = create(f.source);
    source.close();
    const directory = join(f.root, "actual");
    mkdirSync(directory);
    symlinkSync(
      f.root,
      join(f.root, "source-link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    symlinkSync(
      directory,
      join(f.root, "destination-link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const result = await run(f.root, [
      join(f.root, "source-link", "source.sqlite3"),
      join(f.root, "destination-link", "snapshot.sqlite3"),
    ]);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(rows(join(directory, "snapshot.sqlite3"))).toEqual(rows(f.source));
  });

  test.skipIf(process.platform === "win32")(
    "keeps destination symlink/parent components and follows file aliases",
    async () => {
      const f = fixture();
      const db = create(f.source);
      db.close();
      const nested = join(f.root, "actual", "child");
      mkdirSync(nested, { recursive: true });
      symlinkSync(nested, join(f.root, "link"), "dir");
      const result = await run(f.root, [
        f.source,
        `${f.root}/link/../snapshot.sqlite3`,
      ]);
      expect(result.status).toBe(0);
      expect(rows(join(f.root, "actual", "snapshot.sqlite3"))).toEqual(
        rows(f.source),
      );
      expect(existsSync(f.destination)).toBe(false);
      symlinkSync(join(f.root, "actual", "snapshot.sqlite3"), f.destination);
      chmodSync(join(f.root, "actual", "snapshot.sqlite3"), 0o644);
      expect((await run(f.root, [f.source, f.destination])).status).toBe(0);
      expect(statSync(f.destination).mode & 0o777).toBe(0o600);
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves raw POSIX source, destination, and home bytes through the helper entrypoint",
    () => {
      const f = fixture();
      const db = create(f.source);
      db.close();
      const pathBytes = (byte: number) =>
        process.platform === "linux"
          ? Buffer.from([byte])
          : Buffer.from("東京");
      const rawHome = Buffer.concat([
        Buffer.from(`${f.root}/home-`),
        pathBytes(0xff),
      ]);
      mkdirSync(rawHome);
      const source = Buffer.concat([
        rawHome,
        Buffer.from("/source-"),
        pathBytes(0x80),
      ]);
      const destination = Buffer.concat([
        rawHome,
        Buffer.from("/snapshot-"),
        pathBytes(0xfe),
      ]);
      writeFileSync(source, readFileSync(f.source));
      const metadata = Buffer.concat([
        Buffer.from("x\0"),
        rawHome,
        Buffer.from("\0snapshot-sqlite\0~/source-"),
        pathBytes(0x80),
        Buffer.from("\0~/snapshot-"),
        pathBytes(0xfe),
        Buffer.from([0]),
      ]).toString("hex");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'exec 3<<EOF\n$1\nEOF\nPATH= exec "$2" "$3" --helper',
          "snapshot",
          metadata,
          node,
          helper,
        ],
        { encoding: "utf8" },
      );
      expect({
        status: result.status,
        out: result.stdout,
        err: result.stderr,
      }).toEqual({ status: 0, out: "", err: "" });
      const readable = join(f.root, "readable.sqlite3");
      copyFileSync(destination, readable);
      expect(rows(readable)).toEqual(rows(f.source));
      expect(statSync(destination).mode & 0o777).toBe(0o600);
    },
  );

  test("fails before creating destination parents when the source is missing", async () => {
    const f = fixture();
    const result = await run(f.root, [
      f.source,
      join(f.root, "missing", "snapshot.sqlite3"),
    ]);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("snapshot-sqlite: error:");
    expect(existsSync(join(f.root, "missing"))).toBe(false);
  });

  test("leaves an existing destination and its permissions unchanged when backup fails", async () => {
    const f = fixture();
    writeFileSync(f.source, "not a database");
    const db = create(f.destination);
    db.close();
    if (process.platform !== "win32") chmodSync(f.destination, 0o644);
    const before = readFileSync(f.destination);
    const result = await run(f.root, [f.source, f.destination]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("file is not a database");
    expect(readFileSync(f.destination)).toEqual(before);
    if (process.platform !== "win32")
      expect(statSync(f.destination).mode & 0o777).toBe(0o644);
  });

  test("reports destination creation errors without changing source data", async () => {
    const f = fixture();
    const db = create(f.source);
    db.close();
    writeFileSync(f.destination, "parent is a file");
    const before = readFileSync(f.source);
    const result = await run(f.root, [
      f.source,
      join(f.destination, "child.sqlite3"),
    ]);
    expect(result.status).toBe(1);
    expect(readFileSync(f.source)).toEqual(before);
    expect(readFileSync(f.destination, "utf8")).toBe("parent is a file");
  });

  test("keeps positional help, option terminators, and argument error status", async () => {
    const f = fixture();
    const db = create(join(f.root, "-source"));
    db.close();
    expect((await run(f.root, ["--", "-source", "-destination"])).status).toBe(
      0,
    );
    expect(rows(join(f.root, "-destination"))).toEqual(
      rows(join(f.root, "-source")),
    );
    for (const args of [[], ["source"], ["a", "b", "c"], ["--help=1"]])
      expect((await run(f.root, args)).status).toBe(2);
    for (const args of [["--unknown", "--h"], ["-hignored=value"]]) {
      const help = await run(f.root, args);
      expect(help.status).toBe(0);
      expect(help.stdout).toContain("source destination");
    }
  });
});
