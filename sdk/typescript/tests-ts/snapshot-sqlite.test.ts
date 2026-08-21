import { spawnSync } from "node:child_process";
import { linkSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");

describe("SQLite snapshot helper", () => {
  test("rejects destinations that identify the source database", () => {
    expect(python).not.toBeNull();
    const directory = mkdtempSync(join(tmpdir(), "codex-security-snapshot-"));
    const database = join(directory, "source.sqlite3");
    const alias = join(directory, "source-alias.sqlite3");

    try {
      const setup = spawnSync(
        python!,
        [
          "-c",
          [
            "import sqlite3, sys",
            "connection = sqlite3.connect(sys.argv[1])",
            "connection.execute('CREATE TABLE sample(value TEXT)')",
            "connection.commit()",
            "connection.close()",
          ].join("; "),
          database,
        ],
        { encoding: "utf8", timeout: 5_000 },
      );
      expect(setup.status, setup.stderr).toBe(0);
      linkSync(database, alias);

      for (const destination of [database, alias]) {
        const result = spawnSync(
          python!,
          [
            join(PLUGIN_ROOT, "scripts", "snapshot_sqlite.py"),
            database,
            destination,
          ],
          {
            encoding: "utf8",
            timeout: 2_000,
            killSignal: "SIGKILL",
          },
        );
        expect(result.status, result.stderr).toBe(2);
        expect(result.stderr).toContain(
          "source and destination must refer to different database files",
        );
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
