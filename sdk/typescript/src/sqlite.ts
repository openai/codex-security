import { createRequire } from "node:module";
import { sqliteFilename } from "./windows-path.js";

export interface RuntimeDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): {
    all(...parameters: (string | number)[]): unknown[];
    finalize?(): void;
  };
  close(): void;
}

export function sqliteDatabaseOpener(
  access: "read-existing" | "read-write" = "read-write",
) {
  const require = createRequire(import.meta.url);
  const bun = process.versions["bun"] !== undefined;
  const Database = (
    bun ? require("bun:sqlite").Database : require("node:sqlite").DatabaseSync
  ) as new (filename: string, options?: object) => RuntimeDatabase;

  return (path: string): RuntimeDatabase => {
    const filename = sqliteFilename(path);
    if (access === "read-write") return new Database(filename);
    // Apple's SQLite requires write access to initialize missing WAL sidecars.
    // The history reader sets PRAGMA query_only on this existing-file connection.
    return new Database(
      filename,
      bun
        ? {
            readonly: process.platform !== "darwin",
            readwrite: process.platform === "darwin",
            create: false,
          }
        : { readOnly: true },
    );
  };
}
