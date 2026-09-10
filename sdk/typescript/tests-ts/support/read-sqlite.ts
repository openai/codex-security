import { spawnSync } from "node:child_process";
import { expect } from "bun:test";

// Read standalone WAL databases with Node's bundled SQLite on every platform.
export function readSqliteRows<T>(path: string, sql: string): T[] {
  const child = spawnSync(
    Bun.which("node")!,
    [
      "--no-warnings",
      "--experimental-sqlite",
      "--input-type=module",
      "-e",
      `import { DatabaseSync } from "node:sqlite";
       const database = new DatabaseSync(process.argv[1], { readOnly: true });
       try {
         const statement = database.prepare(process.argv[2]);
         statement.setReadBigInts(true);
         console.log(JSON.stringify(statement.all(), (_key, value) => {
           if (typeof value !== "bigint") return value;
           const number = Number(value);
           return Number.isSafeInteger(number) ? number : value.toString();
         }));
       }
       finally { database.close(); }`,
      path,
      sql,
    ],
    { encoding: "utf8" },
  );
  expect(child.status, child.stderr).toBe(0);
  return JSON.parse(child.stdout) as T[];
}
