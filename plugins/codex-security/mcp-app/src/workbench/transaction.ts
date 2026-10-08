import type { DatabaseSync } from "node:sqlite";

export function transaction<T>(
  database: DatabaseSync,
  begin: "BEGIN" | "BEGIN IMMEDIATE",
  action: () => T,
): T {
  database.exec(begin);
  try {
    const result = action();
    database.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      database.exec("ROLLBACK");
    } catch {
      // SQLite can roll back automatically after a storage failure.
    }
    throw error;
  }
}
