// Assert persisted findings and embeddings in the smoke-test container.
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";

const expectedIds = (JSON.parse(process.argv[2]!) as string[]).sort();
const db = new DatabaseSync("/state/workbench.sqlite3");
try {
  db.exec("PRAGMA busy_timeout = 5000");
  assert.ok(
    Number(
      db.prepare("SELECT COUNT(*) AS count FROM schema_migrations").get()![
        "count"
      ],
    ) > 0,
  );
  const findingIds = db
    .prepare("SELECT id FROM findings ORDER BY id")
    .all()
    .map((row) => row["id"]);
  assert.deepEqual(findingIds, expectedIds);
  const embeddings = db
    .prepare(
      "SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id",
    )
    .all();
  assert.deepEqual(
    embeddings.map((row) => row["finding_id"]),
    expectedIds,
  );
  for (const row of embeddings) {
    const vector = JSON.parse(row["vector_json"] as string);
    assert.equal(
      row["model"],
      "text-embedding-3-large",
      row["finding_id"] as string,
    );
    assert.equal(vector.length, 1536, row["finding_id"] as string);
  }
} finally {
  db.close();
}
console.log(`Verified ${expectedIds.length} stored findings and embeddings.`);
