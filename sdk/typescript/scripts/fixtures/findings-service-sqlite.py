"""Assert persisted findings and embeddings in the smoke-test container."""

import json
import sqlite3
import sys

expected_ids = sorted(json.loads(sys.argv[1]))
with sqlite3.connect("/state/workbench.sqlite3") as db:
    assert db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] > 0
    finding_ids = [row[0] for row in db.execute("SELECT id FROM findings ORDER BY id")]
    assert finding_ids == expected_ids, (finding_ids, expected_ids)
    embeddings = db.execute(
        "SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id"
    ).fetchall()
    assert [row[0] for row in embeddings] == expected_ids
    for finding_id, model, vector_json in embeddings:
        vector = json.loads(vector_json)
        assert model == "text-embedding-3-large", (finding_id, model)
        assert len(vector) == 1536, (finding_id, len(vector))

print(f"Verified {len(expected_ids)} stored findings and embeddings.")
