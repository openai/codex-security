"""Synthetic accepted workers for the installed finalization/SDK contract test."""
import hashlib
import json
import sqlite3
import sys
import uuid
from pathlib import Path

payload = json.load(sys.stdin)
scan_id = payload["scanId"]
scan_dir = Path(payload["scanDir"])
with sqlite3.connect(payload["database"]) as connection:
    connection.execute("PRAGMA foreign_keys = ON")
    timestamp = connection.execute(
        "SELECT created_at FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    connection.execute(
        "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
        "coordinator_generation = 2, phase = 'reducing', "
        "discovery_runs_dispatched = 2, completion_sequence = 2, "
        "consecutive_no_new = 2, stop_after_no_new = 2, max_discovery_runs = 2 "
        "WHERE scan_id = ?", (scan_id,),
    )
    discoveries = []
    for kind, label in [("discovery", "review-1"), ("discovery", "review-2"), ("dedup", "merge-1")]:
        draft = dict(payload["draft"])
        if kind == "dedup":
            draft["sourceCoverage"] = draft.pop("coverage")
        encoded = json.dumps(draft).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        worker_id = str(uuid.uuid4())
        output = scan_dir / "artifacts" / "deep_discovery" / label / "output"
        output.mkdir(parents=True)
        prompt = output.parent / "prompt.md"
        prompt.write_text("Synthetic accepted audit\n")
        accepted = output / "checkpoints" / f"{digest}.json"
        accepted.parent.mkdir()
        accepted.write_bytes(encoded)
        result = output / "result.json"
        result.write_bytes(encoded)
        sequence = len(discoveries) + 1 if kind == "discovery" else None
        connection.execute(
            "INSERT INTO deep_scan_workers "
            "(id, scan_id, kind, status, merge_state, prompt_path, artifact_dir, "
            "result_manifest_path, attempt, completion_sequence, created_at, updated_at, completed_at) "
            "VALUES (?, ?, ?, 'succeeded', ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (worker_id, scan_id, kind, "merged" if kind == "discovery" else "none",
             str(prompt), str(output), str(result), sequence, timestamp, timestamp, timestamp),
        )
        connection.execute(
            "INSERT INTO deep_scan_attempts "
            "(scan_id, worker_id, attempt, status, started_at, completed_at, accepted_result_path, accepted_result_sha256) "
            "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan_id, worker_id, timestamp, timestamp, str(accepted), digest),
        )
        if kind == "discovery":
            discoveries.append(worker_id)
        else:
            for order, discovery in enumerate(discoveries):
                connection.execute(
                    "INSERT INTO deep_scan_dedup_inputs "
                    "(scan_id, dedup_worker_id, discovery_worker_id, input_order) VALUES (?, ?, ?, ?)",
                    (scan_id, worker_id, discovery, order),
                )
            # The committed immutable reference survives loss of the replaceable output.
            result.unlink()
print(json.dumps({"resultPath": str(result), "acceptedPath": str(accepted)}))
