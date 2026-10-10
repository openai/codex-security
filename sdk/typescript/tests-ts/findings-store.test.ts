import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import type { EmbeddedFinding } from "../src/server/storage.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("findings-store-");
const example = (
  JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
      "utf8",
    ),
  ) as FindingsDocument
).findings[0]!;

function finding(index = 1): Finding {
  return {
    ...structuredClone(example),
    findingId: `csf_${index.toString(16).padStart(24, "0")}`,
    occurrenceId: `occ_${index.toString(16).padStart(24, "0")}`,
    fingerprints: {
      algorithm: "codex-security/v1",
      primary: `codex-security/v1:sha256:${index.toString(16).padStart(64, "0")}`,
    },
    title: `Synthetic finding ${index}`,
    extensions: { evidence: { text: "complete evidence ✓", values: [1, 2] } },
  };
}

function embedded(
  index: number,
  vector = [1, 0],
  model = "synthetic",
): EmbeddedFinding {
  return { finding: finding(index), embedding: { model, vector } };
}

afterEach(cleanup);

async function fixture() {
  const directory = await temporaryDirectory();
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(directory, "state with spaces"),
  };
  return { environment, store: new SqliteFindingsStore(environment) };
}

async function database(
  environment: NodeJS.ProcessEnv,
  script: string,
  input?: unknown,
): Promise<unknown> {
  const python = await resolvePluginPython({ environment });
  const result = await runCodexCommand(
    { command: python },
    [
      "-I",
      "-B",
      "-X",
      "utf8",
      "-c",
      `import json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
db = sqlite3.connect(path)
db.row_factory = sqlite3.Row
${script}
`,
      join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      join(PLUGIN_ROOT, "scripts"),
    ],
    environment,
    input === undefined ? undefined : JSON.stringify(input),
  );
  expect(result.success, result.stderr).toBe(true);
  return JSON.parse(result.stdout);
}

test("persists complete findings, repository associations, pages, and idempotent groups atomically", async () => {
  const { store, environment } = await fixture();
  await store.initialize();
  const entries = [embedded(1), embedded(2), embedded(3)];
  expect(await store.insert(entries.slice(0, 2), "repository-a")).toEqual(
    entries.slice(0, 2).map(({ finding }) => finding.findingId),
  );
  await store.insert([entries[0]!], "repository-b");
  await store.insert([entries[2]!]);
  const ids = entries.map(({ finding }) => finding.findingId);
  const groups = await store.storeDedupeGroups([ids.slice(0, 2), ids.slice(1)]);
  expect(await store.storeDedupeGroups([ids.slice(0, 2).reverse()])).toEqual([
    groups[0]!,
  ]);
  await expect(
    store.storeDedupeGroups([[ids[0]!, finding(4).findingId]]),
  ).rejects.toMatchObject({ code: "finding_conflict" });
  const conflict = embedded(1);
  conflict.finding.fingerprints.primary = finding(4).fingerprints.primary;
  await expect(
    store.insert([embedded(4), conflict], "repository-a"),
  ).rejects.toMatchObject({ code: "finding_conflict" });
  const reopened = new SqliteFindingsStore(environment);
  await reopened.initialize();
  expect(await reopened.list({ limit: 2, offset: 0 })).toEqual({
    findings: entries.slice(0, 2).map((e) => e.finding),
    limit: 2,
    offset: 0,
    total: 3,
    nextOffset: 2,
  });
  expect((await reopened.list({ limit: 2, offset: 2 })).findings).toEqual([
    entries[2]!.finding,
  ]);
  expect(await reopened.listDedupeGroups(ids[1]!)).toHaveLength(2);
  expect(
    (
      await reopened.findPotentialDuplicates(ids[0]!, {
        repositoryId: "repository-a",
      })
    ).potentialDuplicates,
  ).toEqual([entries[1]!.finding]);
  expect(
    (
      await reopened.findPotentialDuplicates(ids[0]!, {
        repositoryId: "repository-b",
      })
    ).potentialDuplicates,
  ).toEqual([]);
  expect(
    (await reopened.findPotentialDuplicates(ids[0]!, { allRepositories: true }))
      .potentialDuplicates,
  ).toEqual(entries.slice(1).map((e) => e.finding));
  expect(
    await database(
      environment,
      "print(db.execute('SELECT COUNT(*) FROM scans').fetchone()[0])",
    ),
  ).toBe(0);
});

test("SQLite filters repository and embedding compatibility before exact cosine ranking", async () => {
  const { store, environment } = await fixture();
  await store.initialize();
  const anchor = embedded(1, [7, 0]);
  const boundary = embedded(2, [0.55, Math.sqrt(1 - 0.55 ** 2)]);
  const below = embedded(3, [0.54, Math.sqrt(1 - 0.54 ** 2)]);
  const otherModel = embedded(4, [1, 0], "other-model");
  const otherDimensions = embedded(5, [1, 0, 0]);
  const foreign = embedded(6);
  await store.insert(
    [anchor, below, otherModel, otherDimensions, boundary],
    "repository-a",
  );
  await store.insert([foreign], "repository-b");
  expect(
    await store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-a",
    }),
  ).toEqual({
    finding: anchor.finding,
    potentialDuplicates: [boundary.finding],
  });
  expect(
    await store.findPotentialDuplicates(anchor.finding.findingId, {
      allRepositories: true,
    }),
  ).toEqual({
    finding: anchor.finding,
    potentialDuplicates: [foreign.finding, boundary.finding],
  });
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      repositoryId: "repository-b",
    }),
  ).rejects.toMatchObject({ code: "finding_not_indexed" });
  await database(
    environment,
    `with db:
    db.execute("UPDATE finding_embeddings SET vector_json = '[0,0]' WHERE finding_id = ?", (json.load(sys.stdin),))
print("null")`,
    foreign.finding.findingId,
  );
  expect(
    (
      await store.findPotentialDuplicates(anchor.finding.findingId, {
        repositoryId: "repository-a",
      })
    ).potentialDuplicates,
  ).toEqual([boundary.finding]);
  await expect(
    store.findPotentialDuplicates(anchor.finding.findingId, {
      allRepositories: true,
    }),
  ).rejects.toMatchObject({ code: "embedding_failed" });
});

test("SQLite returns the stable top 50 documents through the SDK", async () => {
  const { store } = await fixture();
  await store.initialize();
  const entries = Array.from({ length: 61 }, (_, index) => embedded(index + 1));
  await store.insert(entries, "repository-a");
  await store.insert([entries[1]!], "repository-b");
  const result = await store.findPotentialDuplicates(
    entries[0]!.finding.findingId,
    {
      repositoryId: "repository-a",
    },
  );
  expect(result).toEqual({
    finding: entries[0]!.finding,
    potentialDuplicates: entries.slice(1, 51).map((entry) => entry.finding),
  });
  expect(
    (
      await store.findPotentialDuplicates(entries[0]!.finding.findingId, {
        allRepositories: true,
      })
    ).potentialDuplicates,
  ).toEqual(result.potentialDuplicates);
});

test("migrates existing complete scan findings and invalidates stale embeddings on CLI updates", async () => {
  const { store, environment } = await fixture();
  const original = finding();
  await database(
    environment,
    `from workbench_schema import MIGRATIONS, apply_migrations
finding = json.load(sys.stdin)
timestamp = "2026-01-01T00:00:00Z"
apply_migrations(db, tuple(m for m in MIGRATIONS if m[0] <= 32), lambda: timestamp, lambda _: None)
with db:
    db.execute("INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', ?, ?)", (timestamp, timestamp))
    db.execute("INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES ('repository-history', '/synthetic/repository', 'Synthetic repository', ?, ?)", (timestamp, timestamp))
    db.execute("INSERT INTO scans (id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES ('scan', 'workspace', 'repository-history', '/synthetic/repository', 'revision', '.', 'standard', '/synthetic/output', 'complete', 'reporting', ?, ?, ?)", (timestamp, timestamp, timestamp))
    db.execute("INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)", (finding["findingId"], finding["fingerprints"]["primary"], finding["ruleId"], finding["identity"]["anchor"], timestamp, timestamp))
    db.execute("INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) VALUES (?, ?, 'scan', ?, ?, ?, ?, ?, ?, ?)", (finding["occurrenceId"], finding["findingId"], finding["title"], finding["summary"], finding["severity"]["level"], finding["confidence"]["level"], finding["remediation"], json.dumps(finding), timestamp))
print("null")`,
    original,
  );
  await store.initialize();
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    original,
  ]);
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories')]))",
    ),
  ).toEqual([["repository-history", original.findingId]]);
  await store.insert([
    { finding: original, embedding: { model: "synthetic", vector: [1, 0] } },
  ]);

  const update = `from workbench_finding_index import index_findings
with db:
    index_findings(db, "scan", {"findings": [json.load(sys.stdin)]}, "2026-01-02T00:00:00Z")
print(db.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0])`;
  expect(await database(environment, update, original)).toBe(1);
  const changed = { ...original, summary: "A newer scan updated this finding" };
  expect(await database(environment, update, changed)).toBe(0);
  await expect(
    store.findPotentialDuplicates(original.findingId, {
      allRepositories: true,
    }),
  ).rejects.toMatchObject({ code: "finding_not_indexed" });
  expect((await store.list({ limit: 50, offset: 0 })).findings).toEqual([
    changed,
  ]);
  await database(environment, update, finding(2));
  expect(
    await database(
      environment,
      "print(json.dumps([list(row) for row in db.execute('SELECT repository_id, finding_id FROM finding_repositories ORDER BY finding_id')]))",
    ),
  ).toEqual([
    ["repository-history", original.findingId],
    ["repository-history", finding(2).findingId],
  ]);
});
