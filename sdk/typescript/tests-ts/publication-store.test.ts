import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  preparePublicationStore,
  recordPublishedIssues,
} from "../src/publication-store.js";
import type { PreparedScanPublication } from "../src/publication.js";
import type { PublishedScanIssue } from "../src/publish.js";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const SCAN_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_SCAN_ID = "33333333-3333-4333-8333-333333333333";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

interface PublicationFixture {
  environment: NodeJS.ProcessEnv;
  publication: PreparedScanPublication;
  python: string;
  stateDirectory: string;
}

async function publicationFixture(
  options: {
    count?: number;
    createDatabase?: boolean;
    seedScan?: boolean;
  } = {},
): Promise<PublicationFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-publication-store-")),
  );
  temporaryDirectories.push(root);
  const scanDirectory = join(root, "completed-scan");
  await mkdir(scanDirectory, { mode: 0o700 });
  const stateDirectory = join(root, "state");
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) {
    throw new Error(
      "Publication workbench tests require a Python interpreter.",
    );
  }
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: stateDirectory,
    PYTHON: python,
  };
  const publication: PreparedScanPublication = {
    scanId: SCAN_ID,
    uploadId: SCAN_ID,
    scanDirectory,
    destination: {
      type: "linear",
      teamId: "team-example",
      projectId: "project-example",
    },
    issues: Array.from({ length: options.count ?? 2 }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      title: `[Codex Security][HIGH] Example finding ${index + 1}`,
      description: `Example finding ${index + 1}`,
      priority: 2,
    })),
  };
  const fixture = { environment, publication, python, stateDirectory };
  if (options.createDatabase !== false) {
    await runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, [
      "database-info",
    ]);
    if (options.seedScan !== false) seedPublicationScan(fixture, publication);
  }
  return fixture;
}

function seedPublicationScan(
  fixture: PublicationFixture,
  publication: PreparedScanPublication,
): void {
  const workspaceId = randomUUID();
  const seed = spawnSync(
    fixture.python,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sqlite3, sys",
        "database, workspace_id, publication = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])",
        "connection = sqlite3.connect(database)",
        "connection.execute('PRAGMA foreign_keys = ON')",
        "timestamp = '2026-08-01T00:00:00Z'",
        "connection.execute('INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)', (workspace_id, timestamp, timestamp))",
        "connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (publication['scanId'], workspace_id, publication['scanDirectory'], 'example-revision', '.', 'standard', publication['scanDirectory'], 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
        "for issue in publication['issues']:",
        "    connection.execute('INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING', (issue['findingId'], 'fingerprint-' + issue['findingId'], 'example-rule', issue['findingId'], timestamp, timestamp))",
        "    connection.execute('INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity, confidence, remediation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (issue['occurrenceId'], issue['findingId'], publication['scanId'], issue['title'], 'example summary', 'high', 'high', 'example remediation', timestamp))",
        "connection.commit()",
        "connection.close()",
      ].join("\n"),
      join(fixture.stateDirectory, "workbench.sqlite3"),
      workspaceId,
      JSON.stringify(publication),
    ],
    { encoding: "utf8" },
  );
  expect(seed.status, seed.stderr).toBe(0);
}

function databaseRows(
  fixture: PublicationFixture,
  query: string,
  values: readonly unknown[] = [],
): Record<string, unknown>[] {
  const result = spawnSync(
    fixture.python,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sqlite3, sys",
        "connection = sqlite3.connect(sys.argv[1])",
        "connection.row_factory = sqlite3.Row",
        "cursor = connection.execute(sys.argv[2], json.loads(sys.argv[3]))",
        "rows = [dict(row) for row in cursor.fetchall()] if cursor.description else []",
        "connection.commit()",
        "connection.close()",
        "print(json.dumps(rows))",
      ].join("\n"),
      join(fixture.stateDirectory, "workbench.sqlite3"),
      query,
      JSON.stringify(values),
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout) as Record<string, unknown>[];
}

function publishedIssue(
  publication: PreparedScanPublication,
  index: number,
  identifier = `EXAMPLE-${index + 1}`,
): PublishedScanIssue {
  const issue = publication.issues[index]!;
  return {
    findingId: issue.findingId,
    occurrenceId: issue.occurrenceId,
    issueIdentifier: identifier,
    url: `https://linear.app/example/issue/${identifier}`,
  };
}

describe("persisted finding publication associations", () => {
  test("rolls back failed migrations without losing populated scan history", async () => {
    const fixture = await publicationFixture({ count: 1 });
    await recordPublishedIssues(
      fixture.publication,
      [publishedIssue(fixture.publication, 0)],
      fixture.environment,
    );
    databaseRows(
      fixture,
      "INSERT INTO finding_triage (occurrence_id, status, close_reason, note, updated_at) VALUES (?, 'closed', 'false_positive', 'synthetic triage note', '2026-08-01T00:00:00Z')",
      [fixture.publication.issues[0]!.occurrenceId],
    );

    const probe = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_db as db
import workbench_schema as schema

connection = sqlite3.connect(sys.argv[2])
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
db.apply_migrations(connection)
before = list(connection.iterdump())
next_version = max(version for version, _, _ in schema.MIGRATIONS) + 1
failing = (next_version, "synthetic failing migration", """
CREATE TABLE synthetic_migration_probe (value TEXT);
INSERT INTO synthetic_migration_probe VALUES ('synthetic');
DELETE FROM finding_triage;
INSERT INTO synthetic_missing_table VALUES (1);
""")
try:
    schema.apply_migrations(connection, (*schema.MIGRATIONS, failing), db.now, db.backfill_security_targets)
except sqlite3.OperationalError as error:
    assert "synthetic_missing_table" in str(error), error
else:
    raise AssertionError("The injected migration must fail")
assert not connection.in_transaction
assert list(connection.iterdump()) == before, "Failed migration changed committed data or schema"
db.apply_migrations(connection)
db.apply_migrations(connection)
assert list(connection.iterdump()) == before, "Reapplying migrations changed existing history"
assert list(connection.execute("PRAGMA foreign_key_check")) == []
assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print(json.dumps({table: connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] for table in ("scans", "finding_occurrences", "finding_triage", "finding_publications")}))
connection.close()
`,
        join(PLUGIN_ROOT, "scripts"),
        join(fixture.stateDirectory, "workbench.sqlite3"),
      ],
      { encoding: "utf8", env: fixture.environment },
    );
    expect(probe.status, probe.stderr).toBe(0);
    expect(JSON.parse(probe.stdout)).toEqual({
      scans: 1,
      finding_occurrences: 1,
      finding_triage: 1,
      finding_publications: 1,
    });
  });

  test("upgrades existing scan history and verifies every completed finding before publication", async () => {
    const fixture = await publicationFixture();
    databaseRows(fixture, "DROP TABLE finding_publications");
    databaseRows(fixture, "DELETE FROM schema_migrations WHERE version >= ?", [
      29,
    ]);

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).resolves.toBeUndefined();

    expect(
      databaseRows(
        fixture,
        "SELECT version, name FROM schema_migrations WHERE version >= ? ORDER BY version",
        [29],
      ),
    ).toEqual([
      { version: 29, name: "persist finding publication associations" },
      {
        version: 30,
        name: "preserve team-only finding publication associations",
      },
    ]);
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("upgrades existing project-scoped associations without changing recorded issues", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const original = publishedIssue(fixture.publication, 0, "EXAMPLE-401");
    await recordPublishedIssues(
      fixture.publication,
      [original],
      fixture.environment,
    );

    databaseRows(
      fixture,
      "DROP INDEX finding_publications_team_only_occurrence",
    );
    databaseRows(
      fixture,
      "DROP INDEX finding_publications_team_only_external_issue",
    );
    databaseRows(fixture, "DELETE FROM schema_migrations WHERE version = ?", [
      30,
    ]);

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).resolves.toBeUndefined();

    expect(
      databaseRows(
        fixture,
        "SELECT version, name FROM schema_migrations WHERE version = ?",
        [30],
      ),
    ).toEqual([
      {
        version: 30,
        name: "preserve team-only finding publication associations",
      },
    ]);
    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications",
      ),
    ).toEqual([
      {
        project_id: "project-example",
        external_id: original.issueIdentifier,
      },
    ]);
  });

  test("rejects a missing local scan-history database without creating one", async () => {
    const fixture = await publicationFixture({ createDatabase: false });

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/scan-history database does not exist/u);

    expect(existsSync(fixture.stateDirectory)).toBe(false);
  });

  test("rejects a scan absent from existing local scan history", async () => {
    const fixture = await publicationFixture({ seedScan: false });

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/scan is not present in the local/u);
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("rejects an incomplete scan before publication", async () => {
    const fixture = await publicationFixture();
    databaseRows(fixture, "UPDATE scans SET status = ? WHERE id = ?", [
      "running",
      SCAN_ID,
    ]);

    await expect(
      preparePublicationStore(fixture.publication, fixture.environment),
    ).rejects.toThrow(/Only completed scans/u);
  });

  test("rejects a selected directory that differs from its recorded scan", async () => {
    const fixture = await publicationFixture();
    const anotherDirectory = join(fixture.stateDirectory, "another-scan");
    await mkdir(anotherDirectory, { mode: 0o700 });

    await expect(
      preparePublicationStore(
        { ...fixture.publication, scanDirectory: anotherDirectory },
        fixture.environment,
      ),
    ).rejects.toThrow(/directory does not match/u);
  });

  test("rejects missing, mismatched, or omitted scan findings before publication", async () => {
    const fixture = await publicationFixture();

    for (const issues of [
      [
        {
          ...fixture.publication.issues[0]!,
          occurrenceId: "occurrence-not-in-scan",
        },
        fixture.publication.issues[1]!,
      ],
      [
        { ...fixture.publication.issues[0]!, findingId: "finding-not-in-scan" },
        fixture.publication.issues[1]!,
      ],
      [fixture.publication.issues[0]!],
    ]) {
      await expect(
        preparePublicationStore(
          { ...fixture.publication, issues },
          fixture.environment,
        ),
      ).rejects.toThrow(/finding|occurrence/u);
    }
  });

  test("rejects a real finding occurrence that belongs to another scan", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const anotherDirectory = join(fixture.stateDirectory, "another-scan");
    await mkdir(anotherDirectory, { mode: 0o700 });
    const otherScan: PreparedScanPublication = {
      ...fixture.publication,
      scanId: OTHER_SCAN_ID,
      uploadId: OTHER_SCAN_ID,
      scanDirectory: anotherDirectory,
      issues: [
        {
          ...fixture.publication.issues[0]!,
          findingId: "finding-other-scan",
          occurrenceId: "occurrence-other-scan",
        },
      ],
    };
    seedPublicationScan(fixture, otherScan);

    await expect(
      preparePublicationStore(
        { ...fixture.publication, issues: otherScan.issues },
        fixture.environment,
      ),
    ).rejects.toThrow(/does not belong to the completed scan/u);
  });

  test("returns only database-backed current results in original finding order", async () => {
    const fixture = await publicationFixture();
    const first = publishedIssue(fixture.publication, 0, "EXAMPLE-101");
    const second = publishedIssue(fixture.publication, 1, "EXAMPLE-102");

    const created = await recordPublishedIssues(
      fixture.publication,
      [second, first],
      fixture.environment,
    );

    expect(created).toEqual([first, second]);
    expect(
      databaseRows(
        fixture,
        "SELECT scan_id, finding_id, occurrence_id, destination_type, team_id, project_id, external_id, external_url FROM finding_publications ORDER BY finding_id",
      ),
    ).toEqual([
      {
        scan_id: SCAN_ID,
        finding_id: first.findingId,
        occurrence_id: first.occurrenceId,
        destination_type: "linear",
        team_id: "team-example",
        project_id: "project-example",
        external_id: first.issueIdentifier,
        external_url: first.url,
      },
      {
        scan_id: SCAN_ID,
        finding_id: second.findingId,
        occurrence_id: second.occurrenceId,
        destination_type: "linear",
        team_id: "team-example",
        project_id: "project-example",
        external_id: second.issueIdentifier,
        external_url: second.url,
      },
    ]);
  });

  test("records optional issue URLs without inventing one", async () => {
    const fixture = await publicationFixture({ count: 1 });
    const issue = publishedIssue(fixture.publication, 0);
    delete issue.url;

    await expect(
      recordPublishedIssues(fixture.publication, [issue], fixture.environment),
    ).resolves.toEqual([issue]);
    expect(
      databaseRows(fixture, "SELECT external_url FROM finding_publications"),
    ).toEqual([{ external_url: null }]);
  });

  test("persists team-only issues with a null project and rejects conflicting associations", async () => {
    const fixture = await publicationFixture();
    const publication: PreparedScanPublication = {
      ...fixture.publication,
      destination: {
        type: "linear",
        teamId: fixture.publication.destination.teamId,
      },
    };
    const first = publishedIssue(publication, 0, "EXAMPLE-411");
    const second = publishedIssue(publication, 1, "EXAMPLE-412");

    await expect(
      preparePublicationStore(publication, fixture.environment),
    ).resolves.toBeUndefined();
    await expect(
      recordPublishedIssues(publication, [first], fixture.environment),
    ).resolves.toEqual([first]);
    await expect(
      recordPublishedIssues(publication, [first], fixture.environment),
    ).resolves.toEqual([first]);

    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications",
      ),
    ).toEqual([{ project_id: null, external_id: first.issueIdentifier }]);

    await expect(
      recordPublishedIssues(
        publication,
        [{ ...second, issueIdentifier: first.issueIdentifier }],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different finding/u);
    await expect(
      recordPublishedIssues(
        publication,
        [{ ...first, url: "https://linear.app/example/issue/EXAMPLE-OTHER" }],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different URL/u);

    await expect(
      recordPublishedIssues(publication, [first, second], fixture.environment),
    ).resolves.toEqual([first, second]);
    expect(
      databaseRows(
        fixture,
        "SELECT project_id, external_id FROM finding_publications ORDER BY id",
      ),
    ).toEqual([
      { project_id: null, external_id: first.issueIdentifier },
      { project_id: null, external_id: second.issueIdentifier },
    ]);
  });

  test("replays exact associations without suppressing distinct issues on republish", async () => {
    const fixture = await publicationFixture();
    const original = publishedIssue(fixture.publication, 0, "EXAMPLE-201");
    const replacement = publishedIssue(fixture.publication, 0, "EXAMPLE-202");
    const additional = publishedIssue(fixture.publication, 1, "EXAMPLE-203");

    await expect(
      recordPublishedIssues(
        fixture.publication,
        [original],
        fixture.environment,
      ),
    ).resolves.toEqual([original]);
    await expect(
      recordPublishedIssues(
        fixture.publication,
        [additional, replacement],
        fixture.environment,
      ),
    ).resolves.toEqual([replacement, additional]);
    await expect(
      recordPublishedIssues(
        fixture.publication,
        [additional, replacement],
        fixture.environment,
      ),
    ).resolves.toEqual([replacement, additional]);

    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 3 }]);
    expect(
      databaseRows(
        fixture,
        "SELECT external_id FROM finding_publications WHERE finding_id = ? ORDER BY id",
        [original.findingId],
      ),
    ).toEqual([
      { external_id: original.issueIdentifier },
      { external_id: replacement.issueIdentifier },
    ]);
  });

  test("rejects swapped occurrences, duplicate mappings, and malformed issue IDs", async () => {
    const fixture = await publicationFixture();
    const first = publishedIssue(fixture.publication, 0);
    const second = publishedIssue(fixture.publication, 1);

    for (const records of [
      [{ ...first, occurrenceId: second.occurrenceId }],
      [first, { ...first, issueIdentifier: "EXAMPLE-999" }],
      [first, { ...second, issueIdentifier: first.issueIdentifier }],
      [{ ...first, issueIdentifier: "  " }],
    ]) {
      await expect(
        recordPublishedIssues(
          fixture.publication,
          records,
          fixture.environment,
        ),
      ).rejects.toThrow(/finding|occurrence|issue|association/u);
    }
    expect(
      databaseRows(
        fixture,
        "SELECT COUNT(*) AS count FROM finding_publications",
      ),
    ).toEqual([{ count: 0 }]);
  });

  test("rolls back the entire import when an issue belongs to another finding", async () => {
    const fixture = await publicationFixture();
    const existing = publishedIssue(fixture.publication, 0, "EXAMPLE-301");
    await recordPublishedIssues(
      fixture.publication,
      [existing],
      fixture.environment,
    );

    await expect(
      recordPublishedIssues(
        fixture.publication,
        [
          publishedIssue(fixture.publication, 0, "EXAMPLE-302"),
          publishedIssue(fixture.publication, 1, existing.issueIdentifier),
        ],
        fixture.environment,
      ),
    ).rejects.toThrow(/already associated with a different finding/u);

    expect(
      databaseRows(
        fixture,
        "SELECT finding_id, external_id FROM finding_publications ORDER BY id",
      ),
    ).toEqual([
      {
        finding_id: existing.findingId,
        external_id: existing.issueIdentifier,
      },
    ]);
  });
});
