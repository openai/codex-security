import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, os, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "from filesystem_identity import serialize_filesystem_identity",
  "settings = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL, display_name TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT, scan_dir TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT PRIMARY KEY, status TEXT, updated_at TEXT, close_reason TEXT);",
  "CREATE TABLE finding_decisions (id TEXT, occurrence_id TEXT, status TEXT, close_reason TEXT, note TEXT, created_at TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "CREATE TABLE scan_comparison_matches (before_occurrence_id TEXT, after_occurrence_id TEXT);",
  "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?, ?)', [('current-target', '/current/repository', 'current'), ('stale-target', '/stale/repository', 'stale')])",
  "stale_directory = sys.argv[1] if settings.get('coverageFailure') in ('noncanonical', 'pruned') else '/private/tmp/codex-security-findings-index-missing-stale'",
  "connection.executemany('INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old', 'current-target', '/current/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/current-old'),",
  "    ('current-new', 'current-target', '/current/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new'),",
  "    ('reused-legacy', None, '/current/repository', 'complete', 'sealed', '2026-03-01', '2026-03-01', '.', '/private/tmp/reused-legacy'),",
  "    ('stale-old', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/stale-old'),",
  "    ('stale-new', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', stale_directory),",
  "    ('orphan-old', None, '/orphan/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/orphan-old'),",
  "    ('orphan-new', None, '/orphan/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/orphan-new'),",
  "])",
  "if settings.get('unsealedScans'):",
  "    connection.execute(\"UPDATE scans SET seal_manifest_digest = NULL WHERE target_id = 'stale-target' OR target_id IS NULL\")",
  "if settings.get('inactiveRepresentative'):",
  "    connection.execute(\"INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir) VALUES ('current-followup', 'current-target', '/current/repository', 'complete', 'sealed', '2026-03-01', '2026-03-01', '.', '/private/tmp/current-followup')\")",
  "if settings.get('clockRollback'):",
  "    connection.execute(\"UPDATE scans SET started_at = '2025-12-01' WHERE id = 'current-new'\")",
  "if settings.get('mixedLegacyOwnership'):",
  "    connection.execute(\"UPDATE scans SET target_device = 7, target_inode = 9 WHERE id = 'current-new'\")",
  "if settings.get('replacedCheckout'):",
  "    connection.execute(\"UPDATE scans SET target_device = -1, target_inode = -1 WHERE target_id = 'current-target'\")",
  "    connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (sys.argv[1],))",
  "if settings.get('ownershipTransition') or settings.get('ownershipReuse'):",
  "    connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (sys.argv[1],))",
  "    connection.execute(\"UPDATE scans SET target_path = ? WHERE target_id = 'current-target'\", (sys.argv[1],))",
  "    metadata = os.stat(sys.argv[1])",
  "    if settings.get('ownershipReuse'):",
  "        connection.execute(\"UPDATE scans SET target_device = ?, target_inode = ?, started_at = '2027-01-01' WHERE id = 'current-old'\", (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))",
  "    connection.execute(\"INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir, target_device, target_inode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\", ('previous-owner-identity', 'current-target', sys.argv[1], 'complete', 'sealed', '2026-01-15', '2026-01-15', '.', '/private/tmp/previous-owner', -1, -1))",
  "    connection.execute(\"DELETE FROM scans WHERE id = 'current-new'\")",
  "    connection.execute(\"INSERT INTO scans (id, target_id, target_path, status, seal_manifest_digest, started_at, updated_at, scope, scan_dir, target_device, target_inode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\", ('current-new', 'current-target', sys.argv[1], 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new', serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))",
  "if settings.get('legacyDescendant'):",
  "    connection.execute(\"UPDATE scans SET target_path = ? WHERE id = 'reused-legacy'\", (os.path.join(sys.argv[1], 'nested'),))",
  "if settings.get('missingOwnershipCheckout'):",
  "    missing_checkout = os.path.join(sys.argv[1], 'codex-security-missing-owner')",
  "    connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (missing_checkout,))",
  "    connection.execute(\"UPDATE scans SET target_path = ? WHERE target_id = 'current-target'\", (missing_checkout,))",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('reused-legacy-occurrence', 'previous-owner-finding', 'reused-legacy', 'critical', '2026-03-01', 'Previous owner secret', 'Must never cross checkout owners'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "    ('orphan-old-occurrence', 'orphan-old-finding', 'orphan-old', 'high', '2026-01-01', 'Older orphan finding', 'Still outside follow-up coverage'),",
  "    ('orphan-new-occurrence', 'orphan-new-finding', 'orphan-new', 'medium', '2026-02-01', 'Latest orphan finding', 'Target row does not exist'),",
  "])",
  "if settings.get('legacyPriority'):",
  "    connection.execute(\"UPDATE finding_occurrences SET severity = 'low' WHERE id = 'current-new-occurrence'\")",
  "    connection.execute(\"UPDATE finding_occurrences SET severity = 'critical' WHERE id = 'orphan-old-occurrence'\")",
  "if settings.get('lateCompletion'):",
  "    connection.execute(\"UPDATE finding_occurrences SET finding_id = 'current-new-finding', created_at = '2026-03-01' WHERE id = 'current-old-occurrence'\")",
  "if settings.get('repeatedStableFinding'):",
  "    connection.execute(\"UPDATE finding_occurrences SET finding_id = 'current-new-finding' WHERE id = 'current-old-occurrence'\")",
  "if settings.get('targetlessHistory'):",
  "    connection.execute(\"INSERT INTO finding_triage VALUES ('orphan-new-occurrence', 'closed', '2026-01-02', 'false_positive')\")",
  "    connection.execute(\"INSERT INTO finding_decisions (occurrence_id) VALUES ('orphan-new-occurrence')\")",
  "    if settings['targetlessHistory'] == 'stable':",
  "        connection.execute(\"UPDATE finding_occurrences SET finding_id = 'orphan-old-finding' WHERE id = 'orphan-new-occurrence'\")",
  "    else:",
  "        connection.execute(\"INSERT INTO scan_comparison_matches VALUES ('orphan-old-occurrence', 'orphan-new-occurrence')\")",
  "if settings.get('closedBeforeRollback'):",
  "    connection.execute(\"UPDATE finding_occurrences SET finding_id = 'current-old-finding', created_at = '2025-12-02' WHERE id = 'current-new-occurrence'\")",
  "    connection.execute(\"INSERT INTO finding_triage VALUES ('current-old-occurrence', 'closed', '2026-01-02', ?)\", (settings['closedBeforeRollback'],))",
  "    connection.execute(\"INSERT INTO finding_decisions (occurrence_id) VALUES ('current-old-occurrence')\")",
  "if settings.get('matchedTriage') and not settings.get('closeAfterRediscovery') and not settings.get('pendingMatchedRemediation'):",
  "    decision_occurrence = 'current-new-occurrence' if settings['matchedTriage'] == 'false_positive' and not settings.get('ownershipReuse') and not settings.get('triageClockRollback') else 'current-old-occurrence'",
  "    connection.execute(\"INSERT INTO finding_triage VALUES (?, 'closed', '2026-01-02', ?)\", (decision_occurrence, settings['matchedTriage']))",
  "    connection.execute('INSERT INTO finding_decisions (occurrence_id) VALUES (?)', (decision_occurrence,))",
  "    if settings.get('triageClockRollback'):",
  "        connection.execute(\"INSERT INTO finding_triage VALUES ('current-new-occurrence', 'open', '2025-12-01', NULL)\")",
  "        connection.execute(\"INSERT INTO finding_decisions (occurrence_id) VALUES ('current-new-occurrence')\")",
  "connection.executemany('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'src/old.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/new.py', 'root_control', 0),",
  "    ('current-new-occurrence', 'src/secondary.py', 'sink', 1),",
  "    ('current-new-occurrence', 'src/ÄUTH-Straße.py', 'sink', 2),",
  "    ('reused-legacy-occurrence', 'src/previous-owner.py', 'root_control', 0),",
  "    ('stale-old-occurrence', 'src/stale.py', 'root_control', 0),",
  "    ('orphan-old-occurrence', 'src/orphan-old.py', 'root_control', 0),",
  "    ('orphan-new-occurrence', 'src/orphan-new.py', 'root_control', 0),",
  "])",
  "if settings.get('pendingMatchedRemediation'):",
  "    connection.execute(\"INSERT INTO finding_occurrences VALUES ('pending-occurrence', 'pending-finding', 'current-new', 'high', '2026-01-15', 'Pending finding', 'Pending remediation')\")",
  "    connection.execute(\"INSERT INTO finding_locations VALUES ('pending-occurrence', 'src/new.py', 'root_control', 0)\")",
  "    connection.execute(\"INSERT INTO scan_comparison_matches VALUES ('pending-occurrence', 'current-new-occurrence')\")",
  "if (settings.get('matchedTriage') and not settings.get('repeatedStableFinding')) or settings.get('indexedAliases'):",
  "    connection.execute('INSERT INTO scan_comparison_matches VALUES (?, ?)', ('current-old-occurrence', 'current-new-occurrence'))",
  "if settings.get('linkedWorktree'):",
  "    connection.execute(\"INSERT INTO security_targets VALUES ('linked-target', '/linked/repository', 'linked')\")",
  "    connection.execute(\"UPDATE scans SET target_id = 'linked-target', target_path = '/linked/repository' WHERE id = 'current-old'\")",
  "    if not settings.get('matchedTriage'):",
  "        linked_decision = 'current-old-occurrence' if settings.get('incompatibleSibling') else 'current-new-occurrence'",
  "        connection.execute(\"INSERT INTO finding_triage VALUES (?, 'closed', '2026-01-02', 'false_positive')\", (linked_decision,))",
  "        connection.execute('INSERT INTO finding_decisions (occurrence_id) VALUES (?)', (linked_decision,))",
  "    connection.execute(\"INSERT INTO scan_comparison_matches VALUES ('current-new-occurrence', 'stale-old-occurrence')\")",
  "    indexes.scan_history.repository_scan_scope = lambda _connection, _repository: (['scans.target_id IN (?, ?)'], ['current-target', 'linked-target'], ['current-target', 'linked-target'], ['/current/repository', '/linked/repository'])",
  "    indexes.scan_history._same_registered_repository = lambda _connection, _before, _after: not settings.get('incompatibleSibling', False)",
  "coverage_reads = []",
  "def coverage(scan):",
  "    assert scan['seal_manifest_digest'] is not None, 'Unsealed scan coverage was read.'",
  "    coverage_reads.append(scan['id'])",
  "    if settings.get('inactiveRepresentative') and scan['id'] == 'current-followup':",
  "        return {'completeness': 'complete', 'includePaths': ['src/new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    if settings.get('mixedLegacyOwnership') and scan['id'] == 'current-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    if scan['id'] == 'stale-new':",
  "        if settings.get('coverageFailure') == 'tampered':",
  "            raise SystemExit('The sealed scan manifest changed after completion.')",
  "        if settings.get('coverageFailure') == 'sealedArtifact':",
  "            raise SystemExit('coverage.json: sealed artifact changed or is missing')",
  "        if settings.get('coverageFailure') == 'pruned':",
  "            raise SystemExit('coverage.json: expected a regular file inside the scan directory.')",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    if scan['id'] == 'orphan-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/orphan-new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "args = argparse.Namespace(query=settings.get('query'), severity=None, status=None, target_id=settings.get('targetIds') or settings.get('targetId'), target_path=settings.get('targetPaths') or settings.get('targetPath'), repository=os.path.join(sys.argv[1], 'nested') if settings.get('scopedLegacyDescendant') else '/current/repository' if settings.get('linkedWorktree') else None, include_resolved=settings.get('includeResolved', False), offset=0, limit=20)",
  "if settings.get('repositories'):",
  "    indexes.scan_history.list_scans = lambda connection: {'scans': [{'scanId': row['id'], 'targetId': row['target_id']} for row in connection.execute('SELECT id, target_id FROM scans')]}",
  "    result = indexes.list_repositories(connection, read_coverage=coverage)",
  "else:",
  "    result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "finding_detail, overview_finding, scan_pages, rejected_previous_owner, rejected_previous_owner_list, rejected_legacy_owner, rejected_legacy_owner_list, rejected_legacy_descendant, rejected_legacy_descendant_list = None, None, None, None, None, None, None, None, None",
  "pending_remediation_error, pending_triage_rows, remediation_guard_error = None, None, None",
  "if settings.get('matchedTriage') or settings.get('targetlessHistory'):",
  "    import workbench_db as workbench",
  "    import workbench_finding_results as finding_results",
  "    if not settings.get('ownershipReuse'):",
  "        connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (sys.argv[1],))",
  "        connection.execute(\"UPDATE scans SET target_path = ? WHERE target_id = 'current-target'\", (sys.argv[1],))",
  "    if settings.get('missingCheckout'):",
  "        metadata = os.stat(sys.argv[1])",
  "        missing_checkout = os.path.join(sys.argv[1], 'codex-security-missing-checkout')",
  "        connection.execute(\"UPDATE security_targets SET current_path = ? WHERE id = 'current-target'\", (missing_checkout,))",
  "        connection.execute(\"UPDATE scans SET target_path = ?, target_device = ?, target_inode = ? WHERE target_id = 'current-target'\", (missing_checkout, serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))",
  "    connection.execute(\"ALTER TABLE finding_occurrences ADD COLUMN details_json TEXT DEFAULT '{}'\")",
  "    connection.execute(\"ALTER TABLE finding_occurrences ADD COLUMN confidence TEXT DEFAULT 'high'\")",
  "    connection.execute(\"ALTER TABLE finding_occurrences ADD COLUMN remediation TEXT DEFAULT 'Fix the finding.'\")",
  "    connection.execute('ALTER TABLE finding_locations ADD COLUMN start_line INTEGER DEFAULT 1')",
  "    connection.execute('ALTER TABLE finding_locations ADD COLUMN end_line INTEGER DEFAULT 1')",
  "    connection.execute('ALTER TABLE finding_triage ADD COLUMN note TEXT')",
  "    connection.execute(\"UPDATE finding_triage SET note = 'Verified test dismissal' WHERE close_reason = 'false_positive'\")",
  "    workbench.require_scan_target_identity = lambda *arguments, **keywords: None",
  "    finding_results.require_scan_target_identity = workbench.require_scan_target_identity",
  "    workbench.finding_remediation_result = lambda *arguments: {'state': 'idle'}",
  "    finding_results.finding_source_excerpt = lambda *arguments: None",
  "    finding_results.finding_artifact_paths = lambda *arguments: []",
  "    workbench.backfill_legacy_finding_details = lambda *arguments: None",
  "    workbench.scan_history.finding_matches = lambda *arguments: ([{'findingId': 'previous-owner-finding', 'occurrenceId': 'current-old-occurrence', 'reason': 'Previous owner match reason', 'scanId': 'current-old', 'title': 'Previous owner match title'}], '2026-01-01', ['current-old', 'current-new']) if settings.get('previousOwnerHistory') else ([], '2026-01-01', [])",
  "    if settings.get('pendingMatchedRemediation'):",
  "        connection.execute('CREATE TABLE finding_remediation_attempts (occurrence_id TEXT, created_at TEXT, pending_action TEXT, state TEXT)')",
  "        connection.execute(\"INSERT INTO finding_remediation_attempts VALUES ('pending-occurrence', '2026-02-01', 'apply', 'running')\")",
  "        connection.commit()",
  "        workbench.scan_context = lambda *arguments: {}",
  "        try:",
  "            workbench.set_finding_triage(connection, argparse.Namespace(occurrence_id='current-old-occurrence', status='closed', close_reason='false_positive', note='Verified test dismissal'))",
  "        except SystemExit as error:",
  "            pending_remediation_error = str(error)",
  "        pending_triage_rows = connection.execute('SELECT COUNT(*) FROM finding_triage').fetchone()[0]",
  "    if settings.get('closeAfterRediscovery'):",
  "        connection.execute('CREATE TABLE finding_remediation_attempts (occurrence_id TEXT, created_at TEXT)')",
  "        connection.commit()",
  "        workbench.scan_context = lambda *arguments: {}",
  "        workbench.set_finding_triage(connection, argparse.Namespace(occurrence_id='current-old-occurrence', status='closed', close_reason=settings['matchedTriage'], note='Verified test dismissal' if settings['matchedTriage'] == 'false_positive' else None))",
  "        result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "    selected_scan = 'orphan-new' if settings.get('targetlessHistory') else 'current-new'",
  "    selected_occurrence = selected_scan + '-occurrence'",
  "    scan = connection.execute('SELECT * FROM scans WHERE id = ?', (selected_scan,)).fetchone()",
  "    occurrence = connection.execute('SELECT * FROM finding_occurrences WHERE id = ?', (selected_occurrence,)).fetchone()",
  "    finding_detail = workbench.finding_result(connection, scan, occurrence, full_details=True)",
  "    if settings.get('targetlessHistory'):",
  "        from collections import defaultdict",
  "        connection.execute(\"CREATE TABLE scan_progress AS SELECT ? scan_id, ? updated_at, '[]' preflight_issues_json, 0 reportable_findings_count, 0 review_items_completed, 0 scope_file_count, 0 review_items_total, 0 phase_items_completed, 0 phase_items_total, NULL phase_progress_unit, 0 preflight_checks_completed, 0 preflight_checks_total, NULL deep_review_pass\", (selected_scan, scan['updated_at']))",
  "        connection.execute('CREATE TABLE scan_artifacts (scan_id TEXT, kind TEXT, path TEXT)')",
  "        workbench.remediation_availability = lambda _scan: (False, None)",
  "        workbench.finding_management_updated_at = lambda *_arguments: None",
  "        overview_scan = defaultdict(lambda: None, dict(scan))",
  "        overview_scan['completion_warnings_json'] = '[]'",
  "        overview_finding = workbench.scan_result(connection, overview_scan)['findings'][0]",
  "    else:",
  "        overview_finding = workbench.finding_result(connection, scan, occurrence, indexed_finding=workbench._indexed_scan_findings(connection, scan).get(occurrence['id']))",
  "    scan_pages = {status: workbench.list_findings(connection, argparse.Namespace(scan_id=selected_scan, query=None, severity=None, status=status, offset=0, limit=20))['findingsPage'] for status in ('open', 'closed')}",
  "    try:",
  "        workbench.require_finding_open(connection, selected_occurrence)",
  "    except SystemExit as error:",
  "        remediation_guard_error = str(error)",
  "    if settings.get('ownershipReuse'):",
  "        from contextlib import nullcontext, redirect_stdout",
  "        from io import StringIO",
  "        workbench.connect = lambda: connection",
  "        workbench.closing = nullcontext",
  "        def rejected_finding_access(occurrence_id, scan_id):",
  "            finding_error, listing_error = None, None",
  "            workbench.parse_args = lambda _description: argparse.Namespace(command='get-finding', occurrence_id=occurrence_id)",
  "            try:",
  "                with redirect_stdout(StringIO()):",
  "                    workbench.main()",
  "            except SystemExit as error:",
  "                finding_error = str(error)",
  "            try:",
  "                workbench.list_findings(connection, argparse.Namespace(scan_id=scan_id, query=None, severity=None, status=None, offset=0, limit=20))",
  "            except SystemExit as error:",
  "                listing_error = str(error)",
  "            return finding_error, listing_error",
  "        rejected_previous_owner, rejected_previous_owner_list = rejected_finding_access('current-old-occurrence', 'current-old')",
  "        checkout = connection.execute(\"SELECT current_path FROM security_targets WHERE id = 'current-target'\").fetchone()[0]",
  "        connection.execute(\"UPDATE scans SET target_path = ? WHERE id = 'reused-legacy'\", (checkout,))",
  "        rejected_legacy_owner, rejected_legacy_owner_list = rejected_finding_access('reused-legacy-occurrence', 'reused-legacy')",
  "        connection.execute(\"UPDATE scans SET target_path = ? WHERE id = 'reused-legacy'\", (os.path.join(checkout, 'nested'),))",
  "        rejected_legacy_descendant, rejected_legacy_descendant_list = rejected_finding_access('reused-legacy-occurrence', 'reused-legacy')",
  "scoped_scan_ids = []",
  "matching_scan_count = None",
  "old_owner_matches = None",
  "if settings.get('ownershipTransition') or settings.get('ownershipReuse'):",
  "    clauses, values, _, _ = indexes.scan_history.repository_scan_scope(connection, args.repository or sys.argv[1])",
  "    scoped_scan_ids = [row['id'] for row in connection.execute('SELECT scans.id FROM scans WHERE ' + ' AND '.join(clauses), values)]",
  "if settings.get('ownershipReuse'):",
  "    matching = indexes.scan_history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[1], force=False), backfill_finding_details=lambda _connection, _scan: None, read_coverage=coverage)",
  "    matching_scan_count = matching['scanCount']",
  "    scans = [connection.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone() for scan in ('current-old', 'current-new')]",
  "    old_owner_matches = indexes.scan_history._same_registered_repository(connection, *scans)",
  "print(json.dumps({'findings': result.get('findings', []), 'findingDetail': finding_detail, 'overviewFinding': overview_finding, 'scanPages': scan_pages, 'rejectedPreviousOwner': rejected_previous_owner, 'rejectedPreviousOwnerList': rejected_previous_owner_list, 'rejectedLegacyOwner': rejected_legacy_owner, 'rejectedLegacyOwnerList': rejected_legacy_owner_list, 'rejectedLegacyDescendant': rejected_legacy_descendant, 'rejectedLegacyDescendantList': rejected_legacy_descendant_list, 'pendingRemediationError': pending_remediation_error, 'pendingTriageRows': pending_triage_rows, 'remediationGuardError': remediation_guard_error, 'repositories': result.get('repositories', []), 'coverageReads': coverage_reads, 'scopedScanIds': scoped_scan_ids, 'matchingScanCount': matching_scan_count, 'oldOwnerMatches': old_owner_matches}))",
].join("\n");

function runFindingsIndex(
  targetId: string | null,
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    closeAfterRediscovery?: boolean;
    clockRollback?: boolean;
    closedBeforeRollback?: "already_fixed" | "false_positive";
    coverageFailure?: "tampered" | "sealedArtifact" | "noncanonical" | "pruned";
    includeResolved?: boolean;
    incompatibleSibling?: boolean;
    inactiveRepresentative?: boolean;
    indexedAliases?: boolean;
    lateCompletion?: boolean;
    legacyDescendant?: boolean;
    legacyPriority?: boolean;
    linkedWorktree?: boolean;
    matchedTriage?: "already_fixed" | "false_positive";
    missingCheckout?: boolean;
    missingOwnershipCheckout?: boolean;
    mixedLegacyOwnership?: boolean;
    ownershipReuse?: boolean;
    ownershipTransition?: boolean;
    pendingMatchedRemediation?: boolean;
    previousOwnerHistory?: boolean;
    repeatedStableFinding?: boolean;
    replacedCheckout?: boolean;
    repositories?: boolean;
    scopedLegacyDescendant?: boolean;
    targetlessHistory?: "stable" | "matched";
    triageClockRollback?: boolean;
    unsealedScans?: boolean;
  } = {},
) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error(
      "A Python interpreter is required for findings-index tests.",
    );
  }
  return Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      findingsIndexProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify({ targetId, ...settings }),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
}

function probeFindingsIndex(
  targetId: string | null,
  settings: Parameters<typeof runFindingsIndex>[1] = {},
): {
  findings: Array<{
    occurrenceId: string;
    scanId: string;
    targetId: string | null;
    targetPath: string;
  }>;
  findingDetail: Record<string, unknown> | null;
  overviewFinding: Record<string, unknown> | null;
  scanPages: Record<
    string,
    { findings: Array<Record<string, unknown>>; total: number }
  > | null;
  rejectedPreviousOwner: string | null;
  rejectedPreviousOwnerList: string | null;
  rejectedLegacyOwner: string | null;
  rejectedLegacyOwnerList: string | null;
  rejectedLegacyDescendant: string | null;
  rejectedLegacyDescendantList: string | null;
  pendingRemediationError: string | null;
  pendingTriageRows: number | null;
  remediationGuardError: string | null;
  repositories: Array<{ targetId: string; openFindingsCount: number }>;
  coverageReads: string[];
  matchingScanCount: number | null;
  oldOwnerMatches: boolean | null;
  scopedScanIds: string[];
} {
  const result = runFindingsIndex(targetId, settings);
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout));
}

describe("workbench findings index", () => {
  test("isolates targetless previous-owner findings and coverage reads", () => {
    const result = probeFindingsIndex("current-target");

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        scanId: "current-new",
        targetId: "current-target",
      }),
    ]);
    expect(result.coverageReads).toEqual(["current-new"]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
  });

  test("keeps legacy findings after newer scans record filesystem ownership", () => {
    const result = probeFindingsIndex("current-target", {
      mixedLegacyOwnership: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "current-old-occurrence" }),
    ]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
  });

  test("counts only active findings when listing repositories", () => {
    const result = probeFindingsIndex(null, { repositories: true });

    expect(result.repositories).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 1,
      }),
    );
  });

  test("uses scan insertion order when the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      clockRollback: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        confirmedInLatestScan: true,
        occurrenceId: "current-new-occurrence",
      }),
    ]);
    expect(result.coverageReads).toEqual(["current-new"]);
  });

  test("keeps rediscovered findings active when the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      clockRollback: true,
      lateCompletion: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
  });

  test.each(["already_fixed", "false_positive"] as const)(
    "reopens %s findings rediscovered after the system clock moves backward",
    (closeReason) => {
      const result = probeFindingsIndex("current-target", {
        clockRollback: true,
        closedBeforeRollback: closeReason,
      });
      expect(result.findings).toEqual([
        expect.objectContaining({
          occurrenceId: "current-new-occurrence",
          status: "open",
        }),
      ]);
    },
  );

  test("uses inherited triage when showing matched finding details", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        status: "closed",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "closed",
      triage: {
        closeReason: "false_positive",
        note: "Verified test dismissal",
        status: "closed",
      },
    });
    expect(result.scanPages?.["closed"]).toMatchObject({
      findings: [
        {
          occurrenceId: "current-new-occurrence",
          status: "closed",
          triage: { closeReason: "false_positive", status: "closed" },
        },
      ],
      total: 1,
    });
    expect(result.scanPages?.["open"]).toMatchObject({
      findings: [],
      total: 0,
    });
    expect(result.remediationGuardError).toBe(
      "Reopen this finding before requesting remediation.",
    );
  });

  test("shows finding history when stable identifiers recur without saved matches", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
      repeatedStableFinding: true,
    });

    expect(result.findingDetail).toMatchObject({
      knownSince: "2026-01-01",
      knownScanIds: ["current-old", "current-new"],
      occurrenceCount: 2,
    });
    expect(result.findingDetail).not.toHaveProperty("matches");
    expect(result.overviewFinding).toMatchObject({
      knownSince: "2026-01-01",
      knownScanIds: ["current-old", "current-new"],
      occurrenceCount: 2,
    });
    expect(result.overviewFinding).not.toHaveProperty("matches");
    expect(result.scanPages?.["closed"]?.findings[0]).toMatchObject({
      knownSince: "2026-01-01",
      knownScanIds: ["current-old", "current-new"],
      occurrenceCount: 2,
    });
  });

  test("rejects closing a finding while any matched occurrence is being remediated", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
      pendingMatchedRemediation: true,
    });

    expect(result.pendingRemediationError).toContain(
      "pending remediation operation",
    );
    expect(result.pendingTriageRows).toBe(0);
  });

  test("keeps rediscovered fixed finding details open", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "already_fixed",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        status: "open",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "open",
      triage: { status: "open" },
    });
    expect(result.findingDetail?.["triage"]).not.toHaveProperty("closeReason");
    expect(result.remediationGuardError).toBeNull();
    expect(result.scanPages?.["open"]).toMatchObject({
      findings: [{ occurrenceId: "current-new-occurrence", status: "open" }],
      total: 1,
    });
    expect(result.scanPages?.["closed"]).toMatchObject({
      findings: [],
      total: 0,
    });
  });

  test.each(["already_fixed", "false_positive"] as const)(
    "keeps an earlier finding closed when marked %s after its rediscovery",
    (closeReason) => {
      const result = probeFindingsIndex("current-target", {
        closeAfterRediscovery: true,
        matchedTriage: closeReason,
      });
      expect(result.findings).toEqual([
        expect.objectContaining({
          occurrenceId: "current-new-occurrence",
          status: "closed",
        }),
      ]);
      expect(result.findingDetail).toMatchObject({
        occurrenceId: "current-new-occurrence",
        status: "closed",
        triage: { closeReason, status: "closed" },
      });
    },
  );

  test("keeps saved finding details available when the checkout is missing", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
      missingCheckout: true,
    });

    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "closed",
    });
    expect(result.scanPages?.["closed"]).toMatchObject({
      findings: [{ occurrenceId: "current-new-occurrence", status: "closed" }],
      total: 1,
    });
  });

  test("keeps earlier checkout owners isolated when the current checkout is missing", () => {
    const result = probeFindingsIndex("current-target", {
      indexedAliases: true,
      matchedTriage: "false_positive",
      missingOwnershipCheckout: true,
      ownershipReuse: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        knownScanIds: ["current-new"],
        occurrenceId: "current-new-occurrence",
        status: "open",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "open",
    });
    expect(result.rejectedPreviousOwner).toContain("checkout owner");
    expect(result.rejectedPreviousOwnerList).toContain("checkout owner");
  });

  test("keeps the latest finding decision after the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
      triageClockRollback: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        status: "open",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "open",
      triage: { status: "open" },
    });
    expect(result.scanPages?.["open"]).toMatchObject({
      findings: [{ occurrenceId: "current-new-occurrence", status: "open" }],
      total: 1,
    });
    expect(result.scanPages?.["closed"]).toMatchObject({
      findings: [],
      total: 0,
    });
  });

  test("does not inherit finding triage from a previous checkout owner", () => {
    const result = probeFindingsIndex("current-target", {
      matchedTriage: "false_positive",
      ownershipReuse: true,
      previousOwnerHistory: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        status: "open",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "open",
      triage: { status: "open" },
    });
    expect(result.findingDetail?.["triage"]).not.toHaveProperty("closeReason");
    expect(result.findingDetail).not.toHaveProperty("matches");
    expect(result.findingDetail).not.toHaveProperty("knownSince");
    expect(result.findingDetail).not.toHaveProperty("knownScanIds");
    expect(result.overviewFinding).not.toHaveProperty("matches");
    expect(result.overviewFinding).not.toHaveProperty("knownSince");
    expect(result.overviewFinding).not.toHaveProperty("knownScanIds");
    expect(JSON.stringify(result.findingDetail)).not.toContain(
      "Previous owner match",
    );
    expect(result.rejectedPreviousOwner).toContain("checkout owner");
    expect(result.rejectedPreviousOwnerList).toContain("checkout owner");
    expect(result.rejectedLegacyOwner).toContain("checkout owner");
    expect(result.rejectedLegacyOwnerList).toContain("checkout owner");
    expect(result.rejectedLegacyDescendant).toContain("checkout owner");
    expect(result.rejectedLegacyDescendantList).toContain("checkout owner");
  });

  test("keeps previous-owner checkout descendants out of global finding lists", () => {
    const result = probeFindingsIndex(null, {
      legacyDescendant: true,
      ownershipReuse: true,
    });

    expect(result.findings).toContainEqual(
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    );
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
  });

  test("finds the registered owner from an exact targetless descendant", () => {
    const result = probeFindingsIndex(null, {
      legacyDescendant: true,
      ownershipReuse: true,
      scopedLegacyDescendant: true,
    });

    expect(result.scopedScanIds).toContain("current-new");
    expect(result.scopedScanIds).not.toContain("current-old");
    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        targetId: "current-target",
      }),
    ]);
  });

  test("retains covered same-owner findings while preparing semantic matching", () => {
    const result = probeFindingsIndex("current-target", {
      includeResolved: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "current-old-occurrence" }),
    ]);
    expect(result.findings).not.toContainEqual(
      expect.objectContaining({ occurrenceId: "reused-legacy-occurrence" }),
    );
    expect(
      probeFindingsIndex("current-target", {
        includeResolved: true,
        ownershipReuse: true,
      }).findings,
    ).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
  });

  test("excludes replaced checkout owners from findings and repository counts", () => {
    expect(
      probeFindingsIndex("current-target", { replacedCheckout: true }).findings,
    ).toEqual([]);
    expect(
      probeFindingsIndex(null, { replacedCheckout: true }).findings,
    ).not.toContainEqual(
      expect.objectContaining({ targetId: "current-target" }),
    );

    expect(
      probeFindingsIndex(null, {
        replacedCheckout: true,
        repositories: true,
      }).repositories,
    ).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 0,
      }),
    );
  });

  test("drops ambiguous legacy history after checkout ownership changes", () => {
    const result = probeFindingsIndex("current-target", {
      ownershipTransition: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
    expect(result.scopedScanIds).toContain("current-new");
    expect(result.scopedScanIds).not.toContain("current-old");
    expect(
      probeFindingsIndex(null, {
        ownershipTransition: true,
        repositories: true,
      }).repositories,
    ).toContainEqual(
      expect.objectContaining({
        targetId: "current-target",
        openFindingsCount: 1,
      }),
    );
  });

  test("rejects recycled filesystem identities after the system clock moves backward", () => {
    const result = probeFindingsIndex("current-target", {
      ownershipReuse: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
    ]);
    expect(result.scopedScanIds).toContain("current-new");
    expect(result.scopedScanIds).not.toContain("current-old");
    expect(result.matchingScanCount).toBe(1);
    expect(result.oldOwnerMatches).toBe(false);
  });

  test("never combines indexed finding aliases across checkout owners", () => {
    const result = probeFindingsIndex("current-target", {
      indexedAliases: true,
      ownershipReuse: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        knownScanIds: ["current-new"],
        matchedFindingIds: ["current-new-finding"],
      }),
    ]);
  });

  test("combines saved finding matches across scoped linked worktrees", () => {
    const result = probeFindingsIndex(null, {
      indexedAliases: true,
      linkedWorktree: true,
      matchedTriage: "false_positive",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        knownScanIds: ["current-old", "current-new"],
        matchedFindingIds: ["current-new-finding", "current-old-finding"],
        occurrenceId: "current-new-occurrence",
        status: "closed",
        targetId: "current-target",
      }),
    ]);
    expect(result.findingDetail).toMatchObject({
      occurrenceId: "current-new-occurrence",
      status: "closed",
      triage: { closeReason: "false_positive", status: "closed" },
    });
    expect(result.scanPages?.["closed"]).toMatchObject({
      findings: [{ occurrenceId: "current-new-occurrence", status: "closed" }],
      total: 1,
    });
    expect(result.scanPages?.["open"]?.findings).toEqual([]);
  });

  test("never combines saved finding matches across independently registered siblings", () => {
    const result = probeFindingsIndex(null, {
      incompatibleSibling: true,
      indexedAliases: true,
      linkedWorktree: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        knownScanIds: ["current-new"],
        occurrenceId: "current-new-occurrence",
        status: "open",
      }),
      expect.objectContaining({
        knownScanIds: ["current-old"],
        occurrenceId: "current-old-occurrence",
        status: "closed",
      }),
    ]);
  });

  test("searches titles and summaries across every active matched finding", () => {
    for (const query of ["RESOLVED CURRENT FINDING", "OLDER ISSUE"]) {
      const result = probeFindingsIndex("current-target", {
        indexedAliases: true,
        mixedLegacyOwnership: true,
        query,
      });

      expect(result.findings).toEqual([
        expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      ]);
    }
  });

  test("does not search resolved matched finding representatives", () => {
    const result = probeFindingsIndex("current-target", {
      inactiveRepresentative: true,
      indexedAliases: true,
      mixedLegacyOwnership: true,
      query: "CURRENT CLI FINDING",
    });

    expect(result.findings).toEqual([]);
  });

  test("keeps an active occurrence as the matched finding representative", () => {
    const result = probeFindingsIndex("current-target", {
      inactiveRepresentative: true,
      indexedAliases: true,
      mixedLegacyOwnership: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        confirmedInLatestScan: false,
        createdAt: "2026-01-01",
        findingId: "current-old-finding",
        knownScanIds: ["current-old", "current-new"],
        knownSince: "2026-01-01",
        locationPath: "src/old.py",
        matchedFindingIds: ["current-new-finding", "current-old-finding"],
        occurrenceCount: 2,
        occurrenceId: "current-old-occurrence",
        scanId: "current-old",
        severity: { level: "high" },
        status: "open",
        summary: "Older issue",
        title: "Resolved current finding",
        updatedAt: "2026-02-01",
      }),
    ]);
  });

  test("preserves the active linked-worktree target and aggregate triage", () => {
    const result = probeFindingsIndex(null, {
      inactiveRepresentative: true,
      indexedAliases: true,
      linkedWorktree: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        confirmedInLatestScan: true,
        knownScanIds: ["current-old", "current-new"],
        locationPath: "src/old.py",
        occurrenceCount: 2,
        occurrenceId: "current-old-occurrence",
        scanId: "current-old",
        status: "closed",
        targetId: "linked-target",
        targetPath: "/linked/repository",
      }),
    ]);
  });

  test("keeps active findings when a later scan artifact was pruned", () => {
    const result = probeFindingsIndex("stale-target", {
      coverageFailure: "pruned",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual(["stale-new"]);
  });

  test.each([false, true])(
    "recognizes completed legacy scans without aggregating unsealed coverage (include resolved: %s)",
    (includeResolved) => {
      const result = probeFindingsIndex("stale-target", {
        includeResolved,
        unsealedScans: true,
      });

      expect(result.findings).toEqual([
        expect.objectContaining({
          confirmedInLatestScan: false,
          occurrenceId: "stale-old-occurrence",
        }),
      ]);
      expect(result.coverageReads).toEqual([]);
    },
  );

  test.each(["tampered", "sealedArtifact"] as const)(
    "rejects %s sealed scan artifacts",
    (coverageFailure) => {
      const result = runFindingsIndex("stale-target", { coverageFailure });

      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain("changed");
    },
  );

  test("indexes every targetless scan even without a saved target", () => {
    const result = probeFindingsIndex(null, {
      targetPath: "/orphan/repository",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        confirmedInLatestScan: false,
        occurrenceId: "orphan-old-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
      expect.objectContaining({
        confirmedInLatestScan: true,
        occurrenceId: "orphan-new-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
    ]);
    expect(result.coverageReads).toEqual(["orphan-new"]);
  });

  test.each([
    ["stable", false],
    ["stable", true],
    ["matched", false],
    ["matched", true],
  ] as const)(
    "preserves targetless finding history and triage through %s identifiers (unsealed: %s)",
    (targetlessHistory, unsealedScans) => {
      const result = probeFindingsIndex(null, {
        targetlessHistory,
        targetPath: "/orphan/repository",
        unsealedScans,
      });

      expect(result.findings).toEqual([
        expect.objectContaining({
          knownScanIds: ["orphan-old", "orphan-new"],
          occurrenceCount: 2,
          occurrenceId: "orphan-new-occurrence",
          status: "closed",
          targetId: null,
          targetPath: "/orphan/repository",
        }),
      ]);
      for (const finding of [result.findingDetail, result.overviewFinding]) {
        expect(finding).toMatchObject({
          occurrenceId: "orphan-new-occurrence",
          status: "closed",
          triage: { closeReason: "false_positive", status: "closed" },
          knownSince: "2026-01-01",
          knownScanIds: ["orphan-old", "orphan-new"],
          occurrenceCount: 2,
        });
      }
      expect(result.scanPages?.["closed"]).toMatchObject({
        findings: [
          {
            occurrenceId: "orphan-new-occurrence",
            status: "closed",
            triage: { closeReason: "false_positive", status: "closed" },
            knownScanIds: ["orphan-old", "orphan-new"],
            occurrenceCount: 2,
          },
        ],
        total: 1,
      });
      expect(result.scanPages?.["open"]).toMatchObject({
        findings: [],
        total: 0,
      });
      expect(result.remediationGuardError).toBe(
        "Reopen this finding before requesting remediation.",
      );
      expect(result.coverageReads).toEqual(
        unsealedScans || targetlessHistory === "stable" ? [] : ["orphan-new"],
      );
    },
  );

  test("keeps multi-target repository queries inside the selected checkout", () => {
    const scoped = probeFindingsIndex(null, {
      targetPaths: ["/current/repository", "/orphan/repository"],
    });
    expect(scoped.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
    expect(scoped.coverageReads).toEqual(["current-new", "orphan-new"]);

    const siblingPrefix = probeFindingsIndex(null, {
      targetPaths: ["/current/repositor"],
    });
    expect(siblingPrefix.findings).toEqual([]);
    expect(siblingPrefix.coverageReads).toEqual([]);
  });

  test("orders registered and legacy findings together by severity", () => {
    const result = probeFindingsIndex(null, {
      legacyPriority: true,
      targetPaths: ["/current/repository", "/orphan/repository"],
    });

    expect(result.findings.map((finding) => finding.occurrenceId)).toEqual([
      "orphan-old-occurrence",
      "orphan-new-occurrence",
      "current-new-occurrence",
    ]);
  });

  test("combines exact target identities with legacy checkout paths", () => {
    const identified = probeFindingsIndex(null, {
      targetIds: ["current-target", "stale-target"],
    });
    expect(identified.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "stale-old-occurrence",
    ]);

    const mixed = probeFindingsIndex(null, {
      targetIds: ["current-target"],
      targetPaths: ["/orphan/repository"],
    });
    expect(mixed.findings.map((finding) => finding.occurrenceId)).toEqual([
      "current-new-occurrence",
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
  });

  test("searches secondary finding source locations", () => {
    for (const query of ["SECONDARY.PY", "äuth-strasse.py"]) {
      const result = probeFindingsIndex("current-target", { query });

      expect(result.findings).toEqual([
        expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      ]);
    }
  });
});
