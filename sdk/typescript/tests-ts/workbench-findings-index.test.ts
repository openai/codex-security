import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const findingsIndexProbe = [
  "import argparse, json, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import workbench_native_indexes as indexes",
  "settings = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE security_targets (id TEXT PRIMARY KEY, current_path TEXT NOT NULL);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, seal_manifest_digest TEXT, started_at TEXT, updated_at TEXT, scope TEXT, scan_dir TEXT);",
  "CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, severity TEXT, created_at TEXT, title TEXT, summary TEXT);",
  "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, updated_at TEXT);",
  "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
  "''')",
  "connection.executemany('INSERT INTO security_targets VALUES (?, ?)', [('current-target', '/current/repository'), ('stale-target', '/stale/repository')])",
  "stale_directory = sys.argv[1] if settings.get('coverageFailure') in ('noncanonical', 'pruned') else '/private/tmp/codex-security-findings-index-missing-stale'",
  "connection.executemany('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old', 'current-target', '/current/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/current-old'),",
  "    ('current-new', 'current-target', '/current/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/current-new'),",
  "    ('reused-legacy', None, '/current/repository', 'complete', 'sealed', '2026-03-01', '2026-03-01', '.', '/private/tmp/reused-legacy'),",
  "    ('stale-old', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/stale-old'),",
  "    ('stale-new', 'stale-target', '/stale/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', stale_directory),",
  "    ('orphan-old', None, '/orphan/repository', 'complete', 'sealed', '2026-01-01', '2026-01-01', '.', '/private/tmp/orphan-old'),",
  "    ('orphan-new', None, '/orphan/repository', 'complete', 'sealed', '2026-02-01', '2026-02-01', '.', '/private/tmp/orphan-new'),",
  "])",
  "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)', [",
  "    ('current-old-occurrence', 'current-old-finding', 'current-old', 'high', '2026-01-01', 'Resolved current finding', 'Older issue'),",
  "    ('current-new-occurrence', 'current-new-finding', 'current-new', 'critical', '2026-02-01', 'Current CLI finding', 'Latest issue'),",
  "    ('reused-legacy-occurrence', 'previous-owner-finding', 'reused-legacy', 'critical', '2026-03-01', 'Previous owner secret', 'Must never cross checkout owners'),",
  "    ('stale-old-occurrence', 'stale-finding', 'stale-old', 'medium', '2026-01-01', 'Unavailable follow-up', 'Coverage is unavailable'),",
  "    ('orphan-old-occurrence', 'orphan-old-finding', 'orphan-old', 'high', '2026-01-01', 'Older orphan finding', 'Still outside follow-up coverage'),",
  "    ('orphan-new-occurrence', 'orphan-new-finding', 'orphan-new', 'medium', '2026-02-01', 'Latest orphan finding', 'Target row does not exist'),",
  "])",
  "if settings.get('lateCompletion'):",
  "    connection.execute(\"UPDATE finding_occurrences SET finding_id = 'current-new-finding', created_at = '2026-03-01' WHERE id = 'current-old-occurrence'\")",
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
  "coverage_reads = []",
  "def coverage(scan):",
  "    coverage_reads.append(scan['id'])",
  "    if scan['id'] == 'stale-new':",
  "        if settings.get('coverageFailure') == 'tampered':",
  "            raise SystemExit('The sealed scan manifest changed after completion.')",
  "        if settings.get('coverageFailure') == 'pruned':",
  "            raise SystemExit('coverage.json: expected a regular file inside the scan directory.')",
  "        raise SystemExit('Scan directory must be an existing canonical non-symlink directory.')",
  "    if scan['id'] == 'orphan-new':",
  "        return {'completeness': 'partial', 'includePaths': ['src/orphan-new.py'], 'excludePaths': [], 'explicitExclusions': []}",
  "    return {'completeness': 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
  "location_queries = []",
  "connection.set_trace_callback(lambda statement: location_queries.append(statement) if 'finding_locations' in statement else None)",
  "args = argparse.Namespace(query=settings.get('query'), severity=None, status=None, target_id=settings.get('targetIds') or settings.get('targetId'), target_path=settings.get('targetPaths') or settings.get('targetPath'), offset=0, limit=20)",
  "result = indexes.list_global_findings(connection, args, read_coverage=coverage)",
  "print(json.dumps({'findings': result['findings'], 'coverageReads': coverage_reads, 'locationQueryCount': len(location_queries)}))",
].join("\n");

const nestedDirectoryScanProbe = [
  "import argparse, json, pathlib, sqlite3, subprocess, sys, tempfile",
  "sys.path.insert(0, sys.argv[1])",
  "from workbench_db import apply_migrations, serialize_filesystem_identity",
  "from workbench_scan_history import _same_repository, list_scans, list_unmatched_scan_pairs",
  "from workbench_target import git_output",
  "from workbench_target_state import ensure_security_target",
  "from unittest.mock import patch",
  "with tempfile.TemporaryDirectory(prefix='codex-security-unversioned-scan-') as directory:",
  "    root = (pathlib.Path(directory) / 'plain-directory').resolve()",
  "    nested = root / 'src' / 'nested'",
  "    nested.mkdir(parents=True)",
  "    independent = root / 'independent-git'",
  "    independent_nested = independent / 'src'",
  "    independent_nested.mkdir(parents=True)",
  "    subprocess.run(['git', 'init', '-q', str(independent)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    service = root / 'independent-service'",
  "    nested_service = service / 'src'",
  "    nested_service.mkdir(parents=True)",
  "    connection = sqlite3.connect(':memory:')",
  "    connection.row_factory = sqlite3.Row",
  "    apply_migrations(connection)",
  "    descendant_queries = []",
  "    connection.set_trace_callback(lambda statement: descendant_queries.append(statement) if 'SELECT target_id, target_path FROM scans' in statement else None)",
  "    timestamp = '2026-08-03T12:00:00Z'",
  "    for scan_id, path in [('scan', root), ('independent-service-scan', service)]:",
  "        target = ensure_security_target(connection, str(path))",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(path), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(path), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    ensure_security_target(connection, str(root / 'src'))",
  "    connection.commit()",
  "    output = {}",
  "    for label, path in [('root', root), ('nested', nested), ('independentGit', independent), ('nestedIndependentGit', independent_nested), ('independentService', service), ('nestedIndependentService', nested_service)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    with patch('workbench_scan_history.git_output', return_value=None):",
  "        for label, path in [('independentGitWithoutGit', independent), ('nestedIndependentGitWithoutGit', independent_nested)]:",
  "            args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "            output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    git_root = (pathlib.Path(directory) / 'legacy-git-checkout').resolve()",
  "    git_service = git_root / 'src'",
  "    git_service.mkdir(parents=True)",
  "    subprocess.run(['git', 'init', '-q', str(git_root)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    connection.execute('INSERT INTO workspaces(id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?)', ('legacy-git-workspace', str(git_service), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('legacy-git-scan', 'legacy-git-workspace', None, str(git_service), 'unversioned', '.', 'standard', directory + '/results/legacy-git', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('legacy-git-scan', timestamp))",
  "    for label, path in [('legacyGitRoot', git_root), ('legacyGitSubdirectory', git_service)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    ensure_security_target(connection, str(git_service))",
  "    args = argparse.Namespace(repository=str(git_root), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['registeredLegacyGitRoot'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    plain_root = (pathlib.Path(directory) / 'unversioned-services').resolve()",
  "    plain_service_a = plain_root / 'service-a'",
  "    plain_service_b = plain_root / 'service-b'",
  "    nested_checkout = plain_root / 'independent-checkout'",
  "    for path in (plain_service_a, plain_service_b, nested_checkout): path.mkdir(parents=True)",
  "    subprocess.run(['git', 'init', '-q', str(nested_checkout)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    for scan_id, path in [('plain-a', plain_service_a), ('plain-b', plain_service_b), ('nested-git', nested_checkout)]:",
  "        target = ensure_security_target(connection, str(path))",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(path), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(path), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    for label, path in [('unversionedRoot', plain_root), ('unversionedService', plain_service_a), ('nestedGitCheckout', nested_checkout)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    moved_checkout = (pathlib.Path(directory) / 'moved-checkout').resolve()",
  "    reused_checkout = (pathlib.Path(directory) / 'reused-checkout').resolve()",
  "    for path in (moved_checkout, reused_checkout): path.mkdir()",
  "    moved_target = ensure_security_target(connection, str(moved_checkout))",
  "    current_target = ensure_security_target(connection, str(reused_checkout))",
  "    for scan_id, target in [('stale-reused-scan', moved_target), ('current-reused-scan', current_target), ('legacy-reused-scan', None)]:",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(reused_checkout), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(reused_checkout), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    moved_nested = moved_checkout / 'src' / 'nested'",
  "    reused_nested = reused_checkout / 'src' / 'nested'",
  "    moved_nested.mkdir(parents=True)",
  "    reused_nested.mkdir(parents=True)",
  "    for label, path in [('reusedCheckout', reused_checkout), ('reusedCheckoutSubdirectory', reused_nested), ('movedCheckout', moved_checkout), ('movedCheckoutSubdirectory', moved_nested)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        selected = list_scans(connection, args)['scans']",
  "        output[label] = [scan['scanId'] for scan in selected]",
  "        if label == 'movedCheckout': output['movedCheckoutCurrentPath'] = selected[0].get('currentTargetPath') == str(moved_checkout)",
  "    stale_parent = root / 'reused-without-current-scan'",
  "    stale_nested = stale_parent / 'src'",
  "    stale_nested.mkdir(parents=True)",
  "    ensure_security_target(connection, str(stale_parent))",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('stale-parent-workspace', moved_target, str(stale_parent), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('stale-parent-scan', 'stale-parent-workspace', moved_target, str(stale_parent), 'unversioned', '.', 'standard', directory + '/results/stale-parent-scan', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('stale-parent-scan', timestamp))",
  "    args = argparse.Namespace(repository=str(stale_nested), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['nestedReusedParentFallsBackToRoot'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    same_origin_outer = (pathlib.Path(directory) / 'same-origin-outer').resolve()",
  "    same_origin_nested = same_origin_outer / 'nested-clone'",
  "    same_origin_nested.mkdir(parents=True)",
  "    for scan_id, path in [('same-origin-outer-scan', same_origin_outer), ('same-origin-nested-scan', same_origin_nested)]:",
  "        subprocess.run(['git', 'init', '-q', str(path)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "        subprocess.run(['git', '-C', str(path), 'remote', 'add', 'origin', 'https://github.com/example/shared.git'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "        target = ensure_security_target(connection, str(path))",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(path), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(path), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    for label, path in [('sameOriginOuter', same_origin_outer), ('sameOriginNested', same_origin_nested)]:",
  "        args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "        output[label] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    stale_owned_checkout = (pathlib.Path(directory) / 'stale-owned-checkout').resolve()",
  "    stale_owned_checkout.mkdir()",
  "    subprocess.run(['git', 'init', '-q', str(stale_owned_checkout)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    stale_owned_target = ensure_security_target(connection, str(stale_owned_checkout))",
  "    stale_metadata = stale_owned_checkout.stat()",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('stale-owned-workspace', stale_owned_target, str(stale_owned_checkout), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_device, target_inode, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('stale-owned-scan', 'stale-owned-workspace', stale_owned_target, str(stale_owned_checkout), serialize_filesystem_identity(stale_metadata.st_dev), serialize_filesystem_identity(stale_metadata.st_ino), 'unversioned', '.', 'standard', directory + '/results/stale-owned', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('stale-owned-scan', timestamp))",
  "    stale_owned_checkout.rename(stale_owned_checkout.with_name('previous-owned-checkout'))",
  "    stale_owned_checkout.mkdir()",
  "    subprocess.run(['git', 'init', '-q', str(stale_owned_checkout)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    stale_args = argparse.Namespace(repository=str(stale_owned_checkout), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['staleRegisteredCheckout'] = [scan['scanId'] for scan in list_scans(connection, stale_args)['scans']]",
  "    stale_matching_reads = []",
  "    stale_matching = list_unmatched_scan_pairs(connection, argparse.Namespace(repository=str(stale_owned_checkout), force=False), backfill_finding_details=lambda *_: None, read_coverage=lambda scan: stale_matching_reads.append(scan['id']) or {})",
  "    output['staleRegisteredMatching'] = {'scanCount': stale_matching['scanCount'], 'coverageReads': stale_matching_reads}",
  "    current_metadata = stale_owned_checkout.stat()",
  "    current_timestamp = '2026-08-03T12:00:01Z'",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('current-owned-workspace', stale_owned_target, str(stale_owned_checkout), current_timestamp, current_timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_device, target_inode, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('current-owned-scan', 'current-owned-workspace', stale_owned_target, str(stale_owned_checkout), serialize_filesystem_identity(current_metadata.st_dev), serialize_filesystem_identity(current_metadata.st_ino), 'unversioned', '.', 'standard', directory + '/results/current-owned', 'complete', 'reporting', current_timestamp, current_timestamp, current_timestamp, current_timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('current-owned-scan', current_timestamp))",
  "    output['reusedRegisteredCheckout'] = [scan['scanId'] for scan in list_scans(connection, stale_args)['scans']]",
  "    sibling_root = (pathlib.Path(directory) / 'sibling-checkout').resolve()",
  "    sibling_a = sibling_root / 'service-a'",
  "    sibling_b = sibling_root / 'service-b'",
  "    sibling_a.mkdir(parents=True); sibling_b.mkdir()",
  "    subprocess.run(['git', 'init', '-q', str(sibling_root)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    sibling_target = ensure_security_target(connection, str(sibling_a))",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('sibling-workspace', sibling_target, str(sibling_a), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('sibling-service-a', 'sibling-workspace', sibling_target, str(sibling_a), 'unversioned', '.', 'standard', directory + '/results/sibling-a', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('sibling-service-a', timestamp))",
  "    sibling_args = argparse.Namespace(repository=str(sibling_b), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['unscannedSiblingService'] = [scan['scanId'] for scan in list_scans(connection, sibling_args)['scans']]",
  "    original_clone = (pathlib.Path(directory) / 'portable-original-clone').resolve()",
  "    related_clone = (pathlib.Path(directory) / 'portable-related-worktree').resolve()",
  "    forged_clone = (pathlib.Path(directory) / 'portable-forged-clone').resolve()",
  "    forged_git_directory = (pathlib.Path(directory) / 'portable-forged-gitdir').resolve()",
  "    original_clone.mkdir()",
  "    subprocess.run(['git', 'init', '-q', str(original_clone)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    subprocess.run(['git', '-C', str(original_clone), 'remote', 'add', 'origin', 'https://github.com/example/portable.git'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    subprocess.run(['git', '-C', str(original_clone), '-c', 'user.name=Codex Security', '-c', 'user.email=codex@example.com', 'commit', '--quiet', '--allow-empty', '-m', 'Initial commit'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    subprocess.run(['git', '-C', str(original_clone), 'worktree', 'add', '--quiet', '--detach', str(related_clone)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    forged_clone.mkdir()",
  "    subprocess.run(['git', 'init', '-q', str(forged_clone)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    subprocess.run(['git', '-C', str(forged_clone), 'remote', 'add', 'origin', 'https://github.com/example/portable.git'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
  "    forged_git_directory.mkdir()",
  "    (forged_git_directory / '.git').write_text('gitdir: ' + str(original_clone / '.git') + chr(10), encoding='utf-8')",
  "    portable_target = ensure_security_target(connection, str(original_clone))",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('portable-workspace', portable_target, str(original_clone), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('portable-scan', 'portable-workspace', portable_target, str(original_clone), 'unversioned', '.', 'standard', directory + '/results/portable-scan', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('portable-scan', timestamp))",
  "    args = argparse.Namespace(repository=str(related_clone), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    related_scans = list_scans(connection, args)['scans']",
  "    output['relatedCheckoutHistory'] = [scan['scanId'] for scan in related_scans]",
  "    output['relatedCheckoutVerified'] = related_scans[0].get('relatedCheckout') is True",
  "    args = argparse.Namespace(repository=str(forged_clone), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['forgedOriginHistory'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    args = argparse.Namespace(repository=str(forged_git_directory), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['forgedGitDirectoryHistory'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    matching_reads = []",
  "    for label, path in [('forgedOriginMatching', forged_clone), ('forgedGitDirectoryMatching', forged_git_directory), ('relatedCheckoutMatching', related_clone), ('reusedCheckoutMatching', reused_checkout), ('movedCheckoutMatching', moved_checkout), ('reusedRegisteredMatching', stale_owned_checkout), ('unscannedSiblingMatching', sibling_b)]:",
  "        matching_args = argparse.Namespace(repository=str(path), force=False)",
  "        matching = list_unmatched_scan_pairs(connection, matching_args, backfill_finding_details=lambda *_: None, read_coverage=lambda scan: matching_reads.append(scan['id']) or {})",
  "        output[label] = {'scanCount': matching['scanCount'], 'coverageReads': matching_reads.copy()}",
  "        matching_reads.clear()",
  "    output['forgedOriginMatchingScans'] = output['forgedOriginMatching']['scanCount']",
  "    targetless_original = connection.execute('SELECT NULL AS target_id, ? AS target_path', (str(original_clone),)).fetchone()",
  "    for label, path in [('forgedTargetlessIdentity', forged_clone), ('forgedGitDirectoryIdentity', forged_git_directory), ('relatedTargetlessIdentity', related_clone)]:",
  "        targetless_checkout = connection.execute('SELECT NULL AS target_id, ? AS target_path', (str(path),)).fetchone()",
  "        output[label] = _same_repository(targetless_original, targetless_checkout)",
  "    reused_services = (pathlib.Path(directory) / 'reused-services').resolve()",
  "    previous_services = (pathlib.Path(directory) / 'previous-services').resolve()",
  "    reused_services.mkdir()",
  "    previous_services.mkdir()",
  "    previous_services_target = ensure_security_target(connection, str(previous_services))",
  "    ensure_security_target(connection, str(reused_services))",
  "    for scan_id, path, target in [('stale-services-root', reused_services, previous_services_target), ('current-service-a', reused_services / 'service-a', None), ('current-service-b', reused_services / 'service-b', None)]:",
  "        if target is None: path.mkdir(); target = ensure_security_target(connection, str(path))",
  "        workspace_id = scan_id + '-workspace'",
  "        connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (workspace_id, target, str(path), timestamp, timestamp))",
  "        connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, workspace_id, target, str(path), 'unversioned', '.', 'standard', directory + '/results/' + scan_id, 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "        connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', (scan_id, timestamp))",
  "    args = argparse.Namespace(repository=str(reused_services), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    output['reusedRootDescendantScans'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "    for index in range(50):",
  "        unrelated = pathlib.Path(directory) / f'unrelated-{index}'",
  "        unrelated.mkdir()",
  "        ensure_security_target(connection, str(unrelated))",
  "    args = argparse.Namespace(repository=str(root), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
  "    previous_descendant_queries = len(descendant_queries)",
  "    with patch('workbench_scan_history.git_output', wraps=git_output) as observed_git:",
  "        output['directTargetScanIds'] = [scan['scanId'] for scan in list_scans(connection, args)['scans']]",
  "        output['directTargetLookupBounded'] = observed_git.call_count <= 3",
  "    output['directTargetSkipsDescendants'] = len(descendant_queries) == previous_descendant_queries",
  "    output['descendantQueriesScoped'] = bool(descendant_queries) and all('WHERE substr(target_path, 1,' in statement for statement in descendant_queries)",
  "    print(json.dumps(output))",
].join("\n");

const relocatedFindingProbe = [
  "import json, os, pathlib, sqlite3, subprocess, sys, tempfile",
  "sys.path.insert(0, sys.argv[1])",
  "from workbench_db import apply_migrations, finding_result, serialize_filesystem_identity",
  "from workbench_scan_history import finding_occurrence_rows",
  "from workbench_target_state import ensure_security_target",
  "with tempfile.TemporaryDirectory(prefix='codex-security-relocated-finding-') as directory:",
  "    checkout = (pathlib.Path(directory) / 'original-checkout').resolve()",
  "    source = checkout / 'src' / 'ÄUTH-Straße.py'",
  "    source.parent.mkdir(parents=True)",
  "    source.write_text('dangerous_sink(user_input)\\n', encoding='utf-8')",
  "    subprocess.run(['git', 'init', '-q', str(checkout)], check=True)",
  "    subprocess.run(['git', '-C', str(checkout), 'add', '.'], check=True)",
  "    subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Codex Security Test', '-c', 'user.email=codex-security@example.com', 'commit', '-qm', 'initial finding source'], check=True)",
  "    revision = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()",
  "    connection = sqlite3.connect(':memory:')",
  "    connection.row_factory = sqlite3.Row",
  "    apply_migrations(connection)",
  "    timestamp = '2026-08-03T12:00:00Z'",
  "    target = ensure_security_target(connection, str(checkout))",
  "    metadata = checkout.stat()",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('workspace', target, str(checkout), timestamp, timestamp))",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_device, target_inode, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('scan', 'workspace', target, str(checkout), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), revision, '.', 'standard', directory + '/results', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('scan', timestamp))",
  "    connection.execute('INSERT INTO findings(id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', ('finding', 'fingerprint', 'rule', 'anchor', timestamp, timestamp))",
  "    connection.execute('INSERT INTO finding_occurrences(id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('occurrence', 'finding', 'scan', 'Äuthorization bypass', 'Über account access', 'high', 'high', 'Require authorization.', '{}', timestamp))",
  "    connection.execute('INSERT INTO finding_locations(occurrence_id, relative_path, start_line, end_line, role, sort_order) VALUES (?, ?, ?, ?, ?, ?)', ('occurrence', 'src/ÄUTH-Straße.py', 1, 1, 'root_control', 0))",
  "    searches = {query: [row['id'] for row in finding_occurrence_rows(connection, 'scan', offset=0, limit=20, query=query)] for query in ['äuthorization', 'über', 'äuth-strasse']}",
  "    scan = connection.execute('SELECT * FROM scans WHERE id = ?', ('scan',)).fetchone()",
  "    occurrence = connection.execute('SELECT * FROM finding_occurrences WHERE id = ?', ('occurrence',)).fetchone()",
  "    moved_checkout = checkout.with_name('moved-checkout')",
  "    checkout.rename(moved_checkout)",
  "    connection.execute('UPDATE security_targets SET current_path = ? WHERE id = ?', (str(moved_checkout), target))",
  "    moved = finding_result(connection, scan, occurrence, full_details=True)",
  "    replacement = checkout.with_name('replacement-checkout')",
  "    replacement.mkdir()",
  "    connection.execute('UPDATE security_targets SET current_path = ? WHERE id = ?', (str(replacement), target))",
  "    replaced = finding_result(connection, scan, occurrence, full_details=True)",
  "    print(json.dumps({'searches': searches, 'movedAbsolutePath': moved['locations'][0].get('absolutePath'), 'expectedMovedAbsolutePath': str(moved_checkout / 'src' / 'ÄUTH-Straße.py'), 'movedSourceExcerpt': moved.get('sourceExcerpt'), 'replacementAbsolutePath': replaced['locations'][0].get('absolutePath'), 'replacementSourceExcerpt': replaced.get('sourceExcerpt')}))",
].join("\n");

const findingDetailProbe = [
  "import json, os, pathlib, sqlite3, sys, tempfile",
  "sys.path.insert(0, sys.argv[1])",
  "from workbench_db import apply_migrations, finding_result, serialize_filesystem_identity",
  "from workbench_target_state import ensure_security_target",
  "with tempfile.TemporaryDirectory(prefix='codex-security-complete-finding-') as directory:",
  "    root = (pathlib.Path(directory) / 'checkout').resolve()",
  "    root.mkdir()",
  "    connection = sqlite3.connect(':memory:')",
  "    connection.row_factory = sqlite3.Row",
  "    apply_migrations(connection)",
  "    timestamp = '2026-08-03T12:00:00Z'",
  "    target = ensure_security_target(connection, str(root))",
  "    connection.execute('INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', ('workspace', target, str(root), timestamp, timestamp))",
  "    metadata = root.stat()",
  "    connection.execute('INSERT INTO scans(id, workspace_id, target_id, target_path, target_device, target_inode, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('scan', 'workspace', target, str(root), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), 'unversioned', '.', 'standard', directory + '/results', 'complete', 'reporting', timestamp, timestamp, timestamp, timestamp))",
  "    connection.execute('INSERT INTO scan_progress(scan_id, updated_at) VALUES (?, ?)', ('scan', timestamp))",
  "    connection.execute('INSERT INTO findings(id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', ('finding', 'fingerprint', 'rule', 'anchor', timestamp, timestamp))",
  "    title = 'T' * 600",
  "    summary = 'S' * 2500",
  "    remediation = 'R' * 2500",
  "    long_path = 'src/' + '/'.join(['deep-component-abcdefghij'] * 100) + '/finding.py'",
  "    long_role = 'role-' + 'r' * 160",
  "    details = {'fingerprints': {'algorithm': 'codex-security/v1', 'primary': 'fingerprint'}, 'rootCause': {'summary': 'Missing authorization', 'evidenceRefs': [f'evidence-{index}' for index in range(5)]}, 'codeEvidence': [{'id': f'evidence-{index}', 'label': f'Source {index}', 'path': f'src/{index}.py', 'startLine': index + 1, 'code': f'unsafe_{index}()', 'explanation': 'Untrusted source.'} for index in range(5)], 'attackPath': {'dataflow': {'evidenceRefs': ['evidence-4'], 'summary': 'Attacker input reaches the sink.'}}, 'confidence': {'level': 'high', 'rationale': 'Confirmed with live replay.'}, 'severity': {'level': 'high', 'rationale': 'Cross-account disclosure.'}, 'remediationTests': ['Reject a cross-account request.'], 'preventiveControls': ['Centralize account authorization.'], 'status': 'open', 'currentTargetPath': '/forged/checkout', 'matches': [{'title': 'forged history'}], 'knownSince': '2000-01-01', 'knownScanIds': ['forged-scan'], 'sourceExcerpt': 'forged excerpt', 'artifactPaths': ['/untrusted/forged-artifact']}",
  "    connection.execute('INSERT INTO finding_occurrences(id, finding_id, scan_id, title, summary, severity, confidence, remediation, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', ('occurrence', 'finding', 'scan', title, summary, 'high', 'high', remediation, json.dumps(details), timestamp))",
  "    connection.execute('INSERT INTO finding_triage(occurrence_id, status, close_reason, note, updated_at) VALUES (?, ?, ?, ?, ?)', ('occurrence', 'closed', 'false_positive', 'Reviewed', timestamp))",
  "    for index in range(9):",
  "        path = long_path if index == 1 else f'src/{index}.py'",
  "        role = 'root_control' if index == 0 else long_role if index == 1 else 'sink'",
  "        connection.execute('INSERT INTO finding_locations(occurrence_id, relative_path, start_line, end_line, role, sort_order) VALUES (?, ?, ?, ?, ?, ?)', ('occurrence', path, index + 1, index + 1, role, index))",
  "    scan = connection.execute('SELECT * FROM scans WHERE id = ?', ('scan',)).fetchone()",
  "    occurrence = connection.execute('SELECT * FROM finding_occurrences WHERE id = ?', ('occurrence',)).fetchone()",
  "    preview = finding_result(connection, scan, occurrence)",
  "    detail = finding_result(connection, scan, occurrence, full_details=True)",
  "    print(json.dumps({'preview': {'evidenceCount': len(preview['codeEvidence']), 'locationCount': len(preview['locations']), 'locationPathLength': len(preview['locations'][1]['path']), 'locationRoleLength': len(preview['locations'][1]['role']), 'hasFingerprints': 'fingerprints' in preview, 'hasRemediationTests': 'remediationTests' in preview, 'titleLength': len(preview['title']), 'summaryLength': len(preview['summary']), 'remediationLength': len(preview['remediation'])}, 'detail': {'evidenceCount': len(detail['codeEvidence']), 'locationCount': len(detail['locations']), 'locationPathLength': len(detail['locations'][1]['path']), 'locationRoleLength': len(detail['locations'][1]['role']), 'absoluteLocationPathComplete': detail['locations'][1].get('absolutePath', '').replace(os.sep, '/').endswith(long_path), 'fingerprints': detail['fingerprints'], 'evidenceRefs': detail['rootCause']['evidenceRefs'], 'nestedEvidenceRefs': detail['attackPath']['dataflow']['evidenceRefs'], 'confidenceRationale': detail['confidence']['rationale'], 'severityRationale': detail['severity']['rationale'], 'remediationTests': detail['remediationTests'], 'preventiveControls': detail['preventiveControls'], 'artifactPaths': detail['artifactPaths'], 'hasForgedCurrentTargetPath': 'currentTargetPath' in detail, 'hasForgedExcerpt': detail.get('sourceExcerpt') == 'forged excerpt', 'hasForgedHistory': any(key in detail for key in ('matches', 'knownSince', 'knownScanIds')), 'status': detail['status'], 'triageStatus': detail['triage']['status'], 'titleLength': len(detail['title']), 'summaryLength': len(detail['summary']), 'remediationLength': len(detail['remediation'])}}))",
].join("\n");

function runFindingsIndex(
  targetId: string | null,
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    coverageFailure?: "tampered" | "noncanonical" | "pruned";
    lateCompletion?: boolean;
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
  settings: {
    targetIds?: string[];
    targetPath?: string;
    targetPaths?: string[];
    query?: string;
    coverageFailure?: "pruned";
    lateCompletion?: boolean;
  } = {},
): {
  findings: Array<{
    occurrenceId: string;
    scanId: string;
    targetId: string | null;
    targetPath: string;
  }>;
  coverageReads: string[];
  locationQueryCount: number;
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

  test("keeps earlier findings when follow-up coverage is unavailable", () => {
    const result = probeFindingsIndex(null);

    expect(result.findings).toEqual([
      expect.objectContaining({ occurrenceId: "current-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "orphan-old-occurrence" }),
      expect.objectContaining({ occurrenceId: "orphan-new-occurrence" }),
      expect.objectContaining({ occurrenceId: "stale-old-occurrence" }),
    ]);
    expect(result.coverageReads).toEqual([
      "current-new",
      "orphan-new",
      "stale-new",
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

  test("ranks repeated findings by scan chronology instead of completion order", () => {
    const result = probeFindingsIndex("current-target", {
      lateCompletion: true,
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "current-new-occurrence",
        scanId: "current-new",
      }),
    ]);
  });

  test("indexes every targetless scan even without a saved target", () => {
    const result = probeFindingsIndex(null, {
      targetPath: "/orphan/repository",
    });

    expect(result.findings).toEqual([
      expect.objectContaining({
        occurrenceId: "orphan-old-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
      expect.objectContaining({
        occurrenceId: "orphan-new-occurrence",
        targetId: null,
        targetPath: "/orphan/repository",
      }),
    ]);
    expect(result.coverageReads).toEqual(["orphan-new"]);
  });

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
      expect(result.locationQueryCount).toBe(1);
    }
  });

  test("searches repository paths only for cross-repository queries", () => {
    const scoped = probeFindingsIndex("current-target", {
      query: "/CURRENT/REPOSITORY",
    });
    expect(scoped.findings).toEqual([]);

    const unscoped = probeFindingsIndex(null, {
      query: "/ORPHAN/REPOSITORY",
    });
    expect(unscoped.findings.map((finding) => finding.occurrenceId)).toEqual([
      "orphan-old-occurrence",
      "orphan-new-occurrence",
    ]);
  });

  test("finds unversioned directory scans from nested subdirectories", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null)
      throw new Error("Python is required for scan-history tests.");
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        "-c",
        nestedDirectoryScanProbe,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      root: ["scan"],
      nested: ["scan"],
      independentGit: [],
      nestedIndependentGit: [],
      independentService: ["independent-service-scan"],
      nestedIndependentService: ["independent-service-scan"],
      independentGitWithoutGit: [],
      nestedIndependentGitWithoutGit: [],
      legacyGitRoot: ["legacy-git-scan"],
      legacyGitSubdirectory: ["legacy-git-scan"],
      registeredLegacyGitRoot: [],
      unversionedRoot: ["plain-a", "plain-b"],
      unversionedService: ["plain-a"],
      nestedGitCheckout: ["nested-git"],
      reusedCheckout: ["current-reused-scan"],
      reusedCheckoutSubdirectory: ["current-reused-scan"],
      movedCheckout: ["stale-reused-scan"],
      movedCheckoutCurrentPath: true,
      movedCheckoutSubdirectory: ["stale-reused-scan"],
      nestedReusedParentFallsBackToRoot: ["scan"],
      sameOriginOuter: ["same-origin-outer-scan"],
      sameOriginNested: ["same-origin-nested-scan"],
      staleRegisteredCheckout: [],
      staleRegisteredMatching: { scanCount: 0, coverageReads: [] },
      reusedRegisteredCheckout: ["current-owned-scan"],
      unscannedSiblingService: [],
      relatedCheckoutHistory: ["portable-scan"],
      relatedCheckoutVerified: true,
      forgedOriginHistory: [],
      forgedGitDirectoryHistory: [],
      forgedOriginMatching: { scanCount: 0, coverageReads: [] },
      forgedGitDirectoryMatching: { scanCount: 0, coverageReads: [] },
      relatedCheckoutMatching: {
        scanCount: 1,
        coverageReads: ["portable-scan"],
      },
      reusedCheckoutMatching: {
        scanCount: 1,
        coverageReads: ["current-reused-scan"],
      },
      movedCheckoutMatching: {
        scanCount: 2,
        coverageReads: ["stale-parent-scan", "stale-reused-scan"],
      },
      reusedRegisteredMatching: {
        scanCount: 1,
        coverageReads: ["current-owned-scan"],
      },
      unscannedSiblingMatching: { scanCount: 0, coverageReads: [] },
      forgedOriginMatchingScans: 0,
      forgedTargetlessIdentity: false,
      forgedGitDirectoryIdentity: false,
      relatedTargetlessIdentity: true,
      reusedRootDescendantScans: ["current-service-a", "current-service-b"],
      directTargetScanIds: ["scan"],
      directTargetLookupBounded: true,
      directTargetSkipsDescendants: true,
      descendantQueriesScoped: true,
    });
  }, 30_000);

  test("casefolds scan-specific searches and verifies moved checkout identity", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null)
      throw new Error("Python is required for finding-identity tests.");
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        "-c",
        relocatedFindingProbe,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    const output = JSON.parse(new TextDecoder().decode(result.stdout)) as {
      searches: Record<string, string[]>;
      movedAbsolutePath: string;
      expectedMovedAbsolutePath: string;
      movedSourceExcerpt?: string;
      replacementAbsolutePath: string | null;
      replacementSourceExcerpt: string | null;
    };
    expect(output.searches).toEqual({
      äuthorization: ["occurrence"],
      über: ["occurrence"],
      "äuth-strasse": ["occurrence"],
    });
    expect(output.movedAbsolutePath).toBe(output.expectedMovedAbsolutePath);
    expect(output.movedSourceExcerpt).toContain("dangerous_sink(user_input)");
    expect(output.replacementAbsolutePath).toBeNull();
    expect(output.replacementSourceExcerpt).toBeNull();
  });

  test("returns complete evidence and locations only in dedicated finding details", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();
    if (python === null)
      throw new Error("Python is required for finding-detail tests.");
    const result = Bun.spawnSync(
      [
        python,
        "-I",
        "-B",
        "-c",
        findingDetailProbe,
        join(PLUGIN_ROOT, "scripts"),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(new TextDecoder().decode(result.stderr)).toBe("");
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      preview: {
        evidenceCount: 4,
        locationCount: 8,
        locationPathLength: 2048,
        locationRoleLength: 128,
        hasFingerprints: false,
        hasRemediationTests: false,
        titleLength: 512,
        summaryLength: 2000,
        remediationLength: 2000,
      },
      detail: {
        evidenceCount: 5,
        locationCount: 9,
        locationPathLength: 2614,
        locationRoleLength: 165,
        absoluteLocationPathComplete: true,
        fingerprints: {
          algorithm: "codex-security/v1",
          primary: "fingerprint",
        },
        evidenceRefs: [
          "evidence-0",
          "evidence-1",
          "evidence-2",
          "evidence-3",
          "evidence-4",
        ],
        nestedEvidenceRefs: ["evidence-4"],
        confidenceRationale: "Confirmed with live replay.",
        severityRationale: "Cross-account disclosure.",
        remediationTests: ["Reject a cross-account request."],
        preventiveControls: ["Centralize account authorization."],
        artifactPaths: [],
        hasForgedCurrentTargetPath: false,
        hasForgedExcerpt: false,
        hasForgedHistory: false,
        status: "closed",
        triageStatus: "closed",
        titleLength: 600,
        summaryLength: 2500,
        remediationLength: 2500,
      },
    });
  });

  test("rejects tampered or noncanonical follow-up scan artifacts", () => {
    for (const coverageFailure of ["tampered", "noncanonical"] as const) {
      const result = runFindingsIndex("stale-target", { coverageFailure });

      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain(
        coverageFailure === "tampered"
          ? "sealed scan manifest changed"
          : "existing canonical non-symlink directory",
      );
    }
  });
});
