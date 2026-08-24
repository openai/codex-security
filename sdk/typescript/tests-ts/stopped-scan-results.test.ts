import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

const stoppedScanProbe = [
  "import argparse, hashlib, json, os, pathlib, shutil, sqlite3, subprocess, sys, uuid",
  "plugin = pathlib.Path(sys.argv[1])",
  "root = pathlib.Path(sys.argv[2])",
  "source = sys.argv[3]",
  "terminal_status = sys.argv[4] if len(sys.argv) > 4 else 'failed'",
  "state = root / 'state'",
  "home = root / 'codex-home'",
  "target = root / 'target'",
  "target_file = target / 'src' / 'extract.py'",
  "target_file.parent.mkdir(parents=True)",
  "target_file.write_text('\\n' * 50, encoding='utf-8')",
  "config = home / 'codex-security' / 'config.toml'",
  "config.parent.mkdir(parents=True)",
  "config.write_text('[deep_scan]\\nworkers = 1\\nmax_discovery_runs = 1\\n', encoding='utf-8')",
  "environment = {**os.environ, 'CODEX_SECURITY_STATE_DIR': str(state), 'CODEX_HOME': str(home)}",
  "script = plugin / 'scripts' / 'workbench_db.py'",
  "def run(*arguments):",
  "    completed = subprocess.run([sys.executable, '-I', '-B', str(script), *arguments], check=True, capture_output=True, text=True, env=environment)",
  "    return json.loads(completed.stdout)",
  "started = run('begin-deep-scan', '--thread-id', 'stopped-result-owner', '--target-path', str(target), '--scope', '.', '--scan-root', str(root / 'scans'), '--available-parallelism', '4')['deepScan']",
  "scan_id = started['scanId']",
  "scan_dir = pathlib.Path(started['scanDir'])",
  "worker_id = str(uuid.uuid4())",
  "artifact_dir = scan_dir / 'artifacts' / 'deep_discovery' / source",
  "artifact_dir.mkdir(parents=True)",
  "prompt_path = artifact_dir / 'prompt.md'",
  "prompt_path.write_text('Review the fixture.\\n', encoding='utf-8')",
  "result_path = artifact_dir / 'result.json'",
  "base = ('upsert-deep-scan-worker', '--scan-id', scan_id, '--worker-id', worker_id, '--kind', 'discovery', '--prompt-path', str(prompt_path), '--artifact-dir', str(artifact_dir), '--attempt', '1')",
  "run(*base, '--status', 'running')",
  "finding = json.loads((plugin / 'examples' / 'completed-scan' / 'findings.json').read_text(encoding='utf-8'))['findings'][0]",
  "finding.setdefault('provenance', {})['candidateId'] = 'checkpoint-candidate'",
  "payload = {'scanId': scan_id, 'findings': [finding], 'coverage': {'completeness': 'partial', 'surfaces': [], 'explicitExclusions': [], 'deferred': [{'candidateId': 'pending-validation', 'reason': 'Validation stopped with the scan.', 'paths': ['src/extract.py']}]}, 'threatModel': {'summary': 'Synthetic stopped-scan threat model.'}}",
  "if source == 'accepted':",
  "    result_path.write_text(json.dumps(payload), encoding='utf-8')",
  "    run(*base, '--status', 'succeeded', '--result-manifest-path', str(result_path))",
  "else:",
  "    checkpoint = {**payload, 'complete': False}",
  "    checkpoint_dir = artifact_dir / 'checkpoints'",
  "    checkpoint_dir.mkdir()",
  "    if source == 'refined-checkpoint':",
  "        earlier = json.loads(json.dumps(checkpoint))",
  "        earlier['findings'][0]['locations'][0].update({'startLine': 21, 'endLine': 26})",
  "        later = json.loads(json.dumps(checkpoint))",
  "        later['findings'][0]['locations'][0].update({'startLine': 24, 'endLine': 26})",
  "        for document in (earlier, later):",
  "            encoded = json.dumps(document).encode()",
  "            (checkpoint_dir / f'{hashlib.sha256(encoded).hexdigest()}.json').write_bytes(encoded)",
  "        result_path.write_text(json.dumps(later), encoding='utf-8')",
  "    else:",
  "        if source == 'distinct-instances':",
  "            first = json.loads(json.dumps(finding))",
  "            first['identity'] = {'anchor': 'shared-anchor', 'instance': 'first'}",
  "            second = json.loads(json.dumps(finding))",
  "            second['identity'] = {'anchor': 'shared-anchor', 'instance': 'second'}",
  "            checkpoint['findings'] = [first, second]",
  "        encoded = json.dumps(checkpoint).encode()",
  "        (checkpoint_dir / f'{hashlib.sha256(encoded).hexdigest()}.json').write_bytes(encoded)",
  "        result_path.write_text('{incomplete', encoding='utf-8')",
  "if source == 'cancel-io-retry':",
  "    os.environ.update(environment)",
  "    sys.path.insert(0, str(plugin / 'scripts'))",
  "    import workbench_db",
  "    connection = workbench_db.connect()",
  "    original_write = workbench_db.saved_results._write_prepared_scan_finalization",
  "    workbench_db.saved_results._write_prepared_scan_finalization = lambda prepared: (_ for _ in ()).throw(OSError('synthetic cancellation publication failure'))",
  "    workbench_db.cancel_scan_locked(connection, argparse.Namespace(scan_id=scan_id, thread_id=None))",
  "    workbench_db.saved_results._write_prepared_scan_finalization = original_write",
  "    connection.close()",
  "    stored = run('get-scan', '--scan-id', scan_id)['scan']",
  "    findings_path = scan_dir / 'findings.json'",
  "    findings = json.loads(findings_path.read_text(encoding='utf-8'))['findings'] if findings_path.exists() else []",
  "    with sqlite3.connect(state / 'workbench.sqlite3') as database:",
  "        frozen = database.execute('SELECT retained_source_digests_json FROM scans WHERE id = ?', (scan_id,)).fetchone()[0]",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'progressStatus': stored['progress']['status'], 'artifactFindingCount': len(findings), 'frozen': json.loads(frozen) if frozen else None}))",
  "    raise SystemExit(0)",
  "run('fail-deep-scan', '--scan-id', scan_id, '--message', 'Synthetic worker stopped.', '--deep-status', terminal_status)",
  "if source == 'legacy-seal-io-retry':",
  "    shutil.rmtree(artifact_dir)",
  "    manifest_path = scan_dir / 'scan-manifest.json'",
  "    legacy_manifest = json.loads(manifest_path.read_text(encoding='utf-8'))",
  "    legacy_manifest['scan']['status'] = 'completed'",
  "    legacy_manifest['scan'].pop('preservedSources', None)",
  "    manifest_path.write_text(json.dumps(legacy_manifest, indent=2, sort_keys=True) + '\\n', encoding='utf-8')",
  "    os.environ.update(environment)",
  "    sys.path.insert(0, str(plugin / 'scripts'))",
  "    import workbench_db",
  "    connection = workbench_db.connect()",
  "    connection.execute('UPDATE scans SET seal_manifest_digest = NULL, retained_source_digests_json = NULL WHERE id = ?', (scan_id,))",
  "    connection.commit()",
  "    original_write = workbench_db.saved_results._write_prepared_scan_finalization",
  "    workbench_db.saved_results._write_prepared_scan_finalization = lambda prepared: (_ for _ in ()).throw(OSError('synthetic publication failure'))",
  "    first_failed = False",
  "    try:",
  "        workbench_db.preserve_scan_results_locked(connection, scan_id)",
  "    except OSError:",
  "        first_failed = True",
  "    frozen_after_failure = connection.execute('SELECT retained_source_digests_json FROM scans WHERE id = ?', (scan_id,)).fetchone()[0]",
  "    workbench_db.saved_results._write_prepared_scan_finalization = original_write",
  "    retry_published = workbench_db.preserve_scan_results_locked(connection, scan_id)",
  "    frozen_after_success = connection.execute('SELECT retained_source_digests_json FROM scans WHERE id = ?', (scan_id,)).fetchone()[0]",
  "    final_manifest = json.loads(manifest_path.read_text(encoding='utf-8'))",
  "    final_findings = json.loads((scan_dir / 'findings.json').read_text(encoding='utf-8'))['findings']",
  "    connection.close()",
  "    print(json.dumps({'firstFailed': first_failed, 'frozenAfterFailure': frozen_after_failure, 'retryPublished': retry_published, 'frozenAfterSuccess': json.loads(frozen_after_success) if frozen_after_success else None, 'status': final_manifest['scan']['status'], 'findingCount': len(final_findings)}))",
  "    raise SystemExit(0)",
  "if source == 'late-checkpoint':",
  "    manifest_before = (scan_dir / 'scan-manifest.json').read_bytes()",
  "    findings_before = (scan_dir / 'findings.json').read_bytes()",
  "    late = json.loads(json.dumps(checkpoint))",
  "    late_finding = json.loads(json.dumps(finding))",
  "    late_finding['occurrenceId'] = 'occ_111111111111111111111111'",
  "    late_finding['ruleId'] = 'late.checkpoint'",
  "    late_finding['title'] = 'Late checkpoint finding'",
  "    late_finding['locations'][0].update({'startLine': 10, 'endLine': 12})",
  "    late_finding.setdefault('provenance', {})['candidateId'] = 'late-checkpoint-candidate'",
  "    late['findings'].append(late_finding)",
  "    encoded = json.dumps(late).encode()",
  "    (checkpoint_dir / f'{hashlib.sha256(encoded).hexdigest()}.json').write_bytes(encoded)",
  "stored = run('get-scan', '--scan-id', scan_id)['scan']",
  "findings_path = scan_dir / 'findings.json'",
  "findings = json.loads(findings_path.read_text(encoding='utf-8'))['findings'] if findings_path.exists() else []",
  "if source == 'late-checkpoint':",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'artifactFindingCount': len(findings), 'manifestUnchanged': manifest_before == (scan_dir / 'scan-manifest.json').read_bytes(), 'findingsUnchanged': findings_before == (scan_dir / 'findings.json').read_bytes()}))",
  "elif source == 'refined-checkpoint':",
  "    histories = [item for finding in findings for item in finding.get('provenance', {}).get('previousFindings', [])]",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'progressStatus': stored['progress']['status'], 'artifactFindingCount': len(findings), 'historyCount': len(histories), 'representedStartLines': sorted([finding['locations'][0]['startLine'] for finding in findings] + [finding['locations'][0]['startLine'] for finding in histories])}))",
  "elif source == 'distinct-instances':",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'artifactFindingCount': len(findings), 'instances': sorted(finding['identity']['instance'] for finding in findings)}))",
  "else:",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'progressStatus': stored['progress']['status'], 'artifactFindingCount': len(findings)}))",
].join("\n");

test.each(["accepted", "checkpoint"] as const)(
  "preserves %s Deep findings when the scan stops",
  (source) => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const root = mkdtempSync(join(tmpdir(), "codex-security-stopped-scan-"));
    temporaryDirectories.push(root);
    const result = spawnSync(
      python!,
      ["-I", "-B", "-c", stoppedScanProbe, PLUGIN_ROOT, root, source],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      findingCount: 1,
      progressStatus: "failed",
      artifactFindingCount: 1,
    });
  },
  30_000,
);

test("keeps refined checkpoints as one finding with retained history", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const root = mkdtempSync(
    join(tmpdir(), "codex-security-refined-checkpoint-"),
  );
  temporaryDirectories.push(root);
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      stoppedScanProbe,
      PLUGIN_ROOT,
      root,
      "refined-checkpoint",
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 1,
    progressStatus: "failed",
    artifactFindingCount: 1,
    historyCount: 1,
    representedStartLines: [21, 24],
  });
}, 30_000);

test.each(["failed", "interrupted"] as const)(
  "keeps the first %s seal immutable when a worker writes late",
  (terminalStatus) => {
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const root = mkdtempSync(join(tmpdir(), "codex-security-late-checkpoint-"));
    temporaryDirectories.push(root);
    const result = spawnSync(
      python!,
      [
        "-I",
        "-B",
        "-c",
        stoppedScanProbe,
        PLUGIN_ROOT,
        root,
        "late-checkpoint",
        terminalStatus,
      ],
      { encoding: "utf8" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      findingCount: 1,
      artifactFindingCount: 1,
      manifestUnchanged: true,
      findingsUnchanged: true,
    });
  },
  30_000,
);

test("retries a legacy stopped seal after transient publication failure", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const root = mkdtempSync(join(tmpdir(), "codex-security-legacy-seal-retry-"));
  temporaryDirectories.push(root);
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      stoppedScanProbe,
      PLUGIN_ROOT,
      root,
      "legacy-seal-io-retry",
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    firstFailed: true,
    frozenAfterFailure: null,
    retryPublished: true,
    frozenAfterSuccess: {},
    status: "failed",
    findingCount: 1,
  });
}, 30_000);

test("preserves distinct instances from one worker candidate", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const root = mkdtempSync(
    join(tmpdir(), "codex-security-distinct-instances-"),
  );
  temporaryDirectories.push(root);
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      stoppedScanProbe,
      PLUGIN_ROOT,
      root,
      "distinct-instances",
    ],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 2,
    artifactFindingCount: 2,
    instances: ["first", "second"],
  });
}, 30_000);

test("retries canceled result publication after a transient failure", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const root = mkdtempSync(join(tmpdir(), "codex-security-cancel-retry-"));
  temporaryDirectories.push(root);
  const result = spawnSync(
    python!,
    ["-I", "-B", "-c", stoppedScanProbe, PLUGIN_ROOT, root, "cancel-io-retry"],
    { encoding: "utf8" },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    findingCount: 1,
    progressStatus: "canceled",
    artifactFindingCount: 1,
    frozen: expect.any(Object),
  });
}, 30_000);
