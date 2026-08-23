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
  "import hashlib, json, os, pathlib, subprocess, sys, uuid",
  "plugin = pathlib.Path(sys.argv[1])",
  "root = pathlib.Path(sys.argv[2])",
  "source = sys.argv[3]",
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
  "        encoded = json.dumps(checkpoint).encode()",
  "        (checkpoint_dir / f'{hashlib.sha256(encoded).hexdigest()}.json').write_bytes(encoded)",
  "        result_path.write_text('{incomplete', encoding='utf-8')",
  "run('fail-deep-scan', '--scan-id', scan_id, '--message', 'Synthetic worker stopped.', '--deep-status', 'failed')",
  "stored = run('get-scan', '--scan-id', scan_id)['scan']",
  "findings_path = scan_dir / 'findings.json'",
  "findings = json.loads(findings_path.read_text(encoding='utf-8'))['findings'] if findings_path.exists() else []",
  "if source == 'refined-checkpoint':",
  "    histories = [item for finding in findings for item in finding.get('provenance', {}).get('previousFindings', [])]",
  "    print(json.dumps({'findingCount': stored['findingCount'], 'progressStatus': stored['progress']['status'], 'artifactFindingCount': len(findings), 'historyCount': len(histories), 'representedStartLines': sorted([finding['locations'][0]['startLine'] for finding in findings] + [finding['locations'][0]['startLine'] for finding in histories])}))",
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
