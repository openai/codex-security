import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';

const workflow = parse(readFileSync(new URL('../examples/pull-request.yml', import.meta.url), 'utf8'));
const scan = workflow.jobs.security;
const gate = workflow.jobs['required-review'];
const step = gate.steps[0];

test('the required PR check runs even when the scan job is skipped', () => {
  assert.ok(workflow.on.pull_request.types.includes('edited'), 'Retargeting a PR must rerun the scan against its new base.');
  assert.equal(gate.name, 'Codex Security');
  assert.equal(gate.needs, 'security');
  assert.equal(gate.if, 'always()');
  assert.deepEqual(scan.outputs, {
    'scan-status': '${{ steps.security.outputs.scan-status }}',
    'skip-reason': '${{ steps.security.outputs.skip-reason }}',
  });
  assert.deepEqual(step.env, {
    SCAN_JOB_RESULT: '${{ needs.security.result }}',
    SCAN_STATUS: '${{ needs.security.outputs.scan-status }}',
    SKIP_REASON: '${{ needs.security.outputs.skip-reason }}',
  });
  assert.equal(scan.if, 'github.event.pull_request.head.repo.full_name == github.repository');
  const checkout = scan.steps.find((entry: {uses?: string}) => entry.uses?.startsWith('actions/checkout@'));
  assert.equal(checkout.with.ref, '${{ github.event.pull_request.head.sha }}');
  assert.equal(checkout.with['fetch-depth'], 0);
  assert.equal(checkout.with['persist-credentials'], false);
  const action = scan.steps.find((entry: {id?: string}) => entry.id === 'security');
  assert.equal(action.with['fail-on-severity'], 'high');
});

for (const [jobResult, scanStatus, skipReason, accepted] of [
  ['success', 'completed', '', true],
  ['success', 'skipped', 'empty-diff', true],
  ['success', 'failed', '', false],
  ['success', 'skipped', 'dry-run', false],
  ['success', '', '', false],
  ['failure', 'completed', '', false],
  ['failure', 'skipped', 'empty-diff', false],
  ['cancelled', 'completed', '', false],
  ['skipped', '', '', false],
] as const) {
  test(`required PR check handles ${jobResult}/${scanStatus || 'no scan'}/${skipReason || 'no skip reason'}`, () => {
    const result = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step.run], {
      encoding: 'utf8', env: {PATH: process.env.PATH, SCAN_JOB_RESULT: jobResult, SCAN_STATUS: scanStatus, SKIP_REASON: skipReason},
    });
    assert.ifError(result.error);
    assert.equal(result.status, accepted ? 0 : 1, result.stderr);
  });
}
