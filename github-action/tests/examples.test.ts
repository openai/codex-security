import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';

const workflow = parse(readFileSync(new URL('../examples/pull-request.yml', import.meta.url), 'utf8'));
const scan = workflow.jobs.security;
const gate = workflow.jobs['required-review'];
const step = gate.steps[0];

function context(action: string, changes: Record<string, unknown> = {}, fork = false) {
  return {repository: 'example/repo', event: {
    action, changes, pull_request: {number: 7, head: {repo: {full_name: fork ? 'example/fork' : 'example/repo'}}},
  }};
}

function evaluate(expression: string, github: ReturnType<typeof context>): unknown {
  // These workflow expressions use the same boolean operators as JavaScript.
  return new Function('github', 'always', `return (${expression});`)(github, () => true);
}

function render(value: string, github: ReturnType<typeof context>): string {
  return value.replace(/\$\{\{([\s\S]*?)\}\}/g, (_, expression) => String(evaluate(expression, github)));
}

test('the required PR check runs even when the scan job is skipped', () => {
  assert.ok(workflow.on.pull_request.types.includes('edited'), 'Retargeting a PR must rerun the scan against its new base.');
  assert.equal(render(gate.name, context('synchronize')), 'Codex Security');
  assert.equal(gate.needs, 'security');
  assert.equal(evaluate(gate.if, context('synchronize', {}, true)), true);
  assert.deepEqual(scan.outputs, {
    'scan-status': '${{ steps.security.outputs.scan-status }}',
    'skip-reason': '${{ steps.security.outputs.skip-reason }}',
  });
  assert.deepEqual(step.env, {
    SCAN_JOB_RESULT: '${{ needs.security.result }}',
    SCAN_STATUS: '${{ needs.security.outputs.scan-status }}',
    SKIP_REASON: '${{ needs.security.outputs.skip-reason }}',
  });
  assert.equal(evaluate(scan.if, context('synchronize', {}, true)), false);
  const checkout = scan.steps.find((entry: {uses?: string}) => entry.uses?.startsWith('actions/checkout@'));
  assert.equal(checkout.with.ref, '${{ github.event.pull_request.head.sha }}');
  assert.equal(checkout.with['fetch-depth'], 0);
  assert.equal(checkout.with['persist-credentials'], false);
  const action = scan.steps.find((entry: {id?: string}) => entry.id === 'security');
  assert.equal(action.with['fail-on-severity'], 'high');
});

for (const [label, action, changes, review] of [
  ['opened', 'opened', {}, true],
  ['new commits', 'synchronize', {}, true],
  ['reopened', 'reopened', {}, true],
  ['ready for review', 'ready_for_review', {}, true],
  ['base retarget without a new head', 'edited', {base: {ref: {from: 'previous-base'}}}, true],
  ['title edit', 'edited', {title: {from: 'Previous title'}}, false],
  ['body edit', 'edited', {body: {from: 'Previous body'}}, false],
] as const) {
  test(`PR workflow admission handles ${label}`, () => {
    const github = context(action, changes);
    assert.equal(evaluate(scan.if, github), review);
    assert.equal(evaluate(gate.if, github), review);
    if (review) {
      assert.equal(render(gate.name, github), 'Codex Security');
      assert.equal(render(workflow.concurrency.group, github), render(workflow.concurrency.group, context('synchronize')));
    }
  });
}

for (const field of ['title', 'body']) {
  test(`${field} edits cannot cancel a scan or replace its required result`, () => {
    const github = context('edited', {[field]: {from: 'Previous value'}});
    assert.equal(workflow.concurrency['cancel-in-progress'], true);
    assert.notEqual(render(workflow.concurrency.group, github), render(workflow.concurrency.group, context('synchronize')));
    assert.notEqual(render(gate.name, github), 'Codex Security');
  });
}

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
