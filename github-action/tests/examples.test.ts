import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';

const workflow = parse(readFileSync(new URL('../examples/pull-request.yml', import.meta.url), 'utf8'));
const scan = workflow.jobs.security;
const gate = workflow.jobs['required-review'];
const step = gate.steps.find((value: {name: string}) => value.name === 'Require a completed review or an empty diff');

function context(action: string, changes: Record<string, unknown> = {}, fork = false) {
  return {run_id: 42, token: 'synthetic-read-only-token', repository: 'example/repo', event: {
    action, changes, pull_request: {number: 7, head: {sha: 'a'.repeat(40), repo: {full_name: fork ? 'example/fork' : 'example/repo'}}, base: {ref: 'main', sha: 'b'.repeat(40)}},
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
  assert.equal(render(gate.name, context('synchronize')), 'Codex Security / main');
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
      assert.equal(render(gate.name, github), 'Codex Security / main');
    }
  });
}

for (const field of ['title', 'body']) {
  test(`${field} edits cannot cancel a scan or replace its required result`, () => {
    const github = context('edited', {[field]: {from: 'Previous value'}});
    github.run_id = 43;
    assert.equal(workflow.concurrency['cancel-in-progress'], true);
    assert.notEqual(render(workflow.concurrency.group, github), render(workflow.concurrency.group, context('synchronize')));
    assert.notEqual(render(gate.name, github), 'Codex Security / main');
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
    const result = spawnSync('/bin/bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', step.run], {
      encoding: 'utf8', env: {PATH: process.env.PATH, SCAN_JOB_RESULT: jobResult, SCAN_STATUS: scanStatus, SKIP_REASON: skipReason},
    });
    assert.ifError(result.error);
    assert.equal(result.status, accepted ? 0 : 1, result.stderr);
  });
}


async function prBindingFixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'action-pr-binding-'));
  t.after(() => rm(directory, {recursive:true, force:true}));
  const gh = join(directory, 'gh');
  await writeFile(gh, `#!${process.execPath}
    const assert = require('node:assert/strict');
    assert.deepEqual(process.argv.slice(2), ['api', 'repos/example/repo/pulls/7', '--jq', '[.head.sha, .base.ref, .base.sha] | @tsv']);
    assert.equal(process.env.GH_TOKEN, 'synthetic-read-only-token');
    console.log(process.env.SYNTHETIC_CURRENT_PR);
    process.exitCode = Number(process.env.SYNTHETIC_API_EXIT);
  `, {mode:0o700});
  const before = scan.steps[0];
  const after = gate.steps[0];
  assert.equal(workflow.permissions['pull-requests'], 'read');
  assert.equal(before.name, 'Verify the PR still matches this scan');
  assert.deepEqual(after, before);
  return (github: ReturnType<typeof context>, current: ReturnType<typeof context>, accepting = false, apiExit = 0) => {
    const pr = current.event.pull_request;
    const result = spawnSync('/bin/bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c',
      accepting ? gate.steps.map((value: {run: string}) => value.run).join('\n') : before.run], {
      encoding:'utf8', env:{PATH:directory, GITHUB_REPOSITORY:github.repository,
        ...Object.fromEntries(Object.entries(before.env).map(([key, value]) => [key, render(String(value), github)])),
        SYNTHETIC_CURRENT_PR:[pr.head.sha, pr.base.ref, pr.base.sha].join('\t'), SYNTHETIC_API_EXIT:String(apiExit),
        SCAN_JOB_RESULT:'success', SCAN_STATUS:'completed', SKIP_REASON:''},
    });
    assert.ifError(result.error);
    return result;
  };
}

for (const [label, currentHead, currentRef, currentBase, apiExit, accepted] of [
  ['current snapshot', 'a', 'main', 'b', 0, true],
  ['stale head', 'c', 'main', 'b', 0, false],
  ['retarget with the same base commit', 'a', 'release', 'b', 0, false],
  ['target advanced', 'a', 'main', 'c', 0, false],
  ['API failure', 'a', 'main', 'b', 7, false],
] as const) {
  test(`PR snapshot binding fails closed before scanning and accepting: ${label}`, async t => {
    const run = await prBindingFixture(t);
    const original = context('synchronize');
    const current = context('synchronize');
    current.event.pull_request.head.sha = currentHead.repeat(40);
    current.event.pull_request.base = {ref:currentRef, sha:currentBase.repeat(40)};
    for (const accepting of [false, true]) {
      const result = run(original, current, accepting, apiExit);
      assert.equal(result.status === 0, accepted, result.stderr);
      if (apiExit === 0 && !accepted) assert.match(result.stderr, /PR head or target changed/);
    }
  });
}

test('case-only retargets isolate an old rerun and reject its completed result', async t => {
  const run = await prBindingFixture(t);
  const original = context('opened');
  const current = context('edited', {base: {ref: {from: 'main'}}});
  current.event.pull_request.base.ref = 'Main';
  current.run_id = 43;
  const oldRerun = {...original, run_attempt:2};
  const group = (github: ReturnType<typeof context>) => render(workflow.concurrency.group, github).toLowerCase();
  assert.notEqual(group(original), group(current));
  assert.equal(group(original), group(oldRerun));
  assert.notEqual(render(gate.name, original), render(gate.name, current));
  assert.equal(run(original, original).status, 0);
  // The target changes after the initial check, while the first scan is running.
  assert.equal(run(original, current, true).status, 1);
  assert.equal(run(current, current).status, 0);
  assert.equal(run(current, current, true).status, 0);
  assert.equal(run(oldRerun, current).status, 1);
  assert.equal(run(oldRerun, current, true).status, 1);
});

test('same-head PRs targeting different branches require distinct check names', () => {
  const first = context('opened');
  const second = context('opened');
  second.event.pull_request.number = 8;
  second.event.pull_request.base.ref = 'release';
  second.run_id = 43;
  assert.equal(first.event.pull_request.head.sha, second.event.pull_request.head.sha);
  assert.equal(first.event.pull_request.base.sha, second.event.pull_request.base.sha);
  assert.notEqual(render(gate.name, first), render(gate.name, second));
  assert.notEqual(render(workflow.concurrency.group, first), render(workflow.concurrency.group, second));
});
