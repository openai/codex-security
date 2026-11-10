import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { parse } from 'yaml';

const workflow = parse(await readFile(new URL('../../.github/workflows/action-ci.yml', import.meta.url), 'utf8'));
const upstream = 'openai/codex-security';
const fork = 'example/fork';

test('node-ci owns pull requests and main pushes; forks can qualify their own pushes', () => {
  assert.ok('workflow_call' in workflow.on);
  assert.ok('workflow_dispatch' in workflow.on);
  assert.ok(!('pull_request' in workflow.on));
  assert.ok(workflow.on.push['branches-ignore'].includes('main'));
  assert.ok(workflow.on.push.tags.includes('**'));

  for (const [event, repository, ref, headRepo, validate, smoke] of [
    ['pull_request', upstream, 'refs/pull/1/merge', upstream, true, true],
    ['pull_request', upstream, 'refs/pull/1/merge', fork, true, false],
    ['push', upstream, 'refs/heads/main', undefined, true, true],
    ['push', upstream, 'refs/heads/topic', undefined, false, false],
    ['push', fork, 'refs/heads/topic', undefined, true, true],
    ['push', fork, 'refs/tags/test', undefined, true, true],
    ['workflow_dispatch', upstream, 'refs/heads/main', undefined, true, true],
    ['schedule', upstream, 'refs/heads/main', undefined, true, true],
  ]) {
    const github = { event_name: event, repository, ref, event: { pull_request: { head: { repo: { full_name: headRepo } } } } };
    for (const [id, expected] of [['validate', validate], ['dependencies', validate], ['smoke', smoke]]) {
      const condition = workflow.jobs[id].if ?? 'true';
      assert.equal(new Function('github', `return (${condition})`)(github), expected, `${event} ${repository} ${ref}: ${id}`);
    }
  }
});

test('the called workflow requires every eligible job to finish successfully', () => {
  const expression = workflow.on.workflow_call.outputs.passed.value;
  const passed = new Function('jobs', 'github', `return (${expression.slice(3, -2)})`);
  for (const headRepo of [upstream, fork]) {
    const github = { event_name: 'pull_request', repository: upstream, event: { pull_request: { head: { repo: { full_name: headRepo } } } } };
    // A skipped job never sets its outputs. Only fork PR smoke may be skipped.
    const expected = { validate: 'success', dependencies: 'success', smoke: headRepo === fork ? '' : 'success' };
    for (const [id, expectedStatus] of Object.entries(expected)) {
      assert.equal(workflow.jobs[id].outputs.result, '${{ job.status }}');
      for (const status of ['success', 'failure', 'cancelled', '']) {
        const jobs = Object.fromEntries(Object.entries({ ...expected, [id]: status }).map(([job, result]) =>
          [job, { outputs: result ? { result } : {} }]));
        assert.equal(passed(jobs, github), status === expectedStatus, `${headRepo}: ${id} ${status || 'skipped'}`);
      }
    }
  }
});


test('hosted smoke uses the shipped sandbox setup without a CI-only prerequisite', () => {
  for (const job of [workflow.jobs.validate, workflow.jobs.smoke]) {
    assert.ok(job.steps.every(step => !/needrestart|setup-ubuntu-sandbox/.test(step.run ?? '')));
  }
  assert.ok(workflow.jobs.validate.steps.some(step => step.run === 'node scripts/linux-smoke.mjs'));
  assert.ok(workflow.jobs.smoke.steps.some(step => step.uses === './'));
});
