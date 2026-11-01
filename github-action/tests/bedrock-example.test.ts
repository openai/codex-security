import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { parse } from 'yaml';
import { parseInputs, scanArguments } from '../src/inputs.js';

test('Bedrock OIDC example scopes temporary credentials to the native scan step', async () => {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  const workflows = [...readme.matchAll(/```yaml\n([\s\S]*?)\n```/g)].map(match => parse(match[1]));
  const workflow = workflows.find(value => value.name === 'Codex Security Bedrock');
  assert.ok(workflow);
  assert.deepEqual(Object.keys(workflow.on), ['workflow_dispatch']);
  const job = workflow.jobs.security;
  assert.equal(job.permissions['id-token'], 'write');
  assert.equal(job.env, undefined);
  const aws = job.steps.find((step: any) => step.id === 'aws');
  const scan = job.steps.find((step: any) => step.id === 'security');
  assert.ok(job.steps.indexOf(aws) < job.steps.indexOf(scan));
  assert.match(aws.uses, /^aws-actions\/configure-aws-credentials@[a-f0-9]{40}$/);
  assert.equal(aws.with['output-env-credentials'], false);
  assert.equal(aws.with['output-credentials'], true);
  assert.equal(aws.with['role-to-assume'], '${{ vars.AWS_ROLE_ARN }}');
  assert.equal(aws.with['aws-region'], '${{ vars.AWS_REGION }}');
  assert.deepEqual(scan.env, {
    AWS_REGION:'${{ vars.AWS_REGION }}',
    AWS_ACCESS_KEY_ID:'${{ steps.aws.outputs.aws-access-key-id }}',
    AWS_SECRET_ACCESS_KEY:'${{ steps.aws.outputs.aws-secret-access-key }}',
    AWS_SESSION_TOKEN:'${{ steps.aws.outputs.aws-session-token }}',
  });
  assert.equal(scan.with.model, '${{ vars.BEDROCK_MODEL_ID }}');
  const inputs = parseInputs(name => scan.with[name] ?? '', '/checkout');
  const args = scanArguments(inputs, {repository:'/checkout'}, '/results');
  assert.equal(args[args.indexOf('--provider') + 1], 'amazon-bedrock');
  assert.equal(args[args.indexOf('--auth') + 1], 'auto');
});
