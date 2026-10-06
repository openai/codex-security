import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { parse } from 'yaml';
import { INPUT_NAMES, parseInputs } from '../src/inputs.js';
import { OUTPUT_NAMES } from '../src/main.js';
const metadata = parse(await readFile(new URL('../../action.yml', import.meta.url), 'utf8'));
assert.deepEqual(Object.keys(metadata.inputs).sort(), [...INPUT_NAMES].sort(), 'action.yml inputs must match the parser');
assert.deepEqual(Object.keys(metadata.outputs).sort(), [...OUTPUT_NAMES].sort(), 'action.yml outputs must match implementation');
assert.equal(metadata.runs.using, 'node24');
assert.equal(metadata.runs.main, 'github-action/dist/index.cjs');
assert.equal(metadata.runs.post, 'github-action/dist/post.cjs');
assert.equal(metadata.runs['post-if'], 'always()');
const defaults = parseInputs(name => String(metadata.inputs[name]?.default ?? '').replace('${{ github.workspace }}', '/checkout'), '/checkout');
assert.equal(defaults.failOnSeverity, 'none');
assert.equal(defaults.scope, 'repository');
assert.equal(defaults.uploadArtifacts, false);
assert.equal(defaults.verbose, true);
for (const group of [metadata.inputs, metadata.outputs]) for (const value of Object.values(group) as {description: string}[]) assert.ok(value.description);
const examples = await readFile(new URL('../README.md', import.meta.url), 'utf8');
let workflowCount = 0;
for (const match of examples.matchAll(/```yaml\n([\s\S]*?)\n```/g)) {
  const example = parse(match[1]);
  if (!example?.jobs) continue;
  workflowCount++;
  for (const job of Object.values(example.jobs) as {steps: {uses?: string; with?: Record<string,unknown>}[]}[]) {
    for (const step of job.steps) {
      if (step.uses?.startsWith('openai/codex-security@')) {
        for (const key of Object.keys(step.with ?? {})) assert.ok(INPUT_NAMES.includes(key as typeof INPUT_NAMES[number]), `Workflow example uses unknown input ${key}`);
      } else if (step.uses) assert.match(step.uses, /@[a-f0-9]{40}$/, 'Example dependency must use a full commit SHA');
    }
  }
}
assert.equal(workflowCount, 2, 'README must include complete PR and repository workflows');
console.log('Action metadata and implementation contract agree.');
