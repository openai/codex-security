import test from 'node:test';
import assert from 'node:assert/strict';
import { parseInputs, scanArguments } from '../src/inputs.js';
const parse = (values: Record<string, string> = {}) => parseInputs(key => values[key] ?? '', '/checkout');

test('defaults are stable across events', () => {
  const input = parse();
  assert.deepEqual(input, {
    repository: '/checkout', scope: 'repository', paths: [], diffBase: undefined, mode: 'standard', cyberAccessProgram: undefined,
    provider: 'openai', model: 'gpt-5.6-sol', effort: 'xhigh', maxCost: undefined, maxTimeHours: undefined, failOnSeverity: 'none',
    verbose: true, dryRun: false, summary: true, annotations: true,
    uploadArtifacts: false, artifactName: 'codex-security', retentionDays: 7,
  });
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.equal(args[args.indexOf('--mode') + 1], 'standard');
  assert.ok(!args.includes('--max-time-hours'));
  assert.ok(!args.includes('--fail-on-severity'));
  assert.ok(!args.includes('--python'));
  assert.ok(!args.includes('--cyber-access-program'));
});
test('provider and model inputs map directly to scan CLI arguments in both modes', () => {
  for (const provider of ['openai', 'openrouter', 'fireworks', 'amazon-bedrock'])
  for (const mode of ['standard', 'deep']) for (const dryRun of ['false', 'true']) {
    const input = parse({provider, model:'synthetic/model', mode, 'dry-run':dryRun});
    const args = scanArguments(input, {repository:'/checkout'}, '/results');
    assert.equal(args[args.indexOf('--provider') + 1], provider);
    assert.equal(args[args.indexOf('--auth') + 1], provider === 'amazon-bedrock' || dryRun === 'true' ? 'auto' : 'api-key');
    assert.ok(args.includes('--model=synthetic/model'));
    assert.equal(args.includes('--dry-run'), dryRun === 'true');
  }
  assert.throws(() => parse({provider:'unsupported'}), /provider must be one of/);
  for (const provider of ['amazon-bedrock', 'openrouter', 'fireworks']) for (const model of ['', '  ']) {
    const args = scanArguments(parse({provider, model}), {repository:'/checkout'}, '/results');
    assert.ok(!args.some(arg => arg.startsWith('--model')), 'Leave missing model validation to the CLI');
  }
  assert.equal(parse({provider:'openai'}).model, 'gpt-5.6-sol');
});
test('reasoning efforts pass through to both scan modes', () => {
  for (const mode of ['standard', 'deep']) for (const effort of ['ultra', 'synthetic-future-effort', '--help']) {
    const args = scanArguments(parse({mode, effort}), {repository:'/checkout'}, '/results');
    assert.ok(args.includes(`--effort=${effort}`));
    assert.ok(!args.includes(effort));
  }
  assert.equal(parse({effort:'  '}).effort, 'xhigh');
});
test('Cyber access selections reach both standard and Deep scan CLI invocations', () => {
  for (const mode of ['standard', 'deep']) for (const program of ['standard', 'daybreak_blue', 'daybreak_red']) {
    const args = scanArguments(parse({mode, 'cyber-access-program':program}), {repository:'/checkout'}, '/results');
    assert.equal(args[args.indexOf('--cyber-access-program') + 1], program);
  }
  const blank = scanArguments(parse({'cyber-access-program':'  '}), {repository:'/checkout'}, '/results');
  assert.ok(!blank.includes('--cyber-access-program'));
  assert.throws(() => parse({'cyber-access-program':'unsupported'}), /cyber-access-program must be one of/);
});
test('Deep scans forward an explicit discovery budget and selected repository paths', () => {
  const input = parse({mode:'deep', paths:'./src/\nlib', 'max-time-hours':'1.5'});
  assert.equal(input.mode, 'deep');
  assert.equal(input.maxTimeHours, 1.5);
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.equal(args[args.indexOf('--mode') + 1], 'deep');
  assert.equal(args[args.indexOf('--max-time-hours') + 1], '1.5');
  assert.deepEqual(args.filter(arg => arg.startsWith('--path=')).map(arg => arg.slice('--path=./'.length)), ['src', 'lib']);
});
test('Deep scans leave an unset discovery budget to the CLI', () => {
  const input = parse({mode:'deep'});
  assert.equal(input.maxTimeHours, undefined);
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.equal(args[args.indexOf('--mode') + 1], 'deep');
  assert.ok(!args.includes('--max-time-hours'));
});
test('Deep scan mode and discovery budgets reject unsupported combinations', () => {
  assert.throws(() => parse({mode:'thorough'}), /mode must be one of: standard, deep/);
  assert.throws(() => parse({mode:'deep', scope:'diff'}), /mode: deep requires scope: repository/);
  assert.throws(() => parse({'max-time-hours':'1'}), /max-time-hours requires mode: deep/);
  for (const value of ['NaN', 'Infinity', '-1', '0', '96.1'])
    assert.throws(() => parse({mode:'deep', 'max-time-hours':value}), {message: 'max-time-hours must be a positive number no greater than 96.'});
  assert.equal(parse({mode:'deep', 'max-time-hours':'96'}).maxTimeHours, 96);
});
test('verbose diagnostics default on and can be explicitly disabled', () => {
  const args = (values: Record<string, string>) => scanArguments(parse(values), {repository:'/checkout'}, '/results');
  assert.ok(args({}).includes('--verbose'));
  assert.ok(!args({verbose:'false'}).includes('--verbose'));
});
test('only repository and diff scopes are supported, with separate path and diff inputs', () => {
  assert.throws(() => parse({scope:'diff', paths:'src\nlib'}), /cannot be combined/);
  assert.throws(() => parse({scope:'working-tree'}), /scope must be one of: repository, diff/);
  assert.throws(() => parse({'diff-base':'HEAD~1'}), /requires scope: diff/);
});
test('numeric and boolean parsing follows their documented types', () => {
  for (const value of ['NaN','Infinity','-1','0','10 dollars']) assert.throws(() => parse({'max-cost':value}), {message: 'max-cost must be a positive number.'});
  assert.equal(parse({'max-cost':'1e99'}).maxCost, 1e99);
  assert.equal(parse({'max-cost':'1e-2'}).maxCost, 0.01);
  for (const value of ['yes','TRUE','1']) assert.throws(() => parse({verbose:value}));
  for (const value of ['0','1.5','91']) assert.throws(() => parse({'retention-days':value}), {message: 'retention-days must be an integer between 1 and 90.'});
});
test('path lists accept literal filenames but reject unsafe locations and option injection', () => {
  assert.deepEqual(parse({paths:'src/my folder\nlib'}).paths, ['src/my folder','lib']);
  assert.deepEqual(parse({paths:'src/[slug]/page.tsx\nsrc/star*file.ts\nsrc/question?file.ts'}).paths,
    ['src/[slug]/page.tsx', 'src/star*file.ts', 'src/question?file.ts']);
  for (const paths of ['/etc','../other','src/../../other','a\\b','C:/other','x\u0000'])
    assert.throws(() => parse({paths}));
});
test('CLI path arguments use normalized, deduplicated repository-relative paths', () => {
  const input = parse({paths:'./src\nsrc/\nsrc\n./lib//./my folder/\n./\n.'});
  assert.deepEqual(input.paths, ['src', 'lib/my folder', '.']);
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.deepEqual(args.filter(arg => arg.startsWith('--path=')).map(arg => arg.slice('--path=./'.length)), input.paths);
});
test('option-shaped model values remain bound to the model option', () => {
  const input = parse({model:'--plugin-path=synthetic'});
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.ok(args.includes('--model=--plugin-path=synthetic'));
  assert.ok(!args.includes('--plugin-path=synthetic'));
});
test('dry-run allows keyless configuration validation', () => {
  const dryArgs=scanArguments(parse({'dry-run':'true'}),{repository:'/checkout'},'/results');
  assert.equal(dryArgs[dryArgs.indexOf('--auth')+1],'auto'); assert.ok(dryArgs.includes('--dry-run'));
});
test('dry-run cannot be combined with findings enforcement', () => {
  for (const threshold of ['low', 'medium', 'high', 'critical'])
    assert.throws(() => parse({'dry-run':'true', 'fail-on-severity':threshold}), /dry-run requires fail-on-severity: none/);
  assert.equal(parse({'dry-run':'true', 'fail-on-severity':'none'}).dryRun, true);
});
test('CLI arguments preserve literal values and enforce CI policy', () => {
  const input = parse({paths:'src/my folder',model:'model; echo never-execute', effort:'medium', 'max-cost':'5', 'fail-on-severity':'high'});
  const args = scanArguments(input, {repository:'/checkout'}, '/private/results');
  assert.equal(args[args.indexOf('--provider') + 1], 'openai');
  assert.equal(args[args.indexOf('--auth') + 1], 'api-key');
  assert.ok(args.includes('--model=model; echo never-execute')); assert.ok(args.includes('--path=./src/my folder'));
  assert.ok(!args.some(arg => arg.startsWith('approval_policy=')));
  assert.ok(!args.some(arg => arg.startsWith('approvals_reviewer=')));
  assert.ok(args.includes('analytics.enabled=false'));
  assert.ok(args.includes('--effort=medium'));
  assert.equal(args[args.indexOf('--max-cost') + 1], '5');
  assert.equal(args[args.indexOf('--fail-on-severity') + 1], 'high');
  assert.ok(!args.some(value => value.includes('API_KEY')));
});
test('diff arguments use the verified checkout and resolved comparison revisions', () => {
  const input = parse({repository:'component', scope:'diff', 'diff-base':'main'});
  assert.equal(input.repository, 'component');
  assert.equal(input.diffBase, 'main');
  const args = scanArguments(input, {repository:'/checkout/component', diffBase:'base-sha', diffHead:'head-sha'}, '/results');
  assert.equal(args[1], '/checkout/component');
  assert.equal(args[args.indexOf('--diff') + 1], 'base-sha');
  assert.equal(args[args.indexOf('--head') + 1], 'head-sha');
});
test('report publication and artifact settings remain configurable', () => {
  const input = parse({summary:'false', annotations:'false', 'upload-artifacts':'true', 'artifact-name':'reports-component', 'retention-days':'14'});
  assert.equal(input.summary, false);
  assert.equal(input.annotations, false);
  assert.equal(input.uploadArtifacts, true);
  assert.equal(input.artifactName, 'reports-component');
  assert.equal(input.retentionDays, 14);
  assert.equal(parse({'artifact-name':'reports for synthetic component'}).artifactName, 'reports for synthetic component');
});


test('normalized option-shaped paths remain literal CLI values', () => {
  const input = parse({paths:'--help\n./--version', 'dry-run':'true'});
  assert.deepEqual(input.paths, ['--help', '--version']);
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.ok(args.includes('--path=./--help'));
  assert.ok(args.includes('--path=./--version'));
  assert.ok(!args.includes('--help'));
  assert.ok(!args.includes('--version'));
});

test('literal tilde folders remain repository-relative when forwarded to the CLI', () => {
  const input = parse({paths:'./~/example.ts\n~\nmodule:handler.ts'});
  assert.deepEqual(input.paths, ['~/example.ts', '~', 'module:handler.ts']);
  const args = scanArguments(input, {repository:'/checkout'}, '/results');
  assert.deepEqual(args.filter(arg => arg.startsWith('--path=')),
    ['--path=./~/example.ts', '--path=./~', '--path=./module:handler.ts']);
});
