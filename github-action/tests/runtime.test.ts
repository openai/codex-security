import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, realpath, symlink, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { captureRunnerPath, checkPython, checkSandbox, setupHostedSandbox, cleanupRuntime, resolveTool, runtimeEnvironment, scanCredentials, setupRuntime, writeRuntimeLauncher } from '../src/runtime.js';
import { runProcess } from '../src/process.js';

test('tool discovery preserves the selected PATH launcher spelling', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-tools-')));
  const previousPath = process.env.PATH;
  t.after(async () => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    await rm(root, { recursive: true, force: true });
  });
  const bin = join(root, 'custom-tools');
  await mkdir(bin);
  const npm = join(root, 'npm-cli.js');
  const python = join(bin, 'python3');
  await writeFile(npm, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  await writeFile(python, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  await symlink(npm, join(bin, 'npm'));
  process.env.PATH = bin;
  assert.equal(await resolveTool('npm'), join(bin, 'npm'));
  assert.equal(await resolveTool('python3'), python);
  process.env.PATH = relative(process.cwd(), bin);
  assert.equal(await realpath(await resolveTool('npm')), await realpath(npm));
  assert.equal(await realpath(await resolveTool('python3')), python);
  await writeFile(join(root, 'python3'), '#!/bin/sh\nprintf original-workspace\n', {mode:0o755});
  const captured = captureRunnerPath(':custom-tools:', root);
  assert.equal(captured, `${root}:${bin}:${root}`);
  assert.equal(await resolveTool('python3', captured), join(root, 'python3'));
  const elsewhere = join(root, 'elsewhere');
  await mkdir(elsewhere);
  const selected = await runProcess('/bin/sh', ['-c', 'python3'], {cwd:elsewhere, env:{PATH:captured}});
  assert.equal(selected.stdout, 'original-workspace');
  await rm(join(bin, 'npm'));
  await rm(python);
  await assert.rejects(resolveTool('npm'), /npm/);
  await assert.rejects(resolveTool('python3'), /python3/);
});

test('runtime installation accepts npm shell shims and uses the Action Node executable', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-npm-shim-')));
  const python = await resolveTool('python3');
  const previousPath = process.env.PATH;
  const previousTrackingId = process.env.RUNNER_TRACKING_ID;
  const previousLibraryPath = process.env.LD_LIBRARY_PATH;
  const previousRunnerEnvironment = process.env.RUNNER_ENVIRONMENT;
  t.after(async () => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousTrackingId === undefined) delete process.env.RUNNER_TRACKING_ID;
    else process.env.RUNNER_TRACKING_ID = previousTrackingId;
    if (previousLibraryPath === undefined) delete process.env.LD_LIBRARY_PATH;
    else process.env.LD_LIBRARY_PATH = previousLibraryPath;
    if (previousRunnerEnvironment === undefined) delete process.env.RUNNER_ENVIRONMENT;
    else process.env.RUNNER_ENVIRONMENT = previousRunnerEnvironment;
    await rm(root, { recursive: true, force: true });
  });
  const bin = join(root, 'tools');
  await mkdir(bin);
  await symlink(python, join(bin, 'python3'));
  await writeFile(join(bin, 'node'), '#!/bin/sh\nexit 72\n', {mode:0o755});
  await writeFile(join(bin, 'npm'), String.raw`#!/bin/sh
exec node - "$@" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
fs.writeFileSync('npm-invocation.json', JSON.stringify({
  args: process.argv.slice(2), cwd: process.cwd(), nodePath: process.execPath, env: process.env,
}));
const bin = path.join('node_modules', '@openai', 'codex-security', 'bin');
fs.mkdirSync(bin, {recursive:true});
fs.writeFileSync(path.join(bin, 'codex-security.mjs'), '// Synthetic installed CLI entrypoint.\n');
const packageRoot = path.dirname(bin);
fs.writeFileSync(path.join(packageRoot, 'package.json'), '{"type":"module"}');
fs.mkdirSync(path.join(packageRoot, 'dist'));
fs.writeFileSync(path.join(packageRoot, 'dist/runtime.js'), [
  "import { writeFileSync } from 'node:fs';",
  "export function resolveCodexCommand(env) { return {command: env.CODEX_HOME + '/synthetic-codex'}; }",
  "export async function probeCodexSandbox(command, env) { writeFileSync('sandbox-invocation.json', JSON.stringify({command, env})); }",
].join('\n'));
NODE
`, {mode:0o755});
  process.env.RUNNER_ENVIRONMENT = 'self-hosted';
  process.env.PATH = `${relative(process.cwd(), bin)}:`;
  process.env.RUNNER_TRACKING_ID = 'synthetic-first-job';
  const libraryPath = (previousLibraryPath === undefined ? '' : previousLibraryPath + ':') + '/synthetic-first-library';
  process.env.LD_LIBRARY_PATH = libraryPath;
  const captured = captureRunnerPath();
  const runtime = await setupRuntime({actionRoot:fileURLToPath(new URL('../', import.meta.url)), tempRoot:root});
  const invocation = JSON.parse(await readFile(join(runtime.root, 'install', 'npm-invocation.json'), 'utf8'));
  assert.equal(invocation.nodePath, process.execPath);
  assert.equal(invocation.cwd, join(runtime.root, 'install'));
  assert.equal(invocation.args[0], 'ci');
  assert.ok(invocation.args.includes('--ignore-scripts'));
  assert.ok(invocation.args.includes('--include=optional'));
  assert.ok(invocation.args.includes('--registry=https://registry.npmjs.org/'));
  assert.equal(invocation.env.PATH, `${join(runtime.root, 'bin')}:${captured}`);
  assert.equal(invocation.env.RUNNER_TRACKING_ID, 'synthetic-first-job');
  assert.equal(invocation.env.LD_LIBRARY_PATH, libraryPath);
  assert.equal(invocation.env.OPENAI_API_KEY, undefined);
  assert.equal(invocation.env.ACTIONS_RUNTIME_TOKEN, undefined);
  const credentials = scanCredentials('openai', {OPENAI_API_KEY:'synthetic-scan-key'});
  assert.equal(runtime.env(credentials).PYTHON, 'python3');
  assert.equal(runtime.env(credentials).CODEX_MCP_NODE_PATH, join(runtime.root, 'bin', 'node'));
  const sandboxInvocation = JSON.parse(await readFile(join(runtime.root, 'sandbox-invocation.json'), 'utf8'));
  assert.equal(sandboxInvocation.command.command, join(runtime.codexHome, 'synthetic-codex'));
  assert.equal(sandboxInvocation.env.CODEX_HOME, runtime.codexHome);
  assert.equal(sandboxInvocation.env.PATH, invocation.env.PATH);
  assert.equal(sandboxInvocation.env.OPENAI_API_KEY, undefined);
  assert.equal(sandboxInvocation.env.ACTIONS_RUNTIME_TOKEN, undefined);
  process.env.RUNNER_TRACKING_ID = 'synthetic-later-job';
  process.env.LD_LIBRARY_PATH = '/synthetic-later-library';
  assert.equal(runtime.env(credentials).RUNNER_TRACKING_ID, 'synthetic-first-job');
  assert.equal(runtime.env(credentials).LD_LIBRARY_PATH, libraryPath);
  const child = await runProcess(join(runtime.root, 'bin', 'node'), ['-e', 'console.log(process.env.RUNNER_TRACKING_ID)'],
    {cwd:root, env:{...runtime.env(credentials), RUNNER_TRACKING_ID:undefined}});
  assert.equal(child.exitCode, 0, child.stderr);
  assert.equal(child.stdout.trim(), 'synthetic-first-job');
  await cleanupRuntime(runtime.root, root);
});

test('hosted Ubuntu sandbox setup uses system commands despite checkout PATH shadows', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-hosted-sandbox-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const existsSync = fs.existsSync;
  t.mock.method(fs, 'existsSync', (path: fs.PathLike) => path === '/.dockerenv' ? false : existsSync(path));
  const checkout = join(root, 'checkout');
  await mkdir(checkout);
  for (const command of ['sudo', 'apt-get', 'apparmor_parser']) {
    await writeFile(join(checkout, command), `#!${process.execPath}
      require('node:fs').writeFileSync('checkout-command-ran', 'unexpected');
      process.exit(70);
    `, {mode:0o755});
  }
  const sudo = join(root, 'synthetic-system-sudo');
  await writeFile(sudo, `#!${process.execPath}
    require('node:fs').appendFileSync('setup.jsonl', JSON.stringify({args:process.argv.slice(2),env:process.env}) + '\\n');
    console.log('Synthetic sandbox setup output.');
  `, {mode:0o755});
  const execute: typeof runProcess = async (executable, args, options) => {
    assert.equal(executable, '/usr/bin/sudo');
    return runProcess(sudo, args, options);
  };
  const env = runtimeEnvironment({root, home:root, codexHome:root, stateDirectory:root, runnerPath:`${checkout}:/usr/bin:/bin`});
  await setupHostedSandbox({cwd:root, env, runnerEnvironment:'github-hosted', imageOS:'ubuntu24', log:() => {throw new Error('synthetic log failure');}}, execute);
  const calls = (await readFile(join(root, 'setup.jsonl'), 'utf8')).trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(calls.map(call => call.args), [
    ['-n','/usr/bin/apt-get','update'],
    ['-n','/usr/bin/apt-get','install','--yes','bubblewrap','apparmor-profiles'],
    ['-n','/usr/sbin/apparmor_parser','-r','/usr/share/apparmor/extra-profiles/bwrap-userns-restrict'],
  ]);
  for (const call of calls) {
    assert.equal(call.env.OPENAI_API_KEY, undefined);
    assert.equal(call.env.ACTIONS_RUNTIME_TOKEN, undefined);
    assert.equal(call.env.CODEX_HOME, root);
    assert.equal(call.env.PATH, env.PATH);
  }
  assert.equal(fs.existsSync(join(root, 'checkout-command-ran')), false);
  await writeFile(sudo, `#!${process.execPath}\nconsole.error('synthetic apt diagnostic'); process.exit(17);\n`, {mode:0o755});
  await assert.rejects(setupHostedSandbox({cwd:root,env,runnerEnvironment:'github-hosted',imageOS:'ubuntu24'}, execute),
    /Ubuntu sandbox setup failed: sudo -n \/usr\/bin\/apt-get update \(exit 17\).*synthetic apt diagnostic/s);
});

test('sandbox setup leaves self-hosted runners and other images unchanged', async t => {
  const execute = t.mock.fn<typeof runProcess>(async () => { throw new Error('Sandbox provisioning must not run.'); });
  for (const [runnerEnvironment,imageOS] of [['self-hosted','ubuntu24'],['github-hosted','ubuntu22'],[undefined,undefined]])
    await setupHostedSandbox({cwd:'/unused',env:{PATH:'/no-sudo'},runnerEnvironment,imageOS}, execute);
  assert.equal(execute.mock.callCount(), 0);
});

test('sandbox setup skips Docker job containers with inherited hosted Ubuntu labels', async t => {
  const existsSync = fs.existsSync;
  t.mock.method(fs, 'existsSync', (path: fs.PathLike) => path === '/.dockerenv' ? true : existsSync(path));
  const execute = t.mock.fn<typeof runProcess>(async () => { throw new Error('Container provisioning must not run.'); });
  await setupHostedSandbox({cwd:'/unused',env:{PATH:'/no-sudo'},runnerEnvironment:'github-hosted',imageOS:'ubuntu24'}, execute);
  assert.equal(execute.mock.callCount(), 0);
});

test('sandbox preflight preserves the shipped SDK diagnostic and fails before scanning', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-sandbox-failure-')));
  t.after(() => rm(root, {recursive:true,force:true}));
  await mkdir(join(root, 'bin'));
  await mkdir(join(root, 'dist'));
  await writeFile(join(root, 'package.json'), '{"type":"module"}');
  await writeFile(join(root, 'dist/runtime.js'), `
    export function resolveCodexCommand() { return {command:'/synthetic-codex'}; }
    export async function probeCodexSandbox() { throw new Error('synthetic bwrap diagnostic'); }
  `);
  await assert.rejects(checkSandbox(process.execPath, join(root, 'bin/codex-security.mjs'), root, {}),
    /Codex Security sandbox preflight failed.*synthetic bwrap diagnostic/s);
});

test('Python launcher selection and preflight preserve virtualenv context', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-venv-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const venv = join(root, 'venv');
  execFileSync(await resolveTool('python3'), ['-m', 'venv', '--without-pip', venv], {stdio:['ignore','pipe','pipe']});
  const bin = join(venv, 'bin');
  const runnerPath = captureRunnerPath('venv/bin::/usr/bin:/bin', root);
  const python = await resolveTool('python3', runnerPath);
  assert.equal(python, join(bin, 'python3'));
  const env = runtimeEnvironment({root, home:root, codexHome:root, stateDirectory:root, runnerPath, runnerLibraryPath:process.env.LD_LIBRARY_PATH});
  await checkPython(python, root, env);
  const result = await runProcess(python, ['-I', '-c', 'import sys; print(sys.prefix)'], {cwd:root, env});
  assert.equal(result.stdout.trim(), venv);
  const repository = join(root, 'repository');
  await mkdir(repository);
  const child = await runProcess('/bin/sh', ['-c', 'python3 -I -c "import sys; print(sys.prefix)"'], {cwd:repository, env});
  assert.equal(child.stdout.trim(), venv);
  assert.equal(env.PYTHON, 'python3');
});

test('private Python launcher restores loader settings and preserves virtualenv and literal arguments', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-python-loader-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const venv = join(root, "venv 'quoted' $literal");
  execFileSync(await resolveTool('python3'), ['-m', 'venv', '--without-pip', venv], {stdio:['ignore','pipe','pipe']});
  await mkdir(join(root, 'bin'));
  const launcher = join(root, 'bin', 'python3');
  const libraryPath = (process.env.LD_LIBRARY_PATH === undefined ? '' : process.env.LD_LIBRARY_PATH + ':') + "/synthetic/libs 'quoted' $literal;\nnext";
  await writeRuntimeLauncher(launcher, join(venv, 'bin', 'python3'), 'LD_LIBRARY_PATH', libraryPath);
  const env = runtimeEnvironment({root, home:root, codexHome:root, stateDirectory:root, runnerLibraryPath:libraryPath});
  const arguments_ = ["literal 'quotes'", '$literal; argument', '--option', '', 'two\nlines'];
  for (const loader of [undefined, '/another-library']) {
    const result = await runProcess(launcher, ['-I', '-c',
      'import json,os,sys; print(json.dumps(dict(prefix=sys.prefix,loader=os.environ.get("LD_LIBRARY_PATH"),args=sys.argv[1:])))',
      ...arguments_], {cwd:root, env:{...env, LD_LIBRARY_PATH:loader}});
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {prefix:venv, loader:libraryPath, args:arguments_});
  }
});

test('private Node launchers restore per-scan runner tracking and preserve literal arguments', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-node-tracking-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const arguments_ = ["literal 'quotes'", '$literal; argument', '--option', '', 'two\nlines'];
  const markers = ["synthetic-first 'quoted' $literal;\njob", 'synthetic-second-job'];
  const launchers = await Promise.all(markers.map(async (marker, index) => {
    const launcher = join(root, `node-${index}`);
    await writeRuntimeLauncher(launcher, process.execPath, 'RUNNER_TRACKING_ID', marker);
    return launcher;
  }));
  for (const tracking of [undefined, 'synthetic-other-job']) {
    const results = await Promise.all(launchers.map(launcher => runProcess(launcher, ['-e',
      `const child = require('node:child_process').execFileSync(process.execPath, ['-e', 'process.stdout.write(process.env.RUNNER_TRACKING_ID)'], {encoding:'utf8'});
       console.log(JSON.stringify({node:process.execPath,tracking:process.env.RUNNER_TRACKING_ID,child,args:process.argv.slice(1)}))`,
      '--', ...arguments_], {cwd:root, env:{RUNNER_TRACKING_ID:tracking}})));
    for (const [index, result] of results.entries()) {
      assert.equal(result.exitCode, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), {node:process.execPath, tracking:markers[index], child:markers[index], args:arguments_});
    }
  }
});

test('Python preflight checks the required version and modules in an isolated process', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-python-')));
  const previousSecret = process.env.RUNTIME_TEST_SECRET;
  process.env.RUNTIME_TEST_SECRET = 'must-not-inherit';
  t.after(async () => {
    if (previousSecret === undefined) delete process.env.RUNTIME_TEST_SECRET;
    else process.env.RUNTIME_TEST_SECRET = previousSecret;
    await rm(root, { recursive: true, force: true });
  });
  const python = join(root, 'python3');
  await writeFile(python, `#!${process.execPath}
    require('node:fs').writeFileSync('invocation.json', JSON.stringify({
      args: process.argv.slice(2), cwd: process.cwd(), env: process.env,
    }));
  `, { mode: 0o755 });
  const env = runtimeEnvironment({ root, home: root, codexHome: root, stateDirectory: root });
  await checkPython(python, root, env);
  const invocation = JSON.parse(await readFile(join(root, 'invocation.json'), 'utf8'));
  assert.deepEqual(invocation.args, ['-I', '-c', 'import sys, sqlite3, tomllib; assert sys.version_info >= (3, 11)']);
  assert.equal(invocation.cwd, root);
  for (const [key, value] of Object.entries(env)) assert.equal(invocation.env[key], value);
  assert.equal(invocation.env.RUNTIME_TEST_SECRET, undefined);
});

test('Python preflight reports a failed or terminated prerequisite check', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-python-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const python = join(root, 'python3');
  for (const script of ['process.exit(1)', 'process.kill(process.pid, "SIGTERM")']) {
    await writeFile(python, `#!${process.execPath}\n${script}\n`, { mode: 0o755 });
    await assert.rejects(checkPython(python, root, {}), /Python 3\.11.*sqlite3.*tomllib/);
  }
});

test('scan environment excludes all inherited credential/config channels', () => {
  const poison = { INPUT_GITHUB_TOKEN: 'secret', GITHUB_TOKEN: 'secret', ACTIONS_RUNTIME_TOKEN: 'secret', GITHUB_OUTPUT: 'file', NODE_OPTIONS: '--require=evil', PYTHONPATH: 'evil', NPM_CONFIG_REGISTRY: 'evil', AWS_SECRET_ACCESS_KEY: 'secret', CODEX_CLI_PATH: 'evil', CODEX_MCP_NODE_PATH: 'evil', OPENAI_BASE_URL: 'evil', HTTPS_PROXY: 'evil' };
  const previous = Object.fromEntries(Object.keys(poison).map((key) => [key, process.env[key]]));
  Object.assign(process.env, poison);
  try {
    const paths = { root: '/tmp/owned', home: '/tmp/owned/home', codexHome: '/tmp/owned/codex', stateDirectory: '/tmp/owned/state' };
    const installer = runtimeEnvironment(paths);
    const scanner = runtimeEnvironment(paths, scanCredentials('openai', {OPENAI_API_KEY:'scan-only-key'}));
    for (const key of Object.keys(poison)) { assert.equal(installer[key], undefined); assert.equal(scanner[key], undefined); }
    assert.equal(installer.OPENAI_API_KEY, undefined);
    assert.equal(scanner.OPENAI_API_KEY, 'scan-only-key');
    assert.equal(scanner.PYTHONSAFEPATH, '1');
    assert.equal(scanner.GIT_CONFIG_VALUE_0, '');
  } finally { for (const key of Object.keys(poison)) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } }
});

test('each scan retains its runner tool path while keeping its environment isolated', async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-path-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const tools = join(root, 'runner-tools');
  await mkdir(tools);
  const tool = join(tools, 'synthetic-tool');
  await writeFile(tool, '#!/bin/sh\nprintf selected-runner-tool\n', { mode: 0o755 });
  const paths = { root, home: root, codexHome: root, stateDirectory: root, runnerPath: tools, runnerTrackingId:'synthetic-first-job', runnerLibraryPath:'/synthetic-first-library' };
  const first = runtimeEnvironment(paths, scanCredentials('openai', {OPENAI_API_KEY:'first-scan-key'}));
  const second = runtimeEnvironment({...paths, runnerPath:'/other/tools', runnerTrackingId:'synthetic-second-job', runnerLibraryPath:'/synthetic-second-library'}, scanCredentials('openai', {OPENAI_API_KEY:'second-scan-key'}));
  const result = await runProcess('/bin/sh', ['-c', 'synthetic-tool'], {cwd:root, env:first});
  assert.equal(result.stdout, 'selected-runner-tool');
  assert.equal(first.PATH, `${join(root, 'bin')}:${tools}`);
  assert.equal(second.PATH, `${join(root, 'bin')}:/other/tools`);
  assert.equal(first.OPENAI_API_KEY, 'first-scan-key');
  assert.equal(second.OPENAI_API_KEY, 'second-scan-key');
  assert.equal(first.RUNNER_TRACKING_ID, 'synthetic-first-job');
  assert.equal(second.RUNNER_TRACKING_ID, 'synthetic-second-job');
  assert.equal(first.CODEX_MCP_NODE_PATH, join(root, 'bin', 'node'));
  assert.equal(first.LD_LIBRARY_PATH, '/synthetic-first-library');
  assert.equal(second.LD_LIBRARY_PATH, '/synthetic-second-library');
  assert.equal(runtimeEnvironment({...paths, runnerLibraryPath:undefined}).LD_LIBRARY_PATH, undefined);
  assert.equal(runtimeEnvironment({...paths, runnerLibraryPath:''}).LD_LIBRARY_PATH, '');
  assert.equal(runtimeEnvironment({...paths, runnerTrackingId:undefined}).RUNNER_TRACKING_ID, undefined);
  assert.equal(runtimeEnvironment({...paths, runnerTrackingId:undefined}).CODEX_MCP_NODE_PATH, undefined);
});

test('Bedrock credentials reach child processes without unrelated runner credentials', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-bedrock-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const paths = {root, home:join(root, 'home'), codexHome:join(root, 'codex'), stateDirectory:join(root, 'state')};
  const sources = [
    {AWS_ACCESS_KEY_ID:'synthetic-access-key', AWS_SECRET_ACCESS_KEY:'synthetic-secret-key', AWS_SESSION_TOKEN:'synthetic-session-token', AWS_REGION:'us-east-2'},
    {AWS_BEARER_TOKEN_BEDROCK:'synthetic-bearer-token', AWS_DEFAULT_REGION:'us-west-2'},
    {AWS_PROFILE:'synthetic-profile', AWS_CONFIG_FILE:'/synthetic/config', AWS_SHARED_CREDENTIALS_FILE:'/synthetic/credentials'},
    {AWS_ROLE_ARN:'arn:aws:iam::123456789012:role/synthetic-role', AWS_ROLE_SESSION_NAME:'synthetic-session', AWS_WEB_IDENTITY_TOKEN_FILE:'/synthetic/token'},
    {AWS_CONTAINER_CREDENTIALS_FULL_URI:'http://127.0.0.1/synthetic', AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE:'/synthetic/token'},
  ];
  for (const aws of sources) {
    const source = {...aws, OPENAI_API_KEY:'must-not-forward', CODEX_API_KEY:'must-not-forward',
      GITHUB_TOKEN:'must-not-forward', ACTIONS_RUNTIME_TOKEN:'must-not-forward',
      NODE_OPTIONS:'--require=unrelated', CODEX_CLI_PATH:'/unrelated/codex', AWS_UNRELATED_SECRET:'must-not-forward'};
    const credentials = scanCredentials('amazon-bedrock', source);
    const env = runtimeEnvironment(paths, credentials);
    const child = await runProcess(process.execPath, ['-e', 'console.log(JSON.stringify(process.env))'], {cwd:root, env});
    assert.equal(child.exitCode, 0, child.stderr);
    const actual = JSON.parse(child.stdout);
    assert.deepEqual(Object.fromEntries(Object.entries(actual).filter(([name]) => name.startsWith('AWS_'))), aws);
    for (const name of ['OPENAI_API_KEY', 'CODEX_API_KEY', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'NODE_OPTIONS', 'CODEX_CLI_PATH'])
      assert.equal(actual[name], undefined);
    assert.equal(actual.HOME, paths.home); assert.equal(actual.CODEX_HOME, paths.codexHome);
    const installer = runtimeEnvironment(paths);
    for (const name of Object.keys(aws)) assert.equal(installer[name], undefined);
  }
});

test('API providers forward only their own captured key to child processes', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-provider-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const paths = {root, home:root, codexHome:root, stateDirectory:root};
  const source = {OPENAI_API_KEY:'synthetic-openai', CODEX_API_KEY:'synthetic-alias',
    OPENROUTER_API_KEY:'synthetic-openrouter', FIREWORKS_API_KEY:'synthetic-fireworks',
    AWS_SESSION_TOKEN:'unrelated-aws', GITHUB_TOKEN:'unrelated-github'};
  const cases = [['openai', 'OPENAI_API_KEY'], ['openrouter', 'OPENROUTER_API_KEY'], ['fireworks', 'FIREWORKS_API_KEY']] as const;
  const captured = cases.map(([provider, key]) => ({credentials:scanCredentials(provider, source), key, value:source[key]}));
  source.OPENROUTER_API_KEY = source.FIREWORKS_API_KEY = 'changed-after-capture';
  await Promise.all(captured.map(async ({credentials, key, value}) => {
    const child = await runProcess(process.execPath, ['-e', 'console.log(JSON.stringify(process.env))'],
      {cwd:root, env:runtimeEnvironment(paths, credentials)});
    assert.equal(child.exitCode, 0, child.stderr);
    const actual = JSON.parse(child.stdout);
    for (const name of Object.keys(source)) assert.equal(actual[name], name === key ? value : undefined);
    for (const name of Object.keys(source)) assert.equal(runtimeEnvironment(paths)[name], undefined);
  }));
});

test('Bedrock credential snapshots stay isolated when the caller changes credentials', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'runtime-bedrock-snapshot-')));
  t.after(() => rm(root, {recursive:true, force:true}));
  const paths = {root, home:root, codexHome:root, stateDirectory:root};
  const source = {AWS_BEARER_TOKEN_BEDROCK:'synthetic-first-token', AWS_REGION:'us-east-2'};
  const first = scanCredentials('amazon-bedrock', source);
  source.AWS_BEARER_TOKEN_BEDROCK = 'synthetic-second-token'; source.AWS_REGION = 'us-west-2';
  const second = scanCredentials('amazon-bedrock', source);
  const results = await Promise.all([first, second].map(credentials => runProcess(process.execPath,
    ['-e', 'console.log(JSON.stringify([process.env.AWS_BEARER_TOKEN_BEDROCK,process.env.AWS_REGION]))'],
    {cwd:root, env:runtimeEnvironment(paths, credentials)})));
  assert.deepEqual(results.map(result => JSON.parse(result.stdout)), [
    ['synthetic-first-token', 'us-east-2'], ['synthetic-second-token', 'us-west-2'],
  ]);
});

test('shipped runtime lock matches the manifest and records dependency integrity', async () => {
  const lock = JSON.parse(await readFile(new URL('../runtime/package-lock.json', import.meta.url), 'utf8'));
  const manifest = JSON.parse(await readFile(new URL('../runtime/package.json', import.meta.url), 'utf8'));
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  assert.equal(lock.packages['node_modules/@openai/codex-security'].version, manifest.dependencies['@openai/codex-security']);
  for (const [path, entry] of Object.entries(lock.packages) as [string, { integrity?: string }][]) {
    if (path) assert.match(entry.integrity ?? '', /^sha512-/, `${path} is missing recorded integrity`);
  }
});

test('cleanup preserves reports and rejects arbitrary or symlink roots', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'runtime-test-'));
  const base = await import('node:fs/promises').then((fs) => fs.realpath(temp));
  const owned = join(base, 'codex-security-runtime-abc');
  const reports = join(base, 'codex-security-reports-abc');
  try {
    await mkdir(owned); await mkdir(reports);
    await writeFile(join(owned, '.codex-security-action-owned'), 'codex-security-action-v1\n');
    await writeFile(join(reports, 'report.sarif'), '{}');
    const link = join(base, 'codex-security-runtime-link');
    await symlink(owned, link);
    await assert.rejects(cleanupRuntime(link, base), /Refusing/);
    await assert.rejects(cleanupRuntime(reports, base), /Refusing/);
    await cleanupRuntime(owned, base);
    assert.ok((await stat(join(reports, 'report.sarif'))).isFile());
    await cleanupRuntime(owned, base);
  } finally { await rm(base, { recursive: true, force: true }); }
});
