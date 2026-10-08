// Exercise the published, locked CLI and exporter without credentials or model calls.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { parseInputs, scanArguments } from '../src/inputs.js';
import { analyzeResults } from '../src/results.js';
import { captureRunnerPath, checkPython, resolveTool, runtimeEnvironment, writeRuntimeLauncher } from '../src/runtime.js';
import runtimeManifest from '../runtime/package.json' with { type: 'json' };

const cliPackage = resolve(import.meta.dirname, '../runtime/node_modules/@openai/codex-security');
const installed = JSON.parse(await readFile(join(cliPackage, 'package.json'), 'utf8'));
assert.equal(installed.version, runtimeManifest.dependencies['@openai/codex-security']);
const cli = join(cliPackage, 'bin/codex-security.mjs');
const root = await mkdtemp(join(await realpath(tmpdir()), 'codex-action-cli-test-'));
try {
  const repository = join(root, 'repository');
  const home = join(root, 'home');
  await mkdir(repository);
  await mkdir(home);
  await mkdir(join(home, '.codex'), {mode:0o700});
  // Pass runner tool lookup/loader settings and isolated homes, without credentials or user configuration.
  const env = { PATH: process.env.PATH, LD_LIBRARY_PATH:process.env.LD_LIBRARY_PATH, HOME: home, CI: 'true', NO_COLOR: '1',
    CODEX_HOME: join(home, '.codex'), CODEX_SECURITY_STATE_DIR: join(root, 'state'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
  const git = (...args: string[]) => execFileSync('git', [
    '-c', 'user.name=Integration Test', '-c', 'user.email=test@example.invalid',
    '-c', 'commit.gpgsign=false', ...args,
  ], { cwd: repository, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-b', 'main');
  await writeFile(join(repository, 'example.ts'), 'export const example = 1;\n');
  git('add', 'example.ts');
  git('commit', '-m', 'Synthetic fixture');

  const run = (args: string[], expectedExit: number, environment: NodeJS.ProcessEnv = env) => {
    const result = spawnSync(process.execPath, [cli, ...args], {
      cwd: repository, env:environment, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(result.status, expectedExit, result.stderr);
    return result.stdout;
  };
  for (const threshold of [false, true]) {
    const resultsDirectory = join(root, threshold ? 'threshold-results' : 'report-results');
    const exitCode = threshold ? 1 : 0;
    const stdout = run(['scan', repository, '--mock', '--format', 'json', '--output-dir', resultsDirectory,
      ...(threshold ? ['--fail-on-severity', 'high'] : [])], exitCode);
    const cliResult = JSON.parse(stdout);
    assert.equal(cliResult.turn.mock, true, 'The integration scan must remain synthetic');
    assert.ok(cliResult.findings.findings.length > 0);
    // Verify native SARIF, then exercise the CLI's manual export without model calls.
    assert.equal(cliResult.sarifPath, join(resultsDirectory, 'exports/results.sarif'));
    run(['export', resultsDirectory, '--export-format', 'sarif', '--source-root', repository,
      '--output', cliResult.sarifPath], 0);
    const result = await analyzeResults({ stdout, resultsDirectory, exitCode, publishable: true, scannedSha:git('rev-parse', 'HEAD').trim() });
    assert.equal(result.scanStatus, 'completed');
    assert.equal(result.policyStatus, threshold ? 'failed' : 'passed');
    assert.equal(result.reportStatus, 'ready');
    assert.equal(result.sarifUploadReady, true);
    const sarif = JSON.parse(await readFile(result.paths.sarifPath, 'utf8'));
    assert.ok(sarif.runs.every((run: any) => run.automationDetails === undefined),
      'upload-sarif must be able to apply the workflow category to the real CLI export');
    assert.equal(result.findings.length, cliResult.findings.findings.length);
    assert.ok(result.counts);
    for (const [level, count] of Object.entries(result.counts)) {
      assert.equal(count, cliResult.findings.findings.filter((finding: any) => finding.severity.level === level).length);
    }
    assert.deepEqual(result.findings.map(finding => finding.title),
      cliResult.findings.findings.map((finding: any) => finding.title));
    assert.equal(result.estimatedCost, cliResult.cost?.estimatedUsd);
  }

  // Deep Scan cannot use --mock; validate the Action's actual arguments without model calls.
  const deepInputs: Record<string, string> = {mode: 'deep', 'max-time-hours': '0.25', paths: 'example.ts', 'dry-run': 'true'};
  const deepArguments = scanArguments(parseInputs(name => deepInputs[name] ?? '', repository),
    {repository}, join(root, 'deep-results'));
  const deepPreflight = JSON.parse(run(deepArguments, 0));
  assert.equal(deepPreflight.dryRun, true);
  assert.equal(deepPreflight.mode, 'deep');
  assert.equal(deepPreflight.maxTimeHours, 0.25);
  assert.deepEqual(deepPreflight.target.paths, ['example.ts']);

  // Normalization must not let a literal repository path become a framework option.
  await mkdir(join(repository, '--help'));
  await writeFile(join(repository, '--help/example.ts'), 'export const example = 1;\n');
  git('add', '--', '--help/example.ts');
  git('commit', '-m', 'Synthetic option-shaped path');
  const pathInputs: Record<string, string> = {paths: './--help', 'dry-run': 'true'};
  const pathArguments = scanArguments(parseInputs(name => pathInputs[name] ?? '', repository),
    {repository}, join(root, 'path-results'));
  const pathPreflight = JSON.parse(run(pathArguments, 0));
  assert.equal(pathPreflight.dryRun, true);
  assert.deepEqual(pathPreflight.target.paths, ['--help']);

  // Existing glob, tilde, and colon filenames are literal repository scopes.
  const literalFiles = ['src/[slug]/page.tsx', 'src/star*file.ts', 'src/question?file.ts', '~/example.ts', 'module:handler.ts'];
  const decoys = ['src/s/page.tsx', 'src/l/page.tsx', 'src/starOtherfile.ts', 'src/questionXfile.ts'];
  for (const path of [...literalFiles, ...decoys]) {
    await mkdir(dirname(join(repository, path)), {recursive:true});
    await writeFile(join(repository, path), 'export const synthetic = 1;\n');
  }
  git('add', '.'); git('commit', '-m', 'Synthetic literal path scopes');
  const scopes = ['src/[slug]', ...literalFiles.slice(1)];
  const literalInputs: Record<string, string> = {paths: scopes.join('\n'), 'dry-run': 'true'};
  const python = await resolveTool('python3');
  const literalArguments = scanArguments(parseInputs(name => literalInputs[name] ?? '', repository),
    {repository}, join(root, 'literal-results'));
  const literalPreflight = JSON.parse(run(literalArguments, 0));
  assert.equal(literalPreflight.dryRun, true);
  assert.deepEqual(literalPreflight.target.paths, scopes);
  const scopesFile = join(root, 'literal-scopes.json');
  const sourceInput = join(root, 'literal-source.jsonl');
  await writeFile(scopesFile, JSON.stringify(scopes));
  execFileSync(python, [join(cliPackage, '_bundled_plugin/scripts/generate_rank_input.py'),
    'make-repo-scope-input', '--repo', repository, '--scopes-file', scopesFile, '--out', sourceInput],
    {cwd: repository, env, stdio: ['ignore', 'pipe', 'pipe']});
  const selectedFiles = (await readFile(sourceInput, 'utf8')).trim().split('\n').map(row => JSON.parse(row).path).sort();
  assert.deepEqual(selectedFiles, [...literalFiles].sort(), 'Real scope selection must preserve literal names and exclude glob-matching decoys');

  // Preserve the runner-selected virtualenv through Action preflight and the
  // pinned CLI's resolver, which otherwise canonicalizes explicit Python paths.
  const venv = join(root, 'venv');
  execFileSync(python, ['-m', 'venv', '--without-pip', venv], {env, stdio:['ignore','pipe','pipe']});
  const venvPython = join(venv, 'bin', 'python3');
  const runnerPath = captureRunnerPath(['venv/bin', '', env.PATH ?? '/usr/bin:/bin'].join(delimiter), root);
  assert.equal(await resolveTool('python3', runnerPath), venvPython);
  const libraryPath = (env.LD_LIBRARY_PATH === undefined ? '' : env.LD_LIBRARY_PATH + ':') + join(root, "loader 'quoted' $literal");
  await mkdir(join(root, 'bin'));
  await mkdir(join(root, 'tmp'));
  const pythonLauncher = join(root, 'bin', 'python3');
  await writeRuntimeLauncher(pythonLauncher, venvPython, 'LD_LIBRARY_PATH', libraryPath);
  const nodeLauncher = join(root, 'bin', 'node');
  await writeRuntimeLauncher(nodeLauncher, process.execPath, 'RUNNER_TRACKING_ID', 'synthetic-cli-job');
  const venvEnv = runtimeEnvironment({root, home, codexHome:env.CODEX_HOME, stateDirectory:env.CODEX_SECURITY_STATE_DIR,
    runnerPath, runnerTrackingId:'synthetic-cli-job', runnerLibraryPath:libraryPath});
  // Use the published MCP launcher and its actual allowlist without a model turn.
  // The synthetic server reports its marker and one actual Node child's marker.
  const mcpConfig = JSON.parse(await readFile(join(cliPackage, '_bundled_plugin/.mcp.json'), 'utf8')).mcpServers['codex-security'];
  const mcpFixture = join(root, 'synthetic-plugin');
  await mkdir(join(mcpFixture, 'scripts'), {recursive:true});
  await mkdir(join(mcpFixture, 'mcp'));
  const mcpLauncher = join(mcpFixture, 'scripts/launch_codex_security_mcp');
  await copyFile(join(cliPackage, '_bundled_plugin/scripts/launch_codex_security_mcp'), mcpLauncher);
  await writeFile(join(mcpFixture, 'mcp/server.mjs'), `
    import { execFileSync } from 'node:child_process';
    console.log(JSON.stringify({tracking:process.env.RUNNER_TRACKING_ID,
      child:execFileSync(process.execPath, ['-e', 'process.stdout.write(process.env.RUNNER_TRACKING_ID)'], {encoding:'utf8'})}));
  `);
  const mcpEnv = Object.fromEntries([...mcpConfig.env_vars, 'PATH', 'HOME'].map(name => [name, venvEnv[name]]));
  assert.equal(mcpEnv.RUNNER_TRACKING_ID, undefined);
  assert.equal(mcpEnv.LD_LIBRARY_PATH, undefined);
  assert.equal(mcpEnv.CODEX_MCP_NODE_PATH, nodeLauncher);
  const mcpResult = JSON.parse(execFileSync(mcpLauncher, mcpConfig.args, {cwd:repository, env:mcpEnv, encoding:'utf8'}));
  assert.deepEqual(mcpResult, {tracking:'synthetic-cli-job', child:'synthetic-cli-job'});
  await checkPython(venvPython, root, venvEnv);
  const selected = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', `
    import { execFileSync } from 'node:child_process';
    const { resolvePluginPython, resolveCodexCommand, probeCodexSandbox } = await import(process.argv[1]);
    const codex = resolveCodexCommand(process.env);
    await probeCodexSandbox(codex, process.env);
    const python = await resolvePluginPython({environment:process.env, protectedRoot:process.cwd()});
    console.log(JSON.stringify({python, codex:codex.command,
      ...JSON.parse(execFileSync(python, ['-I', '-c', 'import json,os,sys; print(json.dumps(dict(prefix=sys.prefix,loader=os.environ.get("LD_LIBRARY_PATH"))))'],
        {encoding:'utf8', env:{...process.env, LD_LIBRARY_PATH:undefined}})),
      tracking:process.env.RUNNER_TRACKING_ID}));
  `, join(cliPackage, 'dist/runtime.js')], {cwd:repository, env:venvEnv, encoding:'utf8'}));
  assert.equal(selected.python, pythonLauncher);
  assert.equal(selected.prefix, venv);
  assert.equal(selected.loader, libraryPath);
  assert.equal(selected.tracking, 'synthetic-cli-job');

  // Exercise filesystem enforcement with the scan and network-disabled Deep
  // worker profiles, using the same pinned Codex and child PATH as the Action.
  const sandboxWorkspace = join(root, 'sandbox-workspace');
  const outsideFile = join(root, 'outside-sandbox-workspace.txt');
  const workspaceFile = join(sandboxWorkspace, 'result.txt');
  await mkdir(sandboxWorkspace);
  await writeFile(outsideFile, 'unchanged');
  for (const [mode, profile] of [
    ['scan', '{filesystem={":root"="read",":workspace_roots"="write"}}'],
    ['worker', '{extends=":read-only",filesystem={":root"="read"},network={enabled=false}}'],
  ] as const) {
    const proof = JSON.parse(execFileSync(selected.codex, [
      'sandbox', '-c', `permissions.integration=${profile}`, '-P', 'integration', '-C', sandboxWorkspace,
      '--', 'node', '--input-type=module', '-e', `
        import assert from 'node:assert/strict';
        import { readFileSync, writeFileSync } from 'node:fs';
        const [source, outside, workspace, mode] = process.argv.slice(1);
        assert.equal(readFileSync(source, 'utf8'), 'export const example = 1;\\n');
        const denied = error => ['EACCES', 'EPERM', 'EROFS'].includes(error.code);
        assert.throws(() => writeFileSync(outside, 'changed'), denied);
        if (mode === 'scan') writeFileSync(workspace, 'scan output');
        else assert.throws(() => writeFileSync(workspace, 'worker output'), denied);
        writeFileSync(1, JSON.stringify({mode, tracking:process.env.RUNNER_TRACKING_ID}));
      `, join(repository, 'example.ts'), outsideFile, workspaceFile, mode,
    ], {cwd:sandboxWorkspace, env:venvEnv, encoding:'utf8', timeout:30_000}));
    assert.deepEqual(proof, {mode, tracking:'synthetic-cli-job'});
    assert.equal(await readFile(outsideFile, 'utf8'), 'unchanged');
    assert.equal(await readFile(workspaceFile, 'utf8'), 'scan output');
  }
  // The actual pinned helper must still work when an MCP-style child drops the loader variable.
  const strippedEnv = {...venvEnv, LD_LIBRARY_PATH:undefined};
  const loaderSourceInput = join(root, 'loader-source.jsonl');
  execFileSync(selected.python, [join(cliPackage, '_bundled_plugin/scripts/generate_rank_input.py'),
    'make-repo-scope-input', '--repo', repository, '--scopes-file', scopesFile, '--out', loaderSourceInput],
    {cwd:repository, env:strippedEnv, stdio:['ignore','pipe','pipe']});
  assert.equal(await readFile(loaderSourceInput, 'utf8'), await readFile(sourceInput, 'utf8'));
  const venvArguments = scanArguments(parseInputs(name => deepInputs[name] ?? '', repository),
    {repository}, join(root, 'venv-results'));
  assert.equal(JSON.parse(run(venvArguments, 0, strippedEnv)).dryRun, true);

  // The CLI owns scan validation: an output directory inside the source checkout is forbidden.
  const resultsDirectory = join(repository, 'results');
  const stdout = run(['scan', repository, '--mock', '--format', 'json', '--output-dir', resultsDirectory], 2);
  const cliError = JSON.parse(stdout);
  assert.equal(cliError.status, 'failed');
  const result = await analyzeResults({ stdout, resultsDirectory, exitCode: 2, publishable: true, scannedSha:git('rev-parse', 'HEAD').trim() });
  assert.equal(result.scanStatus, 'failed');
  assert.equal(result.policyStatus, 'not-evaluated');
  assert.equal(result.sarifUploadReady, false);
  assert.ok(result.errors.some(error => error.includes(cliError.message)));
  console.log(`Pinned CLI ${installed.version}: real JSON results, severity exits, SARIF export, Deep Scan, literal-path and virtualenv preflights, sandbox readiness and filesystem enforcement, MCP runner tracking, and failures passed without model calls.`);
} finally {
  await rm(root, { recursive: true, force: true });
}
