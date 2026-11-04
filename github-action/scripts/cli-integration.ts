// Exercise the locked CLI or an installed release candidate with synthetic local requests only.
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { parse as parseYaml } from 'yaml';
import { parseInputs, scanArguments } from '../src/inputs.js';
import { analyzeResults } from '../src/results.js';
import { captureRunnerPath, checkPython, checkSandbox, resolveTool, runtimeEnvironment, SandboxUnavailableError, writeRuntimeLauncher } from '../src/runtime.js';
import runtimeManifest from '../runtime/package.json' with { type: 'json' };

const [candidatePackage, candidateVersion] = process.argv.slice(2);
assert.equal(process.argv.length === 2 || process.argv.length === 4, true,
  'Expected no arguments, or an installed CLI package directory and version');
const cliPackage = candidatePackage === undefined
  ? resolve(import.meta.dirname, '../runtime/node_modules/@openai/codex-security')
  : resolve(candidatePackage);
const installed = JSON.parse(await readFile(join(cliPackage, 'package.json'), 'utf8'));
assert.equal(installed.name, '@openai/codex-security');
assert.equal(installed.version, candidateVersion ?? runtimeManifest.dependencies['@openai/codex-security']);
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
    assert.equal(cliResult.sarifPath, join(resultsDirectory, 'exports/results.sarif'));
    // Analyze one native scan export untouched; exercise manual export on the other run.
    if (threshold) {
      await rm(cliResult.sarifPath);
      run(['export', resultsDirectory, '--export-format', 'sarif', '--source-root', repository,
        '--output', cliResult.sarifPath], 0);
    }
    const result = await analyzeResults({ stdout, resultsDirectory, exitCode, publishable: true, scannedSha:git('rev-parse', 'HEAD').trim() });
    assert.equal(result.scanStatus, 'completed');
    assert.equal(result.policyStatus, threshold ? 'failed' : 'passed');
    assert.equal(result.reportStatus, 'ready');
    assert.equal(result.sarifUploadReady, true);
    const sarif = JSON.parse(await readFile(result.paths.sarifPath, 'utf8'));
    const expectedIds = cliResult.findings.findings.map((finding: any) => [finding.occurrenceId, finding.ruleId]);
    assert.ok(expectedIds.flat().every((id: unknown) => typeof id === 'string' && id.length > 0));
    assert.deepEqual(sarif.runs.flatMap((run: any) => run.results.map((finding: any) =>
      [finding.properties?.occurrenceId, finding.ruleId])).sort(), expectedIds.sort());
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
    assert.deepEqual(result.usage, cliResult.turn?.usage ?? undefined);
    assert.deepEqual(result.estimatedCostRange, cliResult.cost?.estimatedUsdRange);
  }

  // Deep Scan cannot use --mock; validate the Action's actual arguments without model calls.
  // Exercise all explicit cyber programs in existing CLI preflights; the Action input
  // tests cover forwarding every spelling in both modes.
  const deepInputs: Record<string, string> = {mode: 'deep', 'cyber-access-program': 'daybreak_blue', 'max-time-hours': '0.25', paths: 'example.ts', 'dry-run': 'true'};
  const deepArguments = scanArguments(parseInputs(name => deepInputs[name] ?? '', repository),
    {repository}, join(root, 'deep-results'));
  const deepPreflight = JSON.parse(run(deepArguments, 0));
  assert.equal(deepPreflight.dryRun, true);
  assert.equal(deepPreflight.mode, 'deep');
  assert.equal(deepPreflight.maxTimeHours, 0.25);
  assert.deepEqual(deepPreflight.target.paths, ['example.ts']);

  // Validate workflow model and cost settings against both the published pin and release candidates.
  const diffBase = git('rev-parse', 'HEAD').trim();
  await writeFile(join(repository, 'added.ts'), 'export const added = true;\n');
  git('add', 'added.ts'); git('commit', '-m', 'Synthetic pull request');
  const diffHead = git('rev-parse', 'HEAD').trim();
  for (const example of ['repository', 'pull-request']) {
    const workflow = parseYaml(await readFile(resolve(import.meta.dirname, `../examples/${example}.yml`), 'utf8'));
    const values: Record<string, string> = workflow.jobs.security.steps.find((step: {id?: string}) => step.id === 'security').with;
    const production = parseInputs(name => values[name] ?? '', repository);
    assert.equal(production.dryRun, false);
    for (const mode of production.scope === 'repository' ? ['standard', 'deep'] : ['standard']) for (const program of [undefined, 'daybreak_blue']) {
      // Test the example's program selection first, then the optional Blue variant.
      // The production policy was already parsed; dry-run cannot enforce it.
      const dryValues: Record<string, string> = {...values, mode,
        ...(program === undefined ? {} : {'cyber-access-program':program}),
        'fail-on-severity':'none', 'dry-run':'true'};
      const inputs = parseInputs(name => dryValues[name] ?? '', repository);
      const target = production.scope === 'diff' ? {repository, diffBase, diffHead} : {repository};
      const args = scanArguments(inputs, target, join(root, `budget-${example}-${mode}-${program ?? 'example'}`));
      const result = JSON.parse(run(args, 0));
      assert.equal(result.dryRun, true);
      assert.equal(result.mode, mode);
      assert.equal(result.model, production.model);
      assert.equal(result.reasoningEffort, production.effort);
      assert.equal(result.maxCostUsd, production.maxCost);
    }
  }

  // Exercise each installed provider while covering both scan modes.
  for (const [provider, mode] of [['amazon-bedrock', 'deep'], ['openrouter', 'standard'], ['fireworks', 'deep']]) {
    const values: Record<string, string> = {provider, model:'synthetic/model', mode, 'dry-run':'true'};
    const args = scanArguments(parseInputs(name => values[name] ?? '', repository),
      {repository}, join(root, `${provider}-${mode}`));
    const preflight = JSON.parse(run(args, 0));
    assert.equal(preflight.dryRun, true); assert.equal(preflight.mode, mode);
    assert.equal(preflight.model, 'synthetic/model');
    assert.equal(preflight.modelProvider, provider);
    if (provider === 'amazon-bedrock') assert.equal(preflight.authentication.method, 'aws_credentials');
  }
  // The CLI shares missing-model validation across external providers and scan modes.
  const missingValues: Record<string, string> = {provider:'openrouter', 'dry-run':'true'};
  const missingArgs = scanArguments(parseInputs(name => missingValues[name] ?? '', repository),
    {repository}, join(root, 'missing-model'));
  const missing = spawnSync(process.execPath, [cli, ...missingArgs], {cwd:repository, env, encoding:'utf8', timeout:120_000});
  if (missing.error) throw missing.error;
  assert.equal(missing.status, 2);
  assert.match(missing.stderr + missing.stdout, /--model is required when using --provider openrouter/);

  // Exercise Action arguments through the installed CLI and native request serializer.
  // A terminal fixture error stops each scan before any model output or tool execution.
  const requests: Array<{headers: IncomingHttpHeaders; body: any}> = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk);
    if (request.method === 'POST' && request.url?.endsWith('/responses')) {
      requests.push({headers:request.headers, body:JSON.parse(Buffer.concat(chunks).toString())});
      response.writeHead(400, {'content-type':'application/json'});
      response.end(JSON.stringify({error:{message:'Synthetic attribution fixture', type:'invalid_request_error'}}));
    } else {
      // Tell native WebSocket negotiation to fall back to HTTP.
      response.writeHead(request.url?.endsWith('/responses') ? 426 : 200, {'content-type':'application/json'});
      response.end('{"models":[]}');
    }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const endpoint = `http://127.0.0.1:${address.port}`;
    for (const provider of ['openai', 'amazon-bedrock']) {
      requests.length = 0;
      const requestHome = join(root, `request-${provider}`);
      const codexHome = join(requestHome, '.codex');
      await mkdir(codexHome, {recursive:true, mode:0o700});
      const values: Record<string, string> = {provider, model:'gpt-5.6-sol', verbose:'false'};
      const args = scanArguments(parseInputs(name => values[name] ?? '', repository),
        {repository}, join(root, `request-${provider}-results`));
      for (const override of [
        provider === 'openai' ? `openai_base_url="${endpoint}/v1"`
          : `model_providers.amazon-bedrock.base_url="${endpoint}/v1"`,
        `chatgpt_base_url="${endpoint}"`, 'features.enable_request_compression=false',
        'otel.exporter="none"', 'otel.metrics_exporter="none"', 'otel.trace_exporter="none"',
      ]) args.push('--codex', override);
      const failure = await promisify(execFile)(process.execPath, [cli, ...args], {
        cwd:repository, timeout:120_000, maxBuffer:8 * 1024 * 1024,
        env:{...env, HOME:requestHome, CODEX_HOME:codexHome,
          CODEX_SECURITY_STATE_DIR:join(requestHome, 'state'),
          HTTP_PROXY:endpoint, HTTPS_PROXY:endpoint, ALL_PROXY:endpoint, NO_PROXY:'127.0.0.1',
          OPENAI_API_KEY:'synthetic-api-key',
          AWS_BEARER_TOKEN_BEDROCK:'synthetic-bedrock-token', AWS_REGION:'us-east-1'},
      }).then(() => assert.fail('The synthetic request must fail'), error => error);
      assert.equal(failure.code, 2, failure.stderr);
      assert.equal(requests.length, 1, failure.stderr);
      const request = requests[0];
      for (const metadata of [
        JSON.parse(String(request.headers['x-codex-turn-metadata'])),
        JSON.parse(request.body.client_metadata['x-codex-turn-metadata']),
      ]) {
        assert.equal(metadata.codex_security_integration, 'github_action');
        assert.equal(metadata.codex_security_provider, provider);
        assert.equal(metadata.analytics_enabled, false);
        assert.equal(metadata.thread_source, 'security_scan');
      }
    }
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }

  // Normalization must not let a literal repository path become a framework option.
  await mkdir(join(repository, '--help'));
  await writeFile(join(repository, '--help/example.ts'), 'export const example = 1;\n');
  git('add', '--', '--help/example.ts');
  git('commit', '-m', 'Synthetic option-shaped path');
  const pathInputs: Record<string, string> = {paths: './--help', 'cyber-access-program':'daybreak_red', 'dry-run': 'true'};
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
  const literalInputs: Record<string, string> = {paths: scopes.join('\n'), 'cyber-access-program':'standard', 'dry-run': 'true'};
  const python = await resolveTool('python3');
  const literalArguments = scanArguments(parseInputs(name => literalInputs[name] ?? '', repository),
    {repository}, join(root, 'literal-results'));
  const literalPreflight = JSON.parse(run(literalArguments, 0));
  assert.equal(literalPreflight.dryRun, true);
  assert.deepEqual(literalPreflight.target.paths, scopes);
  const scopesFile = join(root, 'literal-scopes.json');
  const sourceInput = join(root, 'literal-source.jsonl');
  await writeFile(scopesFile, JSON.stringify(scopes));
  const legacyGenerator = join(cliPackage, '_bundled_plugin/scripts/generate_rank_input.py');
  const usesPythonGenerator = existsSync(legacyGenerator);
  const generateScopeInput = (output: string, pythonCommand: string, environment: NodeJS.ProcessEnv) =>
    execFileSync(usesPythonGenerator ? pythonCommand : process.execPath,
      [usesPythonGenerator ? legacyGenerator : join(cliPackage, '_bundled_plugin/mcp/helpers.mjs'),
        'make-repo-scope-input', '--repo', repository, '--scopes-file', scopesFile, '--out', output],
      {cwd: repository, env: environment, stdio: ['ignore', 'pipe', 'pipe']});
  generateScopeInput(sourceInput, python, env);
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
  const shadowBin = join(repository, 'bin');
  await mkdir(shadowBin);
  await writeFile(join(shadowBin, 'bwrap'), '#!/bin/sh\n: > "$0.ran"\nexit 70\n', {mode:0o755});
  const probeEnv = {...venvEnv, CODEX_HOME:join(root, 'probe-home')};
  await checkSandbox(process.execPath, cli, {repository, provider:'openrouter', model:'example/model'}, {
    ...probeEnv, PATH:shadowBin + delimiter + venvEnv.PATH,
  });
  await assert.rejects(checkSandbox(process.execPath, cli, {repository, provider:'openrouter', model:''}, probeEnv),
    error => error instanceof Error && !(error instanceof SandboxUnavailableError) && /model/i.test(error.message));
  await assert.rejects(readFile(join(shadowBin, 'bwrap.ran')), {code:'ENOENT'});
  await rm(shadowBin, {recursive:true});
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

  const nativeProbe = join(root, 'native-probe');
  const nativeEnv = {...probeEnv, CODEX_CLI_PATH:nativeProbe, PROBE_CODEX:selected.codex};
  const probe = (nodePath = process.execPath) => checkSandbox(nodePath, cli, {repository, provider:'openai', model:''}, nativeEnv);
  await writeFile(nativeProbe, `#!/bin/sh\nexec "$PROBE_CODEX" -c 'model_provider="synthetic-undefined"' "$@"\n`, {mode:0o755});
  await assert.rejects(probe, error => error instanceof Error && !(error instanceof SandboxUnavailableError) && error.message.includes('synthetic-undefined'));
  await writeFile(nativeProbe, '#!/bin/sh\n[ "$1" != sandbox ] && exec "$PROBE_CODEX" "$@"\n');
  await assert.rejects(probe, SandboxUnavailableError);
  // Observe both real SDK child boundaries without invoking a sandbox or a model.
  const probeInvocations = join(root, 'probe-invocations.jsonl');
  for (const featuresExit of [0, 19]) {
    await writeFile(probeInvocations, '');
    await writeFile(nativeProbe, `#!${process.execPath}
      const fs = require('node:fs'); const path = require('node:path');
      fs.appendFileSync(${JSON.stringify(probeInvocations)}, JSON.stringify({args:process.argv.slice(2),
        config:fs.readFileSync(path.join(process.env.CODEX_HOME, 'config.toml'), 'utf8')}) + '\\n');
      if (process.argv[2] === 'sandbox') {
        console.error('synthetic sandbox failure sk-example-original'); process.exitCode = 1;
      } else {
        console.log('synthetic configuration stdout'); console.error('synthetic configuration stderr');
        process.exitCode = ${featuresExit};
      }
    `);
    await assert.rejects(probe, error => error instanceof Error
      && (error instanceof SandboxUnavailableError) === (featuresExit === 0)
      && error.message.includes('synthetic sandbox failure sk-example-original')
      && (featuresExit === 0 || (error.message.includes('synthetic configuration stdout')
        && error.message.includes('synthetic configuration stderr') && error.message.includes('exit 19'))));
    const invocations = (await readFile(probeInvocations, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    assert.deepEqual(invocations.map(call => call.args[0]), ['sandbox', 'features']);
    for (const call of invocations) assert.match(call.config, /\[analytics\]\s+enabled = false/);
  }
  await writeFile(nativeProbe, `#!${process.execPath}\nprocess.on('SIGTERM', () => process.exit(0)); process.kill(process.ppid, 'SIGINT'); setInterval(() => {}, 1000);\n`);
  await assert.rejects(probe(nativeProbe), /sandbox preflight was interrupted/);

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
  // The bundled helper must still work when an MCP-style child drops the loader variable.
  const strippedEnv = {...venvEnv, LD_LIBRARY_PATH:undefined};
  const loaderSourceInput = join(root, 'loader-source.jsonl');
  generateScopeInput(loaderSourceInput, selected.python, strippedEnv);
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
  console.log(`${candidatePackage === undefined ? 'Pinned' : 'Candidate'} CLI ${installed.version}: real JSON results, severity exits, SARIF export, Deep Scan, literal-path and virtualenv preflights, sandbox readiness and filesystem enforcement, MCP runner tracking, request attribution and analytics opt-outs, and failures passed without external model calls.`);
} finally {
  await rm(root, { recursive: true, force: true });
}
