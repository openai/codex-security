// Runs the SHIPPED action in a temporary checkout with dry-run and no secrets.
import { mkdir, mkdtemp, writeFile, readFile, rm, lstat } from 'node:fs/promises';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
import { parse } from 'yaml';
const repositoryRoot = resolve(import.meta.dirname, '../..');
const metadata = parse(await readFile(join(repositoryRoot, 'action.yml'), 'utf8'));
const root = await mkdtemp(join(tmpdir(), 'codex-action-linux-smoke-'));
const baseEnv = {PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:'/dev/null'};
try {
  const git = (...args) => execFileSync('/usr/bin/git', ['-c','user.name=Smoke','-c','user.email=smoke@example.invalid',...args], {cwd:root,env:baseEnv,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','-b','main'); git('remote','add','origin','https://github.com/example/smoke.git');
  await writeFile(join(root,'app.js'), 'export const add = (a, b) => a + b;\n');
  git('add','app.js'); git('commit','-m','fixture');
  const sha=git('rev-parse','HEAD');
  // GitHub command files sit outside the checkout, as in an actual job.
  const commandRoot = await mkdtemp(join(tmpdir(),'codex-action-commands-'));
  try {
    for (const name of ['output','state','summary']) await writeFile(join(commandRoot,name),'');
    await writeFile(join(commandRoot,'event.json'),'{}');
    const action = resolve(repositoryRoot, metadata.runs.main);
    const run = spawnSync(process.execPath,[action], {cwd:root, encoding:'utf8', timeout:600_000,maxBuffer:8*1024*1024,env:{...baseEnv,
      GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_EVENT_PATH:join(commandRoot,'event.json'),
      GITHUB_REPOSITORY:'example/smoke',GITHUB_SHA:sha,GITHUB_REF:'refs/heads/main',GITHUB_ACTOR:'smoke',GITHUB_SERVER_URL:'https://github.com',
      GITHUB_WORKSPACE:root,RUNNER_TEMP:commandRoot,GITHUB_OUTPUT:join(commandRoot,'output'),GITHUB_STATE:join(commandRoot,'state'),GITHUB_STEP_SUMMARY:join(commandRoot,'summary'),
      'INPUT_DRY-RUN':'true',INPUT_VERBOSE:'true',
    }});
    if (run.status !== 0) {
      console.error(run.stdout); console.error(run.stderr);
      throw run.error ?? new Error(`Packaged action exited ${run.status}`);
    }
    const output=await readFile(join(commandRoot,'output'),'utf8');
    assert.match(output,/scan-status<<[^\n]+\nskipped\n/);
    assert.match(output,/skip-reason<<[^\n]+\ndry-run\n/);
    assert.doesNotMatch(output,/sarif-upload-ready<<[^\n]+\ntrue\n/);
    const state = await readFile(join(commandRoot, 'state'), 'utf8');
    const runtimeRoot = /^runtime-root<<([^\n]+)\n([^\n]+)\n\1$/m.exec(state)?.[2];
    const runtimeTempRoot = /^runtime-temp-root<<([^\n]+)\n([^\n]+)\n\1$/m.exec(state)?.[2];
    assert.ok(runtimeRoot && runtimeTempRoot, 'Main entrypoint must save cleanup state');
    const runPost = async () => {
      const post = spawnSync(process.execPath, [resolve(repositoryRoot, metadata.runs.post)], {
        cwd: root, encoding: 'utf8', timeout: 10_000,
        env: {...baseEnv, 'STATE_runtime-root': runtimeRoot, 'STATE_runtime-temp-root': runtimeTempRoot},
      });
      assert.equal(post.status, 0, `Post entrypoint failed: ${post.stderr}`);
      await assert.rejects(lstat(runtimeRoot), {code: 'ENOENT'});
    };
    // Main already cleaned up; post must tolerate the absent runtime.
    await assert.rejects(lstat(runtimeRoot), {code: 'ENOENT'});
    await runPost();
    // Simulate a runtime left behind when main could not finish cleanup.
    await mkdir(join(runtimeRoot, 'home'), {recursive: true, mode: 0o700});
    await writeFile(join(runtimeRoot, '.codex-security-action-owned'), 'codex-security-action-v1\n', {mode: 0o600});
    await writeFile(join(runtimeRoot, 'home', 'auth.json'), '{"token":"synthetic-smoke-token"}\n', {mode: 0o600});
    await runPost();
    console.log('Packaged Linux action installed the locked CLI, passed dry-run, and verified post cleanup for absent and leftover runtimes without credentials or model calls.');
  } finally { await rm(commandRoot,{recursive:true,force:true}); }
} finally { await rm(root,{recursive:true,force:true}); }
