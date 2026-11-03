import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, realpath, writeFile, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseInputs } from '../src/inputs.js';
import { resolveTarget, validateEvent, originMatches, git, gitEnvironment, type EventContext } from '../src/targets.js';

function eventContext(head = 'a'.repeat(40), eventName = 'pull_request', base = head): EventContext {
  const repository = 'example/repo';
  const pr = eventName === 'pull_request';
  return {
    eventName, repository, sha:head, serverUrl:'https://github.com',
    ref:pr ? 'refs/pull/7/merge' : 'refs/heads/main',
    payload:pr ? {number:7, pull_request:{
      number:7, head:{sha:head,repo:{full_name:repository}}, base:{sha:base,repo:{full_name:repository}},
    }} : {},
  };
}

async function fixture(t: any) {
  const path = await realpath(await mkdtemp(join(tmpdir(),'action-target-')));
  t.after(() => rm(path,{recursive:true,force:true}));
  const run = (...args: string[]) => execFileSync('/usr/bin/git', ['-c','user.name=Test','-c','user.email=test@example.invalid',...args], {cwd:path,env:gitEnvironment(),encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  run('init','-b','main'); run('remote','add','origin','https://github.com/example/repo.git');
  await mkdir(join(path,'src')); await writeFile(join(path,'src/app.ts'),'export const n = 1;\n');
  await writeFile(join(path,'SECURITY.md'),'Only authorized boundaries count.\n');
  run('add','.'); run('commit','-m','base'); const base = run('rev-parse','HEAD');
  const change = async (file = 'src/app.ts', text = 'export const n = 2;\n') => {
    await writeFile(join(path,file),text); run('add','.'); run('commit','-m','change'); return run('rev-parse','HEAD');
  };
  const event = (head: string, eventName?: string) => eventContext(head, eventName, base);
  const inputs = (values: Record<string,string>={scope:'diff'}) => parseInputs(key=>values[key]??'',path);
  return {path,run,base,change,event,inputs};
}
test('Git children retain the runner process-tracking marker', async t => {
  const f = await fixture(t);
  const previous = process.env.RUNNER_TRACKING_ID;
  t.after(() => {
    if (previous === undefined) delete process.env.RUNNER_TRACKING_ID;
    else process.env.RUNNER_TRACKING_ID = previous;
  });
  process.env.RUNNER_TRACKING_ID = 'synthetic-git-runner-tracking';
  f.run('config', 'alias.capture-tracking', '!printf "%s" "$RUNNER_TRACKING_ID"');
  assert.equal(await git(f.path, ['capture-tracking']), 'synthetic-git-runner-tracking');
});
test('PR target resolves merge base and preserves exact upload head identity', async t => {
  const f=await fixture(t); const head=await f.change();
  f.run('checkout','-b','updated-base',f.base);
  const updatedBase=await f.change('SECURITY.md','Updated policy.\n');
  f.run('checkout','--detach',head);
  const event=f.event(head);
  event.payload.pull_request.base.sha=updatedBase;
  const target=await resolveTarget(f.inputs(),event);
  assert.equal(target.diffBase,f.base); assert.equal(target.diffHead,head);
  assert.equal(target.analysisRef,'refs/pull/7/head'); assert.equal(target.publishable,true);
});
test('GitHub Cloud matches HTTPS, SSH and SCP origin spellings for each event host', () => {
  for (const [host, sshUser] of [['github.com', 'git'], ['example-enterprise.ghe.com', 'example-enterprise']]) {
    for (const origin of [
      `https://${host}/example/repo.git`, `https://${host}:443/example/repo`,
      `https://${host.toUpperCase()}/Example/Repo.git/`,
      `${sshUser}@${host}:example/repo.git`, `${sshUser}@${host.toUpperCase()}:Example/Repo/`,
      `ssh://${sshUser}@${host}/example/repo`, `ssh://${sshUser}@${host.toUpperCase()}:22/Example/Repo.git/`,
    ]) {
      assert.equal(originMatches(origin, 'example/repo', `https://${host}`), true, origin);
    }
  }
});
test('target resolution checks the configured SSH origin against the triggering host and repository', async t => {
  const f = await fixture(t); const head = await f.change();
  const enterpriseEvent = {...f.event(head), serverUrl:'https://example-enterprise.ghe.com'};
  f.run('remote', 'set-url', 'origin', 'example-enterprise@example-enterprise.ghe.com:example/repo.git');
  const pr = await resolveTarget(f.inputs(), enterpriseEvent);
  assert.equal(pr.scannedSha, head); assert.equal(pr.publishable, true);
  assert.equal(pr.analysisRef, 'refs/pull/7/head'); assert.equal(pr.diffBase, f.base);
  const schedule = f.event(head, 'schedule');
  await assert.rejects(resolveTarget(f.inputs({scope:'repository'}), schedule), /origin does not match/);

  f.run('remote', 'set-url', 'origin', 'ssh://git@ssh.github.com:443/example/repo.git');
  const target = await resolveTarget(f.inputs({scope:'repository'}), schedule);
  assert.equal(target.scannedSha, head); assert.equal(target.publishable, true);
  assert.equal(target.analysisRef, 'refs/heads/main'); assert.equal(target.diffBase, undefined);
  await assert.rejects(resolveTarget(f.inputs(), enterpriseEvent), /origin does not match/);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository'}), {...schedule, repository:'example/other'}), /origin does not match/);
});
test('origins must match the event host, SSH endpoint and literal repository path', () => {
  for (const origin of ['https://ssh.github.com/example/repo.git', 'ssh://git@ssh.github.com:22/example/repo.git',
    'ssh://git@ssh.github.com:443/other/repo.git', 'ssh://other@ssh.github.com:443/example/repo.git',
    'git@github.com:example/repo.git#suffix', 'git@github.com:example/repo.git?suffix',
    'git@github.com:other/../example/repo.git']) {
    assert.equal(originMatches(origin, 'example/repo', 'https://github.com'), false, origin);
  }
  for (const origin of ['https://github.com/example/repo.git', 'https://other-enterprise.ghe.com/example/repo.git',
    'other-enterprise@other-enterprise.ghe.com:example/repo.git', 'https://example-enterprise.ghe.com/other/repo.git',
    'example-enterprise@example-enterprise.ghe.com:other/repo.git']) {
    assert.equal(originMatches(origin, 'example/repo', 'https://example-enterprise.ghe.com'), false, origin);
  }
});
test('unsupported server URLs fail eligibility', () => {
  const event = eventContext();
  for (const serverUrl of ['', 'https://github.example.invalid', 'http://example-enterprise.ghe.com',
    'https://ghe.com', 'https://example-enterprise.ghe.com.example.invalid', 'https://example-enterprise-ghe.com']) {
    assert.throws(() => validateEvent({...event, serverUrl}), /supports GitHub.com and GitHub Enterprise Cloud/, serverUrl);
  }
});
test('manual diff scans resolve an explicit base against the checked-out head', async t => {
  const f=await fixture(t);
  f.run('tag','scan-base');
  const head=await f.change();
  const target=await resolveTarget(f.inputs({scope:'diff','diff-base':'scan-base'}),f.event(head,'workflow_dispatch'));
  assert.equal(target.diffBase,f.base); assert.equal(target.diffHead,head);
  assert.equal(target.scannedSha,head); assert.equal(target.emptyDiff,false);
});
test('large diffs are nonempty without collecting every changed pathname', async t => {
  const f = await fixture(t);
  const blob = f.run('rev-parse', `${f.base}:src/app.ts`);
  const entries = Array.from({length:20_000}, (_, index) =>
    `100644 blob ${blob}\tsrc-${String(index).padStart(5, '0')}-${'x'.repeat(210)}.ts\n`).join('');
  const tree = execFileSync('/usr/bin/git', ['mktree'], {
    cwd:f.path, env:gitEnvironment(), input:entries, encoding:'utf8',
  }).trim();
  const base = f.run('commit-tree', tree, '-p', f.base, '-m', 'Synthetic large diff base');
  const head = f.run('commit-tree', f.run('rev-parse', `${f.base}^{tree}`), '-p', base, '-m', 'Synthetic large diff head');
  f.run('reset', '--hard', head);
  for (const eventName of ['pull_request', 'workflow_dispatch']) {
    const event = f.event(head, eventName);
    if (eventName === 'pull_request') event.payload.pull_request.base.sha = base;
    const inputs = f.inputs(eventName === 'pull_request' ? {scope:'diff'} : {scope:'diff', 'diff-base':base});
    const target = await resolveTarget(inputs, event);
    assert.equal(target.diffBase, base);
    assert.equal(target.diffHead, head);
    assert.equal(target.emptyDiff, false);
  }
});
test('a changed submodule commit is nonempty even when Git ignores the submodule', async t => {
  const f = await fixture(t);
  await writeFile(join(f.path, '.gitmodules'), '[submodule "lib"]\n\tpath = lib\n\turl = ../lib.git\n\tignore = all\n');
  await mkdir(join(f.path, 'lib'));
  f.run('add', '.gitmodules');
  f.run('update-index', '--add', '--cacheinfo', `160000,${f.base},lib`);
  f.run('commit', '-m', 'Add submodule');
  const base = f.run('rev-parse', 'HEAD');
  f.run('update-index', '--cacheinfo', `160000,${base},lib`);
  f.run('commit', '-m', 'Update submodule');
  const event = f.event(f.run('rev-parse', 'HEAD'));
  event.payload.pull_request.base.sha = base;
  assert.equal((await resolveTarget(f.inputs(), event)).emptyDiff, false);
});
test('empty diff is a verified no-op and schedule has no PR dependency', async t => {
  const f=await fixture(t);
  assert.equal((await resolveTarget(f.inputs(),f.event(f.base))).emptyDiff,true);
  const target=await resolveTarget(f.inputs({scope:'repository'}),f.event(f.base,'schedule'));
  assert.equal(target.analysisRef,'refs/heads/main'); assert.equal(target.diffBase,undefined);
});
test('repository scans accept file and directory paths inside the checkout', async t => {
  const f=await fixture(t);
  const inputs=f.inputs({scope:'repository',paths:'src\nsrc/app.ts'});
  const target=await resolveTarget(inputs,f.event(f.base,'schedule'));
  assert.equal(target.scannedSha,f.base);
});
test('scan paths must stay inside the checkout without traversing symlinks', async t => {
  const f=await fixture(t);
  const outside=await fixture(t);
  await symlink(outside.path,join(f.path,'linked-src'));
  f.run('add','.'); f.run('commit','-m','linked source');
  const head=f.run('rev-parse','HEAD');
  const event=f.event(head,'schedule');
  await assert.rejects(resolveTarget({...f.inputs({scope:'repository'}),paths:[outside.path]},event),/escapes the repository/);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository',paths:'linked-src/src/app.ts'}),event),/must not traverse symlinks/);
});
test('wrong checkout, local changes, missing diff base and option revisions are refused',async t=>{
  const f=await fixture(t); const head=await f.change();
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),/must check out/);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository'}),f.event(f.base,'schedule')),/HEAD must match GITHUB_SHA/);
  await assert.rejects(resolveTarget(f.inputs(),f.event(head,'workflow_dispatch')),/diff-base is required/);
  await assert.rejects(resolveTarget(f.inputs({scope:'diff','diff-base':'--help'}),f.event(head)),/Git rev-parse failed/);
  await writeFile(join(f.path,'src/app.ts'),'dirty');
  await assert.rejects(resolveTarget(f.inputs(),f.event(head)),/local changes/);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository'}),f.event(head,'schedule')),/local changes/);
});
test('forks and privileged events fail eligibility',()=>{
  const event=eventContext();
  event.payload.pull_request.head.repo.full_name='fork/repo'; assert.throws(()=>validateEvent(event),/Fork PR/);
  for(const eventName of ['pull_request_target','workflow_run','merge_group']) assert.throws(()=>validateEvent({...event,eventName}),/Unsupported event/);
});
test('persisted Git credentials and origin userinfo are refused without revealing secrets',async t=>{
  const f=await fixture(t);
  f.run('config','http.https://github.com/.extraheader','AUTHORIZATION: bearer CANARY');
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),error=> /persist-credentials/.test(String(error))&&!String(error).includes('CANARY'));
  f.run('config','--unset','http.https://github.com/.extraheader');
  f.run('remote','set-url','origin','https://CANARY@github.com/example/repo.git');
  await assert.rejects(resolveTarget(f.inputs(),f.event(f.base)),error=>/origin/.test(String(error))&&!String(error).includes('CANARY'));
});
test('enterprise checkouts retain the Git credential protections', async t => {
  const f = await fixture(t);
  const event = {...f.event(f.base), serverUrl:'https://example-enterprise.ghe.com'};
  f.run('remote', 'set-url', 'origin', `${event.serverUrl}/example/repo.git`);
  const key = `http.${event.serverUrl}/.extraheader`;
  f.run('config', key, 'AUTHORIZATION: bearer synthetic-token');
  await assert.rejects(resolveTarget(f.inputs(), event), /persist-credentials/);
  f.run('config', '--unset', key);
  for (const origin of ['https://synthetic-token@example-enterprise.ghe.com/example/repo.git',
    'https://example-enterprise:synthetic-token@example-enterprise.ghe.com/example/repo.git',
    'ssh://example-enterprise:synthetic-token@example-enterprise.ghe.com/example/repo.git']) {
    f.run('remote', 'set-url', 'origin', origin);
    await assert.rejects(resolveTarget(f.inputs(), event), /origin does not match/);
  }
});

test('worktree configuration is optional and clean linked checkouts are accepted', async t => {
  const f = await fixture(t);
  f.run('config', 'extensions.worktreeConfig', 'true');
  assert.equal((await resolveTarget(f.inputs(), f.event(f.base))).scannedSha, f.base);
  const root = await mkdtemp(join(tmpdir(), 'action-linked-worktree-'));
  t.after(() => rm(root, {recursive:true, force:true}));
  const checkout = join(root, 'checkout');
  f.run('worktree', 'add', '--detach', checkout, f.base);
  f.run('-C', checkout, 'config', '--worktree', 'core.editor', 'synthetic-editor');
  const inputs = {...f.inputs({scope:'repository'}), repository:checkout};
  const target = await resolveTarget(inputs, f.event(f.base, 'schedule'));
  assert.equal(target.repository, await realpath(checkout));
  assert.equal(target.scannedSha, f.base);
  for (const [key, value] of [
    ['http.https://github.com/.extraheader', 'AUTHORIZATION: bearer synthetic-worktree-key'],
    ['include.path', join(f.path, 'synthetic-external-config')],
  ]) {
    f.run('-C', checkout, 'config', '--worktree', key, value);
    await assert.rejects(resolveTarget(inputs, f.event(f.base, 'schedule')), /persist-credentials/);
    f.run('-C', checkout, 'config', '--worktree', '--unset', key);
  }
});

test('Git failures preserve diagnostic details', async t => {
  const f = await fixture(t);
  await assert.rejects(git(f.path, ['show', 'missing-synthetic-revision']), /unknown revision|ambiguous argument/);
});


test('selected paths require literal filesystem entries without glob expansion', async t => {
  const f = await fixture(t);
  const paths = ['src/[slug]/page.tsx', 'src/star*file.ts', 'src/question?file.ts'];
  for (const path of [...paths, 'src/s/page.tsx', 'src/starOtherfile.ts', 'src/questionXfile.ts']) {
    await mkdir(dirname(join(f.path, path)), {recursive:true});
    await writeFile(join(f.path, path), 'export const synthetic = 1;\n');
  }
  f.run('add', '.'); f.run('commit', '-m', 'Synthetic literal paths');
  const head = f.run('rev-parse', 'HEAD');
  const event = f.event(head, 'schedule');
  const target = await resolveTarget(f.inputs({scope:'repository', paths:[...paths, 'src/[slug]'].join('\n')}), event);
  assert.equal(target.scannedSha, head);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository', paths:'src/[sl]/page.tsx'}), event), /ENOENT/);
  await assert.rejects(resolveTarget(f.inputs({scope:'repository', paths:'src/*.tsx'}), event), /ENOENT/);
});
