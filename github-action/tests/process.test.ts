import assert from 'node:assert/strict';
import { test } from 'node:test';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runProcess, safeLogLines } from '../src/process.js';

test('child receives only supplied environment and literal arguments', async () => {
  process.env.ACTION_TEST_SECRET = 'must-not-inherit';
  const value = '$(touch /tmp/not-a-shell); --anything';
  const result = await runProcess(process.execPath, ['-e', 'console.log(JSON.stringify({value: process.argv[1], secret: process.env.ACTION_TEST_SECRET}))', value], { cwd: tmpdir(), env: {} });
  assert.equal(result.exitCode, 0);
  assert.deepEqual(JSON.parse(result.stdout), { value });
  delete process.env.ACTION_TEST_SECRET;
});

test('every untrusted physical log line is prefixed and diagnostic text is preserved', () => {
  const lines = safeLogLines('\x1b[31m::error::secret\r::add-mask::other\n::set-output name=x::bad\u2028::warning::text');
  assert.equal(lines.length, 4);
  for (const line of lines) assert.match(line, /^\[codex-security\] /);
  assert.ok(lines.join('').includes('secret'));
  assert.ok(!lines.join('').includes('\x1b'));
});

test('legacy runner command markers are escaped anywhere in a diagnostic', () => {
  const lines = safeLogLines('##[warning]forged\nSynthetic diagnostic: ##[stop-commands]token\n#\x1b[31m#[add-mask]value');
  assert.deepEqual(lines, [
    '[codex-security] ##\\[warning]forged',
    '[codex-security] Synthetic diagnostic: ##\\[stop-commands]token',
    '[codex-security] ##\\[add-mask]value',
  ]);
  for (const line of lines) assert.ok(!line.includes('##['));
});

test('credential-shaped diagnostics and encodings survive control normalization', () => {
  const key = 'sk-test/secret+value';
  const forms = [key, Buffer.from(key).toString('base64'), encodeURIComponent(key)];
  const splitByColor = 'sk-test/\x1b[31msecret+value';
  const output = safeLogLines([...forms, splitByColor].join('\n')).join('\n');
  for (const form of forms) assert.ok(output.includes(form));
  assert.ok(!output.includes('[REDACTED]'));
});

test('process output and long diagnostics are preserved while workflow commands stay inert', async () => {
  const logs: string[] = [];
  const diagnostic = `::error::${'detail'.repeat(2000)}`;
  const result = await runProcess(process.execPath, ['-e', 'process.stdout.write("a".repeat(20000));process.stderr.write(process.argv[1] + "\\n")', diagnostic], { cwd: tmpdir(), env: {}, log: (line) => logs.push(line) });
  assert.equal(Buffer.byteLength(result.stdout), 20000);
  assert.equal(result.stderr, `${diagnostic}\n`);
  assert.ok(logs.every((line) => line.startsWith('[codex-security] ')));
  assert.deepEqual(logs, [`[codex-security] ${diagnostic}`]);
});

test('stderr streams before exit with split diagnostic text and UTF-8 safely reassembled', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'codex-log-test-'));
  t.after(() => rm(root, {recursive: true, force: true}));
  const ack = join(root, 'ack');
  const logs: string[] = [];
  let acknowledged: Promise<void> | undefined;
  const result = await runProcess(process.execPath, ['-e', `
    const fs = require('node:fs');
    process.stdout.write('private structured output');
    process.stderr.write('::warning::split-');
    setTimeout(() => {
      process.stderr.write(Buffer.concat([Buffer.from('secret '), Buffer.from('🔎').subarray(0, 2)]));
      setTimeout(() => {
        process.stderr.write(Buffer.concat([Buffer.from('🔎').subarray(2), Buffer.from(' ready\\n')]));
        const poll = setInterval(() => {
          if (fs.existsSync(process.argv[1])) {
            clearInterval(poll);
            process.stderr.write('final line without newline');
          }
        }, 10);
      }, 20);
    }, 20);
  `, ack], {cwd: root, env: {}, timeoutMs: 5000, log: line => {
    logs.push(line);
    if (line.includes('ready')) acknowledged = writeFile(ack, 'logged while running');
  }});
  await acknowledged;
  assert.equal(result.exitCode, 0);
  assert.equal(result.timedOut, false);
  assert.equal(result.stdout, 'private structured output');
  assert.deepEqual(logs, ['[codex-security] ::warning::split-secret 🔎 ready', '[codex-security] final line without newline']);
});

test('optional diagnostic logging failures do not stop the child or lose captured output', async () => {
  const result = await runProcess(process.execPath, ['-e', `
    process.stderr.write('ready\\n');
    setTimeout(() => {
      process.stdout.write('completed result');
      process.stderr.write('final diagnostic');
    }, 20);
  `], {cwd: tmpdir(), env: {}, log: () => { throw new Error('log destination unavailable'); }});
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'completed result');
  assert.equal(result.stderr, 'ready\nfinal diagnostic');
});

for (const timeoutMs of [undefined, 1000]) {
  test(`exited children release inherited descendant pipes ${timeoutMs === undefined ? 'without' : 'with'} an explicit timeout`, {timeout:5000}, async (t) => {
    const logs: string[] = [];
    const result = await runProcess(process.execPath, ['-e', String.raw`
      const { spawn } = require('node:child_process');
      spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'],
        {stdio:['ignore', 'inherit', 'inherit']}).unref();
      process.stderr.write('early diagnostic\n');
      process.stdout.write(JSON.stringify({detail:'x'.repeat(256 * 1024)}),
        () => process.stderr.write('final diagnostic 🔎'));
    `], {cwd:tmpdir(), env:{}, timeoutMs, signal:t.signal, log:line => logs.push(line)});
    assert.equal(result.exitCode, 0);
    assert.equal(result.signal, null);
    assert.equal(result.timedOut, false);
    assert.equal(result.interrupted, false);
    assert.equal(JSON.parse(result.stdout).detail, 'x'.repeat(256 * 1024));
    assert.equal(result.stderr, 'early diagnostic\nfinal diagnostic 🔎');
    assert.deepEqual(logs, ['[codex-security] early diagnostic', '[codex-security] final diagnostic 🔎']);
  });
}

test('timeout terminates an owned process group', async () => {
  const result = await runProcess(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { cwd: tmpdir(), env: {}, timeoutMs: 100 });
  assert.equal(result.timedOut, true);
  assert.notEqual(result.exitCode, 0);
});

test('timeout remains unsuccessful when the process handles termination with exit zero', {timeout:30_000}, async (t) => {
  t.mock.timers.enable({apis:['setTimeout']});
  const result = await runProcess(process.execPath, ['-e', 'process.on("SIGTERM",()=>process.exit(0));process.stderr.write("ready\\n");setInterval(()=>{},1000)'], {
    cwd:tmpdir(), env:{}, timeoutMs:200, signal:t.signal,
    log:line => { if (line === '[codex-security] ready') t.mock.timers.tick(200); },
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.timedOut, true);
});

test('AbortSignal stops a running child and paths must be absolute', async () => {
  const controller = new AbortController();
  const running = runProcess(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { cwd: tmpdir(), env: {}, signal: controller.signal });
  controller.abort();
  const result = await running;
  assert.notEqual(result.exitCode, 0);
  assert.equal(result.interrupted, true);
  await assert.rejects(runProcess('node', [], { cwd: tmpdir(), env: {} }), /absolute/);
});

test('full structured output and diagnostic capture remain readable beyond the former limit', async () => {
  const length = 4 * 1024 * 1024 + 1;
  const result = await runProcess(process.execPath, ['-e', `
    process.stdout.write(JSON.stringify({detail:'x'.repeat(${length})}));
    process.stderr.write('diagnostic'.repeat(500000));
  `], {cwd: tmpdir(), env: {}});
  assert.equal(result.exitCode, 0);
  assert.equal(JSON.parse(result.stdout).detail.length, length);
  assert.equal(result.stderr, 'diagnostic'.repeat(500000));
});
