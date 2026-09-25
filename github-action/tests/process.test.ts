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

test('every untrusted physical log line is prefixed and secrets redacted', () => {
  const lines = safeLogLines('\x1b[31m::error::secret\r::add-mask::other\n::set-output name=x::bad\u2028::warning::text', ['secret']);
  assert.equal(lines.length, 4);
  for (const line of lines) assert.match(line, /^\[codex-security\] /);
  assert.ok(!lines.join('').includes('secret'));
  assert.ok(!lines.join('').includes('\x1b'));
});

test('diagnostic redaction includes common secret encodings after control normalization', () => {
  const key = 'sk-test/secret+value';
  const forms = [key, Buffer.from(key).toString('base64'), encodeURIComponent(key)];
  const splitByColor = 'sk-test/\x1b[31msecret+value';
  const output = safeLogLines([...forms, splitByColor].join('\n'), [key]).join('\n');
  for (const form of forms) assert.ok(!output.includes(form));
  assert.equal(output.split('[REDACTED]').length - 1, 4);
});

test('process capture is bounded and stderr workflow commands are inert', async () => {
  const logs: string[] = [];
  const result = await runProcess(process.execPath, ['-e', 'process.stdout.write("a".repeat(20000));process.stderr.write("::error::TOKEN\\n")'], { cwd: tmpdir(), env: {}, maxOutputBytes: 128, secrets: ['TOKEN'], log: (line) => logs.push(line) });
  assert.equal(Buffer.byteLength(result.stdout), 128);
  assert.equal(result.truncated, true);
  assert.ok(logs.every((line) => line.startsWith('[codex-security] ')));
  assert.ok(logs.every((line) => !line.includes('TOKEN')));
});

test('stderr streams before exit with split credentials and UTF-8 safely reassembled', async (t) => {
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
  `, ack], {cwd: root, env: {}, secrets: ['split-secret'], timeoutMs: 5000, log: line => {
    logs.push(line);
    if (line.includes('ready')) acknowledged = writeFile(ack, 'logged while running');
  }});
  await acknowledged;
  assert.equal(result.exitCode, 0);
  assert.equal(result.timedOut, false);
  assert.equal(result.stdout, 'private structured output');
  assert.deepEqual(logs, ['[codex-security] ::warning::[REDACTED] 🔎 ready', '[codex-security] final line without newline']);
});

test('capture truncation drops an incomplete credential and logs its limit once', async () => {
  const logs: string[] = [];
  const result = await runProcess(process.execPath, ['-e', `
    process.stderr.write('ready\\nsecret-value');
    setTimeout(() => process.stderr.write('more output'), 20);
  `], {cwd: tmpdir(), env: {}, maxOutputBytes: 12, secrets: ['secret-value'], log: line => logs.push(line)});
  assert.equal(result.truncated, true);
  assert.equal(Buffer.byteLength(result.stderr), 12);
  assert.deepEqual(logs, ['[codex-security] ready', '[codex-security] Child output reached the capture limit; additional output is omitted.']);
});

test('timeout terminates an owned process group', async () => {
  const result = await runProcess(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { cwd: tmpdir(), env: {}, timeoutMs: 100 });
  assert.equal(result.timedOut, true);
  assert.notEqual(result.exitCode, 0);
});

test('timeout remains unsuccessful when the process handles termination with exit zero', async () => {
  const result = await runProcess(process.execPath, ['-e', 'process.on("SIGTERM",()=>process.exit(0));setInterval(()=>{},1000)'], { cwd: tmpdir(), env: {}, timeoutMs: 200 });
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

test('full structured stdout stays readable while diagnostic capture remains bounded', async () => {
  const length = 4 * 1024 * 1024 + 1;
  const result = await runProcess(process.execPath, ['-e', `
    process.stdout.write(JSON.stringify({detail:'x'.repeat(${length})}));
    process.stderr.write('diagnostic'.repeat(100));
  `], {cwd: tmpdir(), env: {}, maxOutputBytes: 128, maxStdoutBytes: Infinity});
  assert.equal(result.exitCode, 0);
  assert.equal(JSON.parse(result.stdout).detail.length, length);
  assert.equal(Buffer.byteLength(result.stderr), 128);
  assert.equal(result.truncated, true); // Only diagnostics were truncated.
});
