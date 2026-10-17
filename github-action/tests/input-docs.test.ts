import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

test('input docs preserve backslashes and escape adjacent table delimiters', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'action-input-docs-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const action = join(root, 'github-action');
  await mkdir(join(action, 'scripts'), { recursive: true });
  await mkdir(join(action, 'examples'));
  await symlink(fileURLToPath(new URL('../node_modules', import.meta.url)), join(action, 'node_modules'), 'junction');
  const script = join(action, 'scripts', 'generate-input-docs.mjs');
  await copyFile(new URL('../scripts/generate-input-docs.mjs', import.meta.url), script);
  await writeFile(join(root, 'action.yml'), JSON.stringify({
    inputs: {
      example: { description: 'Path C:\\temp\\|value\nnext line', default: 'C:\\temp\\|<&value>  *text*' },
      plain: { description: 'ordinary text', default: 'plain' },
      path: { description: 'ordinary path', default: 'C:\\temp' },
      choices: { description: 'pipe only', default: 'one|two' },
    },
    outputs: { example: { description: 'one|two' } },
  }));
  const readme = join(action, 'README.md');
  let markers = '<!-- action-reference:start -->\n<!-- action-reference:end -->\n';
  for (const name of ['repository', 'pull-request']) {
    await writeFile(join(action, 'examples', `${name}.yml`), `name: ${name}\njobs: {}\n`);
    markers += `<!-- action-workflow:${name}:start -->\n<!-- action-workflow:${name}:end -->\n`;
  }
  await writeFile(readme, markers);
  execFileSync(process.execPath, [script]);
  const generated = await readFile(readme, 'utf8');
  assert.ok(generated.includes(String.raw`Path C:\\temp\\\|value next line`), generated);
  assert.ok(generated.includes(String.raw`one\|two`), generated);
  assert.ok(generated.includes('`plain`'), generated);
  const encodedDefault = /<code>(.*?)<\/code>/.exec(generated)?.[1];
  assert.ok(encodedDefault, generated);
  assert.equal(encodedDefault.replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code))), 'C:\\temp\\|<&value>  *text*');
  assert.ok(generated.includes('`C:\\temp`'), generated);
  assert.ok(generated.includes('`one\\|two`'), generated);
  execFileSync(process.execPath, [script, '--check']);
  await writeFile(join(action, 'examples', 'repository.yml'), 'name: updated repository\njobs: {}\n');
  assert.throws(() => execFileSync(process.execPath, [script, '--check'], {stdio: 'pipe'}));
  execFileSync(process.execPath, [script]);
  assert.match(await readFile(readme, 'utf8'), /name: updated repository/);
  execFileSync(process.execPath, [script, '--check']);
});
