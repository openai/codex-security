import { readFile, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { parse } from 'yaml';

const data = parse(await readFile(new URL('../../action.yml', import.meta.url), 'utf8'));
const escape = value => String(value).replace(/\|/g, '\\|').replace(/\n/g, ' ');
let reference = '## Inputs\n\nInputs are strings. Quote booleans and use newline-separated literal paths for lists.\n\n| Input | Default | Meaning |\n| --- | --- | --- |\n';
for (const [name, value] of Object.entries(data.inputs)) {
  reference += `| \`${name}\` | ${value.default === undefined ? 'Unset' : '`' + escape(value.default) + '`'} | ${escape(value.description)} |\n`;
}
reference += '\n## Outputs\n\nAll outputs are strings. An empty cost or count means unavailable, not zero.\n\n| Output | Meaning |\n| --- | --- |\n';
for (const [name, value] of Object.entries(data.outputs)) reference += `| \`${name}\` | ${escape(value.description)} |\n`;

const path = new URL('../README.md', import.meta.url);
const current = await readFile(path, 'utf8');
const start = '<!-- action-reference:start -->';
const end = '<!-- action-reference:end -->';
assert.ok(current.includes(start) && current.includes(end), 'README must contain action reference markers');
const updated = current.slice(0, current.indexOf(start)) + start + '\n\n' + reference + '\n' + current.slice(current.indexOf(end));
if (process.argv.includes('--check')) {
  assert.equal(current, updated, 'Action reference differs from action.yml. Run npm run docs.');
} else {
  await writeFile(path, updated);
}
