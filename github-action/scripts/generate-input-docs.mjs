import { readFile, writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { format } from 'prettier';
import { parse } from 'yaml';

const data = parse(await readFile(new URL('../../action.yml', import.meta.url), 'utf8'));
// Code spans preserve literal backslashes; prose needs them escaped as well as pipes.
const escape = (value, code = false) => String(value).replace(/[\\|]/g, character => code && character === '\\' ? character : '\\' + character).replace(/\n/g, ' ');
const defaultValue = value => {
  const text = String(value).replace(/\n/g, ' ');
  // A backslash next to a pipe cannot round-trip through a GFM table code span.
  if (text.includes('\\|')) return '<code>' + Array.from(text, character => `&#${character.codePointAt(0)};`).join('') + '</code>';
  return '`' + escape(text, true) + '`';
};
let reference = '## Inputs\n\nInputs are strings. Quote booleans and use newline-separated literal paths for lists.\n\n| Input | Default | Meaning |\n| --- | --- | --- |\n';
for (const [name, value] of Object.entries(data.inputs)) {
  reference += `| \`${name}\` | ${value.default === undefined ? 'Unset' : defaultValue(value.default)} | ${escape(value.description)} |\n`;
}
reference += '\n## Outputs\n\nAll outputs are strings. An empty cost or count means unavailable, not zero.\n\n| Output | Meaning |\n| --- | --- |\n';
for (const [name, value] of Object.entries(data.outputs)) reference += `| \`${name}\` | ${escape(value.description)} |\n`;
reference = await format(reference, { parser: 'markdown' });

const path = new URL('../README.md', import.meta.url);
const current = await readFile(path, 'utf8');
function replaceSection(text, section, content, label) {
  const start = `<!-- ${section}:start -->`;
  const end = `<!-- ${section}:end -->`;
  const startIndex = text.indexOf(start);
  const endIndex = text.indexOf(end);
  assert.ok(startIndex >= 0 && startIndex < endIndex, `README must contain ${label} markers in order`);
  return text.slice(0, startIndex) + start + '\n\n' + content + '\n' + text.slice(endIndex);
}
let updated = replaceSection(current, 'action-reference', reference, 'action reference');
for (const name of ['repository', 'pull-request']) {
  const workflow = await readFile(new URL(`../examples/${name}.yml`, import.meta.url), 'utf8');
  const snippet = await format('```yaml\n' + workflow + '```\n', { parser: 'markdown' });
  updated = replaceSection(updated, `action-workflow:${name}`, snippet, `${name} workflow`);
}
if (process.argv.includes('--check')) {
  assert.equal(current, updated, 'Action reference or workflow examples are out of date. Run npm run docs.');
} else {
  await writeFile(path, updated);
}
