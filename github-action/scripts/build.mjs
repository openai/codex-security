import { build } from 'esbuild';
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, relative } from 'node:path';

const check = process.argv.includes('--check');
const root = resolve(import.meta.dirname, '..');
const hash = value => createHash('sha256').update(value).digest('hex');
const bundle = await build({
  absWorkingDir: root, entryPoints: {index: 'src/entry.ts', post: 'src/post.ts'}, outdir: 'dist',
  outExtension: {'.js': '.cjs'}, platform: 'node', target: 'node24', format: 'cjs',
  bundle: true, write: false, sourcemap: false, legalComments: 'eof', metafile: true,
});
const generated = new Map(bundle.outputFiles.map(file => [relative(root, file.path), Buffer.from(file.contents)]));
const lock = JSON.parse(await readFile(resolve(root, 'package-lock.json'), 'utf8'));
const runtimeManifest = JSON.parse(await readFile(resolve(root, 'runtime/package.json'), 'utf8'));
const cliVersion = runtimeManifest.dependencies['@openai/codex-security'];
const cliLockBytes = await readFile(resolve(root, 'runtime/package-lock.json'));
const cliLock = JSON.parse(cliLockBytes);
function components(packages, namespace) {
  return Object.entries(packages).filter(([path, info]) => path && !info.dev).map(([path, info]) => ({
    type: 'library', 'bom-ref': `${namespace}:${path}`,
    name: info.name || path.slice(path.lastIndexOf('node_modules/') + 13), version: info.version,
    ...(info.license && /^[A-Za-z0-9-.+]+$/.test(info.license) ? {licenses: [{license: {id: info.license}}]} : {}),
    ...(info.resolved ? {externalReferences: [{type: 'distribution', url: info.resolved}]} : {}),
  }));
}
const sourceFiles = (await readdir(resolve(root, 'src'))).filter(name => name.endsWith('.ts')).sort();
const sourceHash = createHash('sha256');
for (const file of sourceFiles) sourceHash.update(file).update('\0').update(await readFile(resolve(root, 'src', file))).update('\0');
const manifest = {
  actionVersion: '0.1.0', status: 'unreleased', nodeRuntime: 'node24', platform: 'linux-x64', cliVersion,
  sourceSha256: sourceHash.digest('hex'), actionLockSha256: hash(await readFile(resolve(root, 'package-lock.json'))),
  runtimeLockSha256: hash(cliLockBytes),
  buildInputs: Object.fromEntries(await Promise.all(['../action.yml', 'package.json', 'runtime/package.json', 'scripts/build.mjs'].map(async path => [path, {sha256: hash(await readFile(resolve(root, path)))}]))),
  files: Object.fromEntries([...generated].map(([path, bytes]) => [path, {sha256: hash(bytes), bytes: bytes.length}])),
};
const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
  metadata: {component: {type: 'application', name: 'codex-security-action', version: '0.1.0'}},
  components: [...components(lock.packages, 'action'), ...components(cliLock.packages, 'cli')],
};
if (!check) await mkdir(resolve(root, 'dist'), {recursive: true});
for (const [path, bytes] of generated) {
  if (check) {
    const existing = await readFile(resolve(root, path)).catch(() => Buffer.alloc(0));
    if (!bytes.equals(existing)) throw new Error(`${path} differs from a clean build. Run npm run build and review the generated changes.`);
  } else await writeFile(resolve(root, path), bytes);
}
// Release metadata is generated for CI artifacts, not needed by the runner.
await mkdir(resolve(root, 'build'), {recursive: true});
for (const [name, value] of [['release-manifest.json', manifest], ['sbom.cdx.json', sbom]]) {
  await writeFile(resolve(root, 'build', name), JSON.stringify(value, null, 2) + '\n');
}
console.log(check ? 'Distribution matches source; generated release metadata.' : 'Built action, cleanup entrypoint, and release metadata.');
