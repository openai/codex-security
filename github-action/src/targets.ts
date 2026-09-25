import { lstat, realpath } from 'node:fs/promises';
import { resolve, relative, sep, isAbsolute } from 'node:path';
import { runProcess } from './process.js';
import type { Inputs } from './inputs.js';

export interface EventContext {
  eventName: string;
  repository: string;
  sha: string;
  ref: string;
  serverUrl: string;
  payload: Record<string, any>;
}
export interface Target {
  repository: string;
  scannedSha: string;
  analysisRef: string;
  publishable: boolean;
  emptyDiff: boolean;
  diffBase?: string;
  diffHead?: string;
}
const SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
export function validateEvent(event: EventContext): void {
  if (!['pull_request','schedule','workflow_dispatch','push'].includes(event.eventName))
    throw new Error(`Unsupported event: ${event.eventName}. Use pull_request, schedule, workflow_dispatch, or push. Privileged PR source-scanning triggers are not supported.`);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(event.repository)) throw new Error('GITHUB_REPOSITORY is invalid.');
  // The artifact service implementation is GitHub.com-specific for this release.
  if (event.serverUrl !== 'https://github.com') throw new Error('This release supports GitHub.com only; GitHub Enterprise Server has not been validated.');
  if (event.eventName === 'pull_request') {
    const pr = event.payload.pull_request;
    if (!pr || pr.head?.repo?.full_name !== event.repository || pr.base?.repo?.full_name !== event.repository)
      throw new Error('Fork PR scans are not supported. Use a dedicated trusted workflow; do not switch to pull_request_target to expose secrets.');
    if (!SHA.test(pr.head?.sha ?? '') || !SHA.test(pr.base?.sha ?? '') || !Number.isSafeInteger(pr.number ?? event.payload.number))
      throw new Error('Pull request context does not identify valid immutable revisions.');
  }
}
export function gitEnvironment(): NodeJS.ProcessEnv {
  return {
    PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0',
  };
}
export async function git(repository: string, args: string[]): Promise<string> {
  const result = await runProcess('/usr/bin/git', [
    '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
    '-c', 'credential.helper=', '-c', 'core.askPass=/bin/false', ...args,
  ], { cwd: repository, env: gitEnvironment(), timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 });
  if (result.exitCode !== 0 || result.truncated || result.timedOut || result.interrupted || result.signal)
    throw new Error(`Git ${args[0]} failed. Check the checkout and fetch-depth: 0 for PR/diff scans. Git diagnostics are withheld because they can contain credentials.`);
  return result.stdout;
}
function refValue(value: string): string {
  if (!value || value.length > 1024 || value.startsWith('-') || /[\x00-\x20\x7f]/.test(value)) throw new Error('Git revision must be a commit or ref, not an option or expression containing whitespace.');
  return value;
}
async function commit(repository: string, value: string): Promise<string> {
  const sha = (await git(repository, ['rev-parse', '--verify', '--end-of-options', `${refValue(value)}^{commit}`])).trim();
  if (!SHA.test(sha)) throw new Error('Git revision did not resolve to a commit ID.');
  return sha;
}
export async function containedPath(repository: string, input: string): Promise<string> {
  const path = resolve(repository, input);
  const rel = relative(repository, path);
  if (isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('A requested path escapes the repository.');
  let cursor = repository;
  for (const segment of rel.split(sep).filter(Boolean)) {
    cursor = resolve(cursor, segment);
    const stat = await lstat(cursor);
    if (stat.isSymbolicLink()) throw new Error('Requested paths must not traverse symlinks.');
  }
  const info = await lstat(path);
  if (!info.isFile() && !info.isDirectory()) throw new Error('A requested path is not a regular file or directory.');
  return path;
}

function originMatches(url: string, repository: string): boolean {
  // Parse without printing potentially embedded tokens.
  try {
    if (url.startsWith('git@github.com:')) return url.slice(15).replace(/\.git$/, '') === repository;
    const parsed = new URL(url);
    return ['https:', 'ssh:'].includes(parsed.protocol) && parsed.hostname === 'github.com' && !parsed.password &&
      (parsed.protocol === 'ssh:' ? parsed.username === 'git' : !parsed.username) &&
      parsed.pathname.replace(/^\//, '').replace(/\.git$/, '') === repository;
  } catch { return false; }
}

export async function resolveTarget(inputs: Inputs, event: EventContext): Promise<Target> {
  validateEvent(event);
  const repository = await realpath(resolve(inputs.repository));
  if ((await git(repository, ['rev-parse', '--show-toplevel'])).trim() !== repository)
    throw new Error('repository must point to the checkout root. Use paths for folders within it.');
  const configKeys = (await git(repository, ['config', '--local', '--no-includes', '--name-only', '--list'])).toLowerCase().split('\n');
  if (configKeys.some(key => /^credential\.|^http\..*extraheader$|^include\.path$|^includeif\..*\.path$|^core\.sshcommand$|^url\..*\.insteadof$/.test(key)))
    throw new Error('The checkout retains Git authentication or external configuration. Use actions/checkout with persist-credentials: false and a dedicated clean job. Credential values have not been printed.');
  const origin = (await git(repository, ['config', '--no-includes', '--get', 'remote.origin.url'])).trim();
  if (!originMatches(origin, event.repository)) throw new Error('The checkout origin does not match GITHUB_REPOSITORY. Cross-repository checkouts are not supported.');
  const scannedSha = await commit(repository, 'HEAD');
  const pr = event.eventName === 'pull_request' ? event.payload.pull_request : undefined;
  if (pr && scannedSha !== pr.head.sha) throw new Error('PR scans must check out github.event.pull_request.head.sha, not the merge commit.');
  if (!pr && scannedSha !== event.sha) throw new Error('Checkout HEAD must match GITHUB_SHA. Select the intended branch when dispatching; do not silently check out a different revision.');
  const status = await git(repository, ['status', '--porcelain=v1', '-z', '--untracked-files=normal']);
  if (status) throw new Error('The checkout has local changes. Scan a clean checkout.');

  for (const path of inputs.paths) await containedPath(repository, path);
  let diffBase: string | undefined;
  let diffHead: string | undefined;
  let emptyDiff = false;
  if (inputs.scope === 'diff') {
    diffHead = scannedSha;
    if (inputs.diffBase) diffBase = await commit(repository, inputs.diffBase);
    else if (pr) diffBase = (await git(repository, ['merge-base', pr.base.sha, diffHead])).trim();
    else throw new Error('diff-base is required for diff scans outside pull_request events.');
    if (!SHA.test(diffBase)) throw new Error('Could not resolve the diff base. Fetch full history.');
    emptyDiff = !(await git(repository, ['diff', '--no-ext-diff', '--no-textconv', '--name-only', '-z', diffBase, diffHead, '--']));
  }
  const analysisRef = pr ? `refs/pull/${pr.number ?? event.payload.number}/head` : event.ref;
  const publishable = /^refs\/(heads|tags|pull)\//.test(analysisRef);
  return { repository, scannedSha, analysisRef: publishable ? analysisRef : '', publishable, emptyDiff, diffBase, diffHead };
}
