export const INPUT_NAMES = [
  'repository', 'scope', 'paths', 'diff-base', 'mode',
  'model', 'effort', 'max-cost', 'max-time-hours', 'fail-on-severity', 'verbose', 'dry-run',
  'summary', 'annotations',
  'upload-artifacts', 'artifact-name', 'retention-days',
] as const;

export type Scope = 'repository' | 'diff';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export type Threshold = 'none' | 'critical' | 'high' | 'medium' | 'low';
export interface Inputs {
  repository: string;
  scope: Scope;
  paths: string[];
  diffBase?: string;
  mode: 'standard' | 'deep';
  model: string;
  effort: string;
  maxCost?: number;
  maxTimeHours?: number;
  failOnSeverity: Threshold;
  verbose: boolean;
  dryRun: boolean;
  summary: boolean;
  annotations: boolean;
  uploadArtifacts: boolean;
  artifactName: string;
  retentionDays: number;
}

export function parseInputs(read: (name: string) => string, workspace: string): Inputs {
  const str = (name: string, fallback = '') => {
    const value = read(name).trim() || fallback;
    if (value.length > 8192 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value))
      throw new Error(`Invalid ${name}: contains control characters or is too long.`);
    return value;
  };
  const single = (name: string, fallback = '') => {
    const value = str(name, fallback);
    if (/[\r\n]/.test(value)) throw new Error(`${name} must be a single value.`);
    return value;
  };
  const choice = <T extends string>(name: string, values: readonly T[], fallback: T): T => {
    const value = single(name, fallback);
    if (!values.includes(value as T)) throw new Error(`${name} must be one of: ${values.join(', ')}.`);
    return value as T;
  };
  const bool = (name: string, fallback: boolean) => choice(name, ['true', 'false'], String(fallback) as 'true' | 'false') === 'true';
  const num = (name: string, integer: boolean, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    const value = single(name);
    if (!value) return undefined;
    if (!/^\d+(?:\.\d+)?$/.test(value)) throw new Error(`${name} must be a finite ${integer ? 'integer' : 'number'}.`);
    const n = Number(value);
    if (!Number.isFinite(n) || (integer && !Number.isSafeInteger(n)) || n < min || n > max)
      throw new Error(`${name} must be ${integer ? 'an integer' : 'a number'} between ${min} and ${max}.`);
    return n;
  };
  const list = (name: string) => str(name).split(/\r?\n/).map(v => v.trim()).filter(Boolean);
  const safeRelative = (name: string, value: string) => {
    if (value.startsWith('-') || value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.includes('\\') || value.split('/').includes('..') || /[*?\[\]\x00-\x1f\x7f]/.test(value))
      throw new Error(`${name} must contain literal repository-relative paths, without globs or '..'.`);
    return value;
  };
  // Match the CLI's scope spelling before constructing arguments or checking reports.
  const paths = [...new Set(list('paths').map(v =>
    safeRelative('paths', v).split('/').filter(part => part && part !== '.').join('/') || '.'))];
  const scope = choice('scope', ['repository', 'diff'], 'repository');
  if (scope !== 'repository' && paths.length)
    throw new Error(`paths cannot be combined with scope: ${scope}. Remove paths to scan changes, or use scope: repository to scan selected paths.`);
  const diffBase = single('diff-base') || undefined;
  if (diffBase && scope !== 'diff') throw new Error('diff-base requires scope: diff.');
  const mode = choice('mode', ['standard', 'deep'], 'standard');
  if (mode === 'deep' && scope !== 'repository') throw new Error('mode: deep requires scope: repository.');
  const maxTimeHours = num('max-time-hours', false, Number.MIN_VALUE, 96);
  if (maxTimeHours !== undefined && mode !== 'deep') throw new Error('max-time-hours requires mode: deep.');
  const dryRun = bool('dry-run', false);
  const artifactName = single('artifact-name', 'codex-security');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(artifactName)) throw new Error('artifact-name must be 1–128 letters, numbers, dots, underscores, or hyphens.');
  const model = single('model', 'gpt-5.6-sol');
  if (model.startsWith('-')) throw new Error('model must be a model name, not a CLI option.');
  return {
    repository: single('repository', workspace), scope, paths, diffBase, mode,
    model, effort: choice('effort', ['minimal','low','medium','high','xhigh','max'], 'xhigh'),
    maxCost: num('max-cost', false, Number.MIN_VALUE), maxTimeHours, failOnSeverity: choice('fail-on-severity', ['none','low','medium','high','critical'], 'none'),
    verbose: bool('verbose', true), dryRun,
    summary: bool('summary', true), annotations: bool('annotations', true),
    uploadArtifacts: bool('upload-artifacts', false), artifactName, retentionDays: num('retention-days', true, 1, 90) ?? 7,
  };
}

export function scanArguments(inputs: Inputs, target: {repository: string; diffBase?: string; diffHead?: string}, resultsDirectory: string, python: string): string[] {
  // The pinned CLI checks API-key presence even during local preflight. Its
  // dry-run branch never starts a model session; auto allows keyless preflight
  // with our empty private credential home. Real scans always use api-key.
  const args = ['scan', target.repository, '--auth', inputs.dryRun ? 'auto' : 'api-key', '--provider', 'openai', '--mode', inputs.mode,
    '--model', inputs.model, '--effort', inputs.effort, '--headless', '--python', python,
    '--output-dir', resultsDirectory, '--format', 'json'];
  // Preserve the pinned CLI's sandbox and automatic approval-review defaults.
  // Forcing approval_policy="never" prevents recovery from hosted Linux sandbox errors.
  args.push('--codex', 'analytics.enabled=false');
  for (const path of inputs.paths) args.push('--path', path);
  const options: Array<[string, string | number | undefined]> = [
    ['--diff', target.diffBase], ['--head', target.diffHead], ['--max-cost', inputs.maxCost],
    ['--max-time-hours', inputs.maxTimeHours],
  ];
  for (const [name, value] of options) if (value !== undefined) args.push(name, String(value));
  if (inputs.failOnSeverity !== 'none') args.push('--fail-on-severity', inputs.failOnSeverity);
  if (inputs.verbose) args.push('--verbose');
  if (inputs.dryRun) args.push('--dry-run');
  return args;
}
