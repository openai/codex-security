export const INPUT_NAMES = [
  'repository', 'scope', 'paths', 'diff-base', 'mode',
  'model', 'cyber-access-program', 'effort', 'max-cost', 'max-time-hours', 'fail-on-severity', 'verbose', 'dry-run',
  'summary', 'annotations',
  'upload-artifacts', 'artifact-name', 'retention-days',
] as const;

export type Inputs = ReturnType<typeof parseInputs>;

export function parseInputs(read: (name: string) => string, workspace: string) {
  const str = (name: string, fallback = '') => read(name).trim() || fallback;
  const choice = <T extends string>(name: string, values: readonly T[], fallback: T): T => {
    const value = str(name, fallback);
    if (!values.includes(value as T)) throw new Error(`${name} must be one of: ${values.join(', ')}.`);
    return value as T;
  };
  const bool = (name: string, fallback: boolean) => choice(name, ['true', 'false'], String(fallback) as 'true' | 'false') === 'true';
  const num = (name: string, integer: boolean, min = 0, max = Infinity) => {
    const value = str(name);
    if (!value) return undefined;
    const n = Number(value);
    if (!Number.isFinite(n) || (integer && !Number.isSafeInteger(n)) || n < min || n > max)
      throw new Error(`${name} must be ${integer ? 'an integer' : 'a number'} between ${min} and ${max}.`);
    return n;
  };
  const list = (name: string) => str(name).split(/\r?\n/).map(v => v.trim()).filter(Boolean);
  const safeRelative = (name: string, value: string) => {
    if (value.startsWith('/') || /^[A-Za-z]:/.test(value) || value.includes('\\') || value.split('/').includes('..') || /[\x00-\x1f\x7f]/.test(value))
      throw new Error(`${name} must contain literal repository-relative paths, without '..'.`);
    return value;
  };
  // Match the CLI's scope spelling before constructing arguments or checking reports.
  const paths = [...new Set(list('paths').map(v =>
    safeRelative('paths', v).split('/').filter(part => part && part !== '.').join('/') || '.'))];
  const scope = choice('scope', ['repository', 'diff'], 'repository');
  if (scope !== 'repository' && paths.length)
    throw new Error(`paths cannot be combined with scope: ${scope}. Remove paths to scan changes, or use scope: repository to scan selected paths.`);
  const diffBase = str('diff-base') || undefined;
  if (diffBase && scope !== 'diff') throw new Error('diff-base requires scope: diff.');
  const mode = choice('mode', ['standard', 'deep'], 'standard');
  if (mode === 'deep' && scope !== 'repository') throw new Error('mode: deep requires scope: repository.');
  const maxTimeHours = num('max-time-hours', false, Number.MIN_VALUE, 96);
  if (maxTimeHours !== undefined && mode !== 'deep') throw new Error('max-time-hours requires mode: deep.');
  const dryRun = bool('dry-run', false);
  const cyberAccessProgram = str('cyber-access-program')
    ? choice('cyber-access-program', ['standard', 'daybreak_blue', 'daybreak_red'], 'standard')
    : undefined;
  return {
    repository: str('repository', workspace), scope, paths, diffBase, mode, cyberAccessProgram,
    model: str('model', 'gpt-5.6-sol'), effort: choice('effort', ['minimal','low','medium','high','xhigh','max'], 'xhigh'),
    maxCost: num('max-cost', false, Number.MIN_VALUE), maxTimeHours, failOnSeverity: choice('fail-on-severity', ['none','low','medium','high','critical'], 'none'),
    verbose: bool('verbose', true), dryRun,
    summary: bool('summary', true), annotations: bool('annotations', true),
    uploadArtifacts: bool('upload-artifacts', false), artifactName: str('artifact-name', 'codex-security'), retentionDays: num('retention-days', true, 1, 90) ?? 7,
  };
}

export function scanArguments(inputs: Inputs, target: {repository: string; diffBase?: string; diffHead?: string}, resultsDirectory: string): string[] {
  // The pinned CLI checks API-key presence even during local preflight. Its
  // dry-run branch never starts a model session; auto allows keyless preflight
  // with our empty private credential home. Real scans always use api-key.
  const args = ['scan', target.repository, '--auth', inputs.dryRun ? 'auto' : 'api-key', '--provider', 'openai', '--mode', inputs.mode,
    `--model=${inputs.model}`, '--effort', inputs.effort, '--headless',
    '--output-dir', resultsDirectory, '--format', 'json'];
  // Preserve the pinned CLI's sandbox and automatic approval-review defaults.
  // Forcing approval_policy="never" prevents recovery from hosted Linux sandbox errors.
  args.push('--codex', 'analytics.enabled=false');
  // Bind the option value and keep it explicitly relative so the CLI treats
  // leading '-' and '~' as literal repository filenames.
  for (const path of inputs.paths) args.push(`--path=./${path}`);
  const options: Array<[string, string | number | undefined]> = [
    ['--cyber-access-program', inputs.cyberAccessProgram],
    ['--diff', target.diffBase], ['--head', target.diffHead], ['--max-cost', inputs.maxCost],
    ['--max-time-hours', inputs.maxTimeHours],
  ];
  for (const [name, value] of options) if (value !== undefined) args.push(name, String(value));
  if (inputs.failOnSeverity !== 'none') args.push('--fail-on-severity', inputs.failOnSeverity);
  if (inputs.verbose) args.push('--verbose');
  if (inputs.dryRun) args.push('--dry-run');
  return args;
}
