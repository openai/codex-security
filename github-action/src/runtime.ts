import { which } from '@actions/io';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { runProcess, safeLogLines } from './process.js';
import runtimeManifest from '../runtime/package.json' with { type: 'json' };

export const SUPPORTED_CLI_VERSION = runtimeManifest.dependencies['@openai/codex-security'];
const MARKER = '.codex-security-action-owned';
const ROOT_PREFIX = 'codex-security-runtime-';
const REGISTRY = 'https://registry.npmjs.org/';

export interface RuntimeOptions {
  actionRoot: string;
  tempRoot: string;
  log?: (line: string) => void;
}
export interface Runtime {
  nodePath: string;
  cliPath: string;
  root: string;
  home: string;
  codexHome: string;
  stateDirectory: string;
  resultsDirectory: string;
  runnerPath?: string;
  runnerTrackingId?: string;
  runnerLibraryPath?: string;
  env: (apiKey: string) => NodeJS.ProcessEnv;
}

/** Deliberately construct a new environment: never copy process.env. */
export function runtimeEnvironment(paths: Pick<Runtime, 'root' | 'home' | 'codexHome' | 'stateDirectory' | 'runnerPath' | 'runnerTrackingId' | 'runnerLibraryPath'>, apiKey?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: `${join(paths.root, 'bin')}:${paths.runnerPath ?? '/usr/bin:/bin'}`,
    HOME: paths.home, CODEX_HOME: paths.codexHome,
    CODEX_SECURITY_STATE_DIR: paths.stateDirectory,
    TMPDIR: join(paths.root, 'tmp'), TMP: join(paths.root, 'tmp'), TEMP: join(paths.root, 'tmp'),
    XDG_CONFIG_HOME: join(paths.home, '.config'), XDG_CACHE_HOME: join(paths.home, '.cache'),
    CI: 'true', NO_COLOR: '1', TERM: 'dumb', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    CODEX_SECURITY_NO_UPDATE_NOTICE: '1', NO_UPDATE_NOTIFIER: '1',
    // The pinned CLI preserves virtualenv launchers when resolving a PATH command.
    PYTHON: 'python3', PYTHONNOUSERSITE: '1', PYTHONSAFEPATH: '1', PYTHONUTF8: '1',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_COUNT: '4',
    GIT_CONFIG_KEY_0: 'credential.helper', GIT_CONFIG_VALUE_0: '',
    GIT_CONFIG_KEY_1: 'core.hooksPath', GIT_CONFIG_VALUE_1: '/dev/null',
    GIT_CONFIG_KEY_2: 'core.fsmonitor', GIT_CONFIG_VALUE_2: 'false',
    GIT_CONFIG_KEY_3: 'core.askPass', GIT_CONFIG_VALUE_3: '/bin/false',
  };
  if (paths.runnerTrackingId !== undefined) {
    env.RUNNER_TRACKING_ID = paths.runnerTrackingId;
    env.CODEX_MCP_NODE_PATH = join(paths.root, 'bin', 'node');
  }
  if (paths.runnerLibraryPath !== undefined) env.LD_LIBRARY_PATH = paths.runnerLibraryPath;
  if (apiKey !== undefined) {
    if (!apiKey || /[\r\n\u0000]/.test(apiKey)) throw new Error('OPENAI_API_KEY must be a nonempty single-line value.');
    env.OPENAI_API_KEY = apiKey;
  }
  return env;
}

async function regularFile(path: string): Promise<string> {
  const target = await realpath(path);
  const info = await lstat(target);
  if (!info.isFile()) throw new Error('Runtime prerequisite must be a regular file.');
  return target;
}

/** Anchor PATH lookup before installer, scanner, or worker cwd changes. */
export function captureRunnerPath(value = process.env.PATH ?? '/usr/bin:/bin', cwd = process.cwd()): string {
  return value.split(delimiter).map(entry => resolve(cwd, entry)).join(delimiter);
}

/** Discover the same launcher that the captured child PATH will select. */
export async function resolveTool(name: 'npm' | 'python3', runnerPath = captureRunnerPath()): Promise<string> {
  for (const directory of runnerPath.split(delimiter)) {
    const executable = await which(join(directory, name));
    if (executable) return executable;
  }
  throw new Error(`Unable to locate ${name} on the runner PATH.`);
}

export async function checkPython(pythonPath: string, cwd: string, env: NodeJS.ProcessEnv): Promise<void> {
  const result = await runProcess(pythonPath, ['-I', '-c', 'import sys, sqlite3, tomllib; assert sys.version_info >= (3, 11)'], { cwd, env, timeoutMs: 10_000 });
  if (result.exitCode !== 0 || result.timedOut || result.interrupted || result.signal)
    throw new Error('Python 3.11 or later with sqlite3 and tomllib is required. Use actions/setup-python to select a compatible interpreter.');
}

/** Restore a captured runner setting after Codex clears an MCP child's environment. */
export async function writeRuntimeLauncher(path: string, executable: string, name: 'LD_LIBRARY_PATH' | 'RUNNER_TRACKING_ID', value: string): Promise<void> {
  const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
  await writeFile(path, `#!/bin/sh\nexport ${name}=${quote(value)}\nexec ${quote(executable)} "$@"\n`, { mode: 0o700, flag: 'wx' });
}

export async function setupRuntime(options: RuntimeOptions): Promise<Runtime> {
  if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Codex Security Action currently supports Linux x64 runners only.');
  if (Number(process.versions.node.split('.')[0]) !== 24) throw new Error('Codex Security Action requires the Node 24 GitHub Actions runtime.');
  if (!isAbsolute(options.actionRoot) || !isAbsolute(options.tempRoot)) throw new Error('Action and temporary roots must be absolute.');
  const runnerPath = captureRunnerPath();
  const runnerTrackingId = process.env.RUNNER_TRACKING_ID;
  const runnerLibraryPath = process.env.LD_LIBRARY_PATH;
  const tempRoot = await realpath(options.tempRoot);
  const actionRoot = await realpath(options.actionRoot);
  const npmPath = await resolveTool('npm', runnerPath);
  const pythonPath = await resolveTool('python3', runnerPath);
  const nodePath = process.execPath;
  const root = await mkdtemp(join(tempRoot, ROOT_PREFIX));
  await chmod(root, 0o700);
  await writeFile(join(root, MARKER), 'codex-security-action-v1\n', { mode: 0o600, flag: 'wx' });
  const home = join(root, 'home');
  const codexHome = join(root, 'codex-home');
  const stateDirectory = join(root, 'state');
  const paths = { root, home, codexHome, stateDirectory, runnerPath, runnerTrackingId, runnerLibraryPath };
  try {
    for (const dir of [home, codexHome, stateDirectory, join(root, 'tmp'), join(root, 'bin'), join(root, 'install')]) await mkdir(dir, { mode: 0o700 });
    if (runnerTrackingId === undefined) await symlink(nodePath, join(root, 'bin', 'node'));
    else await writeRuntimeLauncher(join(root, 'bin', 'node'), nodePath, 'RUNNER_TRACKING_ID', runnerTrackingId);
    if (runnerLibraryPath !== undefined) await writeRuntimeLauncher(join(root, 'bin', 'python3'), pythonPath, 'LD_LIBRARY_PATH', runnerLibraryPath);
    const env = runtimeEnvironment(paths);
    await checkPython(pythonPath, root, env);
    const source = join(actionRoot, 'runtime');
    const lockPath = await regularFile(join(source, 'package-lock.json'));
    const packagePath = await regularFile(join(source, 'package.json'));
    if (!lockPath.startsWith(source + sep) || !packagePath.startsWith(source + sep)) throw new Error('Runtime manifests must remain within the action package.');
    const lockBytes = await readFile(lockPath, 'utf8');
    const destination = join(root, 'install');
    await copyFile(packagePath, join(destination, 'package.json'));
    await writeFile(join(destination, 'package-lock.json'), lockBytes, { mode: 0o600, flag: 'wx' });
    const userConfig = join(root, 'npm-user.conf');
    const globalConfig = join(root, 'npm-global.conf');
    await writeFile(userConfig, '', { mode: 0o600, flag: 'wx' });
    await writeFile(globalConfig, '', { mode: 0o600, flag: 'wx' });
    const install = await runProcess(npmPath, ['ci', '--ignore-scripts', '--include=optional', `--registry=${REGISTRY}`, `--userconfig=${userConfig}`, `--globalconfig=${globalConfig}`, `--cache=${join(root, 'npm-cache')}`, '--no-audit', '--no-fund', '--loglevel=error'], { cwd: destination, env, timeoutMs: 10 * 60 * 1000, log: options.log });
    if (install.exitCode !== 0 || install.timedOut || install.interrupted) {
      // npm sometimes writes lock/usage diagnostics to stdout. This process had
      // no credentials and every physical line is still treated as untrusted.
      for (const line of safeLogLines(install.stdout)) options.log?.(line);
      throw new Error(`Integrity-locked CLI installation failed (exit ${install.exitCode}${install.timedOut ? ', timed out' : ''}${install.interrupted ? ', interrupted' : ''}). Check the prefixed npm diagnostics, registry access, and runner prerequisites.`);
    }
    const cliPath = await regularFile(join(destination, 'node_modules', '@openai', 'codex-security', 'bin', 'codex-security.mjs'));
    // Private reports deliberately live outside the disposable credentials/runtime
    // root so downstream upload-sarif remains usable after the post action.
    const resultsDirectory = await mkdtemp(join(tempRoot, 'codex-security-reports-'));
    await chmod(resultsDirectory, 0o700);
    return { ...paths, nodePath, cliPath, resultsDirectory, env: (apiKey) => runtimeEnvironment(paths, apiKey) };
  } catch (error) {
    await cleanupRuntime(root, tempRoot);
    throw error;
  }
}

export async function cleanupRuntime(root: string, tempRoot: string): Promise<void> {
  if (!isAbsolute(root) || !isAbsolute(tempRoot)) throw new Error('Cleanup requires absolute owned paths.');
  const base = await realpath(tempRoot);
  const info = await lstat(root).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (!info) return;
  const canonical = await realpath(root);
  const child = relative(base, canonical);
  if (!info.isDirectory() || info.isSymbolicLink() || dirname(canonical) !== base || !child.startsWith(ROOT_PREFIX) || child.includes(sep) || resolve(root) !== canonical) throw new Error('Refusing to clean a path outside the owned runtime root.');
  const marker = join(canonical, MARKER);
  if (!(await lstat(marker)).isFile() || await readFile(marker, 'utf8') !== 'codex-security-action-v1\n') throw new Error('Refusing to clean a directory without the ownership marker.');
  await rm(canonical, { recursive: true, force: false });
}
