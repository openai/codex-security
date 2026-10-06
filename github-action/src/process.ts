import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { StringDecoder } from 'node:string_decoder';

export interface ProcessOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  log?: (line: string) => void;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface ProcessResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  interrupted: boolean;
}

/** Prefix modern runner commands and escape legacy commands, which match anywhere. */
export function safeLogLines(value: string): string[] {
  const clean = value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\u2028\u2029]/g, '\n')
    .replace(/##\[/g, '##\\[');
  return clean.split('\n').filter(Boolean).map((line) => `[codex-security] ${line}`);
}

/** Direct execution only. No shell and no inherited environment fallback. */
export async function runProcess(executable: string, args: readonly string[], options: ProcessOptions): Promise<ProcessResult> {
  if (!isAbsolute(executable) || !isAbsolute(options.cwd)) throw new Error('Process executable and working directory must be absolute paths.');
  options.signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], {
      cwd: options.cwd, env: { ...options.env }, shell: false,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    const buffers: Record<'stdout' | 'stderr', Buffer[]> = { stdout: [], stderr: [] };
    let timedOut = false;
    let interrupted = false;
    const stderrDecoder = new StringDecoder('utf8');
    let pendingStderr = '';
    const log = (value: string): void => {
      for (const line of safeLogLines(value)) {
        try { options.log?.(line); }
        catch { /* Optional diagnostics must not interrupt the child process. */ }
      }
    };
    const logStderr = (text: string): void => {
      pendingStderr += text;
      const boundary = pendingStderr.lastIndexOf('\n');
      if (boundary < 0) return;
      // Wait for complete lines so chunk boundaries cannot split UTF-8 or runner-command prefixes.
      log(pendingStderr.slice(0, boundary + 1));
      pendingStderr = pendingStderr.slice(boundary + 1);
    };
    let killTimer: NodeJS.Timeout | undefined;
    let stopped = false;
    const kill = (signal: NodeJS.Signals): void => {
      if (!child.pid) return;
      try {
        if (process.platform !== 'win32') process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') child.kill(signal); }
    };
    const stop = (): void => {
      if (stopped) return;
      stopped = true;
      kill('SIGTERM');
      killTimer = setTimeout(() => kill('SIGKILL'), 2000);
      killTimer.unref();
    };
    const timer = options.timeoutMs === undefined ? undefined : setTimeout(() => { timedOut = true; stop(); }, options.timeoutMs);
    timer?.unref();
    const interrupt = (): void => { interrupted = true; stop(); };
    process.once('SIGINT', interrupt);
    process.once('SIGTERM', interrupt);
    options.signal?.addEventListener('abort', interrupt, { once: true });
    for (const name of ['stdout', 'stderr'] as const) child[name].on('data', (chunk: Buffer) => {
      buffers[name].push(chunk);
      if (name === 'stderr' && options.log) logStderr(stderrDecoder.write(chunk));
    });
    const finish = (): void => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      process.removeListener('SIGINT', interrupt);
      process.removeListener('SIGTERM', interrupt);
      options.signal?.removeEventListener('abort', interrupt);
      // Terminate background descendants still in the owned process group.
      kill('SIGKILL');
    };
    child.once('error', (error) => { finish(); reject(error); });
    child.once('exit', finish);
    child.once('close', (code, signal) => {
      const stdout = Buffer.concat(buffers.stdout).toString('utf8');
      const stderr = Buffer.concat(buffers.stderr).toString('utf8');
      if (options.log) {
        log(pendingStderr + stderrDecoder.end());
      }
      resolve({ exitCode: code ?? 1, signal, stdout, stderr, timedOut, interrupted });
    });
  });
}
