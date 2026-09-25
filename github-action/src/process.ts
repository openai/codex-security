import { spawn } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { StringDecoder } from 'node:string_decoder';

export interface ProcessOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  log?: (line: string) => void;
  timeoutMs?: number;
  maxOutputBytes?: number;
  maxStdoutBytes?: number;
  secrets?: readonly string[];
  signal?: AbortSignal;
}

export interface ProcessResult {
  exitCode: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  interrupted: boolean;
}

/** Prefix every physical line; raw child output must never become runner commands. */
export function safeLogLines(value: string, secrets: readonly string[] = []): string[] {
  let clean = value.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\u2028\u2029]/g, '\n');
  // Sanitize first: stripping a color/control escape can join two secret fragments.
  const forms = [...new Set(secrets.filter(Boolean).flatMap((secret) => [secret, Buffer.from(secret).toString('base64'), encodeURIComponent(secret)]))]
    .sort((a, b) => b.length - a.length);
  for (const form of forms) clean = clean.split(form).join('[REDACTED]');
  return clean.split('\n').filter(Boolean).map((line) => `[codex-security] ${line.slice(0, 4096)}`);
}

/** Direct execution only. No shell and no inherited environment fallback. */
export async function runProcess(executable: string, args: readonly string[], options: ProcessOptions): Promise<ProcessResult> {
  if (!isAbsolute(executable) || !isAbsolute(options.cwd)) throw new Error('Process executable and working directory must be absolute paths.');
  const limit = options.maxOutputBytes ?? 1024 * 1024;
  const stdoutLimit = options.maxStdoutBytes ?? limit;
  const timeout = options.timeoutMs ?? 60 * 60 * 1000;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 16 * 1024 * 1024) throw new Error('Invalid process output limit.');
  if (stdoutLimit !== Infinity && (!Number.isSafeInteger(stdoutLimit) || stdoutLimit < 1)) throw new Error('Invalid stdout limit.');
  if (!Number.isSafeInteger(timeout) || timeout < 1) throw new Error('Invalid process timeout.');
  options.signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [...args], {
      cwd: options.cwd, env: { ...options.env }, shell: false,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    const buffers: Record<'stdout' | 'stderr', Buffer[]> = { stdout: [], stderr: [] };
    const sizes = { stdout: 0, stderr: 0 };
    let truncated = false;
    let timedOut = false;
    let interrupted = false;
    const stderrDecoder = new StringDecoder('utf8');
    let pendingStderr = '';
    let stderrTruncated = false;
    const logStderr = (text: string): void => {
      pendingStderr += text;
      const boundary = pendingStderr.lastIndexOf('\n');
      if (boundary < 0) return;
      // Wait for complete lines so chunk boundaries cannot split secrets or UTF-8.
      for (const line of safeLogLines(pendingStderr.slice(0, boundary + 1), options.secrets)) options.log?.(line);
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
    const timer = setTimeout(() => { timedOut = true; stop(); }, timeout);
    timer.unref();
    const interrupt = (): void => { interrupted = true; stop(); };
    process.once('SIGINT', interrupt);
    process.once('SIGTERM', interrupt);
    options.signal?.addEventListener('abort', interrupt, { once: true });
    for (const name of ['stdout', 'stderr'] as const) child[name].on('data', (chunk: Buffer) => {
      const remaining = (name === 'stdout' ? stdoutLimit : limit) - sizes[name];
      if (remaining > 0) {
        const captured = chunk.subarray(0, remaining);
        buffers[name].push(captured);
        sizes[name] += captured.length;
        if (name === 'stderr' && options.log) logStderr(stderrDecoder.write(captured));
      }
      if (chunk.length > remaining) {
        if (name === 'stderr') {
          stderrTruncated = true;
          // A cut-off line could end partway through a credential. Never emit it.
          pendingStderr = '';
        }
        if (!truncated) options.log?.('[codex-security] Child output reached the capture limit; additional output is omitted.');
        truncated = true;
      }
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
    child.once('close', (code, signal) => {
      finish();
      const stdout = Buffer.concat(buffers.stdout).toString('utf8');
      const stderr = Buffer.concat(buffers.stderr).toString('utf8');
      if (options.log && !stderrTruncated) {
        for (const line of safeLogLines(pendingStderr + stderrDecoder.end(), options.secrets)) options.log(line);
      }
      resolve({ exitCode: code ?? 1, signal, stdout, stderr, truncated, timedOut, interrupted });
    });
  });
}
