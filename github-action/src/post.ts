import { cleanupRuntime } from './runtime-cleanup.js';

// GitHub exposes saved action state to the post entrypoint through STATE_ variables.
const root = process.env['STATE_runtime-root'];
const tempRoot = process.env['STATE_runtime-temp-root'];
if (root && tempRoot) {
  void cleanupRuntime(root, tempRoot).catch(() => {
    process.exitCode = 1;
    process.stdout.write('::error::Codex Security temporary runtime cleanup failed.\n');
  });
}
