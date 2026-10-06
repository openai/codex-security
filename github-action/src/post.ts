import * as core from '@actions/core';
import { cleanupRuntime } from './runtime.js';
const root = core.getState('runtime-root');
const tempRoot = core.getState('runtime-temp-root');
if (root && tempRoot) {
  cleanupRuntime(root, tempRoot).catch(() => core.setFailed('Codex Security temporary runtime cleanup failed.'));
}
