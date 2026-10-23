import { resolve } from 'node:path';
import { runAction } from './main.js';
declare const __dirname: string;
void runAction(resolve(__dirname, '..')).catch(() => { process.exitCode = 1; });
