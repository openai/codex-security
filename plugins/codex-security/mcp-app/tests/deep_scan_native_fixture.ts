import { chmod, writeFile } from "node:fs/promises";
import path from "node:path";

export async function createFakeCodexFixture(
  createTemporaryDirectory: (prefix: string) => Promise<string>,
  preflightProfile: unknown,
  preflightAllowed = true,
  accountResult: {
    account: { type: string } | null;
    requiresOpenaiAuth: boolean;
  } = { account: { type: "apiKey" }, requiresOpenaiAuth: true },
  forcedLoginMethod?: string,
) {
  const root = await createTemporaryDirectory("codex-security-sdk-executor-");
  const markerPath = path.join(root, "invocation.json");
  const preflightMarkerPath = path.join(root, "preflight.json");
  const completionMarkerPath = path.join(root, "completed-usage.txt");
  const scriptPath = path.join(root, "fake-codex.mjs");
  await writeFile(
    scriptPath,
    `#!/usr/bin/env node
import { readFileSync, readdirSync, renameSync, writeFileSync as writeReceiptFile } from "node:fs";
const writeFileSync = (path, value) => { const pending = path + "." + process.pid + ".pending"; writeReceiptFile(pending, value); renameSync(pending, path); };
import { spawnSync } from "node:child_process";
import { join } from "node:path";
const completionMarkerPath = ${JSON.stringify(completionMarkerPath)};
const preflightProfile = process.env.FAKE_CODEX_PREFLIGHT_PROFILE ? JSON.parse(process.env.FAKE_CODEX_PREFLIGHT_PROFILE) : ${JSON.stringify(preflightProfile)};
const preflightAllowed = ${JSON.stringify(preflightAllowed)};
const accountResult = ${JSON.stringify(accountResult)};
const forcedLoginMethod = ${JSON.stringify(forcedLoginMethod ?? null)};
const preflightMarkerPath = process.env.FAKE_CODEX_PREFLIGHT_MARKER ?? ${JSON.stringify(preflightMarkerPath)};
if (!process.argv.includes('app-server')) throw new Error('Expected app-server transport');
const rpc = [];
const sequence = [];
let thread;
let turn;
let login;
let threadId;
const turnId = 'fixture-turn-id';
let stdin = '';
let completed = false;
const environment = {
  argv: process.argv.slice(2), cwd: process.cwd(), codexHome: process.env.CODEX_HOME,
  sqliteHome: process.env.CODEX_SQLITE_HOME, stateDatabase: process.env.CODEX_STATE_DB,
  cacheDirectory: process.env.XDG_CACHE_HOME, configPath: process.env.CODEX_SECURITY_CONFIG_PATH,
  deepConfigPath: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH,
  runnerTrackingId: process.env.RUNNER_TRACKING_ID, libraryPath: process.env.LD_LIBRARY_PATH,
  providerKey: process.env.SYNTHETIC_GATEWAY_KEY, providerHeader: process.env.SYNTHETIC_HEADER_VALUE,
  gitEnvironment: Object.fromEntries(['PATH', 'CODEX_SECURITY_GIT', 'GIT_SSH_COMMAND', 'GIT_CONFIG_GLOBAL'].map(name => [name, process.env[name]])),
};
const preflight = { ...environment, requests: [] };
const runtimeEnvironment = Object.fromEntries(['PATH', 'HOME', 'PYTHON', 'PYTHONUTF8', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH', 'CODEX_SECURITY_STATE_DIR', 'RUNNER_TRACKING_ID'].map(name => [name, process.env[name]]));
function capture() {
  if (!thread) return;
  const toolProbe = stdin.includes('CAPTURE_SYNTHETIC_RG') ? spawnSync('rg', ['--version'], { encoding: 'utf8' }) : undefined;
  if (toolProbe && toolProbe.status !== 0) throw toolProbe.error ?? new Error(toolProbe.stderr);
  const pythonProbe = stdin.includes('CAPTURE_SYNTHETIC_PYTHON') ? spawnSync(process.env.PYTHON, ['-I', '-c', 'import json,os,sys; print(json.dumps([sys.prefix,os.environ.get("LD_LIBRARY_PATH")]))'], { encoding: 'utf8' }) : undefined;
  if (pythonProbe && pythonProbe.status !== 0) throw new Error(pythonProbe.stderr || String(pythonProbe.error));
  const pythonRuntime = pythonProbe ? JSON.parse(pythonProbe.stdout) : undefined;
  const knowledgePath = stdin.includes('synthetic worker configuration fixture') ? process.env.CODEX_SECURITY_KNOWLEDGE_BASE : undefined;
  const knowledgeDocuments = knowledgePath === undefined ? undefined : Object.fromEntries(readdirSync(knowledgePath).map(name => [name, readFileSync(join(knowledgePath, name), 'utf8')]));
  writeFileSync(process.env.FAKE_CODEX_MARKER, JSON.stringify({
    ...environment, rpc, sequence, thread, turn, login, stdin, pid: process.pid, knowledgePath, knowledgeDocuments,
    mcpNodePath: process.env.CODEX_MCP_NODE_PATH, bundledTool: toolProbe?.stdout.trim(), python: process.env.PYTHON, pythonPrefix: pythonRuntime?.[0], pythonLibraryPath: pythonRuntime?.[1], runtimeEnvironment,
    originator: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE,
    ...(stdin.includes('CAPTURE_SYNTHETIC_OPENAI_AUTH') ? { openaiAuthentication: { OPENAI_API_KEY: process.env.OPENAI_API_KEY, CODEX_API_KEY: process.env.CODEX_API_KEY } } : {}),
    ...(stdin.includes('CAPTURE_SYNTHETIC_BEDROCK_AUTH') ? { bedrockAuthentication: Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_BEDROCK_ENV_KEYS).map(name => [name, process.env[name]])) } : {}),
  }));
}
const send = message => process.stdout.write(JSON.stringify(message) + '\\n');
function wire(event) {
  if (event.type === 'thread.started') return null;
  if (event.type === 'error') return { method: 'error', params: { threadId, turnId, error: { message: event.message }, willRetry: true } };
  if (event.type === 'turn.completed' || event.type === 'turn.failed') {
    completed = true;
    const status = event.type === 'turn.completed' ? 'completed' : 'failed';
    sequence.push('terminal:' + status);
    writeFileSync(completionMarkerPath, 'completed\\n');
    return { method: 'turn/completed', params: { threadId, turn: { id: turnId, status, ...(event.error ? { error: event.error } : {}) } } };
  }
  const item = { ...event.item };
  if (item.type === 'error') return { method: 'configWarning', params: { summary: item.message } };
  if (item.type === 'command_execution') {
    item.type = 'commandExecution'; item.aggregatedOutput = item.aggregated_output; item.exitCode = item.exit_code;
    delete item.aggregated_output; delete item.exit_code;
  } else if (item.type === 'file_change') item.type = 'fileChange';
  else if (item.type === 'mcp_tool_call') item.type = 'mcpToolCall';
  else if (item.type === 'agent_message') item.type = 'agentMessage';
  return { method: 'item/completed', params: { threadId, turnId, item } };
}
function emit(event) {
  const message = wire(event);
  if (message) send(message);
  capture();
}
async function runTurn(stdin) {
  sequence.push('active');
  writeFileSync(completionMarkerPath, 'active\\n');
  capture();
if (stdin.includes('THREAD_START_CONFIG_ERROR')) { console.error('Error: thread/start: thread/start failed: agents.max_threads cannot be set when features.multi_agent_v2 is enabled (code -32600)'); process.exit(1); }
if (stdin.includes('CONFIG_ERROR')) { console.error('failed to load configuration: invalid value'); process.exit(2); }
if (stdin.includes('MCP_STARTUP_TIMEOUT') || stdin.includes('CATALOG_AUTH_ONLY') || stdin.includes('SYNC_AUTH_ONLY')) {
  const syncWarning = stdin.includes('SYNC_AUTH_WARNING') || stdin.includes('SYNC_AUTH_ONLY');
  const bothWarnings = stdin.includes('BOTH_AUTH_WARNINGS');
  if (!syncWarning || bothWarnings) console.error('chatgpt authentication required for remote plugin catalog; api key auth is not supported');
  if (syncWarning || bothWarnings) console.error('chatgpt authentication required to sync remote plugins; api key auth is not supported');
  if (!stdin.includes('CATALOG_AUTH_ONLY') && !stdin.includes('SYNC_AUTH_ONLY')) {
    const serverName = stdin.includes('OTHER_MCP_STARTUP_TIMEOUT') ? 'other_server' : stdin.includes('LEGACY_ARTIFACT_MCP_STARTUP_TIMEOUT') ? 'codex_security_artifacts' : 'cs_artifacts';
    const timeout = stdin.includes('REQUEST_TIMED_OUT') ? 'request timed out' : 'timed out handshaking with MCP server after 30s';
    console.error('required MCP servers failed to initialize: ' + serverName + ': ' + timeout);
  }
  if (stdin.includes('WITH_MISSING_API_KEY')) console.error('missing API key');
  if (stdin.includes('WITH_POLICY_REFUSAL')) console.error('Request blocked by cyberPolicy.');
  process.exit(1);
}
emit({ type: 'thread.started', thread_id: threadId });
if (process.env.FAKE_CODEX_ARTIFACT_EVENT) emit(JSON.parse(process.env.FAKE_CODEX_ARTIFACT_EVENT));
if (stdin.includes('IPC_DIAGNOSTIC_EVENT')) emit(JSON.parse(stdin.split('\\n')[1]));
if (stdin.includes('MALFORMED_COMMAND_EVENT')) {
  const output = JSON.parse(stdin.split('\\n')[1]);
  const event = { type: 'item.completed', item: { id: 'fixture-command', type: 'command_execution', command: 'cat example.ts', aggregated_output: output, exit_code: 0, status: 'completed' } };
  process.stdout.write(JSON.stringify(wire(event)).slice(0, -1) + '\\n');
  process.exit(0);
}
const permissionProfileFallbackWarning = 'Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`codex_security_deep_scan_worker\` to required value \`:read-only\`.';
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_ITEM')) emit({ type: 'item.completed', item: { id: 'warning-1', type: 'error', message: permissionProfileFallbackWarning } });
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_EVENT')) emit({ type: 'error', message: permissionProfileFallbackWarning });
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_WARNING')) send({ method: 'warning', params: { threadId, message: permissionProfileFallbackWarning } });
if (stdin.includes('NATIVE_WARNING')) send({ method: 'warning', params: { threadId, message: JSON.parse(stdin.split('\\n')[1]) } });
if (stdin.includes('BLOCK_AFTER_START')) await new Promise(() => {});
if (stdin.includes('RATE_LIMIT_CYBER_POLICY_ERROR')) { emit({ type: 'turn.failed', error: { message: '429 Too Many Requests: Request blocked by cyberPolicy.' } }); process.exit(0); }
if (stdin.includes('CYBER_POLICY_ERROR')) { emit({ type: 'turn.failed', error: { message: 'Request blocked by cyberPolicy.' } }); process.exit(0); }
if (stdin.includes('SAFETY_POLICY_ERROR')) { emit({ type: 'turn.failed', error: { message: 'Request blocked by a safety policy violation.' } }); process.exit(0); }
if (stdin.includes('UPSTREAM_CYBERSECURITY_RISK_ERROR')) { emit({ type: 'turn.failed', error: { message: 'This request has been flagged for possible cybersecurity risk.' } }); process.exit(0); }
if (stdin.includes('UPSTREAM_HIGH_RISK_CYBER_ACTIVITY_ERROR')) { emit({ type: 'turn.failed', error: { message: 'This request has been flagged for potentially high-risk cyber activity.' } }); process.exit(0); }
if (stdin.includes('CYBERSECURITY_RISK_ERROR')) { emit({ type: 'turn.failed', error: { message: 'This content was flagged for possible cybersecurity risk.' } }); process.exit(0); }
if (stdin.includes('HIGH_RISK_CYBER_ACTIVITY_ERROR')) { emit({ type: 'turn.failed', error: { message: 'This content was flagged for potentially high-risk cyber activity.' } }); process.exit(0); }
if (stdin.includes('RETRYABLE_STREAM_ERROR')) emit({ type: 'error', message: 'Reconnecting... 2/5 (stream disconnected before completion: websocket closed by server before response.completed)' });
if (stdin.includes('INCOMPLETE_STREAM')) { emit({ type: 'error', message: 'fixture stream interrupted' }); process.exit(0); }
if (stdin.includes('BWRAP_NAMESPACE_FAILURE')) emit({ type: 'item.completed', item: { id: 'command-1', type: 'command_execution', command: 'super-secret-command', aggregated_output: 'private source text\\nbwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_user_namespaces exceeded (ENOSPC)', exit_code: 1, status: 'failed' } });
if (stdin.includes('ARTIFACT_TOOL_')) {
  const server = stdin.includes('FOREIGN_ARTIFACT_TOOL_') ? 'untrusted_server' : stdin.includes('LEGACY_OWNED_ARTIFACT_TOOL_') ? 'codex_security_artifacts' : 'cs_artifacts';
  const tool = stdin.includes('ADDITIONAL_OWNED_ARTIFACT_TOOL_') ? 'additional_codex_security_worker_tool' : stdin.includes('DISCOVERY_OWNED_ARTIFACT_TOOL_') ? 'record_codex_security_discovery_candidates' : 'record_codex_security_deep_reduction';
  const item = { id: 'mcp-1', type: 'mcp_tool_call', server, tool, arguments: { secret: 'Bearer synthetic-secret', source: 'private source text' }, result: stdin.includes('REJECTED') ? { content: [{ type: 'text', text: 'private output sk-proj-synthetic-secret' }] } : null, error: stdin.includes('TRANSPORT_FAILED') ? { message: '--provider-error transport closed sk-proj-synthetic-secret /private/customer/path' } : null, status: 'failed' };
  emit({ type: 'item.completed', item });
}
emit({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture final response' } });
emit({ type: 'turn.completed', usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } });

  capture();
}
async function handle(message) {
  rpc.push(message);
  if (message.method === 'initialized') return;
  let result;
  if (message.method === 'initialize') result = { userAgent: 'fixture', codexHome: process.env.CODEX_HOME, platformFamily: 'unix', platformOs: 'linux' };
  else if (message.method === 'config/read') result = { config: { ...(forcedLoginMethod ? { forced_login_method: forcedLoginMethod } : {}), default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: preflightProfile } }, origins: {}, layers: null };
  else if (message.method === 'permissionProfile/list') result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: preflightAllowed }], nextCursor: null };
  else if (message.method === 'account/read') result = accountResult;
  else if (message.method === 'configRequirements/read') result = { requirements: { allowedPermissionProfiles: { existing_profile: true } } };
  else if (message.method === 'account/login/start') {
    login = message; result = { type: 'apiKey' };
  } else if (message.method === 'thread/start' || message.method === 'thread/resume') {
    thread = message; threadId = message.params.threadId ?? 'fixture-thread-id';
    result = { thread: { id: threadId, ephemeral: false }, model: message.params.model ?? 'fixture-model' };
    capture();
    if (process.env.FAKE_CODEX_HOLD_THREAD_START === 'true') { sequence.push('thread-pending'); writeFileSync(completionMarkerPath, 'thread-pending\\n'); capture(); return; }
  } else if (message.method === 'turn/start') {
    turn = message; stdin = message.params.input.map(item => item.text ?? '').join('');
    if (stdin.includes('DELAY_TURN_START')) { sequence.push('start-requested'); writeFileSync(completionMarkerPath, 'starting\\n'); capture(); return; }
    send({ jsonrpc: '2.0', id: message.id, result: { turn: { id: turnId, status: 'inProgress' } } });
    send({ method: 'turn/started', params: { threadId, turn: { id: turnId, status: 'inProgress' } } });
    void runTurn(stdin).catch(error => { console.error(error); process.exit(1); });
    return;
  } else if (message.method === 'turn/interrupt') {
    sequence.push('interrupt');
    send({ jsonrpc: '2.0', id: message.id, result: {} });
    if (turn && !completed && !stdin.includes('DELAY_TURN_START')) {
      await new Promise(resolve => setImmediate(resolve));
      sequence.push('terminal:interrupted'); completed = true;
      send({ method: 'turn/completed', params: { threadId, turn: { id: turnId, status: 'interrupted' } } });
    }
    capture();
    return;
  } else {
    send({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }); return;
  }
  if (message.method === 'config/read' || message.method === 'permissionProfile/list') {
    preflight.requests.push({ method: message.method, cwd: message.params?.cwd });
    writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
  }
  send({ jsonrpc: '2.0', id: message.id, result });
}
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => {
  buffer += chunk;
  while (true) {
    const newline = buffer.indexOf('\\n'); if (newline < 0) return;
    const line = buffer.slice(0, newline).trim(); buffer = buffer.slice(newline + 1);
    if (line) void handle(JSON.parse(line)).catch(error => { console.error(error); process.exit(1); });
  }
});
process.stdin.on('end', async () => {
  sequence.push('eof');
  if (thread) {
    if (stdin.includes('COMPLETE_THEN_FLUSH') || stdin.includes('BLOCK_AFTER_START') || stdin.includes('DELAY_TURN_START')) await new Promise(resolve => setTimeout(resolve, 100));
    sequence.push('flushed');
    writeFileSync(completionMarkerPath, 'flushed\\n'); capture();
  }
  process.exit(0);
});
`,
  );
  await chmod(scriptPath, 0o755);
  process.env.FAKE_CODEX_MARKER = markerPath;
  return {
    root,
    markerPath,
    preflightMarkerPath,
    completionMarkerPath,
    executablePath: scriptPath,
  };
}
