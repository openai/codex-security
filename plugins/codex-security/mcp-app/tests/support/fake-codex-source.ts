import path from "node:path";
import { jsonLineInputSource } from "./json-line-input-source.ts";

export function fakeCodexSource(
  preflightProfile: unknown,
  preflightAllowed: boolean,
  accountResult: unknown,
  preflightMarkerPath: string,
): string {
  return `#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
const preflightProfile = process.env.FAKE_CODEX_PREFLIGHT_PROFILE ? JSON.parse(process.env.FAKE_CODEX_PREFLIGHT_PROFILE) : ${JSON.stringify(preflightProfile)};
const preflightAllowed = ${JSON.stringify(preflightAllowed)};
const accountResult = ${JSON.stringify(accountResult)};
const preflightMarkerPath = process.env.FAKE_CODEX_PREFLIGHT_MARKER ?? ${JSON.stringify(preflightMarkerPath)};
const temporaryEnvironment = Object.fromEntries(['TEMP', 'TMP'].map(name => [name, process.env[name]]));
if (process.argv.includes('app-server')) {
  const preflight = { argv: process.argv.slice(2), configPath: process.env.CODEX_SECURITY_CONFIG_PATH, stateDirectory: process.env.CODEX_SECURITY_STATE_DIR, temporaryEnvironment, runnerTrackingId: process.env.RUNNER_TRACKING_ID, libraryPath: process.env.LD_LIBRARY_PATH, cwd: process.cwd(), codexHome: process.env.CODEX_HOME, providerKey: process.env.SYNTHETIC_GATEWAY_KEY, providerHeader: process.env.SYNTHETIC_HEADER_VALUE, cacheDirectory: process.env.XDG_CACHE_HOME, gitEnvironment: Object.fromEntries(['PATH', 'HOME', 'NODE_OPTIONS', 'NODE_DEBUG', 'NODE_EXTRA_CA_CERTS', 'CODEX_MCP_NODE_PATH', 'CODEX_SECURITY_GIT', 'GIT_SSH_COMMAND', 'GIT_CONFIG_GLOBAL'].map(name => [name, process.env[name]])), requests: [] };
  writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
${jsonLineInputSource(`      if (message.method === 'initialized') continue;
      if (message.method === 'config/read' || message.method === 'permissionProfile/list') {
        preflight.requests.push({ method: message.method, cwd: message.params?.cwd });
        writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
      }
      let result;
      if (message.method === 'initialize') {
        result = { userAgent: 'fixture', codexHome: '/fixture', platformFamily: 'unix', platformOs: 'macos' };
      } else if (message.method === 'thread/read') {
        preflight.requests.push({ method: message.method, threadId: message.params.threadId });
        writeFileSync(preflightMarkerPath, JSON.stringify(preflight));
        const failOncePath = join(process.env.CODEX_HOME, message.params.threadId + '.read-fails-once');
        if (existsSync(failOncePath)) {
          unlinkSync(failOncePath);
          process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32603, message: 'synthetic parent read temporary failure' } }) + '\\n');
          continue;
        }
        result = { thread: { id: message.params.threadId, path: join(process.env.CODEX_HOME, message.params.threadId + '.jsonl') } };
      } else if (message.method === 'config/read') {
        result = { config: { default_permissions: 'codex_security_deep_scan_worker', permissions: { codex_security_deep_scan_worker: preflightProfile } }, origins: {}, layers: null };
      } else if (message.method === 'permissionProfile/list') {
        result = { data: [{ id: 'codex_security_deep_scan_worker', description: null, allowed: preflightAllowed }], nextCursor: null };
      } else if (message.method === 'account/read') {
        result = accountResult;
      } else if (message.method === 'configRequirements/read') {
        result = { requirements: { allowedPermissionProfiles: { existing_profile: true } } };
      } else {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'Method not found' } }) + '\\n');
        continue;
      }
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result }) + '\\n');`)}
  process.stdin.on('end', () => process.exit(0));
} else {
const stdin = (await process.stdin.toArray()).join('');
let scopeInput;
{
  const { parse } = await import(${JSON.stringify(import.meta.resolve("smol-toml"))});
  const configuration = process.argv.flatMap((arg, index) => arg === '--config' || arg === '-c' ? [parse(process.argv[index + 1])] : []).findLast(value => value.mcp_servers?.cs_artifacts);
  const file = configuration?.mcp_servers.cs_artifacts.env.CODEX_SECURITY_INCLUDE_PATHS_FILE;
  if (file) scopeInput = { file, ...JSON.parse(readFileSync(file, 'utf8')) };
}

const profileIndex = process.argv.indexOf('--profile');
const profileContents = profileIndex === -1 ? undefined : readFileSync(join(process.env.CODEX_HOME, process.argv[profileIndex + 1] + '.config.toml'), 'utf8');
const openaiAuthentication = stdin.includes('CAPTURE_SYNTHETIC_OPENAI_AUTH') ? { OPENAI_API_KEY: process.env.OPENAI_API_KEY, CODEX_API_KEY: process.env.CODEX_API_KEY } : undefined;
const bedrockAuthentication = stdin.includes('CAPTURE_SYNTHETIC_BEDROCK_AUTH') ? Object.fromEntries(JSON.parse(process.env.FAKE_CODEX_BEDROCK_ENV_KEYS).map((name) => [name, process.env[name]])) : undefined;
const runtimeEnvironment = Object.fromEntries(['PATH', 'HOME', 'PYTHON', 'PYTHONUTF8', 'CODEX_MCP_NODE_PATH', 'CODEX_BROWSER_USE_NODE_PATH', 'CODEX_ELECTRON_RESOURCES_PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH', 'CODEX_SECURITY_STATE_DIR', 'RUNNER_TRACKING_ID'].map(name => [name, process.env[name]]));
const toolProbe = stdin.includes('CAPTURE_SYNTHETIC_RG') ? spawnSync('rg', ['--version'], { encoding: 'utf8' }) : undefined;
if (toolProbe && toolProbe.status !== 0) throw toolProbe.error ?? new Error(toolProbe.stderr);
const pythonProbe = stdin.includes('CAPTURE_SYNTHETIC_PYTHON') ? spawnSync(process.env.PYTHON, ['-I', '-c', 'import json,os,sys; print(json.dumps([sys.prefix,os.environ.get("LD_LIBRARY_PATH")]))'], { encoding: 'utf8' }) : undefined;
if (pythonProbe && pythonProbe.status !== 0) throw new Error(pythonProbe.stderr || String(pythonProbe.error));
const pythonRuntime = pythonProbe ? JSON.parse(pythonProbe.stdout) : undefined;
const knowledgePath = stdin.includes('synthetic worker configuration fixture') ? process.env.CODEX_SECURITY_KNOWLEDGE_BASE : undefined;
const knowledgeDocuments = knowledgePath === undefined ? undefined : Object.fromEntries(readdirSync(knowledgePath).map(name => [name, readFileSync(join(knowledgePath, name), 'utf8')]));
const deepConfig = process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH ? readFileSync(process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH, 'utf8') : undefined;
writeFileSync(process.env.FAKE_CODEX_MARKER, JSON.stringify({ ...(scopeInput === undefined ? {} : { scopeInput }), argv: process.argv.slice(2), stdin, cwd: process.cwd(), knowledgePath, knowledgeDocuments, deepConfig, codexHome: process.env.CODEX_HOME, temporaryEnvironment, cacheDirectory: process.env.XDG_CACHE_HOME, gitEnvironment: Object.fromEntries(['PATH', 'HOME', 'NODE_OPTIONS', 'NODE_DEBUG', 'NODE_EXTRA_CA_CERTS', 'CODEX_MCP_NODE_PATH', 'CODEX_SECURITY_GIT', 'GIT_SSH_COMMAND', 'GIT_CONFIG_GLOBAL'].map(name => [name, process.env[name]])), configPath: process.env.CODEX_SECURITY_CONFIG_PATH, deepConfigPath: process.env.CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH, python: process.env.PYTHON, mcpNodePath: process.env.CODEX_MCP_NODE_PATH, bundledTool: toolProbe?.stdout.trim(), pythonPrefix: pythonRuntime?.[0], pythonLibraryPath: pythonRuntime?.[1], runtimeEnvironment, providerKey: process.env.SYNTHETIC_GATEWAY_KEY, providerHeader: process.env.SYNTHETIC_HEADER_VALUE, originator: process.env.CODEX_INTERNAL_ORIGINATOR_OVERRIDE, ...(profileContents === undefined ? {} : { profileContents }), ...(stdin.includes('COMPLETE_THEN_HANG') ? { pid: process.pid } : {}), ...(openaiAuthentication ? { openaiAuthentication } : {}), ...(bedrockAuthentication ? { bedrockAuthentication } : {}) }));
if (stdin.includes('COMPLETE_THEN_HANG')) process.on('SIGTERM', () => { if (!stdin.includes('IGNORE_TERMINATION')) setTimeout(() => process.exit(0), 100); });

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
const resumeIndex = process.argv.indexOf('resume');
const threadId = resumeIndex === -1 ? 'fixture-thread-id' : process.argv[resumeIndex + 1];
console.log(JSON.stringify({ type: 'thread.started', thread_id: threadId }));
if (stdin.includes('IPC_DIAGNOSTIC_EVENT')) console.log(stdin.split('\\n')[1]);
if (process.env.FAKE_CODEX_ARTIFACT_EVENT) console.log(process.env.FAKE_CODEX_ARTIFACT_EVENT);
if (stdin.includes('MALFORMED_COMMAND_EVENT')) {
  const output = JSON.parse(stdin.split('\\n')[1]);
  const event = { type: 'item.completed', item: { id: 'fixture-command', type: 'command_execution', command: 'cat example.ts', aggregated_output: output, exit_code: 0, status: 'completed' } };
  console.log(JSON.stringify(event).slice(0, -1));
  process.exit(0);
}
const permissionProfileFallbackWarning = 'Configured value for \`permission_profile\` is disallowed by requirements; falling back from \`codex_security_deep_scan_worker\` to required value \`:read-only\`.';
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_ITEM')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'warning-1', type: 'error', message: permissionProfileFallbackWarning } }));
if (stdin.includes('PERMISSION_PROFILE_FALLBACK_EVENT')) console.log(JSON.stringify({ type: 'error', message: permissionProfileFallbackWarning }));
if (stdin.includes('BLOCK_AFTER_START')) await new Promise(() => {});
if (stdin.includes('FAIL_THEN_HANG')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'fixture worker failed' } })); setInterval(() => {}, 1_000); await new Promise(() => {}); }
if (stdin.includes('RATE_LIMIT_CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: '429 Too Many Requests: Request blocked by cyberPolicy.' } })); process.exit(0); }
if (stdin.includes('CYBER_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by cyberPolicy.' } })); process.exit(0); }
if (stdin.includes('SAFETY_POLICY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'Request blocked by a safety policy violation.' } })); process.exit(0); }
if (stdin.includes('UPSTREAM_CYBERSECURITY_RISK_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This request has been flagged for possible cybersecurity risk.' } })); process.exit(0); }
if (stdin.includes('UPSTREAM_HIGH_RISK_CYBER_ACTIVITY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This request has been flagged for potentially high-risk cyber activity.' } })); process.exit(0); }
if (stdin.includes('CYBERSECURITY_RISK_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for possible cybersecurity risk.' } })); process.exit(0); }
if (stdin.includes('HIGH_RISK_CYBER_ACTIVITY_ERROR')) { console.log(JSON.stringify({ type: 'turn.failed', error: { message: 'This content was flagged for potentially high-risk cyber activity.' } })); process.exit(0); }
if (stdin.includes('RETRYABLE_STREAM_ERROR')) console.log(JSON.stringify({ type: 'error', message: 'Reconnecting... 2/5 (stream disconnected before completion: websocket closed by server before response.completed)' }));
if (stdin.includes('INCOMPLETE_STREAM')) { console.log(JSON.stringify({ type: 'error', message: 'fixture stream interrupted' })); process.exit(0); }
if (stdin.includes('BWRAP_NAMESPACE_FAILURE')) console.log(JSON.stringify({ type: 'item.completed', item: { id: 'command-1', type: 'command_execution', command: 'super-secret-command', aggregated_output: 'private source text\\nbwrap: Creating new namespace failed: nesting depth or /proc/sys/user/max_user_namespaces exceeded (ENOSPC)', exit_code: 1, status: 'failed' } }));
if (stdin.includes('ARTIFACT_TOOL_')) {
  const server = stdin.includes('FOREIGN_ARTIFACT_TOOL_') ? 'untrusted_server' : stdin.includes('LEGACY_OWNED_ARTIFACT_TOOL_') ? 'codex_security_artifacts' : 'cs_artifacts';
  const tool = stdin.includes('ADDITIONAL_OWNED_ARTIFACT_TOOL_') ? 'additional_codex_security_worker_tool' : stdin.includes('DISCOVERY_OWNED_ARTIFACT_TOOL_') ? 'record_codex_security_discovery_candidates' : 'record_codex_security_deep_reduction';
  const item = { id: 'mcp-1', type: 'mcp_tool_call', server, tool, arguments: { secret: 'Bearer synthetic-secret', source: 'private source text' }, result: stdin.includes('REJECTED') ? { content: [{ type: 'text', text: 'private output sk-proj-synthetic-secret' }] } : null, error: stdin.includes('TRANSPORT_FAILED') ? { message: '--provider-error transport closed sk-proj-synthetic-secret /private/customer/path' } : null, status: 'failed' };
  console.log(JSON.stringify({ type: 'item.completed', item }));
}
console.log(JSON.stringify({ type: 'item.completed', item: { id: 'message-1', type: 'agent_message', text: 'fixture final response' } }));
console.log(JSON.stringify({ type: 'turn.completed', usage: stdin.includes('NULL_USAGE') ? null : { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
if (stdin.includes('COMPLETE_THEN_HANG')) { setInterval(() => {}, 1_000); await new Promise(() => {}); }
}
`;
}

export function workerGitEnvironment(root: string) {
  return {
    NODE_OPTIONS: "--no-warnings",
    NODE_DEBUG: "synthetic-ambient-debug",
    NODE_EXTRA_CA_CERTS: path.join(root, "ambient-ca.pem"),
    CODEX_MCP_NODE_PATH: path.join(root, "inherited node"),
    HOME: path.join(root, "inherited home"),
    PATH: [path.join(root, "selected tools"), "../selected tools", ""].join(
      path.delimiter,
    ),
    CODEX_SECURITY_GIT: path.join(root, "selected tools", "git"),
    GIT_SSH_COMMAND: "synthetic-ssh --fixture",
    GIT_CONFIG_GLOBAL: path.join(root, "operator.gitconfig"),
  };
}

export function workerScanEnvironment(root: string, index: number) {
  return {
    HOME: path.join(root, `scan home ${index}`),
    PATH: path.join(root, `scan tools ${index}`),
    NODE_OPTIONS: `--stack-trace-limit=${20 + index}`,
    NODE_DEBUG: `synthetic-scan-debug-${index}`,
    NODE_EXTRA_CA_CERTS: path.join(root, `scan-ca-${index}.pem`),
    CODEX_MCP_NODE_PATH: path.join(root, `scan node ${index}`),
  };
}

export const expectedGitEnvironment = (
  gitEnvironment: ReturnType<typeof workerGitEnvironment>,
  nodePath: string,
  environment?: ReturnType<typeof workerScanEnvironment>,
) => ({
  ...gitEnvironment,
  CODEX_MCP_NODE_PATH: nodePath,
  ...(environment === undefined
    ? {}
    : {
        HOME: environment.HOME,
        PATH: environment.PATH,
        NODE_OPTIONS: environment.NODE_OPTIONS,
        NODE_DEBUG: environment.NODE_DEBUG,
        NODE_EXTRA_CA_CERTS: environment.NODE_EXTRA_CA_CERTS,
        CODEX_MCP_NODE_PATH: environment.CODEX_MCP_NODE_PATH,
      }),
});

export function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

export function nativeConfigOverrides(args: readonly string[]) {
  return args.flatMap((arg, index) =>
    arg === "--config" || arg === "-c" ? [args[index + 1]] : [],
  );
}
