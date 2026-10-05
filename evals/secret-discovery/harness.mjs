import { createHash } from "node:crypto";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createFixture, writeFixture } from "./fixtures.mjs";
import { gradeResult } from "./grade.mjs";
import {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  bundledCodexSdkEnvironment,
  deepScanPermissionProfileFallbackError,
  executablePathForSpawn,
  inlineToml,
  preflightDeepScanWorkerPermissionProfile,
} from "./runtime.mjs";

const pluginRoot = fileURLToPath(
  new URL("../../plugins/codex-security/", import.meta.url),
);
const text = { type: "string" };
const array = (items) => ({ type: "array", items });
const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const summary = object({ summary: text });
const location = object({
  path: text,
  startLine: { type: "integer" },
  endLine: { type: ["integer", "null"] },
  role: text,
});

// A compact projection of the production semantic draft, with no case labels.
export const outputSchema = object({
  threatModel: object({
    summary: text,
    assets: array(text),
    trustBoundaries: array(text),
    attackerCapabilities: array(text),
    securityObjectives: array(text),
    assumptions: array(text),
  }),
  findings: array(
    object({
      ruleId: text,
      title: text,
      summary: text,
      taxonomy: object({ category: text, cwe: array(text) }),
      severity: object({
        level: { enum: ["critical", "high", "medium", "low"] },
        rationale: text,
      }),
      confidence: object({
        level: { enum: ["high", "medium", "low"] },
        rationale: text,
      }),
      locations: array(location),
      rootCause: summary,
      validation: summary,
      attackPath: object({ dataflow: summary, reachability: summary }),
      codeEvidence: array(
        object({
          id: text,
          label: text,
          path: text,
          startLine: { type: "integer" },
          code: text,
          explanation: text,
        }),
      ),
      remediation: text,
    }),
  ),
  coverage: object({
    completeness: { enum: ["complete", "partial", "unknown"] },
    surfaces: array(
      object({
        label: text,
        disposition: {
          enum: [
            "reported",
            "no_issue_found",
            "rejected",
            "not_applicable",
            "needs_follow_up",
          ],
        },
        notes: text,
      }),
    ),
    explicitExclusions: array(object({ pattern: text, reason: text })),
    deferred: array(object({ reason: text, paths: array(text) })),
    openQuestions: array(text),
  }),
});

export async function prepareEval(
  root,
  { corePromptPath = join(pluginRoot, "references/core-scan.md") } = {},
) {
  const repo = join(root, "repository");
  const runtime = join(root, "runtime");
  const fixture = createFixture();
  await writeFixture(repo, fixture);
  await mkdir(join(runtime, "references"), { recursive: true });
  const core = await readFile(corePromptPath, "utf8");
  await writeFile(join(runtime, "references/core-scan.md"), core);
  for (const name of ["threat-model.md", "finding-detail-fields.md"]) {
    await cp(
      join(pluginRoot, "references", name),
      join(runtime, "references", name),
    );
  }
  for (const name of ["schemas", "examples/completed-scan"]) {
    await cp(join(pluginRoot, name), join(runtime, name), { recursive: true });
  }
  const prompt = [
    "Perform a complete static security audit of the repository below.",
    `Repository and authorized scope: ${repo}, all current files.`,
    `Plugin reference directory: ${runtime}. Bare reference filenames are relative to ${join(runtime, "references")}.`,
    "Applicable inherited SECURITY.md guidance: none; the caller checked the authorized scope and its ancestors.",
    "User security context: none. Supplied threat model: none. Knowledge base: none.",
    "Subagent allowance: 0. Perform the core workflow sequentially, including its baseline audit and final validation.",
    "This caller has no scan tools. Return the final semantic result as JSON matching the provided output schema; do not write artifacts.",
    "Follow the production core workflow below. Inspect source with offline read-only tools; do not execute application code or contact services.",
    core,
  ].join("\n\n");
  return {
    repo,
    runtime,
    fixture,
    prompt,
    promptSha256: createHash("sha256").update(core).digest("hex"),
  };
}

export function threadSettings(prepared, model) {
  return {
    ...(model ? { model } : {}),
    workingDirectory: prepared.repo,
    additionalDirectories: [prepared.runtime],
    skipGitRepoCheck: true,
    approvalPolicy: "never",
    modelReasoningEffort: "xhigh",
    webSearchMode: "disabled",
    // Do not set sandboxMode: --sandbox overrides the restricted named profile.
  };
}

export function codexSettings(home, codexPath, environment = process.env) {
  // Keep unrelated service credentials out of the eval process entirely.
  const inherited = new Set([
    "PATH",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "TMP",
    "TEMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TZ",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CODEX_API_KEY",
    "OPENAI_API_KEY",
  ]);
  return {
    codexPathOverride: executablePathForSpawn(codexPath),
    env: bundledCodexSdkEnvironment(codexPath, {
      ...Object.fromEntries(
        Object.entries(environment).filter(
          ([name, value]) =>
            value !== undefined && inherited.has(name.toUpperCase()),
        ),
      ),
      CODEX_HOME: home,
      CODEX_SQLITE_HOME: home,
      CODEX_CLI_PATH: codexPath,
    }),
    // Raw TOML preserves literal filesystem keys that SDK object flattening loses.
    // Everything outside the source, references, and minimal runtime is unreadable.
    configOverrides: [
      `default_permissions=${inlineToml(DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID)}`,
      "allow_login_shell=false",
      'shell_environment_policy.inherit="core"',
      "shell_environment_policy.ignore_default_excludes=false",
      "features.memories=false",
      "features.apps=false",
      "features.plugins=false",
      "features.multi_agent=false",
      "features.shell_snapshot=false",
      'approval_policy="never"',
      'model_reasoning_effort="xhigh"',
      'web_search="disabled"',
      'windows.sandbox="elevated"',
      `permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}=${inlineToml(permissionProfile(home, codexPath))}`,
    ],
  };
}

function permissionProfile(home, codexPath) {
  return {
    filesystem: {
      ":minimal": "read",
      ":workspace_roots": "read",
      [dirname(dirname(codexPath))]: { ".": "read" },
      [resolve(home)]: { ".": "deny" },
    },
    network: { enabled: false },
  };
}

export async function preflightEval(prepared, settings, signal) {
  const openAiApiKey = environmentEntry(settings.env, "OPENAI_API_KEY")?.trim();
  const codexApiKey = environmentEntry(settings.env, "CODEX_API_KEY")?.trim();
  const { useOpenAiApiKey } = await preflightDeepScanWorkerPermissionProfile({
    codexPath: settings.codexPathOverride,
    cwd: prepared.repo,
    configOverrides: settings.configOverrides,
    env: settings.env,
    allowOpenAiApiKeyFallback: Boolean(openAiApiKey && !codexApiKey),
    expectedProfile: permissionProfile(
      settings.env.CODEX_HOME,
      settings.env.CODEX_CLI_PATH,
    ),
    signal,
  });
  return {
    ...settings,
    // Native exec reads CODEX_API_KEY; preserve native accounts before mapping the fallback.
    ...(useOpenAiApiKey ? { apiKey: openAiApiKey } : {}),
  };
}

function environmentEntry(environment, requested) {
  const exact = environment[requested];
  if (exact !== undefined || process.platform !== "win32") return exact;
  // Plain snapshots need the same case-insensitive lookup as Windows process.env.
  return Object.entries(environment).find(
    ([name]) => name.toUpperCase() === requested,
  )?.[1];
}

export async function runPreparedEval(prepared, codex, { model, signal } = {}) {
  const thread = codex.startThread(threadSettings(prepared, model));
  const controller = new AbortController();
  const combinedSignal = signal
    ? AbortSignal.any([signal, controller.signal])
    : controller.signal;
  const { events } = await thread.runStreamed(prepared.prompt, {
    outputSchema,
    signal: combinedSignal,
  });
  let finalResponse = "";
  let usage;
  let completed = false;
  let failure;
  try {
    for await (const event of events) {
      const warning =
        event.type === "error"
          ? event.message
          : event.type === "item.completed" && event.item.type === "error"
            ? event.item.message
            : undefined;
      const fallback = deepScanPermissionProfileFallbackError(warning);
      if (fallback && !failure) {
        failure = fallback;
        controller.abort(fallback);
      }
      // Drain the aborted SDK stream so its child exits before state cleanup.
      if (failure) continue;
      if (
        event.type === "item.completed" &&
        event.item.type === "agent_message"
      ) {
        finalResponse = event.item.text;
      } else if (event.type === "turn.completed") {
        completed = true;
        usage = event.usage;
      } else if (event.type === "turn.failed") {
        failure = new Error(event.error.message);
      }
    }
  } catch (error) {
    throw failure ?? error;
  }
  if (failure) throw failure;
  combinedSignal.throwIfAborted();
  if (!completed) throw new Error("Eval stream ended before turn.completed");
  const semanticResult = JSON.parse(finalResponse);
  const report = {
    requestedModel: model ?? null,
    modelSelection: model
      ? "explicit"
      : "Codex default; SDK does not expose resolved model",
    promptSha256: prepared.promptSha256,
    ...gradeResult(semanticResult, prepared.fixture, prepared.repo),
    usage,
  };
  return { report, semanticResult };
}
