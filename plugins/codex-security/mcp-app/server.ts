import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import { missingPythonHelperMessage, resolvePythonCommand } from "./src/python_command.js";
import type { ScanResults } from "./src/types.js";
import { MCP_APP_VERSION } from "./src/version.js";
import {
  handoffClaimTokenSchema,
  recoveryHandoffClaimTokenSchema,
  registerScanHandoffTools
} from "./src/server/handoff-tools.js";
import { registerCompactArtifactTools } from "./src/server/compact-artifact-tools.js";
import { createScanArtifactContext } from "./src/artifact-context.js";
import { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.js";
import {
  DeepScanCoordinatorRegistry,
  DeepScanStartLock,
  startOrJoinDeepScanCoordinator
} from "./src/deep-scan/registry.js";
import { CodexSdkWorkerExecutor } from "./src/deep-scan/executor.js";
import {
  CODEX_SANDBOX_STATE_META_CAPABILITY,
  resolveDeepWorkerParentSandbox,
  type DeepWorkerParentSandbox
} from "./src/deep-scan/parent-sandbox.js";
import { WorkbenchDeepScanStore } from "./src/deep-scan/store.js";
import type { DeepScanRunState } from "./src/deep-scan/types.js";

const execFileAsync = promisify(execFile);
const CONFIGURED_SCAN_ROOT = process.env.CODEX_SECURITY_SCAN_ROOT?.trim();
const CONFIGURED_WORKBENCH_STATE_DIR = process.env.CODEX_SECURITY_STATE_DIR?.trim();
const PLUGIN_ROOT = resolve(__dirname, "..");
const USER_INPUT_WAIT_TIMEOUT_MS = 14 * 60 * 1000;
const WORKBENCH_COMMANDS_WITHOUT_DATABASE = new Set(["inspect-target", "inspect-setup"]);

type JsonObject = Record<string, unknown>;

let defaultScanRoot: Promise<string> | undefined;
let fallbackWorkbenchStateDir: Promise<string> | undefined;
let fallbackWorkbenchStateLogged = false;
let persistentWorkbenchStateSucceeded = false;
let workbenchStateSelectionTail: Promise<void> = Promise.resolve();

const userContextSchema = z.string().trim().min(1);
const editableUserContextSchema = z.string().trim();

function scanRoot(): Promise<string> {
  if (CONFIGURED_SCAN_ROOT) return Promise.resolve(CONFIGURED_SCAN_ROOT);
  // Agent turns can write OS temporary directories but cannot write protected Codex state.
  defaultScanRoot ??= fs.mkdtemp(join(tmpdir(), "codex-security-scans-"));
  return defaultScanRoot;
}

interface WorkspaceState extends JsonObject {
  id: string;
  results?: ScanResults & JsonObject;
  setup: {
    submitted: boolean;
  };
}

const diffTargetSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("working_tree"),
    baseRevision: z.string().trim().min(1).max(512).optional(),
    contentDigest: z.string().trim().min(1).max(128).optional(),
    headRevision: z.string().trim().min(1).max(512).optional()
  }).strict(),
  z.object({
    kind: z.literal("commit"),
    baseRevision: z.string().trim().min(1).max(512).optional(),
    headRevision: z.string().trim().min(1).max(512)
  }).strict(),
  z.object({
    kind: z.literal("range"),
    baseRevision: z.string().trim().min(1).max(512),
    headRevision: z.string().trim().min(1).max(512)
  }).strict()
]);
const currentScanPreflightCheckSchema = z.object({
  capability: z.string().trim().min(1).max(128),
  reason: z.string().trim().min(1).max(1200),
  severity: z.enum(["block", "warn", "suggest"]),
  status: z.enum(["pass", "fail", "unknown"])
}).strict();
const openSchema = {
  diffTarget: diffTargetSchema.optional().describe("Exact local Git revisions for Review changes mode."),
  mode: z.enum(["diff", "standard", "deep"]).optional().describe("Initial scan mode inferred from the user's request."),
  scope: z.string().trim().min(1).max(4096).optional().describe("Optional directory inside targetPath. Use '.' or omit it for the whole target. Target-relative paths are preferred; absolute paths inside targetPath are normalized."),
  sessionId: z.string().uuid().optional().describe("Existing workspace ID to reopen without changing its setup. When provided, omit all other fields."),
  targetPath: z.string().trim().min(1).max(4096).optional().describe("Optional resolved local target path."),
  targetSummary: z.string().trim().min(1).max(2400).optional().describe("Optional bounded target/security context."),
  targetTitle: z.string().trim().min(1).max(200).optional().describe("Optional human-readable target name."),
  userContext: userContextSchema.optional().describe("Optional security focus supplied by the user.")
};
const sessionSchema = { sessionId: z.string().uuid() };
const startScanSchema = {
  ...sessionSchema,
  model: z.string().trim().min(1).max(200).optional(),
  reasoningEffort: z.string().trim().min(1).max(32).optional()
};
const startPromptOnlyScanSchema = {
  diffTarget: diffTargetSchema.optional().describe("Exact local Git revisions for Review changes mode."),
  mode: z.enum(["diff", "standard"]).describe("Prompt-driven scan mode. Deep Scan uses start_codex_security_deep_scan instead."),
  scope: z.string().trim().min(1).max(4096).describe("Directory inside targetPath. Use '.' for the whole target."),
  targetPath: z.string().trim().min(1).max(4096).describe("Resolved local target path."),
  targetSummary: z.string().trim().min(1).max(2400).optional().describe("Optional bounded target or change-set context."),
  userContext: userContextSchema.optional().describe("Optional security focus supplied by the user.")
};
const startHeadlessStandardScanSchema = {
  targetPath: z.string().trim().min(1).max(4096).describe("Resolved local target path."),
  scope: z.string().trim().min(1).max(4096).optional().describe("Optional directory inside targetPath. Omit it or use '.' for the whole target."),
  targetSummary: z.string().trim().max(2400).optional().describe("Optional bounded target context."),
  userContext: editableUserContextSchema.optional().describe("Optional security focus supplied by the user.")
};
type PromptOnlyScanInput = {
  diffTarget?: z.output<typeof diffTargetSchema>;
  mode: "diff" | "standard";
  scope: string;
  targetPath: string;
  targetSummary?: string;
  userContext?: string;
};
const userInputOptionSchema = z.object({
  description: z.string().trim().min(1).max(1200),
  label: z.string().trim().min(1).max(200)
}).strict();
const userInputQuestionSchema = z.object({
  header: z.string().trim().min(1).max(64),
  id: z.string().regex(
    /^[a-z][a-z0-9_]{0,63}$/,
    "Question IDs must use snake_case and start with a lowercase letter."
  ).refine(
    (id) => !["constructor", "prototype"].includes(id),
    "Question IDs must not use reserved object property names."
  ),
  options: z.array(userInputOptionSchema).min(2).max(3),
  question: z.string().trim().min(1).max(1200)
}).strict().superRefine((question, context) => {
  const labels = new Set<string>();
  for (const [index, option] of question.options.entries()) {
    if (labels.has(option.label)) {
      context.addIssue({
        code: "custom",
        message: "Option labels must be unique within a question.",
        path: ["options", index, "label"]
      });
    }
    labels.add(option.label);
  }
});
const userInputQuestionsSchema = z.array(userInputQuestionSchema).min(1).max(3).superRefine(
  (questions, context) => {
    const ids = new Set<string>();
    for (const [index, question] of questions.entries()) {
      if (ids.has(question.id)) {
        context.addIssue({
          code: "custom",
          message: "Question IDs must be unique.",
          path: [index, "id"]
        });
      }
      ids.add(question.id);
    }
  }
);
const requestUserInputSchema = {
  questions: userInputQuestionsSchema.describe(
    "One to three non-sensitive multiple-choice questions for an interactive Codex Security workflow."
  )
};
const targetInspectionSchema = {
  targetPath: z.string().trim().min(1).max(4096)
};
const submissionSchema = {
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: z.string().trim().min(1).max(4096),
  sessionId: z.string().uuid(),
  targetPath: z.string().trim().min(1).max(4096),
  targetSummary: z.string().trim().max(2400).optional(),
  userContext: editableUserContextSchema.optional()
};
const setupInspectionSchema = {
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: z.string().trim().min(1).max(4096),
  targetPath: z.string().trim().min(1).max(4096)
};
const scanSchema = { scanId: z.string().uuid() };
const startDeepScanSchema = {
  scanId: z.string().uuid().optional()
    .describe("Existing app-created or previously returned Deep Scan ID."),
  targetPath: z.string().trim().min(1).max(4096).optional()
    .describe("Resolved local target path for a first terminal or headless Deep Scan call."),
  scope: z.string().trim().min(1).max(4096).optional()
    .describe("Scope inside targetPath. Deep Scan currently requires the whole target."),
  userContext: editableUserContextSchema.optional()
    .describe("Optional security focus supplied by the user."),
  handoffClaimToken: handoffClaimTokenSchema.optional()
    .describe("Existing Deep Scan continuation claim. Pass the same token on every scanId resume, including after an MCP server restart.")
};
const continuationMutationClaimSchema = {
  handoffClaimToken: handoffClaimTokenSchema.optional().describe("Opaque continuation token returned by the native launcher. Pass it on every progress, completion, or failure update after a resume.")
};
const scanContextUpdateSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema,
  userContext: editableUserContextSchema.describe("Complete replacement context for the running scan. Pass an empty string to clear it.")
};
const appScanContextUpdateSchema = {
  ...scanSchema,
  userContext: editableUserContextSchema
};
const phaseProgressUnitSchema = z.enum([
  "checks",
  "threat_surfaces",
  "review_receipts",
  "candidate_findings",
  "validated_findings",
  "report_artifacts"
]);
const progressSchema = {
  deepReviewPass: z.number().int().positive().optional()
    .describe("Current Deep Scan discovery pass. Send it when starting each pass together with that pass's total and zero completed items."),
  phase: z.enum(["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"])
    .optional()
    .describe("Current workflow phase. Send it immediately when the scan enters a new phase so persisted progress advances."),
  phaseItemsCompleted: z.number().int().nonnegative().optional()
    .describe("Completed authoritative coverage, receipts, or artifacts for the current phase. Increase it only after the corresponding work product exists."),
  phaseItemsTotal: z.number().int().nonnegative().optional()
    .describe("Expected authoritative coverage, receipts, or artifacts for the current phase. Increase it before newly discovered work begins."),
  phaseProgressUnit: phaseProgressUnitSchema.optional()
    .describe("What phaseItemsTotal and phaseItemsCompleted count for the current phase."),
  preflightChecks: z.array(currentScanPreflightCheckSchema).max(32).optional()
    .describe("Current standard or diff scan preflight results. Project every helper results entry to capability, reason, severity, and status only. The server derives the item counts and visible block/warn attention items."),
  reportableFindingsCount: z.number().int().nonnegative().optional(),
  reviewItemsCompleted: z.number().int().nonnegative().optional()
    .describe("Cumulative completed reviews or coverage surfaces in the current discovery pass. Increment only after the corresponding review is complete."),
  reviewItemsTotal: z.number().int().nonnegative().optional()
    .describe("Expected reviews or coverage surfaces in the current discovery pass. Increase it before assigning newly discovered work."),
  scanId: z.string().uuid(),
  ...continuationMutationClaimSchema
};
const failSchema = {
  ...continuationMutationClaimSchema,
  message: z.string().trim().min(1).max(2400),
  scanId: z.string().uuid()
};
const completeScanSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema
};
const occurrenceIdSchema = z.string().trim().min(1).max(256);
const scanReadSchema = {
  ...scanSchema,
  occurrenceId: occurrenceIdSchema.optional().describe("Optional finding occurrence to include even when it is outside the bounded findings prefix.")
};
const scanContextSchema = {
  ...scanReadSchema,
  handoffClaimToken: handoffClaimTokenSchema.optional().describe("Opaque delivery token returned by the native scan launcher. Pass it once so Codex can acknowledge that this continuation received the scan.")
};
const findingTriageSchema = {
  closeReason: z.enum(["already_fixed", "wont_fix", "false_positive"]).optional(),
  note: z.string().trim().max(2400).optional(),
  occurrenceId: occurrenceIdSchema,
  status: z.enum(["open", "closed"])
};
const findingRemediationSchema = {
  actionToken: z.string().uuid(),
  baseRevision: z.string().trim().min(1).max(512).optional(),
  expectedVersion: z.number().int().positive(),
  occurrenceId: occurrenceIdSchema,
  patchDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/).optional(),
  patchPath: z.string().trim().min(1).max(4096).optional(),
  requestId: z.string().uuid(),
  state: z.enum(["generated", "applied", "verifying", "verified", "failed"]),
  summary: z.string().trim().max(2400).optional(),
  verificationSummary: z.string().trim().max(2400).optional()
};
const findingRemediationRequestSchema = {
  actionToken: z.string().uuid(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingRemediationActionRequestSchema = {
  action: z.enum(["apply", "verify"]),
  actionToken: z.string().uuid(),
  expectedVersion: z.number().int().positive(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingRemediationClaimSchema = {
  actionToken: z.string().uuid(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid()
};
const findingsExportSchema = {
  format: z.enum(["csv", "json", "sarif"]),
  scanId: z.string().uuid()
};
const collectionPageSchema = {
  limit: z.number().int().positive().max(50).optional(),
  offset: z.number().int().nonnegative().optional()
};
const findingCollectionFiltersSchema = {
  query: z.string().trim().max(512).optional(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
  status: z.enum(["open", "closed"]).optional()
};
const targetCollectionFiltersSchema = {
  query: z.string().trim().max(512).optional(),
  targetId: z.string().trim().min(1).max(256).optional()
};
const findingsPageSchema = {
  ...collectionPageSchema,
  ...findingCollectionFiltersSchema,
  scanId: z.string().uuid()
};
const globalFindingsPageSchema = {
  ...findingCollectionFiltersSchema,
  limit: z.number().int().positive().max(20).optional(),
  offset: z.number().int().nonnegative().optional(),
  targetId: z.string().trim().min(1).max(256).optional()
};
const scanListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  mode: z.enum(["diff", "standard", "deep"]).optional(),
  status: z.enum(["running", "complete", "failed", "canceled"]).optional()
};
const repositoryListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  status: z.enum(["scanned", "not_scanned", "open_findings"]).optional()
};
export function createCodexSecurityServer(): McpServer {
  const server = new McpServer(
    { name: "codex-security", version: MCP_APP_VERSION },
    {
      capabilities: {
        experimental: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: {} },
        extensions: { "com.openai": {} },
        logging: {}
      }
    }
  );
  const deepScanCoordinators = new DeepScanCoordinatorRegistry();
  const deepScanStartLock = new DeepScanStartLock();
  const deepScanStore = new WorkbenchDeepScanStore(runWorkbench);
  const authenticatedArtifactClaims = new Map<string, {
    claimToken: string;
    threadId: string;
  }>();
  server.server.onclose = () => deepScanCoordinators.shutdown("mcp_transport_closed");
  const appMeta = { ui: { visibility: ["app"] as const } };
  const modelActionMeta = { ui: { visibility: ["model"] as const } };

  server.registerTool("start_codex_security_standard_scan", {
    title: "Start or Join Codex Security Standard Scan",
    description: "Headless and CLI only. Start or rejoin a Standard security scan. Do not use for desktop scans, Review changes, Deep Scan, or an existing SDK-owned scan. Use the returned authoritative scanId, scanDir, and handoffClaimToken throughout preflight, reporting, and completion.",
    inputSchema: startHeadlessStandardScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ targetPath, scope, targetSummary, userContext }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting a Standard scan requires the owning Codex thread context.");
    }
    const started = await startHeadlessStandardScan(
      { targetPath, scope, targetSummary, userContext },
      threadId,
      codexModelSettingsFromExtra(extra)
    );
    const scan = isJsonObject(started.scan) ? started.scan : undefined;
    const progress = isJsonObject(scan?.progress) ? scan.progress : undefined;
    const workspace = isJsonObject(started.workspace) ? started.workspace : undefined;
    const workspaceResults = isJsonObject(workspace?.results) ? workspace.results : undefined;
    const scanId = scan?.scanId;
    const scanDir = scan?.scanDir;
    const handoffClaimToken = scan?.handoffClaimToken;
    if (
      (started.startDisposition !== "created" && started.startDisposition !== "joined")
      || typeof scanId !== "string"
      || !z.string().uuid().safeParse(scanId).success
      || typeof handoffClaimToken !== "string"
      || !z.string().uuid().safeParse(handoffClaimToken).success
      || typeof scanDir !== "string"
      || !scanDir.trim()
      || scan?.mode !== "standard"
      || scan.handoffStatus !== "delivered"
      || scan.continuationThreadId !== threadId
      || progress?.status !== "running"
      || (started.startDisposition === "created" && progress.phase !== "preflight")
      || workspaceResults?.scanId !== scanId
    ) {
      return toolErrorResult(
        "Codex Security returned malformed Standard scan ownership; no headless scan can continue."
      );
    }
    authenticatedArtifactClaims.set(scanId, {
      claimToken: handoffClaimToken,
      threadId
    });
    return {
      content: [{
        type: "text" as const,
        text: `${started.startDisposition === "created" ? "Started" : "Rejoined"} Standard scan ${scanId}. When the scan is in preflight, complete security_scan preflight before reviewing the target or creating a goal. Preserve the returned handoffClaimToken for scan progress, the semantic draft, and completion.`
      }],
      structuredContent: {
        ...redactHandoffClaimToken(started),
        scanId,
        scanDir,
        handoffClaimToken
      }
    };
  });

  server.registerTool("start_codex_security_prompt_only_scan", {
    title: "Start Codex Security Prompt-Only Scan",
    description: "Start or rejoin a Standard or diff Codex Security scan from its owning conversation. Use the returned authoritative scanId and scanDir. Standard and diff scans save progress checkpoints before their final semantic draft; the workbench writes the unsealed canonical artifacts. Complete the same scan once. Deep Scan uses start_codex_security_deep_scan instead.",
    inputSchema: startPromptOnlyScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ mode, targetPath, scope, targetSummary, userContext, diffTarget }, extra) => {
    if (mode === "diff" && !diffTarget) {
      return toolErrorResult("Review changes prompt-only scans require diffTarget.");
    }
    if (mode === "standard" && diffTarget) {
      return toolErrorResult("Standard prompt-only scans must omit diffTarget.");
    }
    if (mode === "diff" && !wholeTargetScope(scope, targetPath)) {
      return toolErrorResult("Review changes prompt-only scans require the whole target; use scope '.'.");
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting a prompt-only scan requires the owning Codex thread context.");
    }
    const promptOnly = await startPromptOnlyScan(
      { mode, targetPath, scope, targetSummary, userContext, diffTarget },
      threadId,
      codexModelSettingsFromExtra(extra)
    );
    return promptOnlyScanResult(promptOnly);
  });

  server.registerTool("request_codex_security_user_input", {
    title: "Request Codex Security User Input",
    description: "Fallback for interactive Codex Security workflows when the host-native request_user_input tool is unavailable. Presents one to three non-sensitive multiple-choice questions through standard MCP form elicitation and waits for the user's response. Never call this tool in headless, automation, or other non-interactive sessions.",
    inputSchema: requestUserInputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ questions }, extra) => {
    const signal = abortSignalFromExtra(extra);
    if (!server.server.getClientCapabilities()?.elicitation?.form) {
      return userInputToolResult("unavailable");
    }
    try {
      const result = await server.server.elicitInput(
        buildUserInputElicitation(questions),
        {
          timeout: USER_INPUT_WAIT_TIMEOUT_MS,
          ...(signal ? { signal } : {})
        }
      );
      if (result.action !== "accept") {
        return userInputToolResult(result.action === "decline" ? "declined" : "cancelled");
      }
      if (!isJsonObject(result.content)) {
        throw new Error("Accepted user input did not contain structured answers.");
      }
      const answers: Record<string, string> = {};
      for (const question of questions) {
        const answer = result.content[question.id];
        if (
          typeof answer !== "string" ||
          !question.options.some((option) => option.label === answer)
        ) {
          throw new Error(`User input did not contain a valid answer for ${question.id}.`);
        }
        answers[question.id] = answer;
      }
      return userInputToolResult("accepted", answers);
    } catch (error) {
      if (signal?.aborted) throw error;
      await logUserInputFailure(server, error);
      return userInputToolResult("unavailable");
    }
  });

  server.registerTool("open_codex_security_workspace", {
    title: "Open Codex Security",
    description: "App-only. Create a native Codex Security workspace with the target and requested standard, diff, or deep mode, or reopen one owned by this thread by passing only sessionId. Scope is inside targetPath; use '.' or omit scope for the whole target.",
    inputSchema: openSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: appMeta
  }, async (input, extra) => {
    if (input.sessionId && Object.entries(input).some(([key, value]) => key !== "sessionId" && value !== undefined)) {
      throw new Error("sessionId only reopens an existing workspace; omit it to create a workspace with different setup fields.");
    }
    const mode = input.mode ?? (input.diffTarget ? "diff" : "standard");
    if (input.diffTarget && mode !== "diff") {
      throw new Error("diffTarget requires mode 'diff'.");
    }
    if ((mode === "diff" || mode === "deep") && !wholeTargetScope(input.scope, input.targetPath)) {
      throw new Error(`${mode === "deep" ? "Deep Scan" : "Review changes"} requires the whole target; use scope '.'.`);
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId && !input.sessionId) {
      return openWorkspaceResult(await createWorkspace({ ...input, mode }));
    }
    if (!threadId) {
      throw new Error("Thread metadata is required to create or reopen a Codex Security workspace.");
    }
    return openWorkspaceResult(
      input.sessionId
        ? await getWorkspace(input.sessionId, threadId)
        : await createWorkspace({ ...input, mode }, threadId)
    );
  });

  server.registerTool("inspect_codex_security_target", {
    title: "Inspect Codex Security Target",
    description: "App-only. Validate a local target directory and derive its display and Git metadata without saving setup.",
    inputSchema: targetInspectionSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ targetPath }) => {
    const target = await runWorkbench(["inspect-target", "--target-path", targetPath]);
    return {
      content: [{ type: "text" as const, text: "Validated the local Codex Security target." }],
      structuredContent: { target }
    };
  });

  server.registerTool("inspect_codex_security_setup", {
    title: "Validate Codex Security Setup",
    description: "App-only. Resolve and validate the complete local target, scope, mode, and exact Git change set without saving setup.",
    inputSchema: setupInspectionSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ targetPath, scope, mode, diffTarget }) => {
    const setup = await runWorkbench([
      "inspect-setup",
      "--target-path",
      targetPath,
      "--scope",
      scope,
      "--mode",
      mode,
      ...diffTargetArgs(diffTarget)
    ]);
    return {
      content: [{ type: "text" as const, text: "Validated the local Codex Security setup." }],
      structuredContent: { setup }
    };
  });

  server.registerTool("submit_codex_security_setup", {
    title: "Save Codex Security Setup",
    description: "App-only. Validate and save bounded target, scope, mode, and optional context selections.",
    inputSchema: submissionSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ sessionId, targetPath, scope, mode, targetSummary, userContext, diffTarget }) => {
    return workspaceResult(await runWorkbench([
      "save-workspace",
      "--workspace-id",
      sessionId,
      "--target-path",
      targetPath,
      "--scope",
      scope,
      "--mode",
      mode,
      ...definedArg("--target-summary", targetSummary),
      ...(userContext ? ["--user-context-stdin"] : []),
      ...diffTargetArgs(diffTarget)
    ], userContext) as WorkspaceState);
  });

  server.registerTool("start_codex_security_scan", {
    title: "Start Codex Security Scan",
    description: "App-only. Create a scan record and its local artifact directory before Codex analysis begins.",
    inputSchema: startScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: appMeta
  }, async ({ sessionId, model, reasoningEffort }) => {
    const workspace = await runWorkbench([
      "start-scan",
      "--workspace-id",
      sessionId,
      ...optionalArg("--model", model),
      ...optionalArg("--reasoning-effort", reasoningEffort),
      "--scan-root",
      await scanRoot()
    ]) as WorkspaceState;
    return workspaceResult(workspace);
  });

  server.registerTool("start_codex_security_deep_scan", {
    title: "Start or Join Codex Security Deep Scan",
    description: "Run or rejoin independent Standard security scans and semantically merge their validated findings. Pass scanId and its handoffClaimToken to resume, or targetPath to start headlessly. The call blocks until the aggregate draft is ready, fails, or is canceled. On success, manifestPath identifies the canonical parent scan-manifest.json; call complete_codex_security_scan once.",
    inputSchema: startDeepScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, targetPath, scope, userContext, handoffClaimToken }, extra) => {
    const hasScanId = scanId !== undefined;
    const hasTarget = targetPath !== undefined;
    const normalizedUserContext = userContext || undefined;
    if (hasScanId === hasTarget) {
      return toolErrorResult("Pass exactly one Deep Scan identity: either scanId, or targetPath for a first terminal/headless call.");
    }
    if (hasScanId && (scope !== undefined || normalizedUserContext !== undefined)) {
      return toolErrorResult("When scanId is present, omit targetPath, scope, and userContext; the persisted scan is authoritative.");
    }
    if (hasTarget && !wholeTargetScope(scope, targetPath)) {
      return toolErrorResult("Deep Scan currently requires the whole target; use scope '.'.");
    }
    if (hasTarget && handoffClaimToken !== undefined) {
      return toolErrorResult("handoffClaimToken is only valid with an existing Deep Scan ID.");
    }
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Starting or joining a Deep Scan requires the owning Codex thread context.");
    }
    const modelSettings = codexModelSettingsFromExtra(extra);
    let parentSandbox: DeepWorkerParentSandbox;
    try {
      parentSandbox = resolveDeepWorkerParentSandbox(extra);
    } catch (error: unknown) {
      return toolErrorResult(deepScanInvocationFailureMessage(error));
    }
    const preparation = await deepScanStartLock.run(async () => {
      const begun = await deepScanStore.begin({
        scanId,
        targetPath,
        scope: hasTarget ? scope ?? "." : undefined,
        userContext: normalizedUserContext,
        handoffClaimToken,
        threadId,
        ...modelSettings,
        scanRoot: await scanRoot()
      });
      if (handoffClaimToken) {
        authenticatedArtifactClaims.set(begun.run.scanId, {
          claimToken: handoffClaimToken,
          threadId
        });
      }
      const immediate = deepScanTerminalResult(begun.run);
      if (immediate) return { begun, immediate };
      const started = await startOrJoinDeepScanCoordinator({
        begin: begun,
        registry: deepScanCoordinators,
        options: {
          store: deepScanStore,
          executor: new CodexSdkWorkerExecutor({
            ...modelSettings,
            parentSandbox,
            artifactContext: {
              pluginRoot: PLUGIN_ROOT,
              scanRoot: begun.run.scanDir,
              repoRoot: begun.run.targetPath,
              scanId: begun.run.scanId,
              scope: begun.run.scope
            }
          }),
          pluginRoot: PLUGIN_ROOT,
          log: logDeepScanEvent,
          handoffClaimToken,
          threadId,
          onComplete: async (draft, signal) => {
            const context = await createScanArtifactContext(
              begun.run.scanId,
              runWorkbench,
              {
                requireRunning: true,
                requireClaim: true,
                handoffClaimToken,
                pluginRoot: PLUGIN_ROOT
              }
            );
            await recordCodexSecurityScanDraftViaWorkbench(context, {
              ...draft,
              ...(handoffClaimToken === undefined ? {} : { handoffClaimToken })
            }, runWorkbench, signal);
          },
          onStopped: async (run) => {
            await runWorkbench([
              "preserve-scan-results", "--scan-id", run.scanId,
              "--thread-id", threadId,
              ...optionalArg("--claim-token", handoffClaimToken),
              ...optionalArg("--coordinator-generation", run.coordinatorGeneration?.toString())
            ]);
          }
        }
      });
      return { begun, ...started };
    }).catch((error: unknown) => ({
      invocationFailure: toolErrorResult(deepScanInvocationFailureMessage(error))
    }));
    if ("invocationFailure" in preparation) return preparation.invocationFailure;
    if ("immediate" in preparation) return preparation.immediate;
    const { begun, coordinator, joined } = preparation;
    if (joined) {
      logDeepScanEvent({ event: "coordinator_joined", scanId: begun.run.scanId });
    }
    const terminal = await coordinator.wait(abortSignalFromExtra(extra));
    const result = deepScanTerminalResult(terminal);
    if (!result) {
      return toolErrorResult(deepScanInvocationFailureMessage(
        new Error(`Deep Scan ${terminal.scanId} ended without a terminal result.`)
      ));
    }
    return result;
  });

  const cancelSecurityScan = async (scanId: string, threadId?: string) => {
    const args = [
      "cancel-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--thread-id", threadId)
    ];
    let workspace: Awaited<ReturnType<typeof runWorkbench>> | undefined;
    if (threadId && deepScanCoordinators.get(scanId)) {
      await deepScanStore.get(scanId, threadId);
    }
    const canceledLocally = await deepScanCoordinators.cancelAndWait(
      scanId,
      "user_canceled_scan",
      async () => { workspace = await runWorkbench(args); }
    );
    if (!canceledLocally) workspace = await runWorkbench(args);
    if (workspace === undefined) {
      throw new Error(`Canceling scan ${scanId} did not return its workspace.`);
    }
    return workspaceResult(workspace as unknown as WorkspaceState);
  };

  server.registerTool("cancel_codex_security_scan", {
    title: "Cancel Codex Security Scan",
    description: "Stop a running scan from its owning Codex thread, prevent further progress or completion updates, and cancel any active deterministic Deep Scan SDK workers.",
    inputSchema: scanSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Open the scan's continuation thread and try again, or cancel it from the Codex Security workbench.");
    }
    return cancelSecurityScan(scanId, threadId);
  });

  server.registerTool("cancel_codex_security_scan_from_app", {
    title: "Cancel Codex Security Scan From App",
    description: "App-only. Stop a running scan from the native Codex Security workbench, prevent further progress or completion updates, and cancel any active deterministic Deep Scan SDK workers.",
    inputSchema: scanSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId }) => cancelSecurityScan(scanId));

  registerScanHandoffTools(server, { appMeta, runWorkbench, workspaceResult });

  server.registerTool("get_codex_security_scan", {
    title: "Get Codex Security Scan",
    description: "App-only. Read plugin-owned scan state for native Security monitoring without claiming a pending Codex handoff.",
    inputSchema: scanReadSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, occurrenceId }) => scanActionResult(
    await runWorkbench([
      "get-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--occurrence-id", occurrenceId)
    ]),
    "Loaded Codex Security scan state."
  ));

  server.registerTool("list_codex_security_scans", {
    title: "List Codex Security Scans",
    description: "App-only. Read plugin-owned scan summaries for native Security navigation and route recovery.",
    inputSchema: scanListSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, mode, offset, query, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-scans",
      ...optionalArg("--query", query),
      ...optionalArg("--target-id", targetId),
      ...optionalArg("--status", status),
      ...optionalArg("--mode", mode),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Codex Security scan summaries."
  ));

  server.registerTool("list_codex_security_global_findings", {
    title: "List Codex Security Global Findings",
    description: "App-only. Read the latest plugin-owned finding occurrence for each stable repository target and finding identity.",
    inputSchema: globalFindingsPageSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, severity, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-global-findings",
      ...optionalArg("--query", query),
      ...optionalArg("--severity", severity),
      ...optionalArg("--status", status),
      ...optionalArg("--target-id", targetId),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Codex Security global findings."
  ));

  server.registerTool("list_codex_security_repositories", {
    title: "List Codex Security Repositories",
    description: "App-only. Read plugin-owned repository summaries and their latest scan state.",
    inputSchema: repositoryListSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, status, targetId }) => scanActionResult(
    await runWorkbench([
      "list-repositories",
      ...optionalArg("--query", query),
      ...optionalArg("--target-id", targetId),
      ...optionalArg("--status", status),
      ...optionalNumberArg("--offset", offset),
      ...optionalNumberArg("--limit", limit)
    ]),
    "Loaded Codex Security repositories."
  ));

  server.registerTool("get_codex_security_scan_context", {
    title: "Get Codex Security Scan Context",
    description: "Load the authoritative target, mode, optional user context, artifact directory, live progress, and optional selected finding for a launched scan. Validated legacy finding details may be migrated.",
    inputSchema: scanContextSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, occurrenceId, handoffClaimToken }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (handoffClaimToken) {
      await runWorkbench([
        "mark-handoff-delivered",
        "--scan-id",
        scanId,
        "--claim-token",
        handoffClaimToken,
        ...optionalArg("--thread-id", threadId)
      ]);
    }
    const scanContext = await runWorkbench([
      "get-scan",
      "--scan-id",
      scanId,
      ...optionalArg("--occurrence-id", occurrenceId)
    ]);
    const scan = isJsonObject(scanContext.scan) ? scanContext.scan : undefined;
    if (!handoffClaimToken && scan?.handoffStatus === "pending") {
      const detail = typeof scan.handoffClaimToken === "string"
        ? "Pass the handoffClaimToken returned by the Codex Security scan launcher."
        : "Claim the pending Codex Security scan handoff before loading its context.";
      throw new Error(`This Codex Security scan handoff has not been delivered. ${detail}`);
    }
    if (
      handoffClaimToken
      && threadId
      && scan?.handoffStatus === "delivered"
      && scan.handoffClaimToken === handoffClaimToken
      && (
        scan.continuationThreadId === threadId
        || recoveryHandoffClaimTokenSchema.safeParse(handoffClaimToken).success
      )
    ) {
      authenticatedArtifactClaims.set(scanId, {
        claimToken: handoffClaimToken,
        threadId
      });
    }
    return scanActionResult(
      redactHandoffClaimToken(scanContext),
      "Loaded Codex Security scan context."
    );
  });

  const updateRunningScanContext = async (input: {
    claimToken?: string;
    scanId: string;
    threadId?: string;
    userContext: string;
    workspaceId?: string;
  }) => {
    const updated = await runWorkbench([
      "update-scan-context",
      "--scan-id",
      input.scanId,
      "--user-context-stdin",
      ...definedArg("--workspace-id", input.workspaceId),
      ...definedArg("--thread-id", input.threadId),
      ...optionalArg("--claim-token", input.claimToken)
    ], input.userContext);
    return scanActionResult(updated, "Updated Codex Security scan context.");
  };

  server.registerTool("update_codex_security_scan_context", {
    title: "Update Codex Security Scan Context",
    description: "Replace the context for a running scan. The next phase uses the new value; workers in the current phase keep their original context.",
    inputSchema: scanContextUpdateSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, userContext, handoffClaimToken }, extra) => {
    const threadId = threadIdFromExtra(extra);
    if (!threadId) {
      return toolErrorResult("Updating scan context requires the owning Codex thread.");
    }
    return updateRunningScanContext({
      claimToken: handoffClaimToken,
      scanId,
      threadId,
      userContext
    });
  });

  server.registerTool("update_codex_security_scan_context_from_app", {
    title: "Update Codex Security Scan Context From App",
    description: "App-only. Replace the context for the running scan attached to this workspace.",
    inputSchema: appScanContextUpdateSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, userContext }) => {
    const current = await runWorkbench(["get-scan", "--scan-id", scanId]);
    const workspace = isJsonObject(current.workspace) ? current.workspace : undefined;
    if (typeof workspace?.id !== "string") {
      return toolErrorResult("Updating scan context requires its owning workspace.");
    }
    return updateRunningScanContext({
      scanId,
      userContext,
      workspaceId: workspace.id
    });
  });

  server.registerTool("update_codex_security_scan_progress", {
    title: "Update Codex Security Scan Progress",
    description: "Record a meaningful live scan phase or coverage milestone in the Codex Security workbench.",
    inputSchema: progressSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, deepReviewPass, phase, phaseItemsTotal, phaseItemsCompleted, phaseProgressUnit, preflightChecks, reviewItemsTotal, reviewItemsCompleted, reportableFindingsCount, handoffClaimToken }, extra) => {
    const modelSettings = codexModelSettingsFromExtra(extra);
    const current = await runWorkbench(["get-scan", "--scan-id", scanId]);
    const scan = isJsonObject(current.scan) ? current.scan : undefined;
    const progress = scan && isJsonObject(scan.progress) ? scan.progress : undefined;
    if (
      progress?.status === "running"
      && typeof scan?.handoffClaimToken === "string"
      && scan.handoffClaimToken !== handoffClaimToken
    ) {
      return toolErrorResult("Scan updates are owned by another continuation.");
    }
    if (scan?.mode === "deep" && progress?.phase === "preflight" && progress.status === "running") {
      return scanActionResult(
        redactHandoffClaimToken(current),
        "Deep Scan is still preparing. Discovery progress begins after its setup worker succeeds."
      );
    }
    if (preflightChecks !== undefined && (
      phaseItemsTotal !== undefined
      || phaseItemsCompleted !== undefined
      || phaseProgressUnit !== undefined
    )) {
      throw new Error(
        "preflightChecks derives phaseItemsTotal, phaseItemsCompleted, and phaseProgressUnit; omit those fields."
      );
    }
    const preflightIssues = preflightChecks?.filter((check) =>
      (check.severity === "block" || check.severity === "warn")
      && (check.status === "fail" || check.status === "unknown")
    );
    const derivedPhaseItemsTotal = preflightChecks?.length ?? phaseItemsTotal;
    const derivedPhaseItemsCompleted = preflightChecks
      ? preflightChecks.filter((check) => check.status !== "unknown").length
      : phaseItemsCompleted;
    const derivedPhaseProgressUnit = preflightChecks ? "checks" : phaseProgressUnit;
    const serializedPreflightIssues = preflightIssues
      ? JSON.stringify(preflightIssues)
      : undefined;
    return scanActionResult(await runWorkbench([
      "update-progress",
      "--scan-id",
      scanId,
      ...(scan?.mode === "deep" ? deepScanStore.coordinatorLeaseArgs(scanId) : []),
      ...optionalArg("--model", modelSettings.model),
      ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
      ...optionalArg("--claim-token", handoffClaimToken),
      ...optionalNumberArg("--deep-review-pass", deepReviewPass),
      ...optionalArg("--phase", phase),
      ...optionalNumberArg("--phase-items-total", derivedPhaseItemsTotal),
      ...optionalNumberArg("--phase-items-completed", derivedPhaseItemsCompleted),
      ...optionalArg("--phase-progress-unit", derivedPhaseProgressUnit),
      ...(serializedPreflightIssues ? ["--preflight-issues-json-stdin"] : []),
      ...optionalNumberArg("--review-items-total", reviewItemsTotal),
      ...optionalNumberArg("--review-items-completed", reviewItemsCompleted),
      ...optionalNumberArg("--reportable-findings-count", reportableFindingsCount)
    ], serializedPreflightIssues), "Updated Codex Security scan progress.");
  });

  server.registerTool("complete_codex_security_scan", {
    title: "Complete Codex Security Scan",
    description: "Finalization only: validate and seal already-authored scan-manifest.json, findings.json, and coverage.json, generate report.md, index findings, and mark the scan complete. For an app-backed running scan, scan-manifest.json is an unsealed draft and must omit scan.sealedAt and scan.artifacts; this tool supplies the exact workbench timestamps, seal, artifact digests, and derived finding identities. Call only after those canonical files exist; this tool does not create missing artifacts or run skipped phases. If it fails, surface the exact error and stop the current response without retrying completion or returning a final, no-findings, structured, or benchmark response.",
    inputSchema: completeScanSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, handoffClaimToken }) => {
    try {
      return scanActionResult(await runWorkbench([
        "complete-scan",
        "--scan-id",
        scanId,
        ...optionalArg("--claim-token", handoffClaimToken)
      ]), "Validated and indexed the completed Codex Security scan.");
    } catch (error) {
      throw new Error(completionFailureMessage(error));
    }
  });

  server.registerTool("fail_codex_security_scan", {
    title: "Fail Codex Security Scan",
    description: "Permanently mark a launched Codex Security scan as failed only after a confirmed unrecoverable blocker. For explicit user cancellation, use cancel_codex_security_scan instead. This terminal action cannot be resumed; incomplete or otherwise resumable work must remain running.",
    inputSchema: failSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ scanId, message, handoffClaimToken }) => {
    const failed = await runWorkbench([
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      message,
      ...optionalArg("--claim-token", handoffClaimToken)
    ]);
    deepScanCoordinators.failExternallyPersisted(scanId, message);
    return scanActionResult(failed, "Recorded the Codex Security scan failure.");
  });

  server.registerTool("set_codex_security_finding_triage", {
    title: "Update Codex Security Finding Status",
    description: "App-only. Persist a completed finding's local open or closed triage status. Closed findings require one bounded close reason; reopening clears it.",
    inputSchema: findingTriageSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, status, closeReason, note }) => scanActionResult(await runWorkbench([
    "set-finding-triage",
    "--occurrence-id",
    occurrenceId,
    "--status",
    status,
    ...optionalArg("--close-reason", closeReason),
    ...definedArg("--note", note)
  ]), "Updated the local Codex Security finding status."));

  server.registerTool("request_codex_security_finding_remediation", {
    title: "Request Codex Security Finding Remediation",
    description: "App-only. Queue a completed finding for Codex remediation before sending the host a generate or regenerate request.",
    inputSchema: findingRemediationRequestSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "request-finding-remediation",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Queued the local Codex Security finding remediation request."));

  server.registerTool("request_codex_security_finding_remediation_action", {
    title: "Request Codex Security Finding Remediation Action",
    description: "App-only. Durably claim an apply or verify handoff before asking Codex to perform the local working-tree operation.",
    inputSchema: findingRemediationActionRequestSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, expectedVersion, action, actionToken }) => scanActionResult(await runWorkbench([
    "request-finding-remediation-action",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--expected-version",
    String(expectedVersion),
    "--action",
    action,
    "--action-token",
    actionToken
  ]), `Queued the local Codex Security finding remediation ${action} request.`));

  server.registerTool("claim_codex_security_finding_remediation_resend", {
    title: "Claim Codex Security Finding Remediation Resend",
    description: "App-only. Atomically take ownership of an unowned or stale remediation host request before resending it.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "claim-finding-remediation-resend",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Claimed the local Codex Security finding remediation resend."));

  server.registerTool("release_codex_security_finding_remediation_claim", {
    title: "Release Codex Security Finding Remediation Claim",
    description: "App-only. Release a locally owned remediation host request after message delivery fails.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "release-finding-remediation-claim",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Released the local Codex Security finding remediation claim."));

  server.registerTool("cancel_codex_security_finding_remediation_request", {
    title: "Cancel Codex Security Finding Remediation Request",
    description: "App-only. Roll back an owned remediation request after the user declines its host follow-up.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "cancel-finding-remediation-request",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Canceled the local Codex Security finding remediation request."));

  server.registerTool("mark_codex_security_finding_remediation_delivered", {
    title: "Mark Codex Security Finding Remediation Delivered",
    description: "App-only. Seal host-message delivery ownership before Codex starts a remediation worker.",
    inputSchema: findingRemediationClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ occurrenceId, requestId, actionToken }) => scanActionResult(await runWorkbench([
    "mark-finding-remediation-delivered",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    "--action-token",
    actionToken
  ]), "Marked the local Codex Security finding remediation request as delivered."));

  server.registerTool("set_codex_security_finding_remediation", {
    title: "Update Codex Security Finding Remediation",
    description: "Persist the bounded local remediation workflow state for a completed finding. The UI may mark a request as queued; Codex records generated, applied, verifying, verified, or failed states after performing the corresponding work.",
    inputSchema: findingRemediationSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    _meta: modelActionMeta
  }, async ({ occurrenceId, requestId, actionToken, expectedVersion, state, summary, patchPath, patchDigest, baseRevision, verificationSummary }) => scanActionResult(await runWorkbench([
    "set-finding-remediation",
    "--occurrence-id",
    occurrenceId,
    "--request-id",
    requestId,
    ...optionalArg("--action-token", actionToken),
    "--expected-version",
    String(expectedVersion),
    "--state",
    state,
    ...definedArg("--summary", summary),
    ...definedArg("--patch-path", patchPath),
    ...definedArg("--patch-digest", patchDigest),
    ...definedArg("--base-revision", baseRevision),
    ...definedArg("--verification-summary", verificationSummary)
  ]), "Updated the local Codex Security finding remediation state."));

  server.registerTool("export_codex_security_findings", {
    title: "Export Codex Security Findings",
    description: "App-only. Export retained local findings from completed, failed, or canceled scans as canonical JSON, deterministic SARIF, or a CSV projection. Exported files remain inside the sealed scan directory.",
    inputSchema: findingsExportSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, format }) => scanActionResult(await runWorkbench([
    "export-findings",
    "--scan-id",
    scanId,
    "--format",
    format
  ]), `Exported Codex Security findings as ${format.toUpperCase()}.`));

  server.registerTool("list_codex_security_findings", {
    title: "List Codex Security Findings",
    description: "App-only. Load one bounded page of indexed findings for a completed local scan, migrating validated legacy finding details when needed.",
    inputSchema: findingsPageSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ limit, offset, query, scanId, severity, status }) => scanActionResult(await runWorkbench([
    "list-findings",
    "--scan-id",
    scanId,
    ...optionalArg("--query", query),
    ...optionalArg("--severity", severity),
    ...optionalArg("--status", status),
    ...optionalNumberArg("--offset", offset),
    ...optionalNumberArg("--limit", limit)
  ]), "Loaded a local Codex Security findings page."));

  registerCompactArtifactTools(server, {
    runWorkbench,
    pluginRoot: PLUGIN_ROOT,
    resolveHandoffClaimToken: (scanId, requestContext) => {
      const claim = authenticatedArtifactClaims.get(scanId);
      return claim && claim.threadId === threadIdFromExtra(requestContext)
        ? claim.claimToken
        : undefined;
    }
  });

  return server;
}

async function createWorkspace(input: {
  diffTarget?: z.infer<typeof diffTargetSchema>;
  mode?: "diff" | "standard" | "deep";
  scope?: string;
  targetPath?: string;
  targetSummary?: string;
  targetTitle?: string;
  userContext?: string;
}, threadId?: string): Promise<WorkspaceState> {
  return await runWorkbench([
    "create-workspace",
    "--workspace-id",
    randomUUID(),
    ...optionalArg("--thread-id", threadId),
    ...optionalArg("--mode", input.mode),
    ...optionalArg("--target-path", input.targetPath),
    ...optionalArg("--target-title", input.targetTitle),
    ...optionalArg("--target-summary", input.targetSummary),
    ...optionalArg("--scope", input.scope),
    ...(input.userContext ? ["--user-context-stdin"] : []),
    ...diffTargetArgs(input.diffTarget)
  ], input.userContext) as WorkspaceState;
}

async function getWorkspace(workspaceId: string, threadId?: string): Promise<WorkspaceState> {
  return await runWorkbench([
    "get-workspace",
    "--workspace-id",
    workspaceId,
    ...optionalArg("--thread-id", threadId)
  ]) as WorkspaceState;
}

async function startPromptOnlyScan(
  input: PromptOnlyScanInput,
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {}
): Promise<JsonObject> {
  const { mode, targetPath, scope, targetSummary, userContext, diffTarget } = input;
  return await runWorkbench([
    "start-prompt-only-scan",
    "--thread-id",
    threadId,
    "--target-path",
    targetPath,
    "--scope",
    scope,
    "--mode",
    mode,
    ...optionalArg("--model", modelSettings.model),
    ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
    ...optionalArg("--target-summary", targetSummary),
    ...(userContext ? ["--user-context-stdin"] : []),
    ...diffTargetArgs(diffTarget),
    "--scan-root",
    await scanRoot()
  ], userContext);
}

async function startHeadlessStandardScan(
  input: {
    targetPath: string;
    scope?: string;
    targetSummary?: string;
    userContext?: string;
  },
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {}
): Promise<JsonObject> {
  return await runWorkbench([
    "start-headless-standard-scan",
    "--thread-id",
    threadId,
    "--target-path",
    input.targetPath,
    "--scope",
    input.scope ?? ".",
    ...optionalArg("--model", modelSettings.model),
    ...optionalArg("--reasoning-effort", modelSettings.reasoningEffort),
    ...optionalArg("--target-summary", input.targetSummary),
    ...(input.userContext ? ["--user-context-stdin"] : []),
    "--scan-root",
    await scanRoot()
  ], input.userContext);
}

function wholeTargetScope(scope: string | undefined, targetPath: string | undefined): boolean {
  if (scope === undefined || scope === ".") return true;
  return Boolean(targetPath && resolve(scope) === resolve(targetPath));
}

function openWorkspaceResult(workspace: WorkspaceState) {
  const result = workspaceResult(workspace);
  if (result.structuredContent.workspace.results) {
    delete result.structuredContent.workspace.results.handoffClaimToken;
  }
  return result;
}

function redactHandoffClaimToken(result: JsonObject) {
  const scan = isJsonObject(result.scan) ? result.scan : undefined;
  if (scan) {
    delete scan.handoffClaimToken;
  }
  const workspace = isJsonObject(result.workspace) ? result.workspace : undefined;
  const workspaceResults = workspace && isJsonObject(workspace.results)
    ? workspace.results
    : undefined;
  if (workspaceResults) {
    delete workspaceResults.handoffClaimToken;
  }
  return result;
}

function workspaceResult(workspace: WorkspaceState) {
  const results = workspace.results;
  const setupSummary = workspace.setup.submitted
    ? "Codex Security setup is saved."
    : "Waiting for bounded scan setup choices.";
  const resultsSummary = results && typeof results.scanDir === "string"
    ? ` Scan state is attached at ${results.scanDir}.`
    : "";
  return {
    content: [{ type: "text" as const, text: `${setupSummary}${resultsSummary}` }],
    structuredContent: { workspace }
  };
}

function promptOnlyScanResult(promptOnly: JsonObject) {
  const startDisposition = promptOnly.startDisposition;
  const scan = isJsonObject(promptOnly.scan) ? promptOnly.scan : undefined;
  const workspace = isJsonObject(promptOnly.workspace) ? promptOnly.workspace : undefined;
  const workspaceResults = isJsonObject(workspace?.results) ? workspace.results : undefined;
  const scanId = scan?.scanId;
  const scanDir = scan?.scanDir;
  if (
    (startDisposition !== "created" && startDisposition !== "joined") ||
    !z.string().uuid().safeParse(scanId).success ||
    typeof scanDir !== "string" ||
    !scanDir.trim() ||
    scan?.handoffStatus !== "delivered" ||
    workspaceResults?.scanId !== scanId
  ) {
    return toolErrorResult(
      "Codex Security prompt-only scan returned malformed context; no prompt-driven scan was started."
    );
  }
  const disposition = startDisposition === "joined" ? "Rejoined" : "Started";
  return {
    content: [{
      type: "text" as const,
      text: `${disposition} prompt-driven scan ${scanId}. Use the returned scanId and scanDir for every phase. Author scan-manifest.json as an unsealed draft: omit scan.sealedAt and scan.artifacts because completion supplies the exact workbench timestamps, seal, artifact digests, and derived finding identities. Then call complete_codex_security_scan once to index the completed findings.`
    }],
    structuredContent: promptOnly
  };
}

function scanActionResult(result: JsonObject, summary: string) {
  return {
    content: [{ type: "text" as const, text: summary }],
    structuredContent: result
  };
}

function toolErrorResult(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true
  };
}

function buildUserInputElicitation(
  questions: z.infer<typeof userInputQuestionsSchema>
) {
  const isSingleQuestion = questions.length === 1;
  return {
    mode: "form" as const,
    message: isSingleQuestion
      ? questions[0]!.question
      : "Codex Security needs your input before it can continue.",
    requestedSchema: {
      type: "object" as const,
      properties: Object.fromEntries(questions.map((question) => [
        question.id,
        {
          type: "string" as const,
          title: question.header,
          oneOf: question.options.map((option) => ({
            const: option.label,
            title: option.label
          }))
        }
      ])),
      required: questions.map((question) => question.id)
    }
  };
}

function userInputToolResult(
  status: "accepted" | "declined" | "cancelled" | "unavailable",
  answers?: Record<string, string>
) {
  const text = status === "accepted"
    ? `The user answered the Codex Security question: ${JSON.stringify(answers)}.`
    : status === "declined"
      ? "The user declined the Codex Security input request. Do not infer an answer."
      : status === "cancelled"
        ? "The Codex Security input request was cancelled. Do not infer an answer."
        : "Structured Codex Security input is unavailable in this host. Use the documented plain-chat fallback.";
  return {
    content: [{ type: "text" as const, text }],
    structuredContent: {
      status,
      ...(answers ? { answers } : {})
    }
  };
}

async function logUserInputFailure(server: McpServer, error: unknown): Promise<void> {
  const errorData = boundedErrorData(error);
  try {
    await server.sendLoggingMessage({
      level: "warning",
      logger: "codex-security.user-input",
      data: {
        event: "elicitation_failed",
        error: errorData
      }
    });
  } catch {
    console.warn(
      "Codex Security user-input elicitation failed:",
      JSON.stringify(errorData)
    );
  }
}

function boundedErrorData(error: unknown): { message: string; name: string } {
  const name = error instanceof Error && error.name.trim() ? error.name : "UnknownError";
  const message = error instanceof Error
    ? error.message
    : typeof error === "string"
      ? error
      : "Unknown user-input elicitation failure.";
  return {
    name: name.slice(0, 128),
    message: message.slice(0, 1000)
  };
}

function deepScanTerminalResult(run: DeepScanRunState) {
  if (run.status === "succeeded") {
    if (!run.manifestPath) return undefined;
    return {
      content: [{
        type: "text" as const,
        text: `Deep Scan discovery completed. Independent Standard scans have already performed validation and attack-path analysis and have been consolidated into the canonical scan-manifest.json, findings.json, and coverage.json under ${run.scanDir}. The returned manifestPath is the canonical scan-manifest.json, not a legacy discovery manifest. Any instructions requiring parent candidate listing, centralized validation, attack-path analysis, or another draft apply only to the old discovery-only workflow and must be skipped. The authoritative scan ID is ${run.scanId}. Immediately call complete_codex_security_scan once using that scan ID to seal and publish the scan. Return output only after completion succeeds and generated report.md exists. If completion fails, surface that exact error and return no final, no-findings, structured, or benchmark response.`
      }],
      structuredContent: { manifestPath: run.manifestPath }
    };
  }
  if (run.status === "canceled") {
    if (run.error?.trim()) return toolErrorResult(deepScanFailureMessage(run));
    return {
      content: [{ type: "text" as const, text: `Deep Scan ${run.scanId} was canceled. Saved findings and pending candidates remain available in the scan's retained results. Do not start additional scan work or claim complete coverage.` }],
      structuredContent: { status: "canceled", scanId: run.scanId }
    };
  }
  if (run.status === "failed" || run.status === "interrupted") {
    return toolErrorResult(deepScanFailureMessage(run));
  }
  return undefined;
}

function logDeepScanEvent(event: {
  event: string;
  scanId: string;
  workerId?: string;
  kind?: string;
  attempt?: number;
  count?: number;
  completed?: number;
  newFindings?: number;
  pass?: number;
  reason?: string;
  threadId?: string;
  total?: number;
}): void {
  console.error(JSON.stringify({ component: "codex_security_deep_scan", ...event }));
}

async function runWorkbench(
  args: string[],
  input?: string
): Promise<JsonObject> {
  let pythonCommand: string | undefined;
  try {
    pythonCommand = await resolvePythonCommand();
    return await executeWorkbenchWithStateSelection(pythonCommand, args, input);
  } catch (error) {
    const launchError = pythonCommand
      ? missingPythonHelperMessage(error, pythonCommand)
      : undefined;
    if (launchError) {
      throw new Error(launchError);
    }
    if (isExecError(error) && error.stderr.trim()) {
      throw new Error(error.stderr.trim(), { cause: error });
    }
    throw error;
  }
}

async function executeWorkbenchWithStateSelection(
  pythonCommand: string,
  args: string[],
  input?: string
): Promise<JsonObject> {
  if (WORKBENCH_COMMANDS_WITHOUT_DATABASE.has(args[0] ?? "")) {
    return await executeWorkbench(pythonCommand, args, undefined, input);
  }
  if (CONFIGURED_WORKBENCH_STATE_DIR) {
    return await executeWorkbench(pythonCommand, args, undefined, input);
  }
  if (fallbackWorkbenchStateDir) {
    return await executeWorkbench(pythonCommand, args, await fallbackWorkbenchStateDir, input);
  }
  if (persistentWorkbenchStateSucceeded) {
    return await executeWorkbench(pythonCommand, args, undefined, input);
  }
  return await withWorkbenchStateSelectionLock(async () => {
    if (fallbackWorkbenchStateDir) {
      return await executeWorkbench(pythonCommand, args, await fallbackWorkbenchStateDir, input);
    }
    if (persistentWorkbenchStateSucceeded) {
      return await executeWorkbench(pythonCommand, args, undefined, input);
    }
    try {
      const result = await executeWorkbench(pythonCommand, args, undefined, input);
      persistentWorkbenchStateSucceeded = true;
      return result;
    } catch (error) {
      if (!isUnwritableSqliteOpenError(error)) throw error;
      const fallbackStateDir = await pinFallbackWorkbenchStateDir();
      logWorkbenchStateFallback();
      return await executeWorkbench(pythonCommand, args, fallbackStateDir, input);
    }
  });
}

async function withWorkbenchStateSelectionLock<T>(operation: () => Promise<T>): Promise<T> {
  const predecessor = workbenchStateSelectionTail;
  let release!: () => void;
  workbenchStateSelectionTail = new Promise<void>((resolvePromise) => {
    release = resolvePromise;
  });
  await predecessor;
  try {
    return await operation();
  } finally {
    release();
  }
}

async function executeWorkbench(
  pythonCommand: string,
  args: string[],
  stateDir?: string,
  input?: string
): Promise<JsonObject> {
  const userContextIndex = args.indexOf("--user-context");
  const userContext = userContextIndex === -1 ? undefined : args[userContextIndex + 1];
  const workbenchArgs = [...args];
  if (userContextIndex !== -1) {
    workbenchArgs.splice(userContextIndex, 2, "--user-context-stdin");
  }
  const workbenchInput = input ?? userContext;
  const execution = execFileAsync(pythonCommand, [workbenchScriptPath(), ...workbenchArgs], {
    cwd: PLUGIN_ROOT,
    env: stateDir
      ? { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir }
      : process.env,
    encoding: "utf8" as const,
    maxBuffer: 4 * 1024 * 1024,
    timeout: [
      "begin-deep-scan",
      "claim-deep-scan-dedup",
      "commit-deep-scan-dedup",
      "complete-scan",
      "export-findings",
      "finish-deep-scan",
      "get-scan",
      "get-deep-scan",
      "get-workspace",
      "inspect-setup",
      "list-findings",
      "request-finding-remediation",
      "request-finding-remediation-action",
      "save-workspace",
      "set-finding-triage",
      "set-finding-remediation",
      "start-headless-standard-scan",
      "start-prompt-only-scan",
      "start-scan",
      "upsert-deep-scan-worker"
    ].includes(args[0] ?? "") ? 300_000 : 30_000
  });
  if (workbenchInput !== undefined) {
    execution.child.stdin!.on("error", () => {
      // The workbench may exit before consuming stdin; surface its process error.
    });
    execution.child.stdin!.end(workbenchInput);
  }
  const { stdout } = await execution;
  const result = JSON.parse(stdout) as unknown;
  if (!isJsonObject(result)) {
    throw new Error("Codex Security workbench helper returned invalid JSON.");
  }
  return result;
}

async function pinFallbackWorkbenchStateDir(): Promise<string> {
  fallbackWorkbenchStateDir ??= (async () => {
    const stateDir = join(await scanRoot(), "workbench-state");
    await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
    return stateDir;
  })();
  return await fallbackWorkbenchStateDir;
}

function logWorkbenchStateFallback(): void {
  if (fallbackWorkbenchStateLogged) return;
  fallbackWorkbenchStateLogged = true;
  console.error(JSON.stringify({
    component: "codex_security_workbench",
    event: "state_fallback_pinned",
    reason: "persistent_sqlite_unwritable"
  }));
}

function workbenchScriptPath(): string {
  return join(PLUGIN_ROOT, "scripts", "workbench_db.py");
}

function optionalArg(name: string, value: string | undefined): string[] {
  return value ? [name, value] : [];
}

function definedArg(name: string, value: string | undefined): string[] {
  return value === undefined ? [] : [name, value];
}

function optionalNumberArg(name: string, value: number | undefined): string[] {
  return value === undefined ? [] : [name, String(value)];
}

function diffTargetArgs(target: z.infer<typeof diffTargetSchema> | undefined): string[] {
  if (!target) return [];
  return [
    "--diff-target-kind",
    target.kind,
    ...optionalArg("--diff-base-revision", "baseRevision" in target ? target.baseRevision : undefined),
    ...optionalArg("--diff-head-revision", "headRevision" in target ? target.headRevision : undefined),
    ...optionalArg("--diff-content-digest", "contentDigest" in target ? target.contentDigest : undefined)
  ];
}

function isJsonObject(value: unknown): value is JsonObject {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function threadIdFromExtra(extra: unknown): string | undefined {
  if (!isJsonObject(extra)) return undefined;
  const requestInfo = isJsonObject(extra.requestInfo) ? extra.requestInfo : undefined;
  const metadata = isJsonObject(requestInfo?._meta)
    ? requestInfo._meta
    : isJsonObject(extra._meta)
      ? extra._meta
      : undefined;
  for (const key of ["openai/threadId", "openai/thread_id", "codexThreadId", "codex_thread_id", "threadId", "thread_id"]) {
    const value = metadata?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  const thread = isJsonObject(metadata?.thread) ? metadata.thread : undefined;
  if (typeof thread?.id === "string" && thread.id.trim()) return thread.id.trim();
  return undefined;
}

function codexModelSettingsFromExtra(extra: unknown): {
  model?: string;
  reasoningEffort?: string;
} {
  if (!isJsonObject(extra)) return {};
  const requestInfo = isJsonObject(extra.requestInfo) ? extra.requestInfo : undefined;
  const metadata = isJsonObject(requestInfo?._meta)
    ? requestInfo._meta
    : isJsonObject(extra._meta)
      ? extra._meta
      : undefined;
  // Codex supplies the already-resolved runtime model and effective effort on every MCP call.
  const turnMetadata = isJsonObject(metadata?.["x-codex-turn-metadata"])
    ? metadata["x-codex-turn-metadata"]
    : undefined;
  const model = typeof turnMetadata?.model === "string"
    ? turnMetadata.model.trim()
    : undefined;
  const reasoningEffort = typeof turnMetadata?.reasoning_effort === "string"
    ? turnMetadata.reasoning_effort.trim()
    : undefined;
  return {
    ...(model ? { model } : {}),
    ...(reasoningEffort ? { reasoningEffort } : {})
  };
}

function abortSignalFromExtra(extra: unknown): AbortSignal | undefined {
  if (!isJsonObject(extra)) return undefined;
  return extra.signal instanceof AbortSignal ? extra.signal : undefined;
}

function isExecError(error: unknown): error is { stderr: string } {
  return Boolean(error && typeof error === "object" && "stderr" in error && typeof error.stderr === "string");
}

function completionFailureMessage(error: unknown): string {
  const diagnostic = error instanceof Error && error.message.trim()
    ? error.message.trim()
    : String(error);
  return [
    "Codex Security scan completion failed.",
    diagnostic,
    "Stop the current response and surface this exact MCP error.",
    "Do not retry completion or return a final, no-findings, structured, or benchmark response."
  ].join("\n");
}

function deepScanInvocationFailureMessage(error: unknown): string {
  const diagnostic = error instanceof Error && error.message.trim()
    ? error.message.trim()
    : String(error);
  return [
    "Codex Security Deep Scan discovery did not start or rejoin.",
    diagnostic,
    "Stop the current response and surface this exact MCP error.",
    "Do not call start_codex_security_deep_scan again in this response.",
    "Do not call get_codex_security_scan_context in this response.",
    "Do not call complete_codex_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel, return a final or no-findings result, satisfy a structured output schema, or emit benchmark JSON."
  ].join("\n");
}

function deepScanFailureMessage(run: DeepScanRunState): string {
  const manifest = run.manifestPath ? ` Failure manifest: ${run.manifestPath}.` : "";
  const diagnostic = `${run.error ?? `Deep Scan ${run.scanId} ${run.status}.`}${manifest}`;
  return [
    diagnostic,
    "This is a terminal failure of this logical Deep Scan; no successful discovery manifest was returned.",
    "Stop further scanning and surface this exact stable MCP failure. Read the existing scan context to report saved findings and pending candidates separately, with incomplete coverage.",
    "Do not call start_codex_security_deep_scan again in this response.",
    "Do not call complete_codex_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel for this terminal scan, claim a successful or no-findings scan, satisfy a successful-scan output schema, or emit benchmark JSON."
  ].join("\n");
}

function isUnwritableSqliteOpenError(error: unknown): boolean {
  const diagnostic = isExecError(error)
    ? error.stderr
    : error instanceof Error
      ? error.message
      : "";
  return /sqlite3\.OperationalError:\s*unable to open database file/i.test(diagnostic);
}
