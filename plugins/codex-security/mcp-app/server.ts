import {
  workbenchArgs,
  type WorkbenchFields,
} from "./src/workbench-arguments.js";
import { CodexSecurityStdioTransport } from "./src/stdio-transport.js";
import {
  readingAnnotations,
  writingAnnotations,
} from "./src/server/tool-annotations.js";
import type { JsonObject } from "./src/types.js";
import { isRecord as isJsonObject } from "./src/record.js";
import { randomUUID } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import { resolvePythonCommand } from "./src/python_command.js";
import { version as MCP_APP_VERSION } from "./package.json";
import {
  handoffClaimTokenSchema,
  recoveryHandoffClaimTokenSchema,
  registerScanHandoffTools,
  type HandoffWorkspaceState as WorkspaceState,
} from "./src/server/handoff-tools.js";
import { registerCompactArtifactTools } from "./src/server/compact-artifact-tools.js";
import { registerFindingIssueTools } from "./src/server/finding-issue-tools.js";
import {
  DeepScanCoordinatorRegistry,
  DeepScanCoordinator,
  AsyncLock,
} from "./src/deep-scan/registry.js";
import { startDeepScanEngine } from "./src/deep-scan/engine.js";
import type { DeepScanParentTurn } from "./src/deep-scan/permission-profile-preflight.js";
import {
  CODEX_SANDBOX_STATE_META_CAPABILITY,
  resolveDeepWorkerParentSandbox,
  type DeepWorkerParentSandbox,
} from "./src/deep-scan/parent-sandbox.js";
import { WorkbenchDeepScanStore } from "./src/deep-scan/store.js";
import { readDeepScanProjectConfig } from "./src/deep-scan/project-config.js";
import type {
  DeepScanLogEvent,
  DeepScanRunState,
} from "./src/deep-scan/types.js";
import { PLUGIN_ROOT, runWorkbench, scanRoot } from "./src/workbench-client.js";

const USER_INPUT_WAIT_TIMEOUT_MS = 14 * 60 * 1000;
const trimmedText = z.string().trim();
const requiredText = trimmedText.min(1);
const nonnegativeInteger = z.number().int().nonnegative();
const positiveInteger = z.number().int().positive();
const pathSchema = z
  .string()
  .min(1)
  .max(4096)
  .refine((value) => value.trim().length > 0, "Path must not be blank.");
const verifiedAccessGrantSchema = z
  .strictObject({
    level: z.enum(["tac1", "tac2", "tac3", "government"]),
    source: z.enum(["user", "project", "current_account"]),
  })
  .refine(
    ({ level, source }) =>
      level === "tac1" ||
      (level === "tac2" ? source === "user" : source === "current_account"),
    "Unsupported Daybreak grant source.",
  );
const verifiedAccessSnapshotSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    status: z.enum(["granted", "not_granted", "unknown"]),
    grants: z.array(verifiedAccessGrantSchema),
    checkedAt: z.iso.datetime({ offset: true }).optional(),
    stale: z.boolean(),
    enrollmentUrl: z.url().optional(),
  })
  .superRefine((snapshot, context) => {
    if (snapshot.status === "granted" && snapshot.grants.length === 0) {
      context.addIssue({
        code: "custom",
        message: "Granted Daybreak access requires a grant.",
      });
    }
    if (snapshot.status !== "granted" && snapshot.grants.length !== 0) {
      context.addIssue({
        code: "custom",
        message: "Only granted Daybreak access may include grants.",
      });
    }
  })
  .transform((snapshot) => ({
    ...snapshot,
    checkedAt: snapshot.checkedAt ?? new Date().toISOString(),
  }));
const daybreakEntitlementContextSchema = z.object({
  schemaVersion: z.literal(1),
  entitlements: z.object({
    cyber_trusted_access: verifiedAccessSnapshotSchema,
  }),
});

const diffTargetSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("working_tree"),
    baseRevision: requiredText.max(512).optional(),
    contentDigest: requiredText.max(128).optional(),
    headRevision: requiredText.max(512).optional(),
  }),
  z.strictObject({
    kind: z.literal("commit"),
    baseRevision: requiredText.max(512).optional(),
    headRevision: requiredText.max(512),
  }),
  z.strictObject({
    kind: z.literal("range"),
    baseRevision: requiredText.max(512),
    headRevision: requiredText.max(512),
  }),
]);
const openSchema = {
  diffTarget: diffTargetSchema
    .optional()
    .describe("Exact local Git revisions for Review changes mode."),
  mode: z
    .enum(["diff", "standard", "deep"])
    .optional()
    .describe("Initial scan mode inferred from the user's request."),
  scope: pathSchema
    .optional()
    .describe(
      "Optional directory inside targetPath. Use '.' or omit it for the whole target. Target-relative paths are preferred; absolute paths inside targetPath are normalized.",
    ),
  sessionId: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Existing workspace ID to reopen without changing its setup. When provided, omit all other fields.",
    ),
  targetPath: pathSchema
    .optional()
    .describe("Optional resolved local target path."),
  targetSummary: requiredText
    .max(2400)
    .optional()
    .describe("Optional bounded target/security context."),
  targetTitle: requiredText
    .max(200)
    .optional()
    .describe("Optional human-readable target name."),
  userContext: requiredText
    .optional()
    .describe("Optional security focus supplied by the user."),
};
const sessionSchema = { sessionId: z.string().uuid() };
const startScanSchema = {
  ...sessionSchema,
  model: requiredText.max(200).optional(),
  reasoningEffort: requiredText.max(32).optional(),
};
const startPromptOnlyScanSchema = {
  diffTarget: diffTargetSchema
    .optional()
    .describe("Exact local Git revisions for Review changes mode."),
  mode: z
    .enum(["diff", "standard"])
    .describe(
      "Prompt-driven scan mode. Deep Scan uses start_codex_security_deep_scan instead.",
    ),
  scope: pathSchema.describe(
    "Directory inside targetPath. Use '.' for the whole target.",
  ),
  targetPath: pathSchema.describe("Resolved local target path."),
  targetSummary: requiredText
    .max(2400)
    .optional()
    .describe("Optional bounded target or change-set context."),
  userContext: requiredText
    .optional()
    .describe("Optional security focus supplied by the user."),
};
const startHeadlessStandardScanSchema = {
  targetPath: pathSchema.describe("Resolved local target path."),
  scope: pathSchema
    .optional()
    .describe(
      "Optional directory inside targetPath. Omit it or use '.' for the whole target.",
    ),
  targetSummary: trimmedText
    .max(2400)
    .optional()
    .describe("Optional bounded target context."),
  userContext: trimmedText
    .optional()
    .describe("Optional security focus supplied by the user."),
};
type PromptOnlyScanInput = z.output<
  z.ZodObject<typeof startPromptOnlyScanSchema>
>;
const userInputOptionSchema = z.strictObject({
  description: requiredText.max(1200),
  label: requiredText.max(200),
});
const userInputQuestionSchema = z
  .strictObject({
    header: requiredText.max(64),
    id: z
      .string()
      .regex(
        /^[a-z][a-z0-9_]{0,63}$/,
        "Question IDs must use snake_case and start with a lowercase letter.",
      )
      .refine(
        (id) => !["constructor", "prototype"].includes(id),
        "Question IDs must not use reserved object property names.",
      ),
    options: z.array(userInputOptionSchema).min(2).max(3),
    question: requiredText.max(1200),
  })
  .superRefine((question, context) => {
    const labels = new Set<string>();
    for (const [index, option] of question.options.entries()) {
      if (labels.has(option.label)) {
        context.addIssue({
          code: "custom",
          message: "Option labels must be unique within a question.",
          path: ["options", index, "label"],
        });
      }
      labels.add(option.label);
    }
  });
const userInputQuestionsSchema = z
  .array(userInputQuestionSchema)
  .min(1)
  .max(3)
  .superRefine((questions, context) => {
    const ids = new Set<string>();
    for (const [index, question] of questions.entries()) {
      if (ids.has(question.id)) {
        context.addIssue({
          code: "custom",
          message: "Question IDs must be unique.",
          path: [index, "id"],
        });
      }
      ids.add(question.id);
    }
  });
const requestUserInputSchema = {
  questions: userInputQuestionsSchema.describe(
    "One to three non-sensitive multiple-choice questions for an interactive Codex Security workflow.",
  ),
};
const targetInspectionSchema = {
  targetPath: pathSchema,
};
const projectConfigPathSchema = pathSchema
  .optional()
  .describe(
    "Project YAML/JSON configuration explicitly selected by the user. Never discover or select a repository file automatically. Supported for Deep Scan only.",
  );
const submissionSchema = {
  projectConfigPath: projectConfigPathSchema,
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: pathSchema,
  sessionId: z.string().uuid(),
  targetPath: pathSchema,
  targetSummary: trimmedText.max(2400).optional(),
  userContext: trimmedText.optional(),
};
const setupInspectionSchema = {
  projectConfigPath: projectConfigPathSchema,
  diffTarget: diffTargetSchema.optional(),
  mode: z.enum(["diff", "standard", "deep"]),
  scope: pathSchema,
  targetPath: pathSchema,
};
const scanSchema = { scanId: z.string().uuid() };
const startDeepScanSchema = {
  projectConfigPath: projectConfigPathSchema,
  scanId: z
    .string()
    .uuid()
    .optional()
    .describe("Existing app-created or previously returned Deep Scan ID."),
  targetPath: pathSchema
    .optional()
    .describe(
      "Resolved local target path for a first terminal or headless Deep Scan call.",
    ),
  scope: pathSchema
    .optional()
    .describe(
      "Scope inside targetPath. Deep Scan currently requires the whole target.",
    ),
  userContext: trimmedText
    .optional()
    .describe("Optional security focus supplied by the user."),
  handoffClaimToken: handoffClaimTokenSchema
    .optional()
    .describe(
      "Existing Deep Scan continuation claim. Pass the same token on every scanId resume, including after an MCP server restart.",
    ),
};
const continuationMutationClaimSchema = {
  handoffClaimToken: handoffClaimTokenSchema
    .optional()
    .describe(
      "Opaque continuation token returned by the native launcher. Pass it on every progress, completion, or failure update after a resume.",
    ),
};
const scanContextUpdateSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema,
  userContext: trimmedText.describe(
    "Complete replacement context for the running scan. Pass an empty string to clear it.",
  ),
};
const appScanContextUpdateSchema = {
  ...scanSchema,
  userContext: trimmedText,
};
const phaseProgressUnitSchema = z.enum([
  "checks",
  "threat_surfaces",
  "review_receipts",
  "candidate_findings",
  "validated_findings",
  "report_artifacts",
]);
const progressSchema = {
  deepReviewPass: positiveInteger
    .optional()
    .describe(
      "Current Deep Scan discovery pass. Send it when starting each pass together with that pass's total and zero completed items.",
    ),
  phase: z
    .enum([
      "preflight",
      "threat_model",
      "discovery",
      "validation",
      "attack_path",
      "reporting",
    ])
    .optional()
    .describe(
      "Current workflow phase. Send it immediately when the scan enters a new phase so persisted progress advances.",
    ),
  phaseItemsCompleted: nonnegativeInteger
    .optional()
    .describe(
      "Completed authoritative coverage, receipts, or artifacts for the current phase. Increase it only after the corresponding work product exists.",
    ),
  phaseItemsTotal: nonnegativeInteger
    .optional()
    .describe(
      "Expected authoritative coverage, receipts, or artifacts for the current phase. Increase it before newly discovered work begins.",
    ),
  phaseProgressUnit: phaseProgressUnitSchema
    .optional()
    .describe(
      "What phaseItemsTotal and phaseItemsCompleted count for the current phase.",
    ),
  reportableFindingsCount: nonnegativeInteger.optional(),
  reviewItemsCompleted: nonnegativeInteger
    .optional()
    .describe(
      "Cumulative completed reviews or coverage surfaces in the current discovery pass. Increment only after the corresponding review is complete.",
    ),
  reviewItemsTotal: nonnegativeInteger
    .optional()
    .describe(
      "Expected reviews or coverage surfaces in the current discovery pass. Increase it before assigning newly discovered work.",
    ),
  scanId: z.string().uuid(),
  ...continuationMutationClaimSchema,
};
const failSchema = {
  ...continuationMutationClaimSchema,
  message: requiredText,
  scanId: z.string().uuid(),
};
const completeScanSchema = {
  ...scanSchema,
  ...continuationMutationClaimSchema,
};
const occurrenceIdSchema = requiredText.max(256);
const scanReadSchema = {
  ...scanSchema,
  occurrenceId: occurrenceIdSchema
    .optional()
    .describe(
      "Optional finding occurrence to include even when it is outside the bounded findings prefix.",
    ),
};
const scanContextSchema = {
  ...scanReadSchema,
  requestId: z.string().uuid().optional(),
  actionToken: z.string().uuid().optional(),
  handoffClaimToken: handoffClaimTokenSchema
    .optional()
    .describe(
      "Opaque delivery token returned by the native scan launcher. Pass it once so Codex can acknowledge that this continuation received the scan.",
    ),
};
const findingTriageSchema = {
  closeReason: z
    .enum(["already_fixed", "wont_fix", "false_positive"])
    .optional(),
  note: trimmedText.max(2400).optional(),
  occurrenceId: occurrenceIdSchema,
  status: z.enum(["open", "closed"]),
};
const findingRemediationSchema = {
  actionToken: z.string().uuid(),
  baseRevision: requiredText.max(512).optional(),
  expectedVersion: positiveInteger,
  occurrenceId: occurrenceIdSchema,
  patch: z
    .union([
      z
        .string()
        .refine(
          (value) => value.isWellFormed(),
          "Patch text contains an unpaired Unicode surrogate. Send the original bytes as base64.",
        ),
      z.object({ encoding: z.literal("base64"), content: z.base64() }),
    ])
    .optional()
    .describe(
      "For state generated, supply the exact unified diff as UTF-8 text or as base64 of its original bytes. The workbench saves it and computes its digest. For an existing scan-local file, supply patchPath and patchDigest without patch.",
    ),
  patchDigest: z
    .string()
    .regex(/^sha256:[a-f0-9]{64}$/)
    .optional(),
  patchPath: pathSchema.optional(),
  requestId: z.string().uuid(),
  state: z.enum(["generated", "applied", "verifying", "verified", "failed"]),
  summary: trimmedText.max(2400).optional(),
  verificationSummary: trimmedText.max(2400).optional(),
};
const findingRemediationActionRequestSchema = {
  action: z.enum(["apply", "verify"]),
  actionToken: z.string().uuid(),
  expectedVersion: positiveInteger,
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid(),
};
const findingRemediationClaimSchema = {
  actionToken: z.string().uuid(),
  occurrenceId: occurrenceIdSchema,
  requestId: z.string().uuid(),
};
const findingsExportSchema = {
  artifact: z.enum(["findings", "threat-model"]).default("findings"),
  format: z.enum(["csv", "json", "sarif", "md"]).optional(),
  scanId: z.string().uuid(),
};
const collectionPageSchema = {
  limit: positiveInteger.max(50).optional(),
  offset: nonnegativeInteger.optional(),
};
const findingCollectionFiltersSchema = {
  query: trimmedText.max(512).optional(),
  severity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional(),
  status: z.enum(["open", "closed"]).optional(),
};
const targetCollectionFiltersSchema = {
  query: trimmedText.max(512).optional(),
  targetId: requiredText.max(256).optional(),
};
const findingsPageSchema = {
  ...collectionPageSchema,
  ...findingCollectionFiltersSchema,
  scanId: z.string().uuid(),
};
const globalFindingsPageSchema = {
  ...findingCollectionFiltersSchema,
  limit: positiveInteger.max(20).optional(),
  offset: nonnegativeInteger.optional(),
  targetId: requiredText.max(256).optional(),
};
const scanListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  mode: z.enum(["diff", "standard", "deep"]).optional(),
  status: z.enum(["running", "complete", "failed", "canceled"]).optional(),
};
const repositoryListSchema = {
  ...collectionPageSchema,
  ...targetCollectionFiltersSchema,
  status: z.enum(["scanned", "not_scanned", "open_findings"]).optional(),
};
export function createCodexSecurityServer(): McpServer {
  const server = new McpServer(
    {
      name: "codex-security",
      title: "Codex Security",
      version: MCP_APP_VERSION,
    },
    {
      capabilities: {
        experimental: { [CODEX_SANDBOX_STATE_META_CAPABILITY]: {} },
        extensions: { "com.openai": {} },
        logging: {},
      },
    },
  );
  const deepScanCoordinators = new DeepScanCoordinatorRegistry();
  const deepScanCompletions = new WeakMap<
    DeepScanCoordinator,
    Promise<ReturnType<typeof deepScanTerminalResult>>
  >();
  // Serialize start-or-join so a scan creates only one coordinator.
  const deepScanStartLock = new AsyncLock();
  const deepScanStore = new WorkbenchDeepScanStore(runWorkbench);
  const authenticatedArtifactClaims = new Map<
    string,
    {
      claimToken: string;
      threadId: string;
    }
  >();
  server.server.onclose = () =>
    deepScanCoordinators.shutdown("mcp_transport_closed");
  const appMeta = { ui: { visibility: ["app"] as const } };
  const modelActionMeta = { ui: { visibility: ["model"] as const } };
  const destructiveAnnotations = {
    ...writingAnnotations,
    destructiveHint: true,
  };
  const nonIdempotentWritingAnnotations = {
    ...writingAnnotations,
    idempotentHint: false,
  };

  server.registerTool(
    "get_codex_security_daybreak_access",
    {
      title: "Check Codex Security Daybreak Access",
      description:
        "Check this ChatGPT account's Daybreak access and available Daybreak programs. This check is advisory and never authorizes or blocks a scan. Skip it for Amazon Bedrock scans: it does not check AWS model access or access to local CLI results.",
      inputSchema: z.strictObject({}),
      annotations: readingAnnotations,
      _meta: {
        ...modelActionMeta,
        "openai/requestedEntitlements": ["cyber_trusted_access"],
      },
    },
    (_input, extra) => {
      const access = daybreakAccess(extra);
      const warning =
        access.status === "not_granted"
          ? " This ChatGPT account check is advisory: a scan may run, but protected results associated with this account may not be displayable. It does not determine Amazon Bedrock model access or access to local CLI results."
          : "";
      return scanActionResult(
        access,
        `Codex Security Daybreak access: status=${access.status}; programs=${access.programs.join(", ") || "none"}; checkedAt=${access.checkedAt}; stale=${access.stale}.${warning}`,
      );
    },
  );

  server.registerTool(
    "start_codex_security_standard_scan",
    {
      title: "Start or Join Codex Security Standard Scan",
      description:
        "Start or rejoin a Standard scan from its owning conversation. Returns the bound target, scope, progress and handoff token.",
      inputSchema: startHeadlessStandardScanSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async ({ targetPath, scope, targetSummary, userContext }, extra) => {
      const threadId = threadIdFromExtra(extra);
      if (!threadId) {
        return toolErrorResult(
          "Starting a Standard scan requires the owning Codex thread context.",
        );
      }
      const started = await startHeadlessStandardScan(
        { targetPath, scope, targetSummary, userContext },
        threadId,
        codexModelSettingsFromExtra(extra),
      );
      const scan = startedScanSchema.safeParse(started).data?.scan;
      const progress = isJsonObject(scan?.progress) ? scan.progress : undefined;
      const handoffClaimToken = scan?.handoffClaimToken;
      if (
        !scan ||
        typeof handoffClaimToken !== "string" ||
        !scanSchema.scanId.safeParse(handoffClaimToken).success ||
        scan.mode !== "standard" ||
        scan.continuationThreadId !== threadId ||
        progress?.status !== "running" ||
        (started.startDisposition === "created" &&
          progress.phase !== "threat_model")
      ) {
        return toolErrorResult(
          "Codex Security returned malformed Standard scan ownership.",
        );
      }
      const { scanId, scanDir } = scan;
      authenticatedArtifactClaims.set(scanId, {
        claimToken: handoffClaimToken,
        threadId,
      });
      const advisory =
        started.startDisposition === "created"
          ? standardAccessGuidance
          : undefined;
      return scanActionResult(
        {
          startDisposition: started.startDisposition,
          scanId,
          scanDir,
          handoffClaimToken,
          scan: modelScanContext({ scan }, { omitHandoffClaim: true }).scan,
        },
        [
          advisory,
          `${started.startDisposition === "created" ? "Started" : "Rejoined"} Standard scan ${scanId}. Use its target, scope and token for this review.`,
        ]
          .filter(Boolean)
          .join("\n"),
        scanId,
      );
    },
  );

  server.registerTool(
    "start_codex_security_prompt_only_scan",
    {
      title: "Start Codex Security Prompt-Only Scan",
      description:
        "Start or rejoin a Standard or diff Codex Security scan from its owning conversation. Use the returned authoritative scanId and scanDir. Standard and diff scans save progress checkpoints before their final semantic draft; the workbench writes the unsealed canonical artifacts. Complete the same scan once. Deep Scan uses start_codex_security_deep_scan instead.",
      inputSchema: startPromptOnlyScanSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async (
      { mode, targetPath, scope, targetSummary, userContext, diffTarget },
      extra,
    ) => {
      if (mode === "diff" && !diffTarget) {
        return toolErrorResult(
          "Review changes prompt-only scans require diffTarget.",
        );
      }
      if (mode === "standard" && diffTarget) {
        return toolErrorResult(
          "Standard prompt-only scans must omit diffTarget.",
        );
      }
      if (mode === "diff" && !wholeTargetScope(scope, targetPath)) {
        return toolErrorResult(
          "Review changes prompt-only scans require the whole target; use scope '.'.",
        );
      }
      const threadId = threadIdFromExtra(extra);
      if (!threadId) {
        return toolErrorResult(
          "Starting a prompt-only scan requires the owning Codex thread context.",
        );
      }
      const promptOnly = await startPromptOnlyScan(
        { mode, targetPath, scope, targetSummary, userContext, diffTarget },
        threadId,
        codexModelSettingsFromExtra(extra),
      );
      return promptOnlyScanResult(promptOnly);
    },
  );

  server.registerTool(
    "request_codex_security_user_input",
    {
      title: "Request Codex Security User Input",
      description:
        "Fallback for interactive Codex Security workflows when the host-native request_user_input tool is unavailable. Presents one to three non-sensitive multiple-choice questions through standard MCP form elicitation and waits for the user's response. Never call this tool in headless, automation, or other non-interactive sessions.",
      inputSchema: requestUserInputSchema,
      annotations: { ...readingAnnotations, idempotentHint: false },
      _meta: modelActionMeta,
    },
    async ({ questions }, extra) => {
      const signal = abortSignalFromExtra(extra);
      if (!server.server.getClientCapabilities()?.elicitation?.form) {
        return userInputToolResult("unavailable");
      }
      try {
        const result = await server.server.elicitInput(
          buildUserInputElicitation(questions),
          {
            timeout: USER_INPUT_WAIT_TIMEOUT_MS,
            ...(signal ? { signal } : {}),
          },
        );
        if (result.action !== "accept") {
          return userInputToolResult(
            result.action === "decline" ? "declined" : "cancelled",
          );
        }
        if (!isJsonObject(result.content)) {
          throw new Error(
            "Accepted user input did not contain structured answers.",
          );
        }
        // elicitInput validates accepted content against requestedSchema.
        const answers = Object.fromEntries(
          questions.map(({ id }) => [id, result.content![id] as string]),
        );
        return userInputToolResult("accepted", answers);
      } catch (error) {
        if (signal?.aborted) throw error;
        await logUserInputFailure(server, error);
        return userInputToolResult("unavailable");
      }
    },
  );

  server.registerTool(
    "open_codex_security_workspace",
    {
      title: "Open Codex Security",
      description:
        "App-only. Create a native Codex Security workspace with the target and requested standard, diff, or deep mode, or reopen one owned by this thread by passing only sessionId. Scope is inside targetPath; use '.' or omit scope for the whole target.",
      inputSchema: openSchema,
      annotations: nonIdempotentWritingAnnotations,
      _meta: appMeta,
    },
    async (input, extra) => {
      if (
        input.sessionId &&
        Object.entries(input).some(
          ([key, value]) => key !== "sessionId" && value !== undefined,
        )
      ) {
        throw new Error(
          "sessionId only reopens an existing workspace; omit it to create a workspace with different setup fields.",
        );
      }
      const mode = input.mode ?? (input.diffTarget ? "diff" : "standard");
      if (input.diffTarget && mode !== "diff") {
        throw new Error("diffTarget requires mode 'diff'.");
      }
      if (
        (mode === "diff" || mode === "deep") &&
        !wholeTargetScope(input.scope, input.targetPath)
      ) {
        throw new Error(
          `${mode === "deep" ? "Deep Scan" : "Review changes"} requires the whole target; use scope '.'.`,
        );
      }
      const threadId = threadIdFromExtra(extra);
      if (!threadId && !input.sessionId) {
        return openWorkspaceResult(await createWorkspace({ ...input, mode }));
      }
      if (!threadId) {
        throw new Error(
          "Thread metadata is required to create or reopen a Codex Security workspace.",
        );
      }
      return openWorkspaceResult(
        input.sessionId
          ? await getWorkspace(input.sessionId, threadId)
          : await createWorkspace({ ...input, mode }, threadId),
      );
    },
  );

  server.registerTool(
    "inspect_codex_security_target",
    {
      title: "Inspect Codex Security Target",
      description:
        "App-only. Validate a local target directory and derive its display and Git metadata without saving setup.",
      inputSchema: targetInspectionSchema,
      annotations: readingAnnotations,
      _meta: appMeta,
    },
    async ({ targetPath }) => {
      const target = await workbench("inspect-target", { targetPath });
      return scanActionResult(
        { target },
        "Validated the local Codex Security target.",
      );
    },
  );

  server.registerTool(
    "inspect_codex_security_setup",
    {
      title: "Validate Codex Security Setup",
      description:
        "Resolve and validate the local target, scope, mode, and exact Git change set without saving setup. Deep Scan returns effective limits and their sources before model work; projectConfigPath must be explicitly selected by the user.",
      inputSchema: setupInspectionSchema,
      annotations: readingAnnotations,
      _meta: { ui: { visibility: ["app", "model"] } },
    },
    async ({ targetPath, scope, mode, diffTarget, projectConfigPath }) => {
      const selected = await deepScanProjectSetup(
        targetPath,
        projectConfigPath,
        "preview",
      );
      const setup = await workbench("inspect-setup", {
        targetPath: selected.targetPath,
        scope,
        mode,
        ...diffTargetFields(diffTarget),
        deepScanProjectJson: selected.projectConfigJson,
      });
      return scanActionResult(
        { setup },
        "Validated the local Codex Security setup.",
      );
    },
  );

  server.registerTool(
    "submit_codex_security_setup",
    {
      title: "Save Codex Security Setup",
      description:
        "App-only. Validate and save bounded target, scope, mode, and optional context selections.",
      inputSchema: submissionSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({
      sessionId,
      targetPath,
      scope,
      mode,
      targetSummary,
      userContext,
      diffTarget,
      projectConfigPath,
    }) => {
      const selected = await deepScanProjectSetup(
        targetPath,
        projectConfigPath,
        "save",
      );
      return workspaceResult(
        (await workbench(
          "save-workspace",
          {
            workspaceId: sessionId,
            targetPath: selected.targetPath,
            scope,
            mode,
            targetSummary,
            userContextStdin: Boolean(userContext),
            ...diffTargetFields(diffTarget),
            deepScanProjectJson: selected.projectConfigJson,
          },
          userContext,
        )) as WorkspaceState,
      );
    },
  );

  server.registerTool(
    "start_codex_security_scan",
    {
      title: "Start Codex Security Scan",
      description:
        "App-only. Create a scan record and its local artifact directory before Codex analysis begins.",
      inputSchema: startScanSchema,
      annotations: nonIdempotentWritingAnnotations,
      _meta: appMeta,
    },
    async ({ sessionId, model, reasoningEffort }) => {
      const workspace = (await workbench("start-scan", {
        workspaceId: sessionId,
        model,
        reasoningEffort,
        scanRoot: await scanRoot(),
      })) as WorkspaceState;
      return workspaceResult(workspace, workspace.results?.scanId);
    },
  );

  server.registerTool(
    "start_codex_security_deep_scan",
    {
      title: "Start or Join Codex Security Deep Scan",
      description:
        "Run or rejoin independent Standard security scans and return their deduplicated findings. Pass scanId and its handoffClaimToken to resume, or targetPath to start headlessly. The coordinator finalizes the parent even if this caller detaches. For an SDK-registered scan it returns the aggregate to the SDK for finalization. Follow the returned instructions for the authoritative scanId, scanDir, and manifestPath.",
      inputSchema: startDeepScanSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async (
      {
        scanId,
        targetPath,
        scope,
        userContext,
        handoffClaimToken,
        projectConfigPath,
      },
      extra,
    ) => {
      const hasScanId = scanId !== undefined;
      const hasTarget = targetPath !== undefined;
      const normalizedUserContext = userContext || undefined;
      if (hasScanId === hasTarget) {
        return toolErrorResult(
          "Pass exactly one Deep Scan identity: either scanId, or targetPath for a first terminal/headless call.",
        );
      }
      if (
        hasScanId &&
        (scope !== undefined ||
          normalizedUserContext !== undefined ||
          projectConfigPath !== undefined)
      ) {
        return toolErrorResult(
          "When scanId is present, omit targetPath, scope, userContext, and projectConfigPath; the persisted scan is authoritative.",
        );
      }
      if (hasTarget && !wholeTargetScope(scope, targetPath)) {
        return toolErrorResult(
          "Deep Scan currently requires the whole target; use scope '.'.",
        );
      }
      if (hasTarget && handoffClaimToken !== undefined) {
        return toolErrorResult(
          "handoffClaimToken is only valid with an existing Deep Scan ID.",
        );
      }
      const threadId = threadIdFromExtra(extra);
      if (!threadId) {
        return toolErrorResult(
          "Starting or joining a Deep Scan requires the owning Codex thread context.",
        );
      }
      const modelSettings = codexModelSettingsFromExtra(extra);
      const serviceTier =
        requestMetadataFromExtra(extra)?.["codex/turn-service-tier"];
      let parentSandbox: DeepWorkerParentSandbox;
      try {
        parentSandbox = resolveDeepWorkerParentSandbox(extra);
      } catch (error: unknown) {
        return toolErrorResult(deepScanInvocationFailureMessage(error));
      }
      const completeDeepScan = async (run: DeepScanRunState) => {
        if (run.status !== "succeeded" || run.sdkOwnsCompletion)
          return deepScanTerminalResult(run);
        try {
          const completion = await workbench("complete-scan", {
            scanId: run.scanId,
            claimToken: handoffClaimToken,
            threadId,
            turnId: securityScanTurnId(extra),
          });
          // Full findings and workspace history can exceed the host's tool-result limit.
          const { progress, reportAvailable, usage, cost } =
            completion.scan as {
              progress: { status: string };
              reportAvailable: boolean;
              usage?: JsonObject;
              cost?: { model: string; estimatedUsd: number };
            };
          // Rate-limit snapshots can grow independently of the measured scan totals.
          const { accountRateLimits: _limits, ...scanUsage } = usage ?? {};
          return deepScanTerminalResult(run, {
            scan: {
              progress: { status: progress.status },
              reportAvailable,
              ...(usage && { usage: scanUsage }),
              ...(cost && {
                cost: { model: cost.model, estimatedUsd: cost.estimatedUsd },
              }),
            },
          });
        } catch (error) {
          logDeepScanEvent({
            event: "coordinator_completion_failed",
            scanId: run.scanId,
            reason: failureDiagnostic(error),
          });
          return {
            ...toolErrorResult(
              `${completionFailureMessage(error)}\nScan ID: ${run.scanId}`,
            ),
            structuredContent: { scanId: run.scanId },
          };
        }
      };
      let registeredScanId: string | undefined;
      const preparing = deepScanStartLock.run(async () => {
        const begun = await deepScanStore.begin({
          scanId,
          targetPath,
          scope: hasTarget ? (scope ?? ".") : undefined,
          userContext: normalizedUserContext,
          handoffClaimToken,
          threadId,
          modelThreadId: threadId,
          projectConfigPath,
          ...modelSettings,
          serviceTier:
            typeof serviceTier === "string" ? serviceTier : undefined,
          scanRoot: await scanRoot(),
        });
        registeredScanId = begun.scanId;
        if (handoffClaimToken) {
          authenticatedArtifactClaims.set(begun.scanId, {
            claimToken: handoffClaimToken,
            threadId,
          });
        }
        const immediate = deepScanTerminalResult(begun);
        if (immediate) {
          const coordinator = deepScanCoordinators.get(begun.scanId);
          return {
            begun,
            immediate,
            completion: {
              result:
                (coordinator && deepScanCompletions.get(coordinator)) ??
                completeDeepScan(begun),
            },
          };
        }
        const completion: {
          result?: Promise<ReturnType<typeof deepScanTerminalResult>>;
        } = {};
        const onStart = (coordinator: DeepScanCoordinator) => {
          completion.result = deepScanCompletions.get(coordinator);
          if (!completion.result) {
            // The same hook runs when a remote observer adopts an expired lease.
            // Completion belongs to the coordinator, not an abortable RPC waiter.
            completion.result = coordinator
              .settled()
              .then(completeDeepScan, (error) =>
                toolErrorResult(deepScanInvocationFailureMessage(error)),
              );
            deepScanCompletions.set(coordinator, completion.result);
          }
        };
        const started = await startDeepScanEngine({
          run: begun,
          registry: deepScanCoordinators,
          store: deepScanStore,
          runWorkbench,
          parentSandbox,
          parentTurn: codexParentTurnFromExtra(extra),
          pythonCommand: await resolvePythonCommand(),
          pluginRoot: PLUGIN_ROOT,
          log: logDeepScanEvent,
          handoffClaimToken,
          threadId,
          onStart,
        });
        if (
          !completion.result &&
          started.coordinator instanceof DeepScanCoordinator
        ) {
          onStart(started.coordinator);
        }
        return { begun, ...started, completion };
      });
      let preparation: Awaited<typeof preparing> | undefined;
      let result;
      try {
        preparation = await preparing;
        const { begun } = preparation;
        if (preparation.immediate) {
          result =
            (await preparation.completion.result) ?? preparation.immediate;
        } else {
          const { coordinator, joined } = preparation;
          if (joined) {
            logDeepScanEvent({
              event: "coordinator_joined",
              scanId: begun.scanId,
            });
          }
          const terminal = await coordinator.wait(abortSignalFromExtra(extra));
          result = preparation.completion.result
            ? await preparation.completion.result
            : await completeDeepScan(terminal);
        }
        if (!result) {
          result = toolErrorResult(
            deepScanInvocationFailureMessage(
              new Error(
                `Deep Scan ${begun.scanId} ended without a terminal result.`,
              ),
            ),
          );
        }
        // A canceled waiter or a transport size error never delivers the scan ID.
        const transport = server.server.transport;
        if (
          !handoffClaimToken &&
          "structuredContent" in result &&
          "completion" in result.structuredContent &&
          transport instanceof CodexSecurityStdioTransport
        ) {
          transport.afterResultSent(extra.requestId, extra.signal, () =>
            deepScanStartLock.run(async () => {
              try {
                await workbench("acknowledge-deep-scan-result", {
                  scanId: begun.scanId,
                });
              } catch (error) {
                logDeepScanEvent({
                  event: "target_result_acknowledgment_failed",
                  scanId: begun.scanId,
                  reason: failureDiagnostic(error),
                });
              }
            }),
          );
        }
      } catch (error) {
        // Preparation has a recovery message; waiter failures retain their MCP error text.
        const message = !preparation
          ? deepScanInvocationFailureMessage(error)
          : error instanceof Error
            ? error.message
            : String(error);
        result = toolErrorResult(message);
      }
      return withScanTarget(result, registeredScanId);
    },
  );

  const cancelSecurityScan = async (
    requestedScanId: string,
    threadId?: string,
  ) => {
    const scanId = requestedScanId.toLowerCase();
    const cancelParent = () => workbench("cancel-scan", { scanId, threadId });
    let workspace: Awaited<ReturnType<typeof runWorkbench>> | undefined;
    if (threadId && deepScanCoordinators.get(scanId)) {
      await deepScanStore.get(scanId, threadId);
    }
    const canceledLocally = await deepScanCoordinators.cancelAndWait(
      scanId,
      "user_canceled_scan",
      async () => {
        workspace = await cancelParent();
      },
      async () => {
        const current = (await workbench("get-scan", { scanId }))[
          "workspace"
        ] as JsonObject;
        const scan = current["results"];
        const progress = isJsonObject(scan) ? scan["progress"] : undefined;
        return {
          status:
            isJsonObject(progress) && typeof progress["status"] === "string"
              ? progress["status"]
              : undefined,
          failureMessage:
            isJsonObject(scan) && typeof scan["failureMessage"] === "string"
              ? scan["failureMessage"]
              : undefined,
        };
      },
    );
    if (workspace === undefined && canceledLocally) {
      // A joined caller did not perform the write. Read the requested parent.
      const saved = (await workbench("get-scan", { scanId }))
        .workspace as WorkspaceState;
      const scan = saved.results;
      const progress = isJsonObject(scan?.progress) ? scan.progress : undefined;
      if (progress?.status !== "running") {
        return workspaceResult(
          saved,
          progress?.status === "canceled" && scan?.scanId === scanId
            ? scanId
            : undefined,
        );
      }
    }
    // The displayed workspace may already have a replacement scan.
    const { canceledScanId, ...displayedWorkspace } =
      workspace ?? (await cancelParent());
    return workspaceResult(
      displayedWorkspace as unknown as WorkspaceState,
      canceledScanId === scanId ? canceledScanId : undefined,
    );
  };

  server.registerTool(
    "cancel_codex_security_scan",
    {
      title: "Cancel Codex Security Scan",
      description:
        "Stop a running scan from its owning Codex thread, prevent further progress or completion updates, and cancel any active deterministic Deep Scan SDK workers.",
      inputSchema: scanSchema,
      annotations: destructiveAnnotations,
      _meta: modelActionMeta,
    },
    async ({ scanId }, extra) => {
      const threadId = threadIdFromExtra(extra);
      if (!threadId) {
        return toolErrorResult(
          "Open the scan's continuation thread and try again, or cancel it from the Codex Security workbench.",
        );
      }
      const canceled = await cancelSecurityScan(scanId, threadId);
      modelScanContext(canceled.structuredContent);
      return canceled;
    },
  );

  server.registerTool(
    "cancel_codex_security_scan_from_app",
    {
      title: "Cancel Codex Security Scan From App",
      description:
        "App-only. Stop a running scan from the native Codex Security workbench, prevent further progress or completion updates, and cancel any active deterministic Deep Scan SDK workers.",
      inputSchema: scanSchema,
      annotations: destructiveAnnotations,
      _meta: appMeta,
    },
    async ({ scanId }) => cancelSecurityScan(scanId),
  );

  server.registerTool(
    "recover_codex_security_scan_results",
    {
      title: "Recover Codex Security Scan Results",
      description:
        "App-only. Explicitly validate and republish retained checkpoints for one stopped scan, updating its artifacts, finding index, and counts.",
      inputSchema: scanSchema,
      annotations: destructiveAnnotations,
      _meta: appMeta,
    },
    async ({ scanId }) =>
      scanActionResult(
        await workbench("recover-scan-results", { scanId }),
        "Recovered retained Codex Security scan results.",
      ),
  );

  registerScanHandoffTools(server, { appMeta, runWorkbench, workspaceResult });

  server.registerTool(
    "get_codex_security_scan",
    {
      title: "Get Codex Security Scan",
      description:
        "App-only. Read plugin-owned scan state for native Security monitoring without claiming a pending Codex handoff.",
      inputSchema: scanReadSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ scanId, occurrenceId }) => {
      const context = await workbench("get-scan", { scanId, occurrenceId });
      const loadedId = isJsonObject(context.scan)
        ? context.scan.scanId
        : undefined;
      return scanActionResult(
        context,
        "Loaded Codex Security scan state.",
        loadedId === scanId.toLowerCase() ? loadedId : undefined,
      );
    },
  );

  server.registerTool(
    "list_codex_security_scans",
    {
      title: "List Codex Security Scans",
      description:
        "App-only. Read persisted plugin-owned scan summaries for native Security navigation.",
      inputSchema: scanListSchema,
      annotations: readingAnnotations,
      _meta: appMeta,
    },
    async ({ limit, mode, offset, query, status, targetId }) =>
      scanActionResult(
        await workbench("list-scans", {
          query,
          targetId,
          status,
          mode,
          offset,
          limit,
        }),
        "Loaded Codex Security scan summaries.",
      ),
  );

  server.registerTool(
    "list_codex_security_global_findings",
    {
      title: "List Codex Security Global Findings",
      description:
        "App-only. Read the latest plugin-owned finding occurrence for each stable repository target and finding identity.",
      inputSchema: globalFindingsPageSchema,
      annotations: readingAnnotations,
      _meta: appMeta,
    },
    async ({ limit, offset, query, severity, status, targetId }) =>
      scanActionResult(
        await workbench("list-global-findings", {
          query,
          severity,
          status,
          targetId,
          offset,
          limit,
        }),
        "Loaded Codex Security global findings.",
      ),
  );

  server.registerTool(
    "list_codex_security_repositories",
    {
      title: "List Codex Security Repositories",
      description:
        "App-only. Read plugin-owned repository summaries and their latest scan state.",
      inputSchema: repositoryListSchema,
      annotations: readingAnnotations,
      _meta: appMeta,
    },
    async ({ limit, offset, query, status, targetId }) =>
      scanActionResult(
        await workbench("list-repositories", {
          query,
          targetId,
          status,
          offset,
          limit,
        }),
        "Loaded Codex Security repositories.",
      ),
  );

  server.registerTool(
    "get_codex_security_scan_context",
    {
      title: "Get Codex Security Scan Context",
      description:
        "Load the authoritative target, mode, optional user context, artifact directory, live progress, and optional selected finding for a launched scan. For a remediation stage, pass the supplied occurrenceId, requestId and actionToken to read only its assigned finding. Providing a launch token records delivery. Loading a running Standard scan with its token from the owning conversation advances preflight to threat_model unless a finding was selected. Validated legacy finding details may be migrated.",
      inputSchema: scanContextSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async (
      { scanId, occurrenceId, requestId, actionToken, handoffClaimToken },
      extra,
    ) => {
      if (requestId || actionToken) {
        if (!occurrenceId || !requestId || !actionToken) {
          throw new Error(
            "Remediation context requires occurrenceId, requestId and actionToken.",
          );
        }
        return scanActionResult(
          await workbench("get-scan", {
            scanId,
            occurrenceId,
            requestId,
            actionToken,
          }),
          "Loaded the assigned remediation finding.",
        );
      }
      const threadId = threadIdFromExtra(extra);
      const cached = authenticatedArtifactClaims.get(scanId);
      const { beganStandardReview, ...scanContext } = handoffClaimToken
        ? await workbench("mark-handoff-delivered", {
            scanId,
            claimToken: handoffClaimToken,
            threadId,
            returnContext: true,
            occurrenceId,
          })
        : await workbench("get-scan", {
            scanId,
            occurrenceId,
            modelThreadId: threadId ?? "",
            contextClaimToken:
              threadId && cached?.threadId === threadId
                ? cached.claimToken
                : "",
          });
      const scan = isJsonObject(scanContext.scan)
        ? scanContext.scan
        : undefined;
      if (
        handoffClaimToken &&
        threadId &&
        scan?.handoffStatus === "delivered" &&
        scan.handoffClaimToken === handoffClaimToken &&
        (scan.continuationThreadId === threadId ||
          recoveryHandoffClaimTokenSchema.safeParse(handoffClaimToken).success)
      ) {
        authenticatedArtifactClaims.set(scanId, {
          claimToken: handoffClaimToken,
          threadId,
        });
      }
      return scanActionResult(
        modelScanContext(scanContext, { omitHandoffClaim: true }),
        (beganStandardReview === true && standardAccessGuidance) ||
          "Loaded Codex Security scan context.",
      );
    },
  );

  server.registerTool(
    "rename_codex_security_scan",
    {
      title: "Rename Codex Security Scan",
      description: "App-only. Change the display name of a saved scan.",
      inputSchema: { ...scanSchema, name: z.string() },
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ scanId, name }) =>
      scanActionResult(
        await workbench("rename-scan", { scanId, name }),
        "Renamed Codex Security scan.",
      ),
  );

  const updateRunningScanContext = async (input: {
    claimToken?: string;
    scanId: string;
    threadId?: string;
    userContext: string;
    workspaceId?: string;
  }) => {
    const updated = await workbench(
      "update-scan-context",
      {
        scanId: input.scanId,
        userContextStdin: true,
        workspaceId: input.workspaceId,
        threadId: input.threadId,
        claimToken: input.claimToken,
      },
      input.userContext,
    );
    return scanActionResult(
      input.threadId ? modelScanContext(updated) : updated,
      "Updated Codex Security scan context.",
    );
  };

  server.registerTool(
    "update_codex_security_scan_context",
    {
      title: "Update Codex Security Scan Context",
      description:
        "Replace the context for a running scan. The next phase uses the new value; workers in the current phase keep their original context.",
      inputSchema: scanContextUpdateSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async ({ scanId, userContext, handoffClaimToken }, extra) => {
      const threadId = threadIdFromExtra(extra);
      if (!threadId) {
        return toolErrorResult(
          "Updating scan context requires the owning Codex thread.",
        );
      }
      return updateRunningScanContext({
        claimToken: handoffClaimToken,
        scanId,
        threadId,
        userContext,
      });
    },
  );

  server.registerTool(
    "update_codex_security_scan_context_from_app",
    {
      title: "Update Codex Security Scan Context From App",
      description:
        "App-only. Replace the context for the running scan attached to this workspace.",
      inputSchema: appScanContextUpdateSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ scanId, userContext }) => {
      const current = await workbench("get-scan", { scanId });
      const workspace = isJsonObject(current.workspace)
        ? current.workspace
        : undefined;
      if (typeof workspace?.id !== "string") {
        return toolErrorResult(
          "Updating scan context requires its owning workspace.",
        );
      }
      return updateRunningScanContext({
        scanId,
        userContext,
        workspaceId: workspace.id,
      });
    },
  );

  server.registerTool(
    "update_codex_security_scan_progress",
    {
      title: "Update Codex Security Scan Progress",
      description:
        "Record a meaningful live scan phase or coverage milestone in the Codex Security workbench.",
      inputSchema: progressSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async (
      {
        scanId,
        deepReviewPass,
        phase,
        phaseItemsTotal,
        phaseItemsCompleted,
        phaseProgressUnit,
        reviewItemsTotal,
        reviewItemsCompleted,
        reportableFindingsCount,
        handoffClaimToken,
      },
      extra,
    ) => {
      const modelSettings = codexModelSettingsFromExtra(extra);
      const { scan, deepPreflight } = await workbench("update-progress", {
        scanId,
        modelUpdate: true,
        modelThreadId: threadIdFromExtra(extra) ?? "",
        coordinatorGeneration: deepScanStore.coordinatorGeneration(scanId),
        ...modelSettings,
        claimToken: handoffClaimToken,
        deepReviewPass,
        phase,
        phaseItemsTotal,
        phaseItemsCompleted,
        phaseProgressUnit,
        reviewItemsTotal,
        reviewItemsCompleted,
        reportableFindingsCount,
      });
      return scanActionResult(
        { scan },
        deepPreflight === true
          ? "Deep Scan is still preparing. Discovery progress begins after its setup worker succeeds."
          : "Updated Codex Security scan progress.",
      );
    },
  );

  server.registerTool(
    "complete_codex_security_scan",
    {
      title: "Complete Codex Security Scan",
      description:
        "Finalization only: validate and seal already-authored scan-manifest.json and findings.json, generate report.md, index findings, and mark the scan complete. For an app-backed running scan, scan-manifest.json is an unsealed draft and must omit scan.sealedAt and scan.artifacts; this tool supplies the exact workbench timestamps, seal, artifact digests, and derived finding identities. Call only after those canonical files exist; this tool does not create missing artifacts or run skipped phases. If it fails, surface the exact error and stop the current response without retrying completion or returning a final, no-findings, structured, or benchmark response.",
      inputSchema: completeScanSchema,
      annotations: writingAnnotations,
      _meta: modelActionMeta,
    },
    async ({ scanId, handoffClaimToken }, extra) => {
      try {
        const threadId = threadIdFromExtra(extra);
        const completed = await workbench("complete-scan", {
          scanId,
          claimToken: handoffClaimToken,
          threadId,
          modelThreadId: threadId ?? "",
          turnId: securityScanTurnId(extra),
        });
        return scanActionResult(
          modelScanContext(completed),
          "Validated and indexed the completed Codex Security scan.",
          isJsonObject(completed.scan) ? completed.scan.scanId : undefined,
        );
      } catch (error) {
        throw new Error(completionFailureMessage(error));
      }
    },
  );

  server.registerTool(
    "finalize_codex_security_scan_usage",
    {
      title: "Finalize Codex Security Scan Usage",
      description:
        "App-only. Record final measured usage after the scan's completion turn has finished. Pass the exact thread and turn returned in usage.completion; do not call while that turn is running.",
      inputSchema: {
        ...scanSchema,
        threadId: z.string().trim().min(1),
        turnId: z.string().trim().min(1),
        turnStatus: z.enum(["completed", "interrupted", "failed"]),
      },
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ scanId, threadId, turnId, turnStatus }) =>
      scanActionResult(
        await workbench("finalize-scan-usage", {
          scanId,
          threadId,
          turnId,
          turnStatus,
        }),
        "Recorded final Codex Security scan usage.",
      ),
  );

  server.registerTool(
    "fail_codex_security_scan",
    {
      title: "Fail Codex Security Scan",
      description:
        "Permanently mark a launched Codex Security scan as failed only after a confirmed unrecoverable blocker. For explicit user cancellation, use cancel_codex_security_scan instead. This terminal action cannot be resumed; incomplete or otherwise resumable work must remain running.",
      inputSchema: failSchema,
      annotations: destructiveAnnotations,
      _meta: modelActionMeta,
    },
    async ({ scanId, message, handoffClaimToken }, extra) => {
      const failed = await workbench("fail-scan", {
        scanId,
        modelThreadId: threadIdFromExtra(extra) ?? "",
        message,
        claimToken: handoffClaimToken,
      });
      const scan = failed["scan"];
      const progress = isJsonObject(scan) ? scan["progress"] : undefined;
      if (isJsonObject(progress) && progress["status"] === "failed")
        deepScanCoordinators.get(scanId)?.failExternallyPersisted(message);
      return scanActionResult(
        modelScanContext(failed),
        "Recorded the Codex Security scan failure.",
        isJsonObject(scan) ? scan.scanId : undefined,
      );
    },
  );

  server.registerTool(
    "set_codex_security_finding_triage",
    {
      title: "Update Codex Security Finding Status",
      description:
        "App-only. Persist a completed finding's local open or closed triage status. Closed findings require one bounded close reason; reopening clears it.",
      inputSchema: findingTriageSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ occurrenceId, status, closeReason, note }) =>
      scanActionResult(
        await workbench("set-finding-triage", {
          occurrenceId,
          status,
          closeReason,
          note,
        }),
        "Updated the local Codex Security finding status.",
      ),
  );

  server.registerTool(
    "request_codex_security_finding_remediation",
    {
      title: "Request Codex Security Finding Remediation",
      description:
        "App-only. Queue a completed finding for Codex remediation before sending the host a generate or regenerate request.",
      inputSchema: findingRemediationClaimSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ occurrenceId, requestId, actionToken }) =>
      scanActionResult(
        await workbench("request-finding-remediation", {
          occurrenceId,
          requestId,
          actionToken,
        }),
        "Queued the local Codex Security finding remediation request.",
      ),
  );

  server.registerTool(
    "request_codex_security_finding_remediation_action",
    {
      title: "Request Codex Security Finding Remediation Action",
      description:
        "App-only. Durably claim an apply or verify handoff before asking Codex to perform the local working-tree operation.",
      inputSchema: findingRemediationActionRequestSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ occurrenceId, requestId, expectedVersion, action, actionToken }) =>
      scanActionResult(
        await workbench("request-finding-remediation-action", {
          occurrenceId,
          requestId,
          expectedVersion: String(expectedVersion),
          action,
          actionToken,
        }),
        `Queued the local Codex Security finding remediation ${action} request.`,
      ),
  );

  for (const { name, title, description, annotations, command, message } of [
    {
      name: "claim_codex_security_finding_remediation_resend",
      title: "Claim Codex Security Finding Remediation Resend",
      description:
        "App-only. Atomically take ownership of an unowned or stale remediation host request before resending it.",
      annotations: writingAnnotations,
      command: "claim-finding-remediation-resend",
      message: "Claimed the local Codex Security finding remediation resend.",
    },
    {
      name: "release_codex_security_finding_remediation_claim",
      title: "Release Codex Security Finding Remediation Claim",
      description:
        "App-only. Release a locally owned remediation host request after message delivery fails.",
      annotations: writingAnnotations,
      command: "release-finding-remediation-claim",
      message: "Released the local Codex Security finding remediation claim.",
    },
    {
      name: "cancel_codex_security_finding_remediation_request",
      title: "Cancel Codex Security Finding Remediation Request",
      description:
        "App-only. Roll back an owned remediation request after the user declines its host follow-up.",
      annotations: destructiveAnnotations,
      command: "cancel-finding-remediation-request",
      message: "Canceled the local Codex Security finding remediation request.",
    },
    {
      name: "mark_codex_security_finding_remediation_delivered",
      title: "Mark Codex Security Finding Remediation Delivered",
      description:
        "App-only. Seal host-message delivery ownership before Codex starts a remediation worker.",
      annotations: writingAnnotations,
      command: "mark-finding-remediation-delivered",
      message:
        "Marked the local Codex Security finding remediation request as delivered.",
    },
  ]) {
    server.registerTool(
      name,
      {
        title,
        description,
        inputSchema: findingRemediationClaimSchema,
        annotations,
        _meta: appMeta,
      },
      async ({ occurrenceId, requestId, actionToken }) =>
        scanActionResult(
          await workbench(command, { occurrenceId, requestId, actionToken }),
          message,
        ),
    );
  }

  server.registerTool(
    "set_codex_security_finding_remediation",
    {
      title: "Update Codex Security Finding Remediation",
      description:
        "Persist the bounded local remediation workflow state for a completed finding. The UI may mark a request as queued; Codex records generated, applied, verifying, verified, or failed states after performing the corresponding work.",
      inputSchema: findingRemediationSchema,
      annotations: nonIdempotentWritingAnnotations,
      _meta: modelActionMeta,
    },
    async ({ patch, ...fields }) =>
      scanActionResult(
        await workbench(
          "set-finding-remediation",
          { ...fields, patchStdin: patch !== undefined, assignedFinding: true },
          typeof patch === "object"
            ? Buffer.from(patch.content, patch.encoding)
            : patch,
        ),
        "Updated the local Codex Security finding remediation state.",
      ),
  );

  server.registerTool(
    "export_codex_security_findings",
    {
      title: "Export Codex Security Artifacts",
      description:
        "App-only. Export retained local findings as JSON, SARIF, or CSV, or the saved threat model as Markdown without running another analysis. Findings require completed or preserved stopped results; threat models may be provisional. Defaults to findings in CSV, or Markdown when artifact is threat-model. Exported copies remain in the scan's exports directory, except canonical findings JSON.",
      inputSchema: findingsExportSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ scanId, artifact, format }) =>
      scanActionResult(
        await workbench("export-findings", { scanId, artifact, format }),
        artifact === "threat-model"
          ? "Exported the saved Codex Security threat model as Markdown."
          : `Exported Codex Security findings as ${(format ?? "csv").toUpperCase()}.`,
      ),
  );

  server.registerTool(
    "list_codex_security_findings",
    {
      title: "List Codex Security Findings",
      description:
        "App-only. Load one bounded page of indexed findings for a completed local scan, migrating validated legacy finding details when needed.",
      inputSchema: findingsPageSchema,
      annotations: writingAnnotations,
      _meta: appMeta,
    },
    async ({ limit, offset, query, scanId, severity, status }) =>
      scanActionResult(
        await workbench("list-findings", {
          scanId,
          query,
          severity,
          status,
          offset,
          limit,
        }),
        "Loaded a local Codex Security findings page.",
      ),
  );

  registerFindingIssueTools(server, runWorkbench);
  registerCompactArtifactTools(server, {
    runWorkbench,
    threadIdFromExtra,
    pluginRoot: PLUGIN_ROOT,
    resolveScanRoot: scanRoot,
    resolveHandoffClaimToken: (scanId, requestContext) => {
      const claim = authenticatedArtifactClaims.get(scanId);
      return claim && claim.threadId === threadIdFromExtra(requestContext)
        ? claim.claimToken
        : undefined;
    },
  });

  return server;
}

async function createWorkspace(
  input: {
    diffTarget?: z.infer<typeof diffTargetSchema>;
    mode?: "diff" | "standard" | "deep";
    scope?: string;
    targetPath?: string;
    targetSummary?: string;
    targetTitle?: string;
    userContext?: string;
  },
  threadId?: string,
): Promise<WorkspaceState> {
  return (await workbench(
    "create-workspace",
    {
      workspaceId: randomUUID(),
      threadId,
      mode: input.mode,
      targetPath: input.targetPath,
      targetTitle: input.targetTitle,
      targetSummary: input.targetSummary,
      scope: input.scope,
      userContextStdin: Boolean(input.userContext),
      ...diffTargetFields(input.diffTarget),
    },
    input.userContext,
  )) as WorkspaceState;
}

async function getWorkspace(
  workspaceId: string,
  threadId?: string,
): Promise<WorkspaceState> {
  return (await workbench("get-workspace", {
    workspaceId,
    threadId,
  })) as WorkspaceState;
}

async function startPromptOnlyScan(
  input: PromptOnlyScanInput,
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {},
): Promise<JsonObject> {
  const { mode, targetPath, scope, targetSummary, userContext, diffTarget } =
    input;
  return await workbench(
    "start-prompt-only-scan",
    {
      threadId,
      targetPath,
      scope,
      mode,
      ...modelSettings,
      targetSummary,
      userContextStdin: Boolean(userContext),
      ...diffTargetFields(diffTarget),
      scanRoot: await scanRoot(),
    },
    userContext,
  );
}

async function startHeadlessStandardScan(
  input: {
    targetPath: string;
    scope?: string;
    targetSummary?: string;
    userContext?: string;
  },
  threadId: string,
  modelSettings: { model?: string; reasoningEffort?: string } = {},
): Promise<JsonObject> {
  return await workbench(
    "start-headless-standard-scan",
    {
      threadId,
      targetPath: input.targetPath,
      scope: input.scope ?? ".",
      ...modelSettings,
      targetSummary: input.targetSummary || undefined,
      userContextStdin: Boolean(input.userContext),
      scanRoot: await scanRoot(),
    },
    input.userContext,
  );
}

async function deepScanProjectSetup(
  targetPath: string,
  projectConfigPath: string | undefined,
  action: "preview" | "save",
) {
  if (projectConfigPath === undefined) return { targetPath };
  const inspectWithSetup =
    action === "preview" && (await isCanonicalDirectory(targetPath));
  if (!inspectWithSetup) targetPath = await inspectProjectTarget(targetPath);
  try {
    const project = await readDeepScanProjectConfig(
      projectConfigPath,
      targetPath,
    );
    return { targetPath, projectConfigJson: JSON.stringify(project) };
  } catch (error) {
    // Target or Git errors take precedence over an invalid project file.
    if (inspectWithSetup) await inspectProjectTarget(targetPath);
    throw error;
  }
}

async function isCanonicalDirectory(targetPath: string): Promise<boolean> {
  // Leave home expansion, UNC paths and drive-relative paths to the workbench.
  if (
    process.platform === "win32"
      ? !/^[A-Za-z]:[/\\]/.test(targetPath)
      : !isAbsolute(targetPath)
  )
    return false;
  try {
    return (
      (await realpath(targetPath)) === targetPath &&
      (await stat(targetPath)).isDirectory()
    );
  } catch {
    return false;
  }
}

async function inspectProjectTarget(targetPath: string): Promise<string> {
  const inspected = await workbench("inspect-target", { targetPath });
  if (typeof inspected.targetPath !== "string")
    throw new Error("Missing scan target path.");
  return inspected.targetPath;
}

function wholeTargetScope(
  scope: string | undefined,
  targetPath: string | undefined,
): boolean {
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

function modelScanContext<T extends JsonObject>(
  context: T,
  options?: { omitHandoffClaim: boolean },
): T {
  const workspace = isJsonObject(context.workspace)
    ? context.workspace
    : undefined;
  // Only a workbench action handoff authorizes a model to act on a finding.
  for (const scan of [context.scan, workspace?.results]) {
    if (!isJsonObject(scan)) continue;
    if (options?.omitHandoffClaim) delete scan.handoffClaimToken;
    if (!Array.isArray(scan.findings)) continue;
    for (const finding of scan.findings) {
      if (isJsonObject(finding) && isJsonObject(finding.remediationState)) {
        delete finding.remediationState.actionClaimToken;
      }
    }
  }
  return context;
}

function workspaceResult(workspace: WorkspaceState, scanId?: unknown) {
  const results = workspace.results;
  const setupSummary = workspace.setup.submitted
    ? "Codex Security setup is saved."
    : "Waiting for bounded scan setup choices.";
  const resultsSummary =
    results && typeof results.scanDir === "string"
      ? ` Scan state is attached at ${results.scanDir}.`
      : "";
  return scanActionResult(
    { workspace },
    `${setupSummary}${resultsSummary}`,
    scanId,
  );
}

const standardAccessGuidance =
  "For a ChatGPT-backed scan, follow the optional account check in the plugin's references/access-advisory.md before review. Skip it for Amazon Bedrock or API-key-only scans.";
const startedScanSchema = z
  .object({
    startDisposition: z.enum(["created", "joined"]),
    scan: z.looseObject({
      scanId: scanSchema.scanId,
      scanDir: z.string().refine((value) => value.trim().length > 0),
      handoffStatus: z.literal("delivered"),
    }),
    workspace: z.object({ results: z.object({ scanId: z.string() }) }),
  })
  .refine(({ scan, workspace }) => scan.scanId === workspace.results.scanId);

function promptOnlyScanResult(promptOnly: JsonObject) {
  const start = startedScanSchema.safeParse(promptOnly).data;
  if (!start) {
    return toolErrorResult(
      "Codex Security prompt-only scan returned malformed context; no prompt-driven scan was started.",
    );
  }
  const {
    startDisposition,
    scan: { scanId },
  } = start;
  const advisory =
    start.scan.mode === "standard" && startDisposition === "created"
      ? standardAccessGuidance
      : undefined;
  return scanActionResult(
    modelScanContext(promptOnly),
    `${advisory ? advisory + "\n" : ""}${startDisposition === "joined" ? "Rejoined" : "Started"} prompt-driven scan ${scanId}. Use the returned scanId and scanDir for every phase. Save progress and the final semantic draft with record_codex_security_scan_draft; the workbench writes the unsealed canonical files. Then call complete_codex_security_scan once to seal and index the completed findings.`,
    scanId,
  );
}

function withScanTarget<T extends CallToolResult>(result: T, scanId: unknown) {
  if (scanId === undefined) return result;
  const id = scanSchema.scanId.safeParse(scanId);
  if (!id.success) return result;
  return {
    ...result,
    _meta: {
      ...result._meta,
      "codex/telemetry": { span: { target_id: id.data } },
    },
  };
}

function scanActionResult<T extends JsonObject>(
  result: T,
  summary: string,
  scanId?: unknown,
) {
  return withScanTarget(
    {
      content: [{ type: "text" as const, text: summary }],
      structuredContent: result,
    },
    scanId,
  );
}

function toolErrorResult(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true,
  };
}

function buildUserInputElicitation(
  questions: z.infer<typeof userInputQuestionsSchema>,
) {
  const isSingleQuestion = questions.length === 1;
  return {
    mode: "form" as const,
    message: questions
      .map((question) =>
        [
          ...(isSingleQuestion ? [] : [question.header]),
          question.question,
          ...question.options.map(
            (option) => `- ${option.label}: ${option.description}`,
          ),
        ].join("\n"),
      )
      .join("\n\n"),
    requestedSchema: {
      type: "object" as const,
      properties: Object.fromEntries(
        questions.map((question) => [
          question.id,
          {
            type: "string" as const,
            title: question.header,
            description: question.question,
            oneOf: question.options.map((option) => ({
              const: option.label,
              title: option.label,
            })),
          },
        ]),
      ),
      required: questions.map((question) => question.id),
    },
  };
}

function userInputToolResult(
  status: "accepted" | "declined" | "cancelled" | "unavailable",
  answers?: Record<string, string>,
) {
  const text =
    status === "accepted"
      ? `The user answered the Codex Security question: ${JSON.stringify(answers)}.`
      : status === "declined"
        ? "The user declined the Codex Security input request. Do not infer an answer."
        : status === "cancelled"
          ? "The Codex Security input request was cancelled. Do not infer an answer."
          : "Structured Codex Security input is unavailable in this host. Use the documented plain-chat fallback.";
  return scanActionResult({ status, ...(answers ? { answers } : {}) }, text);
}

async function logUserInputFailure(
  server: McpServer,
  error: unknown,
): Promise<void> {
  const errorData = boundedErrorData(error);
  try {
    await server.sendLoggingMessage({
      level: "warning",
      logger: "codex-security.user-input",
      data: {
        event: "elicitation_failed",
        error: errorData,
      },
    });
  } catch {
    console.warn(
      "Codex Security user-input elicitation failed:",
      JSON.stringify(errorData),
    );
  }
}

function boundedErrorData(error: unknown): { message: string; name: string } {
  const name =
    error instanceof Error && error.name.trim() ? error.name : "UnknownError";
  return {
    name: name.slice(0, 128),
    message: (error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "Unknown user-input elicitation failure."
    ).slice(0, 1000),
  };
}

function deepScanTerminalResult(
  run: DeepScanRunState,
  completion?: JsonObject,
) {
  if (run.status === "succeeded") {
    if (!run.manifestPath) return undefined;
    const outcome =
      run.terminalReason === "capped" && run.completionSequence === 0
        ? "The discovery deadline expired before any Standard scan completed. Report the coverage limitation."
        : "Report the retained findings from completed Standard scans.";
    const instructions = run.sdkOwnsCompletion
      ? `Deep Scan ${run.scanId} stopped. ${outcome} End this turn with the returned scanId and manifestPath. The SDK owns finalization and report generation after the turn ends.`
      : `Deep Scan ${run.scanId} completed. ${outcome} The coordinator sealed scan-manifest.json and findings.json and generated report.md under ${run.scanDir}. Use the returned authoritative scanId, scanDir, and manifestPath. Do not call complete_codex_security_scan again, rerun worker phases, list candidates, submit another draft, or start a replacement scan. Link the generated report.`;
    return scanActionResult(
      {
        scanId: run.scanId,
        scanDir: run.scanDir,
        manifestPath: run.manifestPath,
        completedAudits: run.completionSequence,
        terminalReason: run.terminalReason,
        ...(completion === undefined
          ? {}
          : { completion, reportPath: resolve(run.scanDir, "report.md") }),
        instructions,
      },
      instructions,
    );
  }
  if (run.status === "canceled") {
    if (run.error?.trim()) return toolErrorResult(deepScanFailureMessage(run));
    const instructions = `Deep Scan ${run.scanId} was canceled. Saved findings and pending candidates remain available in the scan's retained results. Do not start additional scan work or claim complete coverage.`;
    return scanActionResult(
      {
        status: "canceled",
        scanId: run.scanId,
        scanDir: run.scanDir,
        instructions,
      },
      instructions,
    );
  }
  if (run.status === "failed" || run.status === "interrupted") {
    if (run.resumeAvailable) {
      const instructions = [
        run.error ?? "Deep Scan was interrupted.",
        `Deep Scan ${run.scanId} is paused. Accepted reviews and unfinished work remain saved; the scan is not complete.`,
        `After usage allowance is available, resume start_codex_security_deep_scan with the same scanId and handoffClaimToken. For a CLI-owned scan, use codex-security scans resume ${run.scanId}. Existing scan limits still apply.`,
        "Do not retry in this response, start a replacement scan, or call complete_codex_security_scan.",
      ].join("\n");
      return {
        ...scanActionResult(
          {
            status: "interrupted",
            scanId: run.scanId,
            scanDir: run.scanDir,
            resumeAvailable: true,
            instructions,
          },
          instructions,
        ),
        isError: true,
      };
    }
    return toolErrorResult(deepScanFailureMessage(run));
  }
  return undefined;
}

function logDeepScanEvent(event: DeepScanLogEvent): void {
  console.error(
    JSON.stringify({ component: "codex_security_deep_scan", ...event }),
  );
}

function workbench(
  command: string,
  fields: WorkbenchFields,
  input?: string | Buffer,
) {
  return runWorkbench(workbenchArgs(command, fields), input);
}

function diffTargetFields(
  target: z.infer<typeof diffTargetSchema> | undefined,
) {
  if (!target) return {};
  return {
    diffTargetKind: target.kind,
    diffBaseRevision: target.baseRevision,
    diffHeadRevision: target.headRevision,
    diffContentDigest:
      target.kind === "working_tree" ? target.contentDigest : undefined,
  };
}

function securityScanTurnId(extra: unknown): string | undefined {
  const metadata = codexTurnMetadataFromExtra(extra);
  return metadata?.thread_source === "security_scan" &&
    typeof metadata.turn_id === "string" &&
    metadata.turn_id
    ? metadata.turn_id
    : undefined;
}

function daybreakAccess(extra: unknown) {
  const metadata = requestMetadataFromExtra(extra);
  const threadId =
    typeof metadata?.threadId === "string" && metadata.threadId.trim()
      ? metadata.threadId.trim()
      : undefined;
  const parsed = threadId
    ? daybreakEntitlementContextSchema.safeParse(
        metadata?.["openai/entitlementContext"],
      )
    : undefined;
  const snapshot = parsed?.success
    ? parsed.data.entitlements.cyber_trusted_access
    : {
        schemaVersion: 1 as const,
        status: "unknown" as const,
        grants: [],
        checkedAt: new Date().toISOString(),
        stale: false,
      };
  const status = snapshot.stale ? "unknown" : snapshot.status;
  const programs =
    status === "granted"
      ? [
          ...new Set(
            snapshot.grants.map(({ level }) =>
              level === "tac3" || level === "government"
                ? "Daybreak Red"
                : "Daybreak Blue",
            ),
          ),
        ]
      : [];
  return {
    schemaVersion: snapshot.schemaVersion,
    status,
    programs,
    checkedAt: snapshot.checkedAt,
    stale: snapshot.stale,
    ...(snapshot.enrollmentUrl
      ? { enrollmentUrl: snapshot.enrollmentUrl }
      : {}),
  };
}

function requestMetadataFromExtra(extra: unknown): JsonObject | undefined {
  if (!isJsonObject(extra)) return undefined;
  const requestInfo = isJsonObject(extra.requestInfo)
    ? extra.requestInfo
    : undefined;
  return isJsonObject(requestInfo?._meta)
    ? requestInfo._meta
    : isJsonObject(extra._meta)
      ? extra._meta
      : undefined;
}

function threadIdFromExtra(extra: unknown): string | undefined {
  const metadata = requestMetadataFromExtra(extra);
  for (const key of [
    "openai/threadId",
    "openai/thread_id",
    "codexThreadId",
    "codex_thread_id",
    "threadId",
    "thread_id",
  ]) {
    const value = metadata?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  const thread = isJsonObject(metadata?.thread) ? metadata.thread : undefined;
  if (typeof thread?.id === "string" && thread.id.trim())
    return thread.id.trim();
  const threadId = codexTurnMetadataFromExtra(extra)?.thread_id;
  return typeof threadId === "string" && threadId.trim()
    ? threadId.trim()
    : undefined;
}

function codexTurnMetadataFromExtra(extra: unknown): JsonObject | undefined {
  const metadata = requestMetadataFromExtra(extra);
  return isJsonObject(metadata?.["x-codex-turn-metadata"])
    ? metadata["x-codex-turn-metadata"]
    : undefined;
}

function codexParentTurnFromExtra(
  extra: unknown,
): DeepScanParentTurn | undefined {
  const metadata = codexTurnMetadataFromExtra(extra);
  const threadId = metadata?.thread_id;
  const turnId = metadata?.turn_id;
  return typeof threadId === "string" &&
    threadId &&
    typeof turnId === "string" &&
    turnId
    ? { threadId, turnId }
    : undefined;
}

function codexModelSettingsFromExtra(extra: unknown): {
  model?: string;
  reasoningEffort?: string;
} {
  // Codex supplies the already-resolved runtime model and effective effort on every MCP call.
  const turnMetadata = codexTurnMetadataFromExtra(extra);
  const model =
    typeof turnMetadata?.model === "string"
      ? turnMetadata.model.trim()
      : undefined;
  const reasoningEffort =
    typeof turnMetadata?.reasoning_effort === "string"
      ? turnMetadata.reasoning_effort.trim()
      : undefined;
  return {
    ...(model ? { model } : {}),
    ...(reasoningEffort ? { reasoningEffort } : {}),
  };
}

function abortSignalFromExtra(extra: unknown): AbortSignal | undefined {
  if (!isJsonObject(extra)) return undefined;
  return extra.signal instanceof AbortSignal ? extra.signal : undefined;
}

function failureDiagnostic(error: unknown): string {
  return error instanceof Error && error.message.trim()
    ? error.message.trim()
    : String(error);
}

function completionFailureMessage(error: unknown): string {
  return [
    "Codex Security scan completion failed.",
    failureDiagnostic(error),
    "Stop the current response and surface this exact MCP error.",
    "Do not retry completion or return a final, no-findings, structured, or benchmark response.",
  ].join("\n");
}

function deepScanInvocationFailureMessage(error: unknown): string {
  return [
    "Codex Security Deep Scan discovery did not start or rejoin.",
    failureDiagnostic(error),
    "Stop the current response and surface this exact MCP error.",
    "Do not call start_codex_security_deep_scan again in this response.",
    "Do not call get_codex_security_scan_context in this response.",
    "Do not call complete_codex_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel, return a final or no-findings result, satisfy a structured output schema, or emit benchmark JSON.",
  ].join("\n");
}

function deepScanFailureMessage(run: DeepScanRunState): string {
  return [
    `${run.error ?? `Deep Scan ${run.scanId} ${run.status}.`}${
      run.manifestPath ? ` Failure manifest: ${run.manifestPath}.` : ""
    }`,
    "This is a terminal failure of this logical Deep Scan; no successful discovery manifest was returned.",
    "Stop further scanning and surface this exact stable MCP failure. Read the existing scan context to report saved findings and pending candidates separately, with the reason execution stopped.",
    "Do not call start_codex_security_deep_scan again in this response.",
    "Do not call complete_codex_security_scan in this response.",
    "Do not start a replacement Deep Scan, call cancel for this terminal scan, claim a successful or no-findings scan, satisfy a successful-scan output schema, or emit benchmark JSON.",
  ].join("\n");
}
