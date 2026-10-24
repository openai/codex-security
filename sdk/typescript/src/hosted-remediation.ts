import { randomUUID } from "node:crypto";
import { z } from "zod";
import { errorMessage } from "./errors.js";
import { bundledPluginRoot, pluginMetadata } from "./runtime.js";
import { normalizeRepository, repositoryRevision } from "./targets.js";
import {
  parseFindingPatch,
  parseFindingVerifications,
  remediationPrompt,
  VerificationModeSchema,
  type FindingPatch,
  type FindingVerification,
} from "./remediation.js";
import {
  ScanExecutionResultSchema,
  type ScanExecutionResult,
} from "./scan-executor.js";
import { VERSION } from "./version.js";

export const HostedRemediationInputSchema = z.strictObject({
  version: z.literal(1),
  operation: z.enum(["patch", "verify"]),
  repository: z.string().min(1),
  revision: z.string().regex(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/),
  finding: z.strictObject({
    id: z.string().min(1),
    context: z.string().trim().min(1),
  }),
  instructions: z.string().optional(),
  validationInstructions: z.string().optional(),
  verificationMode: VerificationModeSchema.optional(),
  model: z.string().min(1),
  reasoningEffort: z.string(),
  identity: z.strictObject({
    runId: z.string().min(1),
    attemptId: z.string().min(1),
    buildId: z.string().min(1),
  }),
});

export type HostedRemediationInput = z.infer<
  typeof HostedRemediationInputSchema
>;

export interface RemediationExecutionRequest {
  version: 1;
  requestId: string;
  operation: HostedRemediationInput["operation"];
  repository: string;
  revision: string;
  identity: HostedRemediationInput["identity"];
  findingId: string;
  prompt: string;
  model: string;
  reasoningEffort: HostedRemediationInput["reasoningEffort"];
  sandbox: "workspace-write" | "read-only";
  runtime: { pluginRoot: string; pluginVersion: string };
}

export type RemediationExecutionResult = ScanExecutionResult;
export type RemediationExecutionEvent = Readonly<Record<string, unknown>>;

export interface RemediationExecutor {
  /** Submit once and settle cancellation with the host's recorded receipt. */
  run(
    request: RemediationExecutionRequest,
    options: {
      signal: AbortSignal;
      onEvent?: (event: RemediationExecutionEvent) => void;
    },
  ): Promise<RemediationExecutionResult>;
}

export interface HostedRemediationOptions {
  executor: RemediationExecutor;
  signal?: AbortSignal;
  onEvent?: (event: RemediationExecutionEvent) => void;
}

export interface HostedRemediationResult {
  version: 1;
  operation: HostedRemediationInput["operation"];
  repository: string;
  revision: string;
  identity: HostedRemediationInput["identity"];
  findingId: string;
  status: RemediationExecutionResult["status"];
  provenance: { cliVersion: string; pluginVersion: string; buildId: string };
  execution?: RemediationExecutionResult;
  patch?: FindingPatch;
  verification?: FindingVerification;
  error?: { code: string; message: string };
}

export class HostedRemediationPreparationError extends Error {
  readonly reason = "revision_mismatch";
  constructor() {
    super("Checkout does not match the frozen revision.");
    this.name = "HostedRemediationPreparationError";
  }
}

/**
 * Run one patch or verification through the supplied host executor.
 * The host prepares the candidate checkout, enforces the requested sandbox,
 * and owns patch artifacts, durable attempts, usage, and reconciliation.
 */
export async function runHostedRemediation(
  value: HostedRemediationInput,
  options: HostedRemediationOptions,
): Promise<HostedRemediationResult> {
  const input = HostedRemediationInputSchema.parse(value);
  const signal = options.signal ?? new AbortController().signal;
  signal.throwIfAborted();
  const repository = await normalizeRepository(input.repository, signal);
  if ((await repositoryRevision(repository, signal)) !== input.revision)
    throw new HostedRemediationPreparationError();
  const pluginRoot = await bundledPluginRoot();
  const { version: pluginVersion } = await pluginMetadata(pluginRoot);
  const prompt = await remediationPrompt({
    operation: input.operation,
    pluginRoot,
    contents: [
      { occurrenceId: input.finding.id, context: input.finding.context },
    ],
    structuredPatch: true,
    verificationIds: [input.finding.id],
    instructions: input.instructions,
    validationInstructions: input.validationInstructions,
    verificationMode: input.verificationMode,
  });
  const target = {
    version: 1 as const,
    operation: input.operation,
    repository,
    revision: input.revision,
    identity: input.identity,
    findingId: input.finding.id,
  };
  const request: RemediationExecutionRequest = {
    ...target,
    requestId: randomUUID(),
    prompt,
    model: input.model,
    reasoningEffort: input.reasoningEffort,
    sandbox: input.operation === "verify" ? "read-only" : "workspace-write",
    runtime: { pluginRoot, pluginVersion },
  };
  const base = {
    ...target,
    provenance: {
      cliVersion: VERSION,
      pluginVersion,
      buildId: input.identity.buildId,
    },
  };
  let execution: RemediationExecutionResult | undefined;
  const onEvent = (event: RemediationExecutionEvent) => {
    void Promise.resolve()
      .then(() => options.onEvent?.(event))
      .catch(() => {});
  };
  try {
    signal.throwIfAborted();
    execution = await options.executor.run(request, { signal, onEvent });
    ScanExecutionResultSchema.parse(execution);
    if (execution.requestId !== request.requestId)
      throw new Error(
        "Execution receipt does not match the remediation request.",
      );
    if (execution.status !== "completed")
      return { ...base, status: execution.status, execution };
    if ((await repositoryRevision(repository)) !== input.revision)
      throw new Error(
        "Checkout changed from the frozen revision during execution.",
      );
    const response = execution.finalResponse ?? "";
    const outcome =
      input.operation === "patch"
        ? { patch: parseFindingPatch(response, input.finding.id) }
        : {
            verification: parseFindingVerifications(response, [
              input.finding.id,
            ])[0]!,
          };
    return { ...base, status: "completed", execution, ...outcome };
  } catch (error) {
    return {
      ...base,
      status: signal.aborted && execution === undefined ? "canceled" : "failed",
      ...(execution === undefined ? {} : { execution }),
      error: {
        code: execution === undefined ? "EXECUTION_FAILED" : "INVALID_RESULT",
        message: errorMessage(error),
      },
    };
  }
}
