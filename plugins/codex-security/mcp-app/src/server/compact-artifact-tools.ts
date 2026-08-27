import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodType } from "zod/v4";
import {
  createScanArtifactContext,
  type ArtifactContext,
  type RunArtifactWorkbench
} from "../artifact-context.js";
import {
  listCodexSecurityReviewItems,
  prepareCodexSecurityReviewItems,
  prepareReviewItemsInputSchema,
  reviewItemsReaderInputSchema
} from "../artifact-inventory.js";
import {
  listCodexSecurityCandidates,
  recordCodexSecurityDiscoveryCandidates,
  workbenchDiscoveryCandidatesInputSchema,
  workbenchListCodexSecurityCandidatesInputSchema
} from "../artifact-discovery.js";
import {
  candidateValidationsInputSchema,
  recordCodexSecurityCandidateValidations
} from "../artifact-validation-phase.js";
import {
  candidateAttackPathsInputSchema,
  recordCodexSecurityCandidateAttackPaths
} from "../artifact-attack-path.js";
import {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  getCodexSecurityDeepReducerInputs,
  recordCodexSecurityDeepReduction
} from "../artifact-deep-reducer.js";
import {
  completedScanInputSchema,
  getCodexSecurityCompletedScan,
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  scanDraftInputSchema,
  type ScanDraftInput
} from "../artifact-scan-draft.js";

type JsonRecord = Record<string, unknown>;

export interface CompactArtifactToolOptions {
  runWorkbench: RunArtifactWorkbench;
  pluginRoot: string;
  resolveHandoffClaimToken?: (
    scanId: string,
    requestContext: unknown
  ) => string | undefined;
}

const modelOnlyMeta = {
  ui: { visibility: ["model"] as const }
};

const readingAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

const writingAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

/** Prepare diff inventories and read existing diff or Deep inventories. */
export function registerReviewItemTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(server, {
    name: "prepare_codex_security_review_items",
    title: "Prepare Codex Security Review Items",
    description: "Generate the changed-file inventory for a diff scan.",
    inputSchema: prepareReviewItemsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = prepareReviewItemsInputSchema.parse(value);
      return prepareCodexSecurityReviewItems(
        await phaseScanContext(input, options, requestContext, "diff")
      );
    }
  });

  registerCompactTool(server, {
    name: "list_codex_security_review_items",
    title: "List Codex Security Review Items",
    description: "Read one page of the diff or Deep scan discovery inventory.",
    inputSchema: reviewItemsReaderInputSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = reviewItemsReaderInputSchema.parse(value);
      return listCodexSecurityReviewItems(
        await phaseScanContext(input, options, requestContext),
        input
      );
    }
  });
}

/** Record diff candidates and read existing diff or Deep candidates. */
export function registerDiscoveryCandidateTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  const writerSchema = workbenchDiscoveryCandidatesInputSchema;
  const readerSchema = workbenchListCodexSecurityCandidatesInputSchema;

  registerCompactTool(server, {
    name: "record_codex_security_discovery_candidates",
    title: "Record Codex Security Discovery Candidates",
    description: "Normalize and replace the selected diff scan's candidates.",
    inputSchema: writerSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = writerSchema.parse(value);
      return recordCodexSecurityDiscoveryCandidates(
        { candidates: input.candidates },
        await phaseScanContext(input, options, requestContext, "diff")
      );
    }
  });

  registerCompactTool(server, {
    name: "list_codex_security_candidates",
    title: "List Codex Security Candidates",
    description: "Read one page of diff or Deep scan discovery candidates.",
    inputSchema: readerSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = readerSchema.parse(value);
      return listCodexSecurityCandidates(
        {
          ...(input.cursor === undefined ? {} : { cursor: input.cursor }),
          ...(input.limit === undefined ? {} : { limit: input.limit })
        },
        await phaseScanContext(input, options, requestContext)
      );
    }
  });
}

/** Record centralized validation results for a diff or Deep scan. */
export function registerCandidateValidationTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(server, {
    name: "record_codex_security_candidate_validations",
    title: "Record Codex Security Candidate Validations",
    description: "Record the diff or Deep scan candidate validation results.",
    inputSchema: candidateValidationsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = candidateValidationsInputSchema.parse(value);
      return recordCodexSecurityCandidateValidations(
        await phaseScanContext(input, options, requestContext),
        { validations: input.validations }
      );
    }
  });
}

/** Record centralized attack-path results for a diff or Deep scan. */
export function registerCandidateAttackPathTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(server, {
    name: "record_candidate_attack_paths",
    title: "Record Codex Security Candidate Attack Paths",
    description: "Record the diff or Deep scan candidate attack-path results.",
    inputSchema: candidateAttackPathsInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = candidateAttackPathsInputSchema.parse(value);
      return recordCodexSecurityCandidateAttackPaths(
        await phaseScanContext(input, options, requestContext),
        { attackPaths: input.attackPaths }
      );
    }
  });
}

/** Register draft construction and read-only completed scan retrieval. */
export function registerScanDraftTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  registerCompactTool(server, {
    name: "record_codex_security_scan_draft",
    title: "Record Codex Security Scan Draft",
    description: "Save semantic findings and coverage as an unsealed draft. Use complete:false for progress checkpoints, then complete:true for the final result; keep unvalidated candidates in coverage.deferred.",
    inputSchema: scanDraftInputSchema,
    readOnly: false,
    handler: async (value, requestContext) => {
      const input = scanDraftInputSchema.parse(value);
      return recordCodexSecurityScanDraftViaWorkbench(
        await scanContext(input, options, true, requestContext),
        input,
        options.runWorkbench,
        signalFromRequestContext(requestContext)
      );
    }
  });

  registerCompactTool(server, {
    name: "get_codex_security_completed_scan",
    title: "Get Completed Codex Security Scan",
    description: "Read the selected scan's existing completed, sealed canonical documents.",
    inputSchema: completedScanInputSchema,
    readOnly: true,
    handler: async (value, requestContext) => {
      const input = completedScanInputSchema.parse(value);
      return getCodexSecurityCompletedScan(
        await scanContext(input, options, false, requestContext),
        input
      );
    }
  });
}

function signalFromRequestContext(requestContext: unknown): AbortSignal | undefined {
  if (typeof requestContext !== "object" || requestContext === null) return undefined;
  const signal = Reflect.get(requestContext, "signal");
  return signal instanceof AbortSignal ? signal : undefined;
}

/** Keep each vertical operation independently reviewable and registered. */
export function registerCompactArtifactTools(
  server: McpServer,
  options: CompactArtifactToolOptions
): void {
  registerReviewItemTools(server, options);
  registerDiscoveryCandidateTools(server, options);
  registerCandidateValidationTools(server, options);
  registerCandidateAttackPathTools(server, options);
  registerScanDraftTools(server, options);
}

/** Expose only the operations appropriate to the inherited worker phase. */
export function registerCompactWorkerArtifactTools(
  server: McpServer,
  context: ArtifactContext
): void {
  if (context.layout === "worker") {
    registerCompactTool(server, {
      name: "record_codex_security_scan_draft",
      title: "Record Codex Security Scan Draft",
      description: "Save this Standard worker's semantic findings and coverage. Use complete:false for progress checkpoints, then complete:true for its final result; keep unvalidated candidates in coverage.deferred.",
      inputSchema: scanDraftInputSchema,
      readOnly: false,
      handler: async (value) => recordCodexSecurityWorkerScanDraft(
        context,
        value as ScanDraftInput
      )
    });
    return;
  }

  if (context.layout !== "reducer") {
    throw new Error("The lightweight artifact server requires a bound discovery or reducer worker.");
  }

  registerCompactTool(server, {
    name: "get_codex_security_deep_reducer_inputs",
    title: "Get Codex Security Deep Reducer Inputs",
    description: "Read the complete Standard scan results assigned to this reducer.",
    inputSchema: deepReducerInputsInputSchema,
    readOnly: true,
    handler: async () => getCodexSecurityDeepReducerInputs(context)
  });

  registerCompactTool(server, {
    name: "record_codex_security_deep_reduction",
    title: "Record Codex Security Deep Reduction",
    description: "Record this reducer's complete aggregated Standard scan result.",
    inputSchema: deepReductionInputSchema,
    readOnly: false,
    handler: async (value) => recordCodexSecurityDeepReduction(
      context,
      value as ScanDraftInput
    )
  });
}

interface CompactToolRegistration {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodType;
  readOnly: boolean;
  handler: (value: unknown, requestContext: unknown) => Promise<object>;
}

function registerCompactTool(
  server: McpServer,
  registration: CompactToolRegistration
): void {
  server.registerTool(registration.name, {
    title: registration.title,
    description: registration.description,
    inputSchema: registration.inputSchema,
    annotations: registration.readOnly ? readingAnnotations : writingAnnotations,
    _meta: modelOnlyMeta
  }, async (input: unknown, requestContext: unknown) => {
    const value = await registration.handler(input, requestContext);
    return {
      content: [{ type: "text" as const, text: JSON.stringify(value) }],
      structuredContent: value as JsonRecord
    };
  });
}

async function scanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requireRunning = true,
  requestContext?: unknown
): Promise<ArtifactContext> {
  return createScanArtifactContext(input.scanId, options.runWorkbench, {
    requireRunning,
    requireClaim: true,
    handoffClaimToken: input.handoffClaimToken
      ?? options.resolveHandoffClaimToken?.(input.scanId, requestContext),
    pluginRoot: options.pluginRoot
  });
}

async function phaseScanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requestContext?: unknown,
  requiredMode?: "diff"
): Promise<ArtifactContext> {
  const context = await scanContext(input, options, true, requestContext);
  if (context.mode !== "deep" && context.mode !== "diff") {
    throw new Error("This operation is only available for Deep or diff scans.");
  }
  if (requiredMode && context.mode !== requiredMode) {
    throw new Error("This operation is only available for diff scans.");
  }
  return context;
}
