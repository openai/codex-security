import { readingAnnotations, writingAnnotations } from "./tool-annotations.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodType } from "zod/v4";
import type { JsonObject as JsonRecord } from "../types.js";
import {
  createScanArtifactContext,
  type ArtifactContext,
  type RunArtifactWorkbench,
} from "../artifact-context.js";
import {
  listCodexSecurityReviewItems,
  prepareCodexSecurityReviewItems,
  prepareReviewItemsInputSchema,
  reviewItemsReaderInputSchema,
} from "../artifact-inventory.js";
import {
  listCodexSecurityCandidates,
  recordCodexSecurityDiscoveryCandidates,
  workbenchDiscoveryCandidatesInputSchema,
  workbenchListCodexSecurityCandidatesInputSchema,
} from "../artifact-discovery.js";
import {
  candidateValidationsInputSchema,
  recordCodexSecurityCandidateValidations,
} from "../artifact-validation-phase.js";
import {
  candidateAttackPathsInputSchema,
  recordCodexSecurityCandidateAttackPaths,
} from "../artifact-attack-path.js";
import {
  deepReducerInputsInputSchema,
  deepReductionInputSchema,
  recordCodexSecurityDeepReduction,
} from "../artifact-deep-reducer.js";
import {
  deepReducerPageResponse,
  getCodexSecurityDeepReducerInputsPage,
} from "../artifact-deep-reducer-pages.js";
import {
  completedScanInputSchema,
  getCodexSecurityCompletedScan,
  recordCodexSecurityScanDraftViaWorkbench,
  recordCodexSecurityWorkerScanDraft,
  scanDraftInputSchema,
} from "../artifact-scan-draft.js";

import {
  readArtifactInputSchema,
  readCodexSecurityArtifact,
  saveArtifactInputSchema,
  saveCodexSecurityArtifact,
  standaloneArtifactContext,
  type ArtifactLocation,
} from "../artifact-storage.js";

export interface CompactArtifactToolOptions {
  runWorkbench: RunArtifactWorkbench;
  pluginRoot: string;
  resolveScanRoot: () => Promise<string>;
  resolveHandoffClaimToken?: (
    scanId: string,
    requestContext: unknown,
  ) => string | undefined;
}

const modelOnlyMeta = {
  ui: { visibility: ["model"] as const },
};

function signalFromRequestContext(
  requestContext: unknown,
): AbortSignal | undefined {
  if (typeof requestContext !== "object" || requestContext === null)
    return undefined;
  const signal = Reflect.get(requestContext, "signal");
  return signal instanceof AbortSignal ? signal : undefined;
}

export function registerCompactArtifactTools(
  server: McpServer,
  options: CompactArtifactToolOptions,
): void {
  /** Prepare diff inventories and read existing diff or Deep inventories. */
  registerCompactTool(server, {
    name: "prepare_codex_security_review_items",
    title: "Prepare Codex Security Review Items",
    description: "Generate the changed-file inventory for a diff scan.",
    inputSchema: prepareReviewItemsInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return prepareCodexSecurityReviewItems(
        await phaseScanContext(input, options, requestContext, "diff"),
      );
    },
  });

  registerCompactTool(server, {
    name: "list_codex_security_review_items",
    title: "List Codex Security Review Items",
    description: "Read one page of the diff or Deep scan discovery inventory.",
    inputSchema: reviewItemsReaderInputSchema,
    readOnly: true,
    handler: async (input, requestContext) => {
      return listCodexSecurityReviewItems(
        await phaseScanContext(input, options, requestContext),
        input,
      );
    },
  });

  /** Record diff candidates and read existing diff or Deep candidates. */
  registerCompactTool(server, {
    name: "record_codex_security_discovery_candidates",
    title: "Record Codex Security Discovery Candidates",
    description: "Normalize and replace the selected diff scan's candidates.",
    inputSchema: workbenchDiscoveryCandidatesInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return recordCodexSecurityDiscoveryCandidates(
        input,
        await phaseScanContext(input, options, requestContext, "diff"),
      );
    },
  });

  registerCompactTool(server, {
    name: "list_codex_security_candidates",
    title: "List Codex Security Candidates",
    description: "Read one page of diff or Deep scan discovery candidates.",
    inputSchema: workbenchListCodexSecurityCandidatesInputSchema,
    readOnly: true,
    handler: async (input, requestContext) => {
      return listCodexSecurityCandidates(
        input,
        await phaseScanContext(input, options, requestContext),
      );
    },
  });

  /** Record centralized validation results for a diff or Deep scan. */
  registerCompactTool(server, {
    name: "record_codex_security_candidate_validations",
    title: "Record Codex Security Candidate Validations",
    description: "Record the diff or Deep scan candidate validation results.",
    inputSchema: candidateValidationsInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return recordCodexSecurityCandidateValidations(
        await phaseScanContext(input, options, requestContext),
        input,
      );
    },
  });

  /** Record centralized attack-path results for a diff or Deep scan. */
  registerCompactTool(server, {
    name: "record_candidate_attack_paths",
    title: "Record Codex Security Candidate Attack Paths",
    description: "Record the diff or Deep scan candidate attack-path results.",
    inputSchema: candidateAttackPathsInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return recordCodexSecurityCandidateAttackPaths(
        await phaseScanContext(input, options, requestContext),
        input,
      );
    },
  });

  /** Register draft construction and read-only completed scan retrieval. */
  registerCompactTool(server, {
    name: "record_codex_security_scan_draft",
    title: "Record Codex Security Scan Draft",
    description:
      "Save the canonical threat model, findings and coverage as an unsealed draft. Use complete:false as soon as a model is available, even with empty findings and partial coverage, then for progress checkpoints; use complete:true for the final result. The host derives threatmodel.md. Keep unvalidated candidates in coverage.deferred. On terminal Standard or diff drafts, close generic review tasks with coverage.resolvedDeferred:[{id,reason}], copying IDs from the returned coverage. Update linked surfaces by their saved IDs.",
    inputSchema: scanDraftInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return recordCodexSecurityScanDraftViaWorkbench(
        await scanContext(input, options, true, requestContext),
        input,
        options.runWorkbench,
        signalFromRequestContext(requestContext),
      );
    },
  });

  registerCompactTool(server, {
    name: "get_codex_security_completed_scan",
    title: "Get Completed Codex Security Scan",
    description:
      "Read the selected scan's existing completed, sealed canonical documents.",
    inputSchema: completedScanInputSchema,
    readOnly: true,
    handler: async (input, requestContext) => {
      return getCodexSecurityCompletedScan(
        await scanContext(input, options, false, requestContext),
        input,
      );
    },
  });
  registerCompactTool(server, {
    name: "save_codex_security_artifact",
    title: "Save Codex Security Artifact",
    description:
      "Save a supplemental document or evidence file with temporary or persistent storage. Use scanId for a running scan, or targetPath for standalone documents and shared threat models. Omit path/content/sourcePath to prepare and return the selected directory. Otherwise provide a portable relative path under artifacts/, findings/ or hardening/ (or threatmodel.md for a standalone model) and either exact text content or a sourcePath inside the returned temporary directory. Scan threatmodel.md is host-generated from semantic drafts; canonical scan files and recovery checkpoints use the existing typed scan tools. Does not edit completed scans or source/configuration files.",
    inputSchema: saveArtifactInputSchema,
    readOnly: false,
    handler: async (input, requestContext) => {
      return saveCodexSecurityArtifact(
        await supplementalContext(input, options, true, requestContext),
        input,
        options.runWorkbench,
      );
    },
  });
  registerCompactTool(server, {
    name: "read_codex_security_artifact",
    title: "Read Codex Security Artifact",
    description:
      "Read a saved supplemental artifact from temporary or persistent storage, including after an MCP restart. Use the same scanId or standalone targetPath, storage and relative path used to save it. A scan's host-generated model is threatmodel.md; standalone legacy threat_model.md remains readable.",
    inputSchema: readArtifactInputSchema,
    readOnly: true,
    handler: async (input, requestContext) => {
      return readCodexSecurityArtifact(
        await supplementalContext(input, options, false, requestContext),
        input,
        options.runWorkbench,
      );
    },
  });
}

async function supplementalContext(
  input: ArtifactLocation,
  options: CompactArtifactToolOptions,
  write: boolean,
  requestContext: unknown,
): Promise<ArtifactContext> {
  if ((input.scanId === undefined) === (input.targetPath === undefined)) {
    throw new Error("Provide exactly one scanId or standalone targetPath.");
  }
  if (input.scanId !== undefined)
    return scanContext(
      { ...input, scanId: input.scanId },
      options,
      write,
      requestContext,
    );
  if (input.handoffClaimToken !== undefined)
    throw new Error("A handoff claim requires a scanId.");
  const root = await options.resolveScanRoot();
  return standaloneArtifactContext(
    input.targetPath!,
    options.runWorkbench,
    write,
    root,
    input.storage,
  );
}

/** Expose only the operations appropriate to the inherited worker phase. */
export function registerCompactWorkerArtifactTools(
  server: McpServer,
  context: ArtifactContext,
): void {
  if (context.layout === "worker") {
    registerCompactTool(server, {
      name: "record_codex_security_scan_draft",
      title: "Record Codex Security Scan Draft",
      description:
        "Save this Standard worker's semantic findings and coverage. Use complete:false for progress checkpoints, then complete:true for its final result; keep unvalidated candidates in coverage.deferred. On terminal drafts, close generic review tasks with coverage.resolvedDeferred:[{id,reason}], copying IDs from the returned coverage. Update linked surfaces by their saved IDs.",
      inputSchema: scanDraftInputSchema,
      readOnly: false,
      handler: async (value) =>
        recordCodexSecurityWorkerScanDraft(context, value),
    });
    return;
  }

  if (context.layout !== "reducer") {
    throw new Error(
      "The lightweight artifact server requires a bound discovery or reducer worker.",
    );
  }

  server.registerTool(
    "get_codex_security_deep_reducer_inputs",
    {
      title: "Get Codex Security Deep Reducer Inputs",
      description:
        "Read a byte-budgeted JSON fragment of the assigned findings and previous aggregate. " +
        "Continue with nextCursor; concatenate json fragments before parsing. " +
        "Use findingRef source:<sourceFindingId> or previous:N to read full retained provenance.",
      inputSchema: deepReducerInputsInputSchema,
      annotations: readingAnnotations,
      _meta: modelOnlyMeta,
    },
    async (input) =>
      deepReducerPageResponse(
        await getCodexSecurityDeepReducerInputsPage(context, input),
      ),
  );

  registerCompactTool(server, {
    name: "record_codex_security_deep_reduction",
    title: "Record Codex Security Deep Reduction",
    description: "Record the merged findings and context for this Deep scan.",
    inputSchema: deepReductionInputSchema,
    readOnly: false,
    handler: async (value) => recordCodexSecurityDeepReduction(context, value),
  });
}

interface CompactToolRegistration<Input> {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodType<Input>;
  readOnly: boolean;
  handler: (value: Input, requestContext: unknown) => Promise<object>;
}

function registerCompactTool<Input>(
  server: McpServer,
  registration: CompactToolRegistration<Input>,
): void {
  server.registerTool(
    registration.name,
    {
      title: registration.title,
      description: registration.description,
      inputSchema: registration.inputSchema,
      annotations: registration.readOnly
        ? readingAnnotations
        : writingAnnotations,
      _meta: modelOnlyMeta,
    },
    async (input, requestContext) => {
      const value = await registration.handler(input, requestContext);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(value) }],
        structuredContent: value as JsonRecord,
      };
    },
  );
}

async function scanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requireRunning = true,
  requestContext?: unknown,
): Promise<ArtifactContext> {
  return createScanArtifactContext(input.scanId, options.runWorkbench, {
    requireRunning,
    requireClaim: true,
    handoffClaimToken:
      input.handoffClaimToken ??
      options.resolveHandoffClaimToken?.(input.scanId, requestContext),
    pluginRoot: options.pluginRoot,
  });
}

async function phaseScanContext(
  input: { scanId: string; handoffClaimToken?: string },
  options: CompactArtifactToolOptions,
  requestContext?: unknown,
  requiredMode?: "diff",
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
