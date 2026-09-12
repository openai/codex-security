import type { JsonObject } from "../config.js";
import {
  CodexSecurityError,
  type DeduplicationReviewStage,
} from "../errors.js";
import type { Finding } from "../models.js";
import { workflowDigest } from "../finding-workflow.js";
import { VERSION } from "../version.js";
import type { CodexReview } from "./codex-review.js";
import {
  FindingDeduplicator,
  deduplicationConcurrency,
  type DetailedDeduplicationResult,
  type DeduplicationPairOutcome,
} from "./deduplication.js";
import {
  CodexDeduplicationReviewer,
  requireFinding,
} from "./deduplication-reviewer.js";
import {
  DEFAULT_RESULT_TOOL_NAMESPACE,
  reviewSubmissionInstructionsFor,
  reviewErrorInstructions,
  sourceReviewInstructions,
} from "./deduplication-prompts.js";
import {
  runCheckpointedReview,
  type DeduplicationCheckpointStore,
} from "./review-checkpoint.js";

export type { DeduplicationCheckpointStore } from "./review-checkpoint.js";

/** Source operations explicitly registered and executed by the injected host. */
export interface DeduplicationSourceTool {
  namespace: string;
  name: string;
  description: string;
  inputSchema: JsonObject;
  /** Changes when implementation semantics or permissions change. */
  version: string;
}

/** Serializable model assignment; the SDK retains all result validation. */
export interface DeduplicationReviewRequest {
  checkpointKey: string;
  /** Model-visible namespace for submit_decisions and submit_error. */
  resultToolNamespace: string;
  stage: DeduplicationReviewStage;
  model: string;
  effort: string;
  prompt: string;
  schema: unknown;
  instructions: {
    submission: string;
    source: string;
    error: string;
  };
  sourceManifest: JsonObject;
  sourceTools: readonly DeduplicationSourceTool[];
}

export interface DeduplicationReviewRunner {
  /**
   * Register the request's result and source tools in the reviewing runtime.
   * Return the complete raw submission, or throw when required execution/source
   * access fails. A blocker must not be converted into a DISTINCT verdict.
   */
  run(
    request: DeduplicationReviewRequest,
    signal?: AbortSignal,
  ): Promise<unknown>;
}

export interface DeduplicationCandidateProvider {
  /** Return complete candidate records; the supplied observation is authoritative. */
  potentialDuplicates(finding: Finding): Promise<readonly Finding[]>;
}

/** Reuse an earlier pair outcome only with its original immutable-input binding. */
export interface PriorDeduplicationDecision {
  findingIds: readonly [string, string];
  decision: "SAME" | "DISTINCT";
  bindingDigest: string;
}

export interface DeduplicateRecordsOptions {
  observations: readonly Finding[];
  candidateProvider: DeduplicationCandidateProvider;
  reviewRunner: DeduplicationReviewRunner;
  /** Host-established repository identities and exact revisions, without credentials. */
  sourceManifest: JsonObject;
  sourceTools?: readonly DeduplicationSourceTool[];
  /** Verify current source availability/binding, including before checkpoint reuse. */
  verifySource(manifest: JsonObject): Promise<void>;
  /** Isolate review checkpoints and prior decisions belonging to separate corpora. */
  scopeKey: string;
  settingsDigest?: string;
  /** Model-visible result-tool namespace; defaults to review_validator. */
  resultToolNamespace?: string;
  checkpointStore?: DeduplicationCheckpointStore;
  priorDecisions?: readonly PriorDeduplicationDecision[];
  /** Defaults to the existing SDK dedupe concurrency (8). */
  concurrency?: number;
  signal?: AbortSignal;
}

export interface BoundDeduplicationPairOutcome extends DeduplicationPairOutcome {
  bindingDigest: string;
}

export interface DeduplicateRecordsResult extends DetailedDeduplicationResult {
  pairOutcomes: BoundDeduplicationPairOutcome[];
  checkpointKeys: string[];
}

// Changes to record review semantics invalidate saved host review bindings.
const RECORD_REVIEW_CONTRACT_VERSION = 2;

function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Review normalized records with host-owned retrieval, source access and storage.
 * This never loads scan artifacts, spawns a model runtime, or publishes groups.
 */
export async function deduplicateRecords(
  options: DeduplicateRecordsOptions,
): Promise<DeduplicateRecordsResult> {
  options.signal?.throwIfAborted();
  const concurrency = deduplicationConcurrency(options.concurrency);
  if (!options.scopeKey.trim())
    throw new CodexSecurityError(
      "A record deduplication scopeKey is required.",
    );

  const resultToolNamespace =
    options.resultToolNamespace ?? DEFAULT_RESULT_TOOL_NAMESPACE;
  if (
    typeof resultToolNamespace !== "string" ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(resultToolNamespace)
  )
    throw new CodexSecurityError(
      "The result tool namespace must be a single identifier.",
    );

  const sourceManifest = freeze(structuredClone(options.sourceManifest));
  const sourceTools = freeze(structuredClone(options.sourceTools ?? []));
  const toolNames = new Set<string>();
  for (const tool of sourceTools) {
    const key = JSON.stringify([tool.namespace, tool.name]);
    if (
      tool.namespace === DEFAULT_RESULT_TOOL_NAMESPACE ||
      tool.namespace === resultToolNamespace ||
      toolNames.has(key)
    )
      throw new CodexSecurityError(
        "Source tools must have distinct names outside the reserved result namespaces.",
      );
    toolNames.add(key);
  }
  const priorDecisions = freeze(
    (options.priorDecisions ?? []).map(
      ({ findingIds, decision, bindingDigest }) => ({
        findingIds: structuredClone(findingIds),
        decision,
        bindingDigest,
      }),
    ),
  );
  const context = freeze({
    version: RECORD_REVIEW_CONTRACT_VERSION,
    sdkVersion: VERSION,
    scopeKey: options.scopeKey,
    settingsDigest: options.settingsDigest,
    resultToolNamespace,
    sourceManifest,
    sourceTools,
  });
  // A finding ID cannot silently acquire another record's evidence in the union
  // of neighborhoods. Freeze before giving any record to a provider or reviewer.
  const records = new Map<string, { finding: Finding; digest: string }>();
  function register(input: Finding): Finding {
    requireFinding(input);
    const finding = freeze(structuredClone(input));
    const digest = workflowDigest(finding);
    const existing = records.get(finding.findingId);
    if (existing && existing.digest !== digest)
      throw new CodexSecurityError(
        "Conflicting finding content for one deduplication identity.",
      );
    if (!existing) records.set(finding.findingId, { finding, digest });
    return existing?.finding ?? finding;
  }
  const observations = options.observations.map(register);
  const assertSourceUnchanged = async () => {
    options.signal?.throwIfAborted();
    await options.verifySource(sourceManifest);
    options.signal?.throwIfAborted();
  };
  await assertSourceUnchanged();

  function pairBinding(findingIds: readonly [string, string]): string {
    return workflowDigest({
      ...context,
      findings: [...findingIds].sort().map((id) => {
        const record = records.get(id);
        if (!record)
          throw new CodexSecurityError(
            "Prior decision refers to a finding outside the current corpus.",
          );
        return { id, digest: record.digest };
      }),
    });
  }
  const checkpointKeys = new Set<string>();
  const runner = {
    async run<T>(review: CodexReview<T>): Promise<T> {
      await assertSourceUnchanged();
      const request = {
        resultToolNamespace,
        stage: review.stage,
        model: review.model,
        effort: review.effort,
        prompt: review.prompt,
        schema: review.schema,
        instructions: {
          submission: reviewSubmissionInstructionsFor(resultToolNamespace),
          source: sourceReviewInstructions,
          error: reviewErrorInstructions,
        },
        sourceManifest,
        sourceTools,
      };
      const binding = freeze({ ...context, request, priorDecisions });
      const key = workflowDigest(binding);
      const result = await runCheckpointedReview({
        review,
        binding,
        store: options.checkpointStore,
        run: () =>
          options.reviewRunner.run(
            freeze({ ...request, checkpointKey: key }),
            options.signal,
          ),
        assertSourceUnchanged,
      });
      if (options.checkpointStore) checkpointKeys.add(key);
      return result;
    },
  };
  const core = new FindingDeduplicator(
    {
      async potentialDuplicates(id) {
        const finding = records.get(id)!.finding;
        const candidates =
          await options.candidateProvider.potentialDuplicates(finding);
        options.signal?.throwIfAborted();
        const neighbors = new Map<string, Finding>();
        for (const candidate of candidates) {
          const registered = register(candidate);
          if (registered.findingId !== id)
            neighbors.set(registered.findingId, registered);
        }
        return { finding, potentialDuplicates: [...neighbors.values()] };
      },
    },
    new CodexDeduplicationReviewer(runner, resultToolNamespace),
    options.signal,
    concurrency,
  );
  const result = await core.runDetailed(
    observations.map((finding) => finding.findingId),
    () => {
      for (const prior of priorDecisions) {
        if (
          prior.findingIds.length !== 2 ||
          !["SAME", "DISTINCT"].includes(prior.decision)
        )
          throw new CodexSecurityError(
            "Prior decisions require one assigned pair and a SAME or DISTINCT decision.",
          );
        if (prior.bindingDigest !== pairBinding(prior.findingIds))
          throw new CodexSecurityError(
            "Prior decision does not match the current record/source binding.",
          );
      }
      return priorDecisions;
    },
  );
  await assertSourceUnchanged();
  return {
    ...result,
    pairOutcomes: result.pairOutcomes.map((outcome) => ({
      ...outcome,
      bindingDigest: pairBinding(outcome.findingIds),
    })),
    checkpointKeys: [...checkpointKeys].sort(),
  };
}
