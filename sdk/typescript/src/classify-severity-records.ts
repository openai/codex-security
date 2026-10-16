import { SCAN_SEVERITIES } from "./scan-settings.js";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { abortable } from "./targets.js";
import {
  parseSeverityDecision,
  severityDecisionSchema,
  severityReviewInstructions,
  type SeverityDecision,
} from "./severity-review.js";

const text = z
  .string()
  .refine((value) => value.trim().length > 0, "Must not be blank.");
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const revision = z.number().int().nonnegative();
const reportSchema = z
  .object({
    findingId: text,
    title: text,
    summary: text,
    occurrenceId: text.optional(),
    severity: z
      .object({
        level: z.enum(SCAN_SEVERITIES),
        rationale: z.string().optional(),
        changeConditions: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

/** Versioned input for repository-free classification of canonical records. */
export const classifySeverityRecordsInputSchema = z
  .object({
    version: z.literal(1),
    rubric: z
      .object({
        revision: revision.positive(),
        markdown: text,
        sha256: digest,
      })
      .strict(),
    model: text,
    effort: z.enum([
      "minimal",
      "low",
      "medium",
      "high",
      "xhigh",
      "max",
      "ultra",
    ]),
    records: z.array(
      z
        .object({
          id: text,
          revision,
          findingJson: text,
          inputSha256: digest,
        })
        .strict(),
    ),
  })
  .strict();

export type ClassifySeverityRecordsInput = z.infer<
  typeof classifySeverityRecordsInputSchema
>;

export interface SeverityClassificationReviewRequest {
  requestId: string;
  stage: "severity-classification";
  model: string;
  effort: ClassifySeverityRecordsInput["effort"];
  trustedInstructions: string;
  prompt: string;
  schema: unknown;
}

export interface ClassifySeverityRecordsOptions {
  reviewRunner: {
    run(
      request: SeverityClassificationReviewRequest,
      options?: { signal?: AbortSignal },
    ): Promise<unknown>;
  };
  signal?: AbortSignal;
}

export type CanonicalSeverityAssessment = Omit<
  SeverityDecision,
  "findingId"
> & {
  id: string;
  revision: number;
  inputSha256: string;
};

interface RecordsResultBinding {
  version: 1;
  rubric: { revision: number; sha256: string };
}

export type ClassifySeverityRecordsResult = RecordsResultBinding &
  (
    | { status: "completed"; assessments: CanonicalSeverityAssessment[] }
    | {
        status: "unresolved";
        assessments: [];
        error: {
          recordId: string;
          code: "review_failed" | "invalid_assessment";
          message: string;
        };
      }
  );

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/**
 * Classify immutable host-provided reports. No filesystem, auth, local model,
 * repository access, retries, or persistence. The host owns those lifecycles.
 */
export async function classifySeverityRecords(
  input: ClassifySeverityRecordsInput,
  options: ClassifySeverityRecordsOptions,
): Promise<ClassifySeverityRecordsResult> {
  options.signal?.throwIfAborted();
  const data = classifySeverityRecordsInputSchema.parse(structuredClone(input));
  if (sha256(data.rubric.markdown) !== data.rubric.sha256)
    throw new Error("Rubric SHA-256 does not match its exact UTF-8 Markdown.");
  const ids = new Set<string>();
  for (const record of data.records) {
    if (ids.has(record.id))
      throw new Error("Canonical record IDs must be unique.");
    ids.add(record.id);
    if (sha256(record.findingJson) !== record.inputSha256)
      throw new Error("Finding SHA-256 does not match its exact UTF-8 JSON.");
    const report = reportSchema.parse(JSON.parse(record.findingJson));
    if (report.findingId !== record.id)
      throw new Error(
        "The report findingId must equal its canonical record ID.",
      );
  }
  const binding: RecordsResultBinding = {
    version: 1,
    rubric: { revision: data.rubric.revision, sha256: data.rubric.sha256 },
  };
  const assessments: CanonicalSeverityAssessment[] = [];
  for (const record of data.records) {
    options.signal?.throwIfAborted();
    let response: unknown;
    try {
      response = await abortable(() => {
        options.signal?.throwIfAborted();
        return options.reviewRunner.run(
          {
            requestId: randomUUID(),
            stage: "severity-classification",
            model: data.model,
            effort: data.effort,
            trustedInstructions: severityReviewInstructions,
            prompt: `{"rubric":${JSON.stringify([data.rubric.markdown])},"knowledgeBase":null,"finding":${record.findingJson}}`,
            schema: z.toJSONSchema(severityDecisionSchema),
          },
          { signal: options.signal },
        );
      }, options.signal);
    } catch (error) {
      options.signal?.throwIfAborted();
      return {
        ...binding,
        status: "unresolved",
        assessments: [],
        error: {
          recordId: record.id,
          code: "review_failed",
          message:
            error instanceof Error ? error.message : "Host review failed.",
        },
      };
    }
    options.signal?.throwIfAborted();
    try {
      const { findingId: _findingId, ...decision } = parseSeverityDecision(
        response,
        record.id,
      );
      assessments.push({
        ...decision,
        id: record.id,
        revision: record.revision,
        inputSha256: record.inputSha256,
      });
    } catch (error) {
      return {
        ...binding,
        status: "unresolved",
        assessments: [],
        error: {
          recordId: record.id,
          code: "invalid_assessment",
          message:
            error instanceof Error ? error.message : "Invalid assessment.",
        },
      };
    }
  }
  return { ...binding, status: "completed", assessments };
}
