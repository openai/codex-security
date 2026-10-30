import { SCAN_SEVERITIES } from "./scan-settings.js";
import {
  getDefaultSeverityRubric,
  severityRubricSchema,
} from "./severity-rubric.js";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { abortable } from "./targets.js";
import {
  parseSeverityDecision,
  reviewSeverity,
  classificationRunsSchema,
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
    rubric: severityRubricSchema.optional(),
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
  /** Independent reviews per record: integer 1–10, default 3. */
  classificationRuns?: number;
  reviewRunner: {
    run(
      request: SeverityClassificationReviewRequest,
      options?: { signal?: AbortSignal },
    ): Promise<unknown>;
  };
  signal?: AbortSignal;
  environment?: NodeJS.ProcessEnv;
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
  classificationRuns: number;
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
  const classificationRuns = classificationRunsSchema
    .default(3)
    .parse(options.classificationRuns);
  const data = classifySeverityRecordsInputSchema.parse(structuredClone(input));
  const rubric = data.rubric ?? (await getDefaultSeverityRubric(options));
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
    classificationRuns,
    version: 1,
    rubric: { revision: rubric.revision, sha256: rubric.sha256 },
  };
  const assessments: CanonicalSeverityAssessment[] = [];
  for (const record of data.records) {
    options.signal?.throwIfAborted();
    let code: "review_failed" | "invalid_assessment" = "review_failed";
    try {
      const { findingId: _findingId, ...decision } = await reviewSeverity(
        async () => {
          code = "review_failed";
          const response = await abortable(() => {
            options.signal?.throwIfAborted();
            return options.reviewRunner.run(
              {
                requestId: randomUUID(),
                stage: "severity-classification",
                model: data.model,
                effort: data.effort,
                trustedInstructions: severityReviewInstructions,
                prompt: `{"rubric":${JSON.stringify([rubric.markdown])},"knowledgeBase":null,"finding":${record.findingJson}}`,
                schema: z.toJSONSchema(severityDecisionSchema),
              },
              { signal: options.signal },
            );
          }, options.signal);
          options.signal?.throwIfAborted();
          code = "invalid_assessment";
          return parseSeverityDecision(response, record.id);
        },
        classificationRuns,
      );
      options.signal?.throwIfAborted();
      assessments.push({
        ...decision,
        id: record.id,
        revision: record.revision,
        inputSha256: record.inputSha256,
      });
    } catch (error) {
      options.signal?.throwIfAborted();
      return {
        ...binding,
        status: "unresolved",
        assessments: [],
        error: {
          recordId: record.id,
          code,
          message:
            error instanceof Error
              ? error.message
              : code === "review_failed"
                ? "Host review failed."
                : "Invalid assessment.",
        },
      };
    }
  }
  return { ...binding, status: "completed", assessments };
}
